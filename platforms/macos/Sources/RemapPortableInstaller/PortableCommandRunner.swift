import Darwin
import Foundation
import RemapInstallKit
import Security

struct PortableCommandResult: Equatable, Sendable {
    let exitStatus: Int32
    let output: Data

    func utf8Output(named operation: String) throws -> String {
        guard let value = String(data: output, encoding: .utf8) else {
            throw InstallError.integrity("\(operation) returned non-UTF-8 output")
        }
        return value
    }
}

struct PortableCommandRunner: Sendable {
    private static let maximumArgumentCount = 64
    private static let maximumArgumentBytes = 65536
    private static let maximumInputBytes = 1_048_576
    private static let maximumOutputBytes = 1_048_576

    func run(
        executable: String,
        arguments: [String],
        input: Data? = nil,
        timeoutSeconds: UInt32 = 30
    ) throws -> PortableCommandResult {
        try validate(
            executable: executable,
            arguments: arguments,
            input: input,
            timeoutSeconds: timeoutSeconds
        )
        try PortableAppleExecutable.validate(executable)
        return try spawn(
            executable: executable,
            arguments: arguments,
            input: input ?? Data(),
            timeoutSeconds: timeoutSeconds
        )
    }

    private func validate(
        executable: String,
        arguments: [String],
        input: Data?,
        timeoutSeconds: UInt32
    ) throws {
        guard executable.hasPrefix("/"),
              URL(fileURLWithPath: executable).standardizedFileURL.path == executable,
              !executable.contains("\0"),
              arguments.count <= Self.maximumArgumentCount,
              arguments.allSatisfy({ !$0.contains("\0") }),
              arguments.reduce(0, { $0 + $1.utf8.count }) <= Self.maximumArgumentBytes,
              (input?.count ?? 0) <= Self.maximumInputBytes,
              1 ... 120 ~= timeoutSeconds
        else {
            throw InstallError.integrity("a portable installer command exceeded its fixed bounds")
        }
    }

    private func spawn(
        executable: String,
        arguments: [String],
        input: Data,
        timeoutSeconds: UInt32
    ) throws -> PortableCommandResult {
        var standardInput = [Int32](repeating: -1, count: 2)
        var combinedOutput = [Int32](repeating: -1, count: 2)
        guard pipe(&standardInput) == 0, pipe(&combinedOutput) == 0 else {
            closePipe(&standardInput)
            closePipe(&combinedOutput)
            throw InstallError.operatingSystem("create portable installer command pipes", errno)
        }
        defer {
            closePipe(&standardInput)
            closePipe(&combinedOutput)
        }
        var actions: posix_spawn_file_actions_t?
        var attributes: posix_spawnattr_t?
        guard posix_spawn_file_actions_init(&actions) == 0,
              posix_spawnattr_init(&attributes) == 0
        else {
            throw InstallError.operatingSystem("initialize a portable installer command", errno)
        }
        defer {
            posix_spawn_file_actions_destroy(&actions)
            posix_spawnattr_destroy(&attributes)
        }
        try addFileActions(
            &actions,
            standardInput: standardInput,
            combinedOutput: combinedOutput
        )
        let spawnFlags = Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
        guard posix_spawnattr_setflags(&attributes, spawnFlags) == 0,
              posix_spawnattr_setpgroup(&attributes, 0) == 0
        else {
            throw InstallError.operatingSystem("isolate a portable installer command", errno)
        }
        var processID: pid_t = 0
        let values = [executable] + arguments
        let environment = [
            "HOME=/var/root",
            "LANG=C",
            "LC_ALL=C",
            "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
            "TMPDIR=/private/var/tmp"
        ]
        let spawnStatus = withCStringArray(values) { argumentValues in
            withCStringArray(environment) { environmentValues in
                posix_spawn(
                    &processID,
                    executable,
                    &actions,
                    &attributes,
                    argumentValues,
                    environmentValues
                )
            }
        }
        guard spawnStatus == 0 else {
            throw InstallError.operatingSystem("start a portable installer command", spawnStatus)
        }
        close(standardInput[0])
        standardInput[0] = -1
        close(combinedOutput[1])
        combinedOutput[1] = -1
        try setNonblocking(combinedOutput[0])
        let writer = PortableInputWriter(descriptor: standardInput[1], data: input)
        standardInput[1] = -1
        writer.start()
        return try collect(
            processID: processID,
            outputDescriptor: combinedOutput[0],
            timeoutSeconds: timeoutSeconds,
            writer: writer
        )
    }

    private func addFileActions(
        _ actions: inout posix_spawn_file_actions_t?,
        standardInput: [Int32],
        combinedOutput: [Int32]
    ) throws {
        let calls = [
            posix_spawn_file_actions_adddup2(&actions, standardInput[0], STDIN_FILENO),
            posix_spawn_file_actions_adddup2(&actions, combinedOutput[1], STDOUT_FILENO),
            posix_spawn_file_actions_adddup2(&actions, combinedOutput[1], STDERR_FILENO),
            posix_spawn_file_actions_addclose(&actions, standardInput[1]),
            posix_spawn_file_actions_addclose(&actions, combinedOutput[0])
        ]
        guard calls.allSatisfy({ $0 == 0 }) else {
            throw InstallError.operatingSystem("configure portable installer command pipes", errno)
        }
    }

    private func collect(
        processID: pid_t,
        outputDescriptor: Int32,
        timeoutSeconds: UInt32,
        writer: PortableInputWriter
    ) throws -> PortableCommandResult {
        let deadline = DispatchTime.now() + .seconds(Int(timeoutSeconds))
        var output = Data()
        var waitStatus: Int32 = 0
        while true {
            _ = try drain(outputDescriptor, into: &output)
            if output.count > Self.maximumOutputBytes {
                terminate(processID)
                _ = waitpid(processID, &waitStatus, 0)
                throw InstallError.integrity("a portable installer command exceeded its output bound")
            }
            let observed = waitpid(processID, &waitStatus, WNOHANG)
            if observed == processID {
                break
            }
            guard observed == 0 else {
                terminate(processID)
                throw InstallError.operatingSystem("wait for a portable installer command", errno)
            }
            guard DispatchTime.now() < deadline else {
                terminate(processID)
                _ = waitpid(processID, &waitStatus, 0)
                throw InstallError.integrity("a portable installer command exceeded its time bound")
            }
            usleep(10000)
        }
        do {
            try drainUntilClosed(outputDescriptor, into: &output)
            try writer.finish()
            guard output.count <= Self.maximumOutputBytes else {
                throw InstallError.integrity("a portable installer command exceeded its output bound")
            }
        } catch {
            terminate(processID)
            throw error
        }
        return PortableCommandResult(
            exitStatus: decodedExitStatus(waitStatus),
            output: output
        )
    }

    private func drain(_ descriptor: Int32, into output: inout Data) throws -> Bool {
        var bytes = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = read(descriptor, &bytes, bytes.count)
            if count > 0 {
                output.append(contentsOf: bytes.prefix(count))
            } else if count == 0 {
                return true
            } else if errno == EAGAIN || errno == EWOULDBLOCK {
                return false
            } else if errno != EINTR {
                throw InstallError.operatingSystem("read portable installer command output", errno)
            }
        }
    }

    private func drainUntilClosed(_ descriptor: Int32, into output: inout Data) throws {
        let deadline = DispatchTime.now() + .seconds(1)
        while DispatchTime.now() < deadline {
            if try drain(descriptor, into: &output) {
                return
            }
            usleep(5000)
        }
        throw InstallError.integrity("a portable installer command left its output pipe open")
    }

    private func terminate(_ processID: pid_t) {
        _ = kill(-processID, SIGTERM)
        usleep(100_000)
        _ = kill(-processID, SIGKILL)
    }

    private func decodedExitStatus(_ status: Int32) -> Int32 {
        let signal = status & 0x7F
        return signal == 0 ? (status >> 8) & 0xFF : 128 + signal
    }

    private func setNonblocking(_ descriptor: Int32) throws {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw InstallError.operatingSystem("bound portable installer command output", errno)
        }
    }

    private func closePipe(_ descriptors: inout [Int32]) {
        for index in descriptors.indices where descriptors[index] >= 0 {
            close(descriptors[index])
            descriptors[index] = -1
        }
    }

    private func withCStringArray<Result>(
        _ values: [String],
        body: (UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>) -> Result
    ) -> Result {
        var pointers = values.map { strdup($0) }
        pointers.append(nil)
        defer {
            for pointer in pointers where pointer != nil {
                free(pointer)
            }
        }
        return pointers.withUnsafeMutableBufferPointer { buffer in
            body(buffer.baseAddress!)
        }
    }
}

private final class PortableInputWriter: @unchecked Sendable {
    private let descriptor: Int32
    private let data: Data
    private let finished = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var failure: Int32?

    init(descriptor: Int32, data: Data) {
        self.descriptor = descriptor
        self.data = data
    }

    func start() {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            defer {
                close(descriptor)
                finished.signal()
            }
            data.withUnsafeBytes { rawBuffer in
                guard let base = rawBuffer.baseAddress else {
                    return
                }
                var offset = 0
                while offset < rawBuffer.count {
                    let count = write(descriptor, base.advanced(by: offset), rawBuffer.count - offset)
                    if count > 0 {
                        offset += count
                    } else if errno != EINTR {
                        lock.withLock { failure = errno }
                        return
                    }
                }
            }
        }
    }

    func finish() throws {
        guard finished.wait(timeout: .now() + .seconds(1)) == .success else {
            throw InstallError.integrity("a portable installer command did not close its input")
        }
        if let failure = lock.withLock({ failure }), failure != EPIPE {
            throw InstallError.operatingSystem("write portable installer command input", failure)
        }
    }
}

private enum PortableAppleExecutable {
    static func validate(_ path: String) throws {
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == 0,
              status.st_mode & 0o022 == 0
        else {
            throw InstallError.integrity("a portable installer system tool is not protected")
        }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
            == errSecSuccess,
            let code
        else {
            throw InstallError.integrity("a portable installer system tool has no code identity")
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement)
            == errSecSuccess,
            let requirement,
            SecStaticCodeCheckValidity(
                code,
                SecCSFlags(rawValue: kSecCSStrictValidate),
                requirement
            ) == errSecSuccess
        else {
            throw InstallError.integrity("a portable installer system tool is not Apple-signed")
        }
    }
}
