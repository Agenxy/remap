import Darwin
import Foundation
import Security

protocol MacOSPackageReceiptControlling: Sendable {
    func version() throws -> String?
    func forget(expectedVersion: String?) throws
}

struct MacOSPackageReceiptStore: MacOSPackageReceiptControlling, Sendable {
    static let identifier = "org.agenxy.Remap.PortableInstaller"

    private let runner: any MacOSPackageReceiptRunning

    static func production() -> Self {
        Self(runner: NativeMacOSPackageReceiptRunner())
    }

    init(runner: any MacOSPackageReceiptRunning) {
        self.runner = runner
    }

    func version() throws -> String? {
        let result = try runner.run(.info)
        if result.exitStatus == 1 {
            guard result.output == Data(Self.missingReceiptMessage.utf8) else {
                throw InstallError.integrity("pkgutil failed while checking Remap's receipt")
            }
            return nil
        }
        guard result.exitStatus == 0,
              result.output.count <= 65536,
              let document = try PropertyListSerialization.propertyList(
                  from: result.output,
                  options: [],
                  format: nil
              ) as? [String: Any],
              Set(document.keys) == [
                  "install-location", "install-time", "pkg-version", "pkgid",
                  "receipt-plist-version", "volume"
              ],
              document["pkgid"] as? String == Self.identifier,
              let installLocation = document["install-location"] as? String,
              installLocation.isEmpty || installLocation == "/",
              document["volume"] as? String == "/",
              document["receipt-plist-version"] as? Int == 1,
              let installTime = document["install-time"] as? Int,
              installTime > 0,
              let version = document["pkg-version"] as? String,
              Self.validVersion(version)
        else {
            throw InstallError.integrity("the Remap package receipt is malformed")
        }
        return version
    }

    func forget(expectedVersion: String?) throws {
        let observed = try version()
        if observed == nil, expectedVersion != nil {
            return
        }
        guard observed == expectedVersion else {
            throw InstallError.collision("package receipt \(Self.identifier)")
        }
        guard observed != nil else {
            return
        }
        let result = try runner.run(.forget)
        guard result.exitStatus == 0, try version() == nil else {
            throw InstallError.integrity("macOS did not remove Remap's package receipt")
        }
    }

    static func validVersion(_ value: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "0123456789.-+")
        return !value.isEmpty
            && value.utf8.count <= 64
            && value.unicodeScalars.allSatisfy(allowed.contains)
    }

    static let missingReceiptMessage =
        "No receipt for '\(identifier)' found at '/'.\n"
}

enum MacOSPackageReceiptCommand: Equatable, Sendable {
    case info
    case forget

    var arguments: [String] {
        switch self {
        case .info:
            ["--pkg-info-plist", MacOSPackageReceiptStore.identifier]
        case .forget:
            ["--forget", MacOSPackageReceiptStore.identifier]
        }
    }
}

struct MacOSPackageReceiptResult: Sendable {
    let exitStatus: Int32
    let output: Data
}

protocol MacOSPackageReceiptRunning: Sendable {
    func run(_ command: MacOSPackageReceiptCommand) throws -> MacOSPackageReceiptResult
}

struct MissingMacOSPackageReceiptRunner: MacOSPackageReceiptRunning, Sendable {
    func run(_ command: MacOSPackageReceiptCommand) throws -> MacOSPackageReceiptResult {
        switch command {
        case .info:
            MacOSPackageReceiptResult(
                exitStatus: 1,
                output: Data(MacOSPackageReceiptStore.missingReceiptMessage.utf8)
            )
        case .forget:
            throw InstallError.integrity("a missing package receipt cannot be forgotten")
        }
    }
}

struct NativeMacOSPackageReceiptRunner: MacOSPackageReceiptRunning, Sendable {
    private static let executable = "/usr/sbin/pkgutil"
    private static let maximumOutputBytes = 65536

    func run(_ command: MacOSPackageReceiptCommand) throws -> MacOSPackageReceiptResult {
        try validateExecutable()
        let process = Process()
        let pipe = Pipe()
        let reader = MacOSPackageReceiptOutputReader(
            handle: pipe.fileHandleForReading,
            maximumByteCount: Self.maximumOutputBytes
        )
        process.executableURL = URL(fileURLWithPath: Self.executable)
        process.arguments = command.arguments
        process.environment = [
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin"
        ]
        process.currentDirectoryURL = URL(fileURLWithPath: "/", isDirectory: true)
        process.standardOutput = pipe
        process.standardError = pipe
        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        reader.start()
        do {
            try process.run()
        } catch {
            reader.stop()
            throw InstallError.operatingSystem("start Apple's pkgutil", errno)
        }
        guard terminated.wait(timeout: .now() + .seconds(5)) == .success else {
            process.terminate()
            if terminated.wait(timeout: .now() + .milliseconds(500)) == .timedOut {
                _ = kill(process.processIdentifier, SIGKILL)
                _ = terminated.wait(timeout: .now() + .milliseconds(500))
            }
            reader.stop()
            throw InstallError.integrity("pkgutil exceeded its five-second execution bound")
        }
        let data = reader.finish()
        guard !reader.exceededLimit else {
            throw InstallError.integrity("pkgutil exceeded its output bound")
        }
        return MacOSPackageReceiptResult(
            exitStatus: process.terminationStatus,
            output: data
        )
    }

    private func validateExecutable() throws {
        var status = stat()
        guard lstat(Self.executable, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == 0,
              status.st_mode & 0o022 == 0
        else {
            throw InstallError.integrity("the absolute pkgutil path is not protected")
        }
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: Self.executable) as CFURL
        var requirement: SecRequirement?
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess,
              let code,
              SecRequirementCreateWithString(
                  "anchor apple" as CFString,
                  [],
                  &requirement
              ) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(
                  code,
                  SecCSFlags(rawValue: kSecCSStrictValidate),
                  requirement
              )
              == errSecSuccess
        else {
            throw InstallError.integrity("pkgutil is not valid Apple-signed code")
        }
    }
}

private final class MacOSPackageReceiptOutputReader: @unchecked Sendable {
    private let handle: FileHandle
    private let maximumByteCount: Int
    private let lock = NSLock()
    private let finished = DispatchSemaphore(value: 0)
    private var data = Data()
    private var overflow = false

    var exceededLimit: Bool {
        lock.withLock { overflow }
    }

    init(handle: FileHandle, maximumByteCount: Int) {
        self.handle = handle
        self.maximumByteCount = maximumByteCount
    }

    func start() {
        DispatchQueue.global(qos: .userInitiated).async { [self] in
            while let chunk = try? handle.read(upToCount: 4096), !chunk.isEmpty {
                lock.withLock {
                    if data.count <= maximumByteCount - chunk.count {
                        data.append(chunk)
                    } else {
                        overflow = true
                    }
                }
            }
            finished.signal()
        }
    }

    func stop() {
        try? handle.close()
        _ = finished.wait(timeout: .now() + .milliseconds(500))
    }

    func finish() -> Data {
        _ = finished.wait(timeout: .now() + .milliseconds(500))
        return lock.withLock { data }
    }
}
