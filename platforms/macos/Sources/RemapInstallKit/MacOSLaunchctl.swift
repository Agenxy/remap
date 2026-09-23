import Darwin
import Foundation
import Security

enum MacOSLaunchdObservation: Equatable, Sendable {
    case loaded(plistPath: InstallAbsolutePath, programPath: InstallAbsolutePath)
    case missing
}

protocol MacOSLaunchdControlling: Sendable {
    func observation(label: String) throws -> MacOSLaunchdObservation
    func bootstrap(plistPath: InstallAbsolutePath) throws
    func bootout(label: String, expected: MacOSLaunchdObservation) throws
    func kickstart(label: String) throws
}

/// Typed boundary around Apple's absolute launchctl binary.
///
/// Apple exposes no public framework API for loading an unsigned source-build LaunchDaemon.
/// This adapter never invokes a shell, accepts only typed argument shapes, authenticates the
/// executable as Apple code, bounds runtime and output, and independently observes every effect.
struct NativeMacOSLaunchdController: MacOSLaunchdControlling, Sendable {
    private let runner: any LaunchctlRunning
    private let unloadTimeout: Duration

    init(runner: any LaunchctlRunning = NativeLaunchctlRunner(), unloadTimeout: Duration = .seconds(5)) {
        self.runner = runner
        self.unloadTimeout = unloadTimeout
    }

    func observation(label: String) throws -> MacOSLaunchdObservation {
        try InstallManifest.validateIdentifier(label, field: "launchd label")
        let result = try runner.run(.print(label: label))
        if result.exitStatus == 113 {
            return .missing
        }
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem("inspect the launchd service", result.exitStatus)
        }
        guard let plist = field("path", in: result.output),
              let program = field("program", in: result.output)
        else {
            throw InstallError.integrity("launchd did not report the loaded plist and program paths")
        }
        return try .loaded(
            plistPath: InstallAbsolutePath(plist),
            programPath: InstallAbsolutePath(program)
        )
    }

    func bootstrap(plistPath: InstallAbsolutePath) throws {
        try requireSuccess(.bootstrap(plistPath: plistPath), operation: "load the launchd service")
    }

    func bootout(label: String, expected: MacOSLaunchdObservation) throws {
        let departing = try observation(label: label)
        guard departing != .missing else { return }
        guard departing == expected else {
            throw InstallError.collision("launchd service \(label)")
        }
        try requireSuccess(.bootout(label: label), operation: "unload the launchd service")
        let deadline = ContinuousClock.now.advanced(by: unloadTimeout)
        while true {
            let current = try observation(label: label)
            if current == .missing {
                return
            }
            guard current == departing else {
                throw InstallError.collision("launchd service \(label)")
            }
            guard ContinuousClock.now < deadline else {
                throw InstallError.integrity("launchd did not unload \(label) before the teardown deadline")
            }
            Thread.sleep(forTimeInterval: 0.1)
        }
    }

    func kickstart(label: String) throws {
        try requireSuccess(.kickstart(label: label), operation: "start the launchd service")
    }

    private func requireSuccess(_ command: LaunchctlCommand, operation: String) throws {
        let result = try runner.run(command)
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem(operation, result.exitStatus)
        }
    }

    /// The service's own value for `key`: the line one tab deep, where
    /// `launchctl print` puts the service's fields. Deeper lines belong to
    /// nested dictionaries (a Unix socket under `Sockets` has a `path` too)
    /// and are not the service's.
    private func field(_ key: String, in output: String) -> String? {
        let prefix = "\t" + key + " = "
        let values = output.split(separator: "\n").compactMap { line -> String? in
            line.hasPrefix(prefix) ? String(line.dropFirst(prefix.count)) : nil
        }
        return values.count == 1 ? values[0] : nil
    }
}

enum LaunchctlCommand: Equatable, Sendable {
    case bootstrap(plistPath: InstallAbsolutePath)
    case bootout(label: String)
    case kickstart(label: String)
    case print(label: String)

    var arguments: [String] {
        switch self {
        case let .bootstrap(plistPath):
            ["bootstrap", "system", plistPath.value]
        case let .bootout(label):
            ["bootout", "system/\(label)"]
        case let .kickstart(label):
            ["kickstart", "-k", "system/\(label)"]
        case let .print(label):
            ["print", "system/\(label)"]
        }
    }
}

struct LaunchctlResult: Equatable, Sendable {
    let exitStatus: Int32
    let output: String
}

protocol LaunchctlRunning: Sendable {
    func run(_ command: LaunchctlCommand) throws -> LaunchctlResult
}

struct NativeLaunchctlRunner: LaunchctlRunning, Sendable {
    private static let executable = "/bin/launchctl"
    private static let maximumOutputBytes = 65536
    private static let timeout = DispatchTimeInterval.seconds(5)

    init() {}

    func run(_ command: LaunchctlCommand) throws -> LaunchctlResult {
        try LaunchctlExecutableIdentity.validate(path: Self.executable)
        let process = Process()
        let pipe = Pipe()
        let output = LaunchctlOutputReader(
            handle: pipe.fileHandleForReading,
            maximumByteCount: Self.maximumOutputBytes
        )
        process.executableURL = URL(fileURLWithPath: Self.executable)
        process.arguments = command.arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin"]
        process.currentDirectoryURL = URL(fileURLWithPath: "/", isDirectory: true)
        process.standardOutput = pipe
        process.standardError = pipe
        let terminated = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in terminated.signal() }
        output.start()
        do {
            try process.run()
        } catch {
            output.stop()
            throw InstallError.operatingSystem("start Apple's launchctl", errno)
        }
        guard terminated.wait(timeout: .now() + Self.timeout) == .success else {
            process.terminate()
            if terminated.wait(timeout: .now() + .milliseconds(500)) == .timedOut {
                _ = kill(process.processIdentifier, SIGKILL)
                _ = terminated.wait(timeout: .now() + .milliseconds(500))
            }
            output.stop()
            throw InstallError.integrity("launchctl exceeded its five-second execution bound")
        }
        let data = output.finish()
        guard !output.exceededLimit else {
            throw InstallError.integrity("launchctl exceeded its output bound")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw InstallError.integrity("launchctl returned non-UTF-8 output")
        }
        return LaunchctlResult(exitStatus: process.terminationStatus, output: text)
    }
}

private final class LaunchctlOutputReader: @unchecked Sendable {
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

private enum LaunchctlExecutableIdentity {
    static func validate(path: String) throws {
        var status = stat()
        guard lstat(path, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_uid == 0,
              status.st_mode & 0o022 == 0
        else {
            throw InstallError.integrity("the absolute launchctl path is not a protected root-owned file")
        }
        var code: SecStaticCode?
        let url = URL(fileURLWithPath: path) as CFURL
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code else {
            throw InstallError.integrity("launchctl has no verifiable code identity")
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString("anchor apple" as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), requirement) == errSecSuccess
        else {
            throw InstallError.integrity("launchctl is not valid Apple-signed code")
        }
    }
}

/// The one fixed launchd publication used to bootstrap Remap's authenticated
/// lifecycle service from the native Installer package.
public enum MacOSInstallerServiceLaunchd {
    public static let label = "org.agenxy.Remap.installer-service"
    public static let plistPath = "/Library/LaunchDaemons/org.agenxy.Remap.installer-service.plist"
    public static let programPath = "/Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"

    public static func bootstrap() throws {
        try bootstrap(controller: NativeMacOSLaunchdController())
    }

    public static func bootout() throws {
        try bootoutIfLoaded()
    }

    public static func bootoutIfLoaded() throws {
        let controller = NativeMacOSLaunchdController()
        let expected = try MacOSLaunchdObservation.loaded(
            plistPath: InstallAbsolutePath(plistPath),
            programPath: InstallAbsolutePath(programPath)
        )
        switch try controller.observation(label: label) {
        case .missing:
            return
        case expected:
            try controller.bootout(label: label, expected: expected)
        default:
            throw InstallError.collision("system/\(label)")
        }
    }

    static func bootstrap(controller: any MacOSLaunchdControlling) throws {
        let expected = try MacOSLaunchdObservation.loaded(
            plistPath: InstallAbsolutePath(plistPath),
            programPath: InstallAbsolutePath(programPath)
        )
        switch try controller.observation(label: label) {
        case .missing:
            try controller.bootstrap(plistPath: InstallAbsolutePath(plistPath))
        case expected:
            // Apple Installer can atomically replace the helper while launchd still
            // runs the old vnode. Restart the exact loaded job before accepting the
            // repaired lifecycle authority.
            try controller.kickstart(label: label)
        default:
            throw InstallError.collision("system/\(label)")
        }
        guard try controller.observation(label: label) == expected else {
            throw InstallError.integrity("launchd did not load the exact lifecycle service")
        }
    }
}
