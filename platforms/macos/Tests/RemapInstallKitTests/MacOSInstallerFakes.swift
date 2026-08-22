import Foundation
@testable import RemapInstallKit

func daemonPlist(
    configuration: MacOSInstallConfiguration,
    program: String
) throws -> Data {
    let stream: [String: Any] = [
        "SockFamily": "IPv4",
        "SockNodeName": "127.0.0.1",
        "SockPassive": true,
        "SockProtocol": "TCP",
        "SockType": "stream"
    ]
    let account = try MacOSAccountLookup.account(for: configuration.ownerUID)
    return try propertyListData([
        "GroupName": account.groupName,
        "HardResourceLimits": ["Core": 0, "NumberOfFiles": 4096],
        "KeepAlive": true,
        "Label": MacOSLaunchdServiceKind.daemon.label,
        "ProcessType": "Background",
        "ProgramArguments": [
            program,
            "--data-dir",
            configuration.dataDirectory.value,
            "--dns-listen",
            "127.0.0.1:53",
            "--http-listen",
            "127.0.0.1:80",
            "--system-socket",
            configuration.systemSocketPath,
            "--launchd-sockets"
        ],
        "RunAtLoad": true,
        "Sockets": [
            "remap-dns-tcp": stream.merging(["SockServiceName": "53"]) { _, next in next },
            "remap-dns-udp": [
                "SockFamily": "IPv4",
                "SockNodeName": "127.0.0.1",
                "SockProtocol": "UDP",
                "SockServiceName": "53",
                "SockType": "dgram"
            ],
            "remap-http": stream.merging(["SockServiceName": "80"]) { _, next in next },
            "remap-system": [
                "SockPathMode": 0o600,
                "SockPathName": configuration.systemSocketPath,
                "SockType": "stream"
            ]
        ],
        "SoftResourceLimits": ["NumberOfFiles": 4096],
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "ThrottleInterval": 5,
        "Umask": 0o77,
        "UserName": account.userName,
        "WorkingDirectory": configuration.dataDirectory.value
    ])
}

func resolverPlist(
    configuration: MacOSInstallConfiguration,
    program: String
) throws -> Data {
    try propertyListData([
        "HardResourceLimits": ["Core": 0, "NumberOfFiles": 128],
        "KeepAlive": true,
        "Label": MacOSLaunchdServiceKind.resolver.label,
        "ProcessType": "Background",
        "ProgramArguments": [
            program,
            "run",
            "--owner-uid",
            String(configuration.ownerUID),
            "--system-socket",
            configuration.systemSocketPath
        ],
        "RunAtLoad": true,
        "SoftResourceLimits": ["NumberOfFiles": 128],
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "ThrottleInterval": 5,
        "Umask": 0o77
    ])
}

private func propertyListData(_ document: [String: Any]) throws -> Data {
    try PropertyListSerialization.data(fromPropertyList: document, format: .xml, options: 0)
}

final class FakeMacOSLaunchdController: @unchecked Sendable, MacOSLaunchdControlling {
    private let lock = NSLock()
    private let systemRoot: String
    private var generationID: String
    private var observations: [String: MacOSLaunchdObservation] = [:]
    private var pendingBootouts: [String: Int] = [:]
    private var recordedBootouts = 0
    private var recordedKickstarts = 0

    var bootoutCount: Int {
        lock.withLock { recordedBootouts }
    }

    var kickstartCount: Int {
        lock.withLock { recordedKickstarts }
    }

    init(systemRoot: String, generationID: String) {
        self.systemRoot = systemRoot
        self.generationID = generationID
    }

    func observation(label: String) throws -> MacOSLaunchdObservation {
        lock.withLock {
            if let remaining = pendingBootouts[label] {
                if remaining > 0 {
                    pendingBootouts[label] = remaining - 1
                } else {
                    pendingBootouts.removeValue(forKey: label)
                    observations[label] = .missing
                }
            }
            return observations[label] ?? .missing
        }
    }

    func bootstrap(plistPath: InstallAbsolutePath) throws {
        let kind = try serviceKind(for: plistPath)
        let program = try programPath(for: kind)
        lock.withLock {
            observations[kind.label] = .loaded(plistPath: plistPath, programPath: program)
        }
    }

    func bootout(label: String) throws {
        lock.withLock {
            recordedBootouts += 1
            if pendingBootouts[label] == nil {
                observations[label] = .missing
            }
        }
    }

    func enable(label _: String) throws {}

    func kickstart(label _: String) throws {
        lock.withLock { recordedKickstarts += 1 }
    }

    func injectForeignDaemon() {
        lock.withLock {
            observations[MacOSLaunchdServiceKind.daemon.label] = .loaded(
                plistPath: foreignPath(),
                programPath: foreignPath()
            )
        }
    }

    func selectGeneration(_ generationID: String) {
        lock.withLock {
            self.generationID = generationID
        }
    }

    func delayEveryBootoutObservation(by count: Int) {
        precondition(count > 0)
        lock.withLock {
            for kind in MacOSLaunchdServiceKind.allCases {
                pendingBootouts[kind.label] = count
            }
        }
    }

    private func serviceKind(for plistPath: InstallAbsolutePath) throws -> MacOSLaunchdServiceKind {
        guard let kind = MacOSLaunchdServiceKind.allCases.first(where: {
            plistPath.value.hasSuffix("/\($0.plistEntry)")
        }) else {
            throw InstallError.integrity("fake launchd received an unknown plist")
        }
        return kind
    }

    private func programPath(for kind: MacOSLaunchdServiceKind) throws -> InstallAbsolutePath {
        let generationID = lock.withLock { generationID }
        return try InstallAbsolutePath(
            systemRoot + "/" + MacOSInstallLayout.installerBase
                + "/Generations/\(generationID)/\(kind.programEntry)"
        )
    }

    private func foreignPath() -> InstallAbsolutePath {
        do {
            return try InstallAbsolutePath("/usr/local/libexec/foreign")
        } catch {
            preconditionFailure("the fixed fake path must be valid")
        }
    }
}

final class FakeMacOSResolverController: @unchecked Sendable, MacOSResolverControlling {
    private let lock = NSLock()
    private var state = MacOSResolverObservation(
        ownerUID: nil,
        productVersion: nil,
        phase: nil,
        configuredServiceIDs: [],
        remapServiceIDs: []
    )
    private var events: [String] = []
    private var rejectNextActivation = false

    func observation() throws -> MacOSResolverObservation {
        lock.withLock { state }
    }

    func setObservation(_ observation: MacOSResolverObservation) {
        lock.withLock {
            state = observation
        }
    }

    func eventSnapshot() -> [String] {
        lock.withLock { events }
    }

    func failNextActivation() {
        lock.withLock { rejectNextActivation = true }
    }

    func activate(
        configuration: MacOSInstallConfiguration,
        productVersion: String
    ) async throws {
        try lock.withLock {
            events.append("publish-plan-before-dns")
            if rejectNextActivation {
                rejectNextActivation = false
                state = MacOSResolverObservation(
                    ownerUID: configuration.ownerUID,
                    productVersion: productVersion,
                    phase: .prepared,
                    configuredServiceIDs: ["test-service"],
                    remapServiceIDs: []
                )
                throw InstallError.integrity("prepared resolver plan was rejected")
            }
            events.append("activate-dns")
            state = MacOSResolverObservation(
                ownerUID: configuration.ownerUID,
                productVersion: productVersion,
                phase: .active,
                configuredServiceIDs: ["test-service"],
                remapServiceIDs: ["test-service"]
            )
        }
    }

    func deactivate() throws {
        lock.withLock {
            events.append("restore-ordinary-dns")
            state = MacOSResolverObservation(
                ownerUID: nil,
                productVersion: nil,
                phase: nil,
                configuredServiceIDs: [],
                remapServiceIDs: []
            )
        }
    }
}

struct FakeMacOSRuntimeHealthChecker: MacOSRuntimeHealthChecking {
    let fails: Bool

    func wait(
        configuration _: MacOSInstallConfiguration,
        productVersion: String,
        requirement: MacOSRuntimeRequirement
    ) async throws -> MacOSRuntimeHealth {
        if fails {
            throw InstallError.integrity("authenticated runtime fault")
        }
        switch requirement {
        case .unavailable:
            return MacOSRuntimeHealth(daemonVersion: nil, authority: false, dns: false, http: false)
        case .authority:
            return MacOSRuntimeHealth(daemonVersion: productVersion, authority: true, dns: false, http: false)
        case .dns:
            return MacOSRuntimeHealth(daemonVersion: productVersion, authority: true, dns: true, http: false)
        case .ready:
            return MacOSRuntimeHealth(daemonVersion: productVersion, authority: true, dns: true, http: true)
        }
    }
}
