import Darwin
import Foundation

enum MacOSPortableLaunchd {
    static func documents(
        generationID: String,
        account: MacOSAccount,
        ownerUID: UInt32,
        dataDirectory: String,
        upstreams: [String]
    ) throws -> [String: [String: Any]] {
        try validate(upstreams: upstreams)
        return [
            MacOSLaunchdServiceKind.daemon.label: daemon(
                generationID: generationID,
                account: account,
                dataDirectory: dataDirectory
            ),
            MacOSLaunchdServiceKind.resolver.label: resolver(
                generationID: generationID,
                ownerUID: ownerUID
            )
        ]
    }

    private static func daemon(
        generationID: String,
        account: MacOSAccount,
        dataDirectory: String
    ) -> [String: Any] {
        let program = generationRoot(generationID) + "/libexec/remapd"
        let stream = tcpSocket()
        return [
            "GroupName": account.groupName,
            "HardResourceLimits": ["Core": 0, "NumberOfFiles": 4096],
            "KeepAlive": true,
            "Label": MacOSLaunchdServiceKind.daemon.label,
            "ProcessType": "Background",
            "ProgramArguments": [
                program,
                "--data-dir",
                dataDirectory,
                "--dns-listen",
                "127.0.0.1:53",
                "--http-listen",
                "127.0.0.1:80",
                "--system-socket",
                "/var/run/org.agenxy.Remap.system.sock",
                "--launchd-sockets"
            ],
            "RunAtLoad": true,
            "Sockets": [
                "remap-dns-tcp": stream.merging(["SockServiceName": "53"]) { _, new in new },
                "remap-dns-udp": [
                    "SockFamily": "IPv4",
                    "SockNodeName": "127.0.0.1",
                    "SockProtocol": "UDP",
                    "SockServiceName": "53",
                    "SockType": "dgram"
                ],
                "remap-http": stream.merging(["SockServiceName": "80"]) { _, new in new },
                "remap-system": [
                    "SockPathMode": 0o600,
                    "SockPathName": "/var/run/org.agenxy.Remap.system.sock",
                    "SockType": "stream"
                ]
            ],
            "SoftResourceLimits": ["NumberOfFiles": 4096],
            "StandardErrorPath": "/dev/null",
            "StandardOutPath": "/dev/null",
            "ThrottleInterval": 5,
            "Umask": 0o077,
            "UserName": account.userName,
            "WorkingDirectory": dataDirectory
        ]
    }

    private static func resolver(
        generationID: String,
        ownerUID: UInt32
    ) -> [String: Any] {
        [
            "HardResourceLimits": ["Core": 0, "NumberOfFiles": 128],
            "KeepAlive": true,
            "Label": MacOSLaunchdServiceKind.resolver.label,
            "ProcessType": "Background",
            "ProgramArguments": [
                generationRoot(generationID) + "/libexec/remap-resolver",
                "run",
                "--owner-uid",
                String(ownerUID),
                "--system-socket",
                "/var/run/org.agenxy.Remap.system.sock"
            ],
            "RunAtLoad": true,
            "SoftResourceLimits": ["NumberOfFiles": 128],
            "StandardErrorPath": "/dev/null",
            "StandardOutPath": "/dev/null",
            "ThrottleInterval": 5,
            "Umask": 0o077
        ]
    }

    private static func tcpSocket() -> [String: Any] {
        [
            "SockFamily": "IPv4",
            "SockNodeName": "127.0.0.1",
            "SockPassive": true,
            "SockProtocol": "TCP",
            "SockType": "stream"
        ]
    }

    private static func generationRoot(_ generationID: String) -> String {
        "/\(MacOSInstallLayout.installerBase)/Generations/\(generationID)"
    }

    private static func validate(upstreams: [String]) throws {
        guard 1 ... 4 ~= upstreams.count, Set(upstreams).count == upstreams.count else {
            throw InstallError.invalidManifest("the resolver plan requires one to four unique upstreams")
        }
        for endpoint in upstreams {
            let address: String
            let family: Int32
            if endpoint.hasPrefix("["), endpoint.hasSuffix("]:53") {
                address = String(endpoint.dropFirst().dropLast(4))
                family = AF_INET6
            } else if endpoint.hasSuffix(":53") {
                address = String(endpoint.dropLast(3))
                family = AF_INET
            } else {
                throw InstallError.invalidManifest("a resolver upstream is not an exact port-53 endpoint")
            }
            var storage = in6_addr()
            guard address.withCString({ inet_pton(family, $0, &storage) }) == 1,
                  address != "0.0.0.0",
                  address != "::",
                  address != "::1",
                  !address.hasPrefix("127."),
                  !address.lowercased().hasPrefix("ff")
            else {
                throw InstallError.invalidManifest("a resolver upstream address is unsafe")
            }
        }
    }
}
