import Darwin
import Foundation

enum MacOSLaunchdPropertyList {
    static func validate(
        _ data: Data,
        kind: MacOSLaunchdServiceKind,
        configuration: MacOSInstallConfiguration,
        account: MacOSAccount,
        programPath: InstallAbsolutePath
    ) throws {
        let document: Any
        do {
            document = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        } catch {
            throw InstallError.invalidManifest("the launchd property list is malformed")
        }
        guard let values = document as? [String: Any], Set(values.keys) == allowedKeys(for: kind) else {
            throw InstallError.invalidManifest("the launchd property list contains unsupported keys")
        }
        guard string(values, "Label") == kind.label else {
            throw InstallError.invalidManifest("the launchd label does not match the managed service")
        }
        switch kind {
        case .daemon:
            try validateDaemon(values, configuration: configuration, account: account, programPath: programPath)
        case .resolver:
            try validateResolver(values, configuration: configuration, programPath: programPath)
        }
    }

    private static func validateDaemon(
        _ values: [String: Any],
        configuration: MacOSInstallConfiguration,
        account: MacOSAccount,
        programPath: InstallAbsolutePath
    ) throws {
        try validateIdentity(values, configuration: configuration, account: account)
        try validateArguments(values, configuration: configuration, programPath: programPath)
        try validateLifecycle(values, fileLimit: 4096)
        try validateSockets(values, configuration: configuration)
    }

    private static func validateResolver(
        _ values: [String: Any],
        configuration: MacOSInstallConfiguration,
        programPath: InstallAbsolutePath
    ) throws {
        guard values["UserName"] == nil,
              values["GroupName"] == nil,
              values["WorkingDirectory"] == nil,
              values["Sockets"] == nil,
              values["ProgramArguments"] as? [String] == [
                  programPath.value,
                  "run",
                  "--owner-uid",
                  String(configuration.ownerUID),
                  "--system-socket",
                  configuration.systemSocketPath
              ]
        else {
            throw InstallError.invalidManifest("the root resolver service has an unexpected authority scope")
        }
        try validateLifecycle(values, fileLimit: 128)
    }

    private static func validateIdentity(
        _ values: [String: Any],
        configuration: MacOSInstallConfiguration,
        account: MacOSAccount
    ) throws {
        guard string(values, "UserName") == account.userName,
              string(values, "GroupName") == account.groupName,
              string(values, "WorkingDirectory") == configuration.dataDirectory.value,
              string(values, "StandardOutPath") == "/dev/null",
              string(values, "StandardErrorPath") == "/dev/null"
        else {
            throw InstallError.invalidManifest("the launchd identity or filesystem scope is incorrect")
        }
    }

    private static func validateArguments(
        _ values: [String: Any],
        configuration: MacOSInstallConfiguration,
        programPath: InstallAbsolutePath
    ) throws {
        guard let arguments = values["ProgramArguments"] as? [String],
              arguments.count >= 10,
              arguments.count <= 20,
              arguments[0 ... 4] == [
                  programPath.value,
                  "--data-dir",
                  configuration.dataDirectory.value,
                  "--dns-listen",
                  "127.0.0.1:\(configuration.dnsPort)"
              ],
              arguments.suffix(5) == [
                  "--http-listen",
                  "127.0.0.1:\(configuration.httpPort)",
                  "--system-socket",
                  configuration.systemSocketPath,
                  "--launchd-sockets"
              ]
        else {
            throw InstallError.invalidManifest("the launchd program arguments do not match the immutable image")
        }
        let upstreamArguments = Array(arguments.dropFirst(5).dropLast(5))
        guard upstreamArguments.count.isMultiple(of: 2), upstreamArguments.count <= 8 else {
            throw InstallError.invalidManifest("the launchd upstream argument count is invalid")
        }
        for index in stride(from: 0, to: upstreamArguments.count, by: 2) {
            guard upstreamArguments[index] == "--dns-upstream",
                  validUpstream(upstreamArguments[index + 1])
            else {
                throw InstallError.invalidManifest("the launchd upstream arguments are invalid")
            }
        }
    }

    private static func validateLifecycle(_ values: [String: Any], fileLimit: Int) throws {
        guard boolean(values, "RunAtLoad") == true,
              boolean(values, "KeepAlive") == true,
              string(values, "ProcessType") == "Background",
              string(values, "StandardOutPath") == "/dev/null",
              string(values, "StandardErrorPath") == "/dev/null",
              integer(values, "ThrottleInterval") == 5,
              integer(values, "Umask") == 0o77,
              let soft = values["SoftResourceLimits"] as? [String: Any],
              Set(soft.keys) == ["NumberOfFiles"],
              integer(soft, "NumberOfFiles") == fileLimit,
              let hard = values["HardResourceLimits"] as? [String: Any],
              Set(hard.keys) == ["Core", "NumberOfFiles"],
              integer(hard, "Core") == 0,
              integer(hard, "NumberOfFiles") == fileLimit
        else {
            throw InstallError.invalidManifest("the launchd lifecycle or resource policy is incorrect")
        }
    }

    private static func validateSockets(
        _ values: [String: Any],
        configuration: MacOSInstallConfiguration
    ) throws {
        guard let sockets = values["Sockets"] as? [String: Any],
              Set(sockets.keys) == ["remap-dns-udp", "remap-dns-tcp", "remap-http", "remap-system"],
              let udp = sockets["remap-dns-udp"] as? [String: Any],
              let tcp = sockets["remap-dns-tcp"] as? [String: Any],
              let http = sockets["remap-http"] as? [String: Any],
              let system = sockets["remap-system"] as? [String: Any],
              validSocket(udp, port: configuration.dnsPort, protocolName: "UDP", type: "dgram"),
              validSocket(tcp, port: configuration.dnsPort, protocolName: "TCP", type: "stream"),
              validSocket(http, port: configuration.httpPort, protocolName: "TCP", type: "stream"),
              validSystemSocket(system, path: configuration.systemSocketPath)
        else {
            throw InstallError.invalidManifest("launchd sockets must bind only Remap loopback listeners")
        }
    }

    private static func validSystemSocket(_ values: [String: Any], path: String) -> Bool {
        Set(values.keys) == ["SockPathMode", "SockPathName", "SockType"]
            && integer(values, "SockPathMode") == 0o600
            && string(values, "SockPathName") == path
            && string(values, "SockType") == "stream"
    }

    private static func validSocket(
        _ values: [String: Any],
        port: UInt16,
        protocolName: String,
        type: String
    ) -> Bool {
        let expectedKeys = type == "stream" ? socketKeys.union(["SockPassive"]) : socketKeys
        return Set(values.keys) == expectedKeys
            && string(values, "SockFamily") == "IPv4"
            && string(values, "SockNodeName") == "127.0.0.1"
            && string(values, "SockServiceName") == String(port)
            && string(values, "SockProtocol") == protocolName
            && string(values, "SockType") == type
            && boolean(values, "SockPassive") == (type == "stream" ? true : nil)
    }

    private static func validUpstream(_ value: String) -> Bool {
        guard value.utf8.count <= 128 else {
            return false
        }
        if value.hasPrefix("["), value.hasSuffix("]:53") {
            return validIPAddress(String(value.dropFirst().dropLast(4)), family: AF_INET6)
        }
        guard value.hasSuffix(":53") else {
            return false
        }
        return validIPAddress(String(value.dropLast(3)), family: AF_INET)
    }

    private static func validIPAddress(_ value: String, family: Int32) -> Bool {
        var storage = in6_addr()
        let result = value.withCString { inet_pton(family, $0, &storage) }
        guard result == 1 else {
            return false
        }
        if family == AF_INET {
            guard let first = value.split(separator: ".").first.flatMap({ UInt8($0) }) else {
                return false
            }
            return value != "0.0.0.0" && first != 127 && !(224 ... 239).contains(first)
        }
        return value != "::" && value != "::1" && !value.lowercased().hasPrefix("ff")
    }

    private static func string(_ values: [String: Any], _ key: String) -> String? {
        values[key] as? String
    }

    private static func integer(_ values: [String: Any], _ key: String) -> Int? {
        guard let number = values[key] as? NSNumber,
              CFGetTypeID(number) != CFBooleanGetTypeID()
        else {
            return nil
        }
        return number.intValue
    }

    private static func boolean(_ values: [String: Any], _ key: String) -> Bool? {
        guard let number = values[key] as? NSNumber,
              CFGetTypeID(number) == CFBooleanGetTypeID()
        else {
            return nil
        }
        return number.boolValue
    }

    private static let socketKeys: Set<String> = [
        "SockFamily", "SockNodeName", "SockProtocol", "SockServiceName", "SockType"
    ]

    private static let daemonKeys: Set<String> = [
        "GroupName", "HardResourceLimits", "KeepAlive", "Label", "ProcessType", "ProgramArguments", "RunAtLoad",
        "Sockets", "SoftResourceLimits", "StandardErrorPath", "StandardOutPath", "ThrottleInterval", "Umask",
        "UserName", "WorkingDirectory"
    ]

    private static let resolverKeys: Set<String> = [
        "HardResourceLimits", "KeepAlive", "Label", "ProcessType", "ProgramArguments", "RunAtLoad",
        "SoftResourceLimits", "StandardErrorPath", "StandardOutPath", "ThrottleInterval", "Umask"
    ]

    private static func allowedKeys(for kind: MacOSLaunchdServiceKind) -> Set<String> {
        switch kind {
        case .daemon:
            daemonKeys
        case .resolver:
            resolverKeys
        }
    }
}
