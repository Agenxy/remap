import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test
func daemonRequiresLaunchdOwnedSystemSocketOutsideTheUserDataDirectory() throws {
    let ownerUID = UInt32(getuid())
    let account = try MacOSAccountLookup.account(for: ownerUID)
    let dataDirectory = account.homeDirectory.value
        + "/Library/Application Support/org.Agenxy.Remap"
    let configuration = try MacOSInstallConfiguration(
        ownerUID: ownerUID,
        dataDirectory: InstallAbsolutePath(dataDirectory),
        controlSocket: InstallAbsolutePath(dataDirectory + "/control.sock"),
        signingCertificateSHA256: InstallDigest.hash(Data("certificate".utf8))
    )
    let program = try InstallAbsolutePath("/Library/Application Support/Agenxy/Remap/remapd")
    let valid = try daemonPlist(configuration: configuration, program: program.value)
    try MacOSLaunchdPropertyList.validate(
        valid,
        kind: .daemon,
        configuration: configuration,
        account: account,
        programPath: program
    )

    let decoded = try #require(
        PropertyListSerialization.propertyList(from: valid, options: [], format: nil)
            as? [String: Any]
    )
    let sockets = try #require(decoded["Sockets"] as? [String: Any])
    let system = try #require(sockets["remap-system"] as? [String: Any])
    #expect(system["SockPathName"] as? String == configuration.systemSocketPath)
    #expect(!configuration.systemSocketPath.hasPrefix(dataDirectory))

    var replacedSystem = system
    replacedSystem["SockPathName"] = dataDirectory + "/system.sock"
    var replacedSockets = sockets
    replacedSockets["remap-system"] = replacedSystem
    var replacedDocument = decoded
    replacedDocument["Sockets"] = replacedSockets
    let replaced = try PropertyListSerialization.data(
        fromPropertyList: replacedDocument,
        format: .xml,
        options: 0
    )
    #expect(throws: InstallError.invalidManifest(
        "launchd sockets must bind only Remap loopback listeners"
    )) {
        try MacOSLaunchdPropertyList.validate(
            replaced,
            kind: .daemon,
            configuration: configuration,
            account: account,
            programPath: program
        )
    }
}
