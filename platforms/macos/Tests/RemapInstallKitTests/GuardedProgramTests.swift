import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

@Test(arguments: ["Desktop", "Documents", "Downloads", "Library/Mobile Documents/com~apple~CloudDocs"])
func guardedDirectoryProgramIsRefusedWithItsPathAndTheGenerationDestination(_ directory: String) throws {
    let ownerUID = UInt32(getuid())
    let account = try MacOSAccountLookup.account(for: ownerUID)
    let dataDirectory = account.homeDirectory.value + "/Library/Application Support/org.Agenxy.Remap"
    let configuration = try MacOSInstallConfiguration(
        ownerUID: ownerUID,
        dataDirectory: InstallAbsolutePath(dataDirectory),
        controlSocket: InstallAbsolutePath(dataDirectory + "/control.sock"),
        signingCertificateSHA256: InstallDigest.hash(Data("certificate".utf8))
    )
    let guarded = account.homeDirectory.value + "/\(directory)/remapd"
    let expected = try InstallAbsolutePath(
        "/\(MacOSInstallLayout.installerBase)/Generations/test/libexec/remapd"
    )
    let document = try daemonPlist(configuration: configuration, program: guarded)
    #expect(throws: InstallError.invalidManifest(
        "launchd program \(String(reflecting: guarded)) must be installed at \(expected.value)"
    )) {
        try MacOSLaunchdPropertyList.validate(
            document,
            kind: .daemon,
            configuration: configuration,
            account: account,
            programPath: expected
        )
    }
}
