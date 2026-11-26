// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapPortableInstaller
import Testing

@Test
func portableReleasePinIsOneOpenSSHPublicKeyLine() {
    let pin = PortableReleaseVerifier.releasePublicKey
    let fields = pin.split(separator: " ", omittingEmptySubsequences: false)
    #expect(fields.count == 3)
    #expect(["ssh-ed25519", "ecdsa-sha2-nistp256"].contains(fields.first.map(String.init)))
    #expect(Data(base64Encoded: String(fields.dropFirst().first ?? "")) != nil)
    #expect(!pin.contains("\n") && !pin.contains("\\"))
}

@Test
func anUnflaggedInstallerIsAReleaseAndSaysNothingMore() {
    // The test build passes neither package condition, so it is a release installer.
    #expect(PortablePackageKind.compiled == nil)
    #expect(PortablePackageKind.announcement(for: nil, productVersion: "0.2.0") == nil)
    #expect(PortablePackageKind.installedName(for: nil, productVersion: "0.2.0") == "Remap 0.2.0")
}

@Test
func aRehearsalInstallerSaysItIsNotARelease() throws {
    let announcement = try #require(PortablePackageKind.announcement(for: .rehearsal, productVersion: "0.2.0"))
    #expect(announcement.hasPrefix("This is a rehearsal of Remap 0.2.0, not a release."))
    #expect(
        PortablePackageKind.installedName(for: .rehearsal, productVersion: "0.2.0")
            == "Remap 0.2.0 (rehearsal, not a release)"
    )
    #expect(PortablePackageKind.announcement(for: .development, productVersion: "0.2.0")?
        .contains("development") == true)
}
