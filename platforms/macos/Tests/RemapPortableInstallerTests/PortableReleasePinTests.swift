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
