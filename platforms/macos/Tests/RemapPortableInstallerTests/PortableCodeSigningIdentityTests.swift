// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapPortableInstaller
import Testing

/// Login Items lists a self-signed program under its certificate's organisation,
/// so the identity a receiving Mac creates names Remap there, not a placeholder.
@Test
func portableSigningCertificateNamesRemapAsItsOrganisation() {
    let lines = PortableCodeSigningIdentityStore.opensslConfiguration
        .split(separator: "\n")
        .map { $0.trimmingCharacters(in: .whitespaces) }
    #expect(lines.contains("CN = \(PortableCodeSigningIdentity.name)"))
    #expect(lines.contains("O = Remap"))
    #expect(!lines.contains { $0.hasPrefix("O = ") && $0 != "O = Remap" })
}
