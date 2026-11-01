// SPDX-License-Identifier: GPL-3.0-or-later
@testable import RemapSystemKit
import Testing

/// configd records a session's name beside each change it makes, so the name
/// says which part of Remap made it.
@Test
func systemConfigurationSessionsAreNamedForRemap() {
    let names = [RemapProduct.configurationSession, RemapProduct.supervisorSession]
    #expect(names.allSatisfy { $0.hasPrefix("Remap ") })
    #expect(Set(names).count == names.count)
}
