// SPDX-License-Identifier: GPL-3.0-or-later
/// Shared product identity for native Remap executables.
public enum RemapProduct {
    /// Version of the native product built from this source tree.
    public static let version = "0.2.0"
    /// The name Remap's System Configuration sessions give configd, which
    /// records it beside every network preference change they make.
    static let configurationSession = "Remap DNS Resolver"
    /// The name of the resolver supervisor's network change subscription.
    static let supervisorSession = "Remap DNS Resolver Supervisor"
}
