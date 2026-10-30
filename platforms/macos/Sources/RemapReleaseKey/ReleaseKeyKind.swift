// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import Security

/// Which Remap signing key a blob holds. The two are never interchangeable (ADR-0035).
///
/// A release key signs what every production installer accepts, so every signature needs the
/// owner present. A rehearsal key signs only what a rehearsal installer accepts, and it signs
/// without anyone present, so that a rehearsal can be built unattended.
enum ReleaseKeyKind: String, CaseIterable, Equatable, Sendable {
    case release
    case rehearsal

    /// The comment a pin of this kind carries, which says what the key is for.
    var defaultComment: String {
        switch self {
        case .release: "remap-release-v2"
        case .rehearsal: "remap-release-rehearsal-only"
        }
    }

    /// Both kinds can only be used inside the Enclave. Only the release key asks for the owner.
    var accessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .release: [.privateKeyUsage, .userPresence]
        case .rehearsal: [.privateKeyUsage]
        }
    }

    func signingReason(namespace: String) -> String {
        "sign a Remap \(rawValue) under \(namespace)"
    }

    var creationNotice: String {
        switch self {
        case .release:
            "created a Remap release signing key in this Mac's Secure Enclave; "
                + "every signature asks for Touch ID or the login password"
        case .rehearsal:
            "created a Remap rehearsal signing key in this Mac's Secure Enclave; "
                + "it signs without Touch ID, so any process running as you on this Mac can sign "
                + "a rehearsal, and no release installer accepts it"
        }
    }

    /// A blob's file name says which kind it holds, so the two paths cannot be swapped: a
    /// rehearsal key's file name contains `rehearsal`, and a release key's never does.
    func admits(path: String) -> Bool {
        let name = path.split(separator: "/").last.map(String.init) ?? ""
        let rehearsalNamed = name.lowercased().contains(Self.rehearsal.rawValue)
        return self == .rehearsal ? rehearsalNamed : !rehearsalNamed
    }
}

/// The label that distinguishes the two kinds' blobs.
///
/// CryptoKit's Secure Enclave keys are not keychain items, so they have no application tag. The
/// label lives in the blob instead: a rehearsal blob begins with `rehearsalLabel`, and a release
/// blob is the Enclave's `dataRepresentation` alone, exactly as ADR-0029 wrote it. Neither kind
/// loads the other's blob.
enum ReleaseKeyBlob {
    static let rehearsalLabel = Data("remap-release-rehearsal-key-v1\n".utf8)

    static func wrap(_ representation: Data, kind: ReleaseKeyKind) -> Data {
        switch kind {
        case .release: representation
        case .rehearsal: rehearsalLabel + representation
        }
    }

    static func unwrap(_ data: Data, kind: ReleaseKeyKind, path: String) throws -> Data {
        let labelled = data.starts(with: rehearsalLabel)
        switch kind {
        case .release:
            guard !labelled else {
                throw ReleaseKeyError.keyFile(
                    "\(path) holds the rehearsal key, which never signs a release"
                )
            }
            return data
        case .rehearsal:
            guard labelled else {
                throw ReleaseKeyError.keyFile(
                    "\(path) does not hold a rehearsal key; the release key never signs a rehearsal"
                )
            }
            return Data(data.dropFirst(rehearsalLabel.count))
        }
    }
}
