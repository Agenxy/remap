// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// The root-owned records the resolver keeps beside its activation record in
/// `/Library/Application Support/Agenxy/Remap`. Each outlives the activation
/// on purpose, so a complete uninstall removes them; otherwise the directory
/// would no longer be as empty as it was before Remap (ADR-0036).
///
/// The activation record itself is not listed. Uninstall deactivates DNS
/// first, so one still present means DNS may still point at Remap, and it is
/// kept as the evidence restoration needs.
enum MacOSResolverRecords {
    /// File name and the exact mode its writer sets.
    static let specifications: [(name: String, mode: UInt16)] = [
        // The last supervisor fallback (ADR-0025).
        ("resolver-bypass-v1.json", 0o600),
        // The owner's deliberate DNS turn-off (ADR-0036).
        ("dns-turned-off-v1.json", 0o644),
        // PR #16 (ADR-0033) keeps loopback reservations here under an
        // exclusive lock file; listed now so that merge is covered.
        ("loopback-reservations-v1.json", 0o600),
        (".loopback-reservations.lock", 0o600)
    ]

    private static let maximumRecordBytes = 1_048_576

    /// Removes every listed record found in `product`. Each must be a
    /// regular, single-link, non-symlink file owned by `ownerUID` with its
    /// writer's exact mode, no ACL, and no flags; anything else is a collision
    /// and is left untouched. The pinned inode whose bytes were read is the
    /// one unlinked.
    static func remove(
        from product: InstallRelativePath,
        authority: FileSystemAuthority,
        ownerUID: UInt32
    ) throws {
        for specification in specifications {
            let path = try product.appending(component: specification.name)
            guard let metadata = try authority.metadata(at: path) else { continue }
            guard metadata.kind == .regularFile,
                  metadata.ownerUID == ownerUID,
                  metadata.mode == specification.mode,
                  metadata.linkCount == 1,
                  metadata.byteCount <= UInt64(maximumRecordBytes),
                  !metadata.hasACL,
                  metadata.flags == 0
            else {
                throw InstallError.collision(path.description)
            }
            let data = try authority.readUniqueFile(at: path, maximumByteCount: maximumRecordBytes)
            try authority.unlinkAuthorityFile(
                at: path,
                expectedDigest: InstallDigest.hash(data),
                expectedByteCount: UInt64(data.count),
                ownerUID: ownerUID,
                groupGID: metadata.groupGID,
                mode: specification.mode
            )
        }
    }
}
