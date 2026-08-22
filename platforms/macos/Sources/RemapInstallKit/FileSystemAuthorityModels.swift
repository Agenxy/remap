import Darwin
import Foundation

/// The type of a node resolved without following its final component.
public enum InstallNodeKind: Equatable, Sendable {
    case directory
    case regularFile
    case symbolicLink
}

/// Security-relevant metadata captured from one node.
public struct InstallNodeMetadata: Equatable, Sendable {
    public let kind: InstallNodeKind
    public let ownerUID: UInt32
    public let groupGID: UInt32
    public let mode: UInt16
    public let byteCount: UInt64
    public let linkCount: UInt64
    public let hasACL: Bool
    public let hasExtendedAttributes: Bool
    public let flags: UInt32
}

struct InstallAuthorityPolicy: Sendable {
    let ownerUID: uid_t
    let groupGID: gid_t
    let requiresRoot: Bool
    let sourceOnly: Bool
    let requiredRootMode: UInt16?
    let systemFlags: Bool

    static let system = InstallAuthorityPolicy(
        ownerUID: 0,
        groupGID: 0,
        requiresRoot: true,
        sourceOnly: false,
        requiredRootMode: nil,
        systemFlags: true
    )

    static func sourcePackage(ownerUID: uid_t, requiresRoot: Bool) -> InstallAuthorityPolicy {
        InstallAuthorityPolicy(
            ownerUID: ownerUID,
            groupGID: 0,
            requiresRoot: requiresRoot,
            sourceOnly: true,
            requiredRootMode: 0o700,
            systemFlags: false
        )
    }
}

enum InstallSystemNodeFlagPolicy {
    private static let fixedFlags: [String: UInt32] = [
        "": UInt32(SF_NOUNLINK),
        "Applications": UInt32(SF_NOUNLINK),
        "Library": UInt32(SF_NOUNLINK),
        "usr": UInt32(UF_HIDDEN | SF_RESTRICTED),
        "usr/local": UInt32(SF_NOUNLINK)
    ]

    static func permitsTraversalFlags(_ flags: UInt32, relativePath: String) -> Bool {
        guard let fixed = fixedFlags[relativePath] else {
            return flags == 0
        }
        if relativePath == "usr/local" {
            return flags == 0 || flags == fixed
        }
        return flags == fixed
    }

    static func permitsCompatibleDirectoryFlags(_ flags: UInt32, relativePath: String) -> Bool {
        flags == 0 || flags == fixedFlags[relativePath]
    }
}

final class InstallDescriptor: @unchecked Sendable {
    let rawValue: Int32

    init(_ rawValue: Int32) {
        self.rawValue = rawValue
    }

    deinit {
        close(rawValue)
    }
}
