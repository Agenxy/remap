import Foundation

/// A normalized path whose components are always relative to an already-open directory descriptor.
public struct InstallRelativePath: Codable, Comparable, CustomStringConvertible, Hashable, Sendable {
    public let components: [String]

    public var description: String {
        components.joined(separator: "/")
    }

    public init(_ value: String) throws {
        guard !value.isEmpty, !value.hasPrefix("/"), !value.contains("\0") else {
            throw InstallError.invalidPath(value)
        }
        let parsed = value.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parsed.allSatisfy(Self.validComponent), value.utf8.count <= 1024 else {
            throw InstallError.invalidPath(value)
        }
        components = parsed
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do {
            try self.init(container.decode(String.self))
        } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid relative path")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }

    public static func < (lhs: InstallRelativePath, rhs: InstallRelativePath) -> Bool {
        lhs.description < rhs.description
    }

    public func appending(_ path: InstallRelativePath) throws -> InstallRelativePath {
        try InstallRelativePath("\(description)/\(path.description)")
    }

    public func appending(component: String) throws -> InstallRelativePath {
        try appending(InstallRelativePath(component))
    }

    private static func validComponent(_ component: String) -> Bool {
        !component.isEmpty && component != "." && component != ".." && component.utf8.count <= 255
    }
}

/// An exact absolute target for a publication symlink.
public struct InstallSymlinkTarget: Codable, Equatable, Sendable {
    public let value: String

    public init(_ value: String) throws {
        let components = value.split(separator: "/", omittingEmptySubsequences: false)
        guard value.hasPrefix("/"),
              !value.hasSuffix("/"),
              !value.contains("\0"),
              value.utf8.count <= 4096,
              components.count > 1,
              components.dropFirst().allSatisfy(Self.validComponent)
        else {
            throw InstallError.invalidPath(value)
        }
        self.value = value
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do {
            try self.init(container.decode(String.self))
        } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid symbolic-link target")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }

    private static func validComponent(_ component: Substring) -> Bool {
        !component.isEmpty && component != "." && component != ".." && component.utf8.count <= 255
    }
}
