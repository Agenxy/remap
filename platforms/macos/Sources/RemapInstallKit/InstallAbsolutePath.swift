import Foundation

/// A normalized absolute path used at a native operating-system boundary.
public struct InstallAbsolutePath: Codable, CustomStringConvertible, Equatable, Hashable, Sendable {
    public let value: String

    public var description: String {
        value
    }

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
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid absolute path")
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
