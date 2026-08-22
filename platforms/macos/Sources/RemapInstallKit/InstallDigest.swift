import CryptoKit
import Foundation

/// A canonical lowercase SHA-256 digest.
public struct InstallDigest: Codable, CustomStringConvertible, Equatable, Hashable, Sendable {
    public let value: String

    public var description: String {
        value
    }

    public init(_ value: String) throws {
        let lowercase = value.lowercased()
        let scalars = lowercase.unicodeScalars
        guard scalars.count == 64, scalars.allSatisfy(Self.isHexadecimal), value == lowercase else {
            throw InstallError.integrity("expected a 64-character lowercase SHA-256 digest")
        }
        self.value = value
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do {
            try self.init(container.decode(String.self))
        } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid SHA-256 digest")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }

    public static func hash(_ data: Data) -> InstallDigest {
        let value = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        return InstallDigest(validatedValue: value)
    }

    private init(validatedValue: String) {
        value = validatedValue
    }

    private static func isHexadecimal(_ scalar: UnicodeScalar) -> Bool {
        ("0" ... "9").contains(scalar) || ("a" ... "f").contains(scalar)
    }
}

enum InstallCanonicalJSON {
    static let decoder: JSONDecoder = .init()

    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }()
}
