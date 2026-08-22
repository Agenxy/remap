import Foundation

enum PropertyLists {
    static func encode(_ dictionary: [String: Any]) throws -> Data {
        guard PropertyListSerialization.propertyList(dictionary, isValidFor: .binary) else {
            throw ResolverError.preferences("encode a DNS configuration")
        }
        return try PropertyListSerialization.data(
            fromPropertyList: dictionary,
            format: .binary,
            options: 0
        )
    }

    static func decode(_ data: Data) throws -> [String: Any] {
        let value = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: nil
        )
        guard let dictionary = value as? [String: Any] else {
            throw ResolverError.invalidActivationRecord
        }
        return dictionary
    }

    static func equal(_ left: [String: Any]?, encoded right: Data) throws -> Bool {
        let left = left ?? [:]
        return try NSDictionary(dictionary: left).isEqual(to: decode(right))
    }
}
