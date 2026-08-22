import Foundation

enum AppText {
    static var availableLocalizations: [String] {
        Bundle.module.localizations
    }

    static func localized(
        _ resource: LocalizedStringResource,
        locale: Locale = .current
    ) -> String {
        let scopedResource = LocalizedStringResource(
            resource.defaultValue,
            table: resource.table,
            locale: locale,
            bundle: .module
        )
        return PseudoLocalization.apply(String(localized: scopedResource), locale: locale)
    }

    static func enabledMappings(
        _ count: UInt64,
        locale: Locale = .current
    ) -> String {
        localized("\(count) mapping enabled", locale: locale)
    }

    static func ownedResolverServices(
        _ count: Int,
        locale: Locale = .current
    ) -> String {
        localized("\(count) owned resolver service", locale: locale)
    }

    static func registryRevision(
        _ revision: UInt64,
        locale: Locale = .current
    ) -> String {
        localized("Registry revision \(revision)", locale: locale)
    }

    static func projectedRegistryRevision(
        _ revision: UInt64,
        locale: Locale = .current
    ) -> String {
        localized("Projected at registry revision \(revision).", locale: locale)
    }

    static func projectionRegistryRevision(
        _ revision: UInt64,
        locale: Locale = .current
    ) -> String {
        localized("This projection was calculated at registry revision \(revision).", locale: locale)
    }

    static func receiptRevision(
        previous: UInt64,
        current: UInt64,
        locale: Locale = .current
    ) -> String {
        localized("Revision \(previous) to \(current)", locale: locale)
    }

    static func mappingAccessibilityValue(
        pattern: String,
        target: String,
        enabled: Bool,
        locale: Locale = .current
    ) -> String {
        let resource: LocalizedStringResource = enabled
            ? "\(PseudoLocalization.firstToken) maps to \(PseudoLocalization.secondToken), enabled"
            : "\(PseudoLocalization.firstToken) maps to \(PseudoLocalization.secondToken), disabled"
        return localizedProtectingValues(
            resource,
            locale: locale,
            replacements: [
                PseudoLocalization.firstToken: pattern,
                PseudoLocalization.secondToken: target
            ]
        )
    }

    private static func localizedProtectingValues(
        _ resource: LocalizedStringResource,
        locale: Locale,
        replacements: [String: String]
    ) -> String {
        let localizedValue = localized(resource, locale: locale)
        return replacements.reduce(localizedValue) { value, replacement in
            value.replacingOccurrences(of: replacement.key, with: replacement.value)
        }
    }
}

private enum PseudoLocalization {
    // en-XA is a development-only locale. It expands every resolved string while
    // preserving protected user data, which catches clipping without shipping a
    // second set of hand-maintained translations.
    static let firstToken = "\u{E000}"
    static let secondToken = "\u{E001}"

    static func apply(_ value: String, locale: Locale) -> String {
        guard locale.identifier.replacingOccurrences(of: "_", with: "-") == "en-XA" else {
            return value
        }
        let expanded = value.map { character in
            replacement(for: character)
        }.joined()
        return "⟦\(expanded) ！！⟧"
    }

    private static func replacement(for character: Character) -> String {
        switch character {
        case "a": "áá"
        case "A": "ÁÁ"
        case "e": "éé"
        case "E": "ÉÉ"
        case "i": "íí"
        case "I": "ÍÍ"
        case "o": "óó"
        case "O": "ÓÓ"
        case "u": "úú"
        case "U": "ÚÚ"
        default: String(character)
        }
    }
}
