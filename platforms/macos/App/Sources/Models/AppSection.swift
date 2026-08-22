import SwiftUI

enum AppSection: String, CaseIterable, Identifiable {
    case overview
    case mappings
    case system

    // The short property name is required by Identifiable.
    // swiftlint:disable:next identifier_name
    var id: Self {
        self
    }

    var title: String {
        switch self {
        case .overview: AppText.localized("Overview")
        case .mappings: AppText.localized("Mappings")
        case .system: AppText.localized("System")
        }
    }

    var keyboardShortcut: KeyEquivalent {
        switch self {
        case .overview: "1"
        case .mappings: "2"
        case .system: "3"
        }
    }

    var symbol: String {
        switch self {
        case .overview: "gauge.with.dots.needle.50percent"
        case .mappings: "arrow.triangle.branch"
        case .system: "network"
        }
    }
}
