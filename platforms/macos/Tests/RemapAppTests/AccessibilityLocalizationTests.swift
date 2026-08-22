import Foundation
@testable import RemapApp
@testable import RemapControlKit
import Testing

@Test
func localizationCatalogPublishesEnglishAndDevelopmentPseudoLocale() {
    #expect(AppText.availableLocalizations.contains("en"))
    #expect(AppText.availableLocalizations.contains("en-XA"))
    #expect(AppText.localized("New Mapping", locale: Locale(identifier: "en")) == "New Mapping")
}

@Test
func pluralStringsUseCatalogRules() {
    let english = Locale(identifier: "en")

    #expect(AppText.enabledMappings(1, locale: english) == "1 mapping enabled")
    #expect(AppText.enabledMappings(2, locale: english) == "2 mappings enabled")
    #expect(AppText.ownedResolverServices(1, locale: english) == "1 owned resolver service")
    #expect(AppText.ownedResolverServices(3, locale: english) == "3 owned resolver services")
}

@Test
func pseudoLocalizationExpandsCopyWithoutChangingUserData() {
    let pseudo = Locale(identifier: "en-XA")
    let value = AppText.mappingAccessibilityValue(
        pattern: "atlas.test",
        target: "http://127.0.0.1:4270",
        enabled: true,
        locale: pseudo
    )

    #expect(value.hasPrefix("⟦"))
    #expect(value.hasSuffix("！！⟧"))
    #expect(value.contains("atlas.test"))
    #expect(value.contains("http://127.0.0.1:4270"))
    #expect(value.count > "atlas.test maps to http://127.0.0.1:4270, enabled".count)
}

@Test
func navigationCommandsHaveStableUniqueShortcuts() {
    let shortcuts = AppSection.allCases.map(\.keyboardShortcut.character)

    #expect(Set(shortcuts).count == AppSection.allCases.count)
    #expect(shortcuts == ["1", "2", "3"])
}

@Test
func newHTTPMappingsDefaultToDestinationCompatibility() {
    let draft = MappingDraft()

    #expect(draft.hostPolicy == .useUpstream)
}

@Test @MainActor
func keyboardNavigationUpdatesThePresentedSection() {
    let presentation = AppPresentation()

    presentation.navigate(to: .system)

    #expect(presentation.selectedSection == .system)
}

@Test
func accessibilityPreferencesStrengthenStatusWithoutDependingOnColor() {
    let defaultStyle = AccessibilityPresentation(
        reduceMotion: false,
        increasedContrast: false,
        differentiateWithoutColor: false
    )
    let accessibleStyle = AccessibilityPresentation(
        reduceMotion: true,
        increasedContrast: true,
        differentiateWithoutColor: true
    )

    #expect(accessibleStyle.disablesMotion)
    #expect(accessibleStyle.statusFillOpacity > defaultStyle.statusFillOpacity)
    #expect(accessibleStyle.statusBorderOpacity > defaultStyle.statusBorderOpacity)
    #expect(accessibleStyle.statusBorderWidth > defaultStyle.statusBorderWidth)
}

@Test
func knownDiagnosticsHaveLocalizedRecoveryCopyAndStableCodes() {
    let diagnostic = RemapDiagnostic(
        code: "E_DAEMON_UNAVAILABLE",
        message: "untrusted fallback",
        hint: nil,
        retryable: true
    )
    let content = AppDiagnosticContent(diagnostic)

    #expect(content.code == "E_DAEMON_UNAVAILABLE")
    #expect(content.message == "Remap isn't running in the background.")
    #expect(content.hint == "Reinstall Remap, then refresh. Your saved mappings are unchanged.")
}

@Test
func removalReviewIsExplicitlyDestructive() {
    let removal = RemapChange.remove(pattern: "atlas.test")
    let update = RemapChange.enable(pattern: "atlas.test")

    #expect(OperationReviewAccessibility.isDestructive(removal))
    #expect(!OperationReviewAccessibility.isDestructive(update))
    #expect(OperationReviewAccessibility.applyLabel(for: removal) == "Apply removal")
    #expect(OperationReviewAccessibility.applyLabel(for: update) == "Apply change")
}
