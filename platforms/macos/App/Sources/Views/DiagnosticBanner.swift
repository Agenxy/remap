import RemapControlKit
import SwiftUI
import UniformTypeIdentifiers

struct DiagnosticBanner: View {
    let diagnostic: RemapDiagnostic
    let dismiss: () -> Void
    @AccessibilityFocusState private var diagnosticFocused: Bool

    var body: some View {
        let content = AppDiagnosticContent(diagnostic)
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(content.message)
                    .font(.headline)
                    .textSelection(.enabled)
                if let hint = content.hint {
                    Text(hint)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(AppText.localized("Error"))
            .accessibilityValue(copyText)
            .accessibilityHint(AppText.localized("Use Copy to place these diagnostic details on the clipboard"))
            .accessibilityFocused($diagnosticFocused)
            Spacer(minLength: 16)
            Button(AppText.localized("Copy")) {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(copyText, forType: .string)
            }
            .help(AppText.localized("Copy the error code, message, and recovery hint"))
            .accessibilityHint(AppText.localized("Copies the complete local diagnostic"))
            Button(action: dismiss) {
                Image(systemName: "xmark")
            }
            .buttonStyle(.plain)
            .accessibilityLabel(AppText.localized("Dismiss error"))
            .accessibilityHint(AppText.localized("Hides this diagnostic"))
        }
        .padding(12)
        .background(.regularMaterial)
        .overlay(alignment: .top) { Divider() }
        .onAppear { diagnosticFocused = true }
    }

    private var copyText: String {
        let content = AppDiagnosticContent(diagnostic)
        return [content.code, content.message, content.hint]
            .compactMap(\.self)
            .joined(separator: "\n")
    }
}
