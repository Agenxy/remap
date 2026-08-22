import RemapControlKit
import SwiftUI

struct InlineDiagnostic: View {
    let diagnostic: RemapDiagnostic
    @AccessibilityFocusState private var diagnosticFocused: Bool

    var body: some View {
        let content = AppDiagnosticContent(diagnostic)
        VStack(alignment: .leading, spacing: 5) {
            Label(content.message, systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)
            if let hint = content.hint {
                Text(hint)
                    .foregroundStyle(.secondary)
            }
        }
        .textSelection(.enabled)
        .padding(12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.08), in: .rect(cornerRadius: 9))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(AppText.localized("Error"))
        .accessibilityValue(accessibilityValue)
        .accessibilityFocused($diagnosticFocused)
        .onAppear { diagnosticFocused = true }
    }

    private var accessibilityValue: String {
        let content = AppDiagnosticContent(diagnostic)
        return [content.code, content.message, content.hint]
            .compactMap(\.self)
            .joined(separator: ". ")
    }
}
