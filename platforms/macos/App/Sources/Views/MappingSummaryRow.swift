import RemapControlKit
import SwiftUI

struct MappingSummaryRow: View {
    let mapping: RemapMapping
    let accessibilityHint: String

    init(
        mapping: RemapMapping,
        accessibilityHint: String = AppText.localized("Select to inspect this mapping")
    ) {
        self.mapping = mapping
        self.accessibilityHint = accessibilityHint
    }

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: mapping.enabled ? "arrow.right.circle.fill" : "pause.circle")
                .foregroundStyle(mapping.enabled ? Color.accentColor : Color.secondary)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(mapping.pattern)
                    .font(.body.monospaced().weight(.medium))
                    .lineLimit(1)
                Text(mapping.target)
                    .font(.callout.monospaced())
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text(mapping.targetKind.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.tertiary)
        }
        .padding(.vertical, 11)
        .contentShape(.rect)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(AppText.localized("Mapping"))
        .accessibilityValue(
            AppText.mappingAccessibilityValue(
                pattern: mapping.pattern,
                target: mapping.target,
                enabled: mapping.enabled
            )
        )
        .accessibilityHint(accessibilityHint)
    }
}
