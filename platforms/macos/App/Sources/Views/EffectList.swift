import RemapControlKit
import SwiftUI

struct EffectList: View {
    let effects: [RemapChangeEffect]

    var body: some View {
        VStack(spacing: 0) {
            ForEach(Array(effects.enumerated()), id: \.offset) { index, effect in
                EffectRow(effect: effect)
                if index != effects.indices.last {
                    Divider()
                }
            }
        }
        .padding(.horizontal, 14)
        .background(.background.secondary, in: .rect(cornerRadius: 10))
    }
}

private struct EffectRow: View {
    let effect: RemapChangeEffect

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack {
                Text(effect.pattern)
                    .font(.body.monospaced().weight(.medium))
                Spacer()
                Text(actionTitle)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
            if let before = effect.before {
                changeLine(label: AppText.localized("Before"), mapping: before)
            }
            if let after = effect.after {
                changeLine(label: AppText.localized("After"), mapping: after)
            }
            if effect.before == nil, effect.after == nil {
                Text(AppText.localized("No stored mapping changes."))
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.vertical, 12)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(effect.pattern)
        .accessibilityValue(accessibilityValue)
        .accessibilityHint(AppText.localized("Review this effect before applying the operation"))
    }

    private func changeLine(label: String, mapping: RemapMapping) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(label)
                .font(.caption.weight(.medium))
                .foregroundStyle(.tertiary)
            Text(mapping.target)
                .font(.callout.monospaced())
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
            Text(mapping.enabled ? AppText.localized("enabled") : AppText.localized("disabled"))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
    }

    private var actionTitle: String {
        switch effect.action {
        case "create": AppText.localized("Create")
        case "update": AppText.localized("Update")
        case "remove": AppText.localized("Remove")
        case "enable": AppText.localized("Enable")
        case "disable": AppText.localized("Disable")
        default: AppText.localized("Change")
        }
    }

    private var accessibilityValue: String {
        let before = effect.before.map { mappingDescription(AppText.localized("Before"), mapping: $0) }
        let after = effect.after.map { mappingDescription(AppText.localized("After"), mapping: $0) }
        return [actionTitle, before, after].compactMap(\.self).joined(separator: ". ")
    }

    private func mappingDescription(_ label: String, mapping: RemapMapping) -> String {
        let state = mapping.enabled ? AppText.localized("enabled") : AppText.localized("disabled")
        return "\(label): \(mapping.target), \(state)"
    }
}
