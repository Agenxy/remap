import RemapControlKit
import SwiftUI

struct ReceiptView: View {
    let receipt: RemapApplyReceipt

    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Label(
                receipt.changed
                    ? AppText.localized("Changes saved")
                    : AppText.localized("Nothing changed"),
                systemImage: "checkmark.circle.fill"
            )
            .font(.title2.weight(.semibold))
            .foregroundStyle(.green)
            Text(AppText.receiptRevision(previous: receipt.previousRevision, current: receipt.revision))
                .font(.body.monospacedDigit())
                .foregroundStyle(.secondary)
            EffectList(effects: receipt.effects)
            VStack(alignment: .leading, spacing: 4) {
                Text(AppText.localized("Operation ID"))
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Text(receipt.operationID)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
            }
            Text(AppText.localized("Keep the operation ID if you need to verify an uncertain retry."))
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(AppText.localized("Operation receipt"))
        .accessibilityValue(
            receipt.changed
                ? AppText.localized("Changes saved")
                : AppText.localized("Nothing changed")
        )
    }
}
