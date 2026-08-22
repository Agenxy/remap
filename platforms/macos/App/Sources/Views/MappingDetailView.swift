import RemapControlKit
import SwiftUI

struct MappingDetailView: View {
    let mapping: RemapMapping
    let editable: Bool
    let edit: () -> Void
    let toggle: () -> Void
    let remove: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                definition
                actions
            }
            .padding(28)
            .frame(maxWidth: 720, alignment: .leading)
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top, spacing: 16) {
                Text(mapping.pattern)
                    .font(.largeTitle.monospaced().weight(.semibold))
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                Spacer()
                StatusPill(
                    title: mapping.enabled ? AppText.localized("Enabled") : AppText.localized("Disabled"),
                    symbol: mapping.enabled ? "checkmark.circle.fill" : "pause.circle.fill",
                    color: mapping.enabled ? .green : .secondary,
                    accessibilityLabel: AppText.localized("Mapping status"),
                    accessibilityHint: AppText.localized("Shows whether this mapping affects name resolution")
                )
            }
            Text(AppText.localized("Requests for this name use the exact destination and host policy below."))
                .foregroundStyle(.secondary)
        }
    }

    private var definition: some View {
        Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 14) {
            detailRow(AppText.localized("Destination"), mapping.target, monospaced: true)
            Divider()
            detailRow(AppText.localized("Kind"), mapping.targetKind)
            Divider()
            detailRow(AppText.localized("Host policy"), hostPolicyDescription)
            Divider()
            detailRow(AppText.localized("Updated"), AppText.registryRevision(mapping.updatedRevision))
        }
        .padding(18)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }

    private var actions: some View {
        HStack {
            Button(AppText.localized("Edit"), action: edit)
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(!editable)
                .accessibilityHint(AppText.localized("Opens this mapping in the editor"))
            Button(
                mapping.enabled ? AppText.localized("Disable") : AppText.localized("Enable"),
                action: toggle
            )
            .disabled(!editable)
            .accessibilityHint(AppText.localized("Opens a review of the exact state change"))
            Spacer()
            Button(AppText.localized("Remove"), role: .destructive, action: remove)
                .disabled(!editable)
                .accessibilityHint(AppText.localized("Opens a destructive review before removing this mapping"))
        }
    }

    private var hostPolicyDescription: String {
        switch mapping.hostPolicy {
        case .preserveClient: AppText.localized("Preserve the client-facing Host header")
        case .useUpstream: AppText.localized("Use the upstream Host header")
        }
    }

    private func detailRow(
        _ label: String,
        _ value: String,
        monospaced: Bool = false
    ) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Text(value)
                .font(monospaced ? .body.monospaced() : .body)
                .textSelection(.enabled)
        }
    }
}
