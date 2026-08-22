import RemapControlKit
import SwiftUI

enum OperationReviewAccessibility {
    static func isDestructive(_ change: RemapChange) -> Bool {
        if case .remove = change {
            return true
        }
        return false
    }

    static func applyLabel(for change: RemapChange) -> String {
        isDestructive(change) ? AppText.localized("Apply removal") : AppText.localized("Apply change")
    }
}

struct OperationReviewView: View {
    let store: RemapStore
    let title: String
    let change: RemapChange

    @Environment(\.dismiss) private var dismiss
    @State private var preview: RemapPreview?
    @State private var receipt: RemapApplyReceipt?
    @State private var diagnostic: RemapDiagnostic?
    @State private var isWorking = true
    @AccessibilityFocusState private var reviewFocused: Bool

    var body: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                if let receipt {
                    ReceiptView(receipt: receipt)
                } else if let preview {
                    Text(
                        preview.willChange
                            ? AppText.localized("Review the exact change")
                            : AppText.localized("Nothing will change")
                    )
                    .font(.title2.weight(.semibold))
                    .accessibilityAddTraits(.isHeader)
                    .accessibilityFocused($reviewFocused)
                    Text(AppText.projectedRegistryRevision(preview.baseRevision))
                        .foregroundStyle(.secondary)
                    EffectList(effects: preview.effects)
                } else if isWorking {
                    ProgressView(AppText.localized("Calculating exact scope…"))
                        .controlSize(.large)
                        .frame(maxWidth: .infinity, maxHeight: .infinity)
                }
                if let diagnostic {
                    InlineDiagnostic(diagnostic: diagnostic)
                }
                Spacer()
            }
            .padding(24)
            .frame(
                minWidth: 500,
                idealWidth: 590,
                minHeight: 360,
                idealHeight: 430,
                alignment: .topLeading
            )
            .navigationTitle(receipt == nil ? title : AppText.localized("Change Applied"))
            .toolbar { toolbar }
        }
        .interactiveDismissDisabled(isWorking)
        .task { await loadPreview() }
    }

    @ToolbarContentBuilder
    private var toolbar: some ToolbarContent {
        ToolbarItem(placement: .cancellationAction) {
            Button(receipt == nil ? AppText.localized("Cancel") : AppText.localized("Close")) { dismiss() }
                .keyboardShortcut(.cancelAction)
        }
        ToolbarItem(placement: .confirmationAction) {
            if receipt != nil {
                Button(AppText.localized("Done")) { dismiss() }
                    .keyboardShortcut(.defaultAction)
            } else if let preview {
                Button(
                    role: preview.willChange && OperationReviewAccessibility.isDestructive(change)
                        ? .destructive
                        : nil
                ) {
                    if preview.willChange {
                        apply(preview)
                    } else {
                        dismiss()
                    }
                } label: {
                    Text(preview.willChange ? AppText.localized("Apply") : AppText.localized("Done"))
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isWorking)
                .accessibilityLabel(
                    preview.willChange
                        ? OperationReviewAccessibility.applyLabel(for: change)
                        : AppText.localized("Done")
                )
                .accessibilityHint(
                    preview.willChange
                        ? AppText.localized("Applies the exact effects shown in this review")
                        : AppText.localized("Closes this review without changing state")
                )
            } else if diagnostic != nil {
                Button(AppText.localized("Retry")) {
                    Task { await loadPreview() }
                }
                .disabled(isWorking)
                .accessibilityHint(AppText.localized("Calculates the exact effects again"))
            }
        }
    }

    private func loadPreview() async {
        isWorking = true
        diagnostic = nil
        do {
            preview = try await store.preview(change)
            reviewFocused = true
        } catch {
            diagnostic = appDiagnostic(error)
        }
        isWorking = false
    }

    private func apply(_ preview: RemapPreview) {
        isWorking = true
        diagnostic = nil
        Task {
            defer { isWorking = false }
            do {
                receipt = try await store.apply(change, expectedRevision: preview.baseRevision)
                self.preview = nil
            } catch {
                diagnostic = appDiagnostic(error)
            }
        }
    }
}
