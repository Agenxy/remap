import RemapControlKit
import SwiftUI

struct MappingEditorView: View {
    let store: RemapStore
    let original: RemapMapping?

    @Environment(\.dismiss) private var dismiss
    @State private var draft: MappingDraft
    @State private var preview: RemapPreview?
    @State private var receipt: RemapApplyReceipt?
    @State private var diagnostic: RemapDiagnostic?
    @State private var isWorking = false
    @FocusState private var focusedField: Field?
    @AccessibilityFocusState private var reviewFocused: Bool

    private enum Field {
        case pattern
        case target
    }

    init(store: RemapStore, original: RemapMapping?) {
        self.store = store
        self.original = original
        _draft = State(initialValue: original.map(MappingDraft.init) ?? MappingDraft())
    }

    var body: some View {
        NavigationStack {
            Group {
                if let receipt {
                    ReceiptView(receipt: receipt)
                } else if let preview {
                    review(preview)
                } else {
                    editor
                }
            }
            .padding(24)
            .frame(
                minWidth: 520,
                idealWidth: 620,
                minHeight: 420,
                idealHeight: 500,
                alignment: .topLeading
            )
            .navigationTitle(title)
            .toolbar { toolbar }
        }
        .interactiveDismissDisabled(isWorking)
        .onAppear {
            focusedField = original == nil ? .pattern : .target
        }
    }

    private var editor: some View {
        Form {
            Section {
                TextField(
                    AppText.localized("Hostname or wildcard"),
                    text: $draft.pattern,
                    prompt: Text("atlas.test", bundle: .module)
                )
                .textContentType(.URL)
                .disabled(original != nil)
                .focused($focusedField, equals: .pattern)
                .onSubmit { focusedField = .target }
                .accessibilityHint(AppText.localized("Enter an exact hostname or wildcard pattern"))
                TextField(
                    AppText.localized("Address or service URL"),
                    text: $draft.target,
                    prompt: Text("http://127.0.0.1:4270", bundle: .module)
                )
                .textContentType(.URL)
                .focused($focusedField, equals: .target)
                .accessibilityHint(AppText.localized("Enter an IP address, hostname, or HTTP service URL"))
                Picker(AppText.localized("Upstream Host"), selection: $draft.hostPolicy) {
                    Text(AppText.localized("Use upstream name")).tag(RemapHostPolicy.useUpstream)
                    Text(AppText.localized("Preserve client name")).tag(RemapHostPolicy.preserveClient)
                }
                .accessibilityHint(AppText.localized("Controls the Host header sent to an HTTP upstream"))
                Toggle(AppText.localized("Enabled"), isOn: $draft.enabled)
                    .accessibilityHint(AppText.localized("Disabled mappings remain stored but do not route traffic"))
            } header: {
                Text(AppText.localized("Mapping"))
            } footer: {
                Text(AppText.localized(
                    "A URL routes HTTP requests through Remap. An IP address or hostname creates a direct DNS mapping."
                ))
            }
            if let diagnostic {
                InlineDiagnostic(diagnostic: diagnostic)
            }
        }
        .formStyle(.grouped)
    }

    private func review(_ preview: RemapPreview) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            Text(
                preview.willChange
                    ? AppText.localized("Review the exact change")
                    : AppText.localized("Nothing will change")
            )
            .font(.title2.weight(.semibold))
            .accessibilityAddTraits(.isHeader)
            .accessibilityFocused($reviewFocused)
            Text(AppText.projectionRegistryRevision(preview.baseRevision))
                .foregroundStyle(.secondary)
            EffectList(effects: preview.effects)
            if let diagnostic {
                InlineDiagnostic(diagnostic: diagnostic)
            }
            Spacer()
        }
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
                Button(preview.willChange ? AppText.localized("Apply") : AppText.localized("Done")) {
                    if preview.willChange {
                        apply(preview)
                    } else {
                        dismiss()
                    }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(isWorking)
                .accessibilityHint(
                    preview.willChange
                        ? AppText.localized("Applies the exact effects shown in this review")
                        : AppText.localized("Closes this review without changing state")
                )
            } else {
                Button(AppText.localized("Review")) { loadPreview() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(isWorking || draft.pattern.isEmpty || draft.target.isEmpty)
                    .accessibilityHint(AppText.localized("Calculates the exact effects without changing state"))
            }
        }
    }

    private var title: String {
        if receipt != nil {
            return AppText.localized("Mapping Applied")
        }
        if preview != nil {
            return AppText.localized("Review Mapping")
        }
        return original == nil ? AppText.localized("New Mapping") : AppText.localized("Edit Mapping")
    }

    private func loadPreview() {
        isWorking = true
        diagnostic = nil
        Task {
            defer { isWorking = false }
            do {
                preview = try await store.preview(draft.change)
                reviewFocused = true
            } catch {
                diagnostic = appDiagnostic(error)
            }
        }
    }

    private func apply(_ preview: RemapPreview) {
        isWorking = true
        diagnostic = nil
        Task {
            defer { isWorking = false }
            do {
                receipt = try await store.apply(
                    draft.change,
                    expectedRevision: preview.baseRevision
                )
                self.preview = nil
            } catch {
                diagnostic = appDiagnostic(error)
            }
        }
    }
}
