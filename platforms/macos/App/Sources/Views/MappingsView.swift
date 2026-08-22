import RemapControlKit
import SwiftUI

struct MappingsView: View {
    let store: RemapStore
    let presentation: AppPresentation

    @State private var query = ""
    @AppStorage("show-disabled-mappings") private var showDisabledMappings = true

    var body: some View {
        HSplitView {
            mappingList
                .frame(minWidth: 290, idealWidth: 340, maxWidth: 440)
            detail
                .frame(minWidth: 410, maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle(AppText.localized("Mappings"))
    }

    private var mappingList: some View {
        List(selection: selectedPattern) {
            ForEach(filteredMappings) { mapping in
                MappingSummaryRow(mapping: mapping)
                    .tag(mapping.pattern)
                    .contextMenu {
                        Button(AppText.localized("Edit")) { presentation.edit(mapping) }
                            .disabled(!store.canMutateMappings)
                        Button(
                            mapping.enabled ? AppText.localized("Disable") : AppText.localized("Enable")
                        ) {
                            reviewToggle(mapping)
                        }
                        .disabled(!store.canMutateMappings)
                        Divider()
                        Button(AppText.localized("Remove"), role: .destructive) {
                            reviewRemoval(mapping)
                        }
                        .disabled(!store.canMutateMappings)
                    }
            }
        }
        .searchable(
            text: $query,
            placement: .sidebar,
            prompt: AppText.localized("Filter mappings")
        )
        .accessibilityLabel(AppText.localized("Mappings"))
        .overlay {
            if store.authorityState != .ready {
                ContentUnavailableView(
                    AppText.localized("Unavailable"),
                    systemImage: "bolt.horizontal.circle"
                )
            } else if filteredMappings.isEmpty {
                ContentUnavailableView.search(text: query)
            }
        }
    }

    @ViewBuilder
    private var detail: some View {
        if let mapping = selectedVisibleMapping {
            MappingDetailView(
                mapping: mapping,
                editable: store.canMutateMappings,
                edit: { presentation.edit(mapping) },
                toggle: { reviewToggle(mapping) },
                remove: { reviewRemoval(mapping) }
            )
        } else if store.authorityState == .ready {
            ContentUnavailableView(
                AppText.localized("Select a mapping"),
                systemImage: "arrow.triangle.branch",
                description: Text(AppText.localized("Choose a mapping to inspect its exact routing policy."))
            )
        } else {
            ContentUnavailableView {
                Label(AppText.localized("Mappings unavailable"), systemImage: "bolt.horizontal.circle")
            } description: {
                Text(AppText.localized(
                    "Remap isn't responding. Try Refresh. If that doesn't work, repair the Remap installation."
                ))
            } actions: {
                Button(AppText.localized("Refresh")) {
                    Task { await store.refresh() }
                }
                .disabled(store.isRefreshing)
                .accessibilityHint(AppText.localized("Tries to reconnect to Remap"))
            }
        }
    }

    private var filteredMappings: [RemapMapping] {
        guard !query.isEmpty else { return visibleMappings }
        return visibleMappings.filter {
            $0.pattern.localizedCaseInsensitiveContains(query)
                || $0.target.localizedCaseInsensitiveContains(query)
        }
    }

    private var visibleMappings: [RemapMapping] {
        showDisabledMappings ? store.mappings : store.mappings.filter(\.enabled)
    }

    private var selectedVisibleMapping: RemapMapping? {
        guard let mapping = store.selectedMapping else { return nil }
        return showDisabledMappings || mapping.enabled ? mapping : nil
    }

    private var selectedPattern: Binding<String?> {
        Binding(
            get: { store.selectedPattern },
            set: { store.selectedPattern = $0 }
        )
    }

    private func reviewToggle(_ mapping: RemapMapping) {
        let change: RemapChange = mapping.enabled
            ? .disable(pattern: mapping.pattern)
            : .enable(pattern: mapping.pattern)
        presentation.review(
            title: mapping.enabled
                ? AppText.localized("Disable Mapping")
                : AppText.localized("Enable Mapping"),
            change: change
        )
    }

    private func reviewRemoval(_ mapping: RemapMapping) {
        presentation.review(
            title: AppText.localized("Remove Mapping"),
            change: .remove(pattern: mapping.pattern)
        )
    }
}
