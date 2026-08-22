import SwiftUI

struct ContentView: View {
    let store: RemapStore
    let presentation: AppPresentation

    var body: some View {
        @Bindable var presentation = presentation
        NavigationSplitView {
            SidebarView(selection: $presentation.selectedSection)
        } detail: {
            detail
        }
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                Button {
                    presentation.createMapping()
                } label: {
                    Label(AppText.localized("New Mapping"), systemImage: "plus")
                }
                .disabled(!store.canMutateMappings)
                .help(AppText.localized("Create a mapping and review its exact effect before applying it"))
                .accessibilityHint(AppText.localized("Opens the mapping editor"))

                Button {
                    Task { await store.refresh() }
                } label: {
                    Label(AppText.localized("Refresh"), systemImage: "arrow.clockwise")
                }
                .disabled(store.isRefreshing)
                .help(AppText.localized("Refresh Remap and network status"))
                .accessibilityHint(AppText.localized("Checks Remap and your Mac's network settings again"))
            }
        }
        .safeAreaInset(edge: .bottom) {
            if let diagnostic = store.diagnostic {
                DiagnosticBanner(diagnostic: diagnostic, dismiss: store.dismissDiagnostic)
            }
        }
        .sheet(item: $presentation.mappingEditor) { editor in
            MappingEditorView(
                store: store,
                original: editor.original
            )
        }
        .sheet(item: $presentation.operationReview) { review in
            OperationReviewView(
                store: store,
                title: review.title,
                change: review.change
            )
        }
        .task {
            await store.observeUntilCancelled()
        }
        .respectsReducedMotion()
    }

    @ViewBuilder
    private var detail: some View {
        switch presentation.selectedSection {
        case .overview:
            OverviewView(store: store, presentation: presentation)
        case .mappings:
            MappingsView(store: store, presentation: presentation)
        case .system:
            SystemView(store: store)
        }
    }
}
