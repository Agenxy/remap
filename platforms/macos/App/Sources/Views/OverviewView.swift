import RemapControlKit
import SwiftUI

struct OverviewView: View {
    let store: RemapStore
    let presentation: AppPresentation
    @AppStorage("show-disabled-mappings") private var showDisabledMappings = true

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                header
                metrics
                mappings
            }
            .padding(28)
            .frame(maxWidth: 900, alignment: .leading)
        }
        .navigationTitle(AppText.localized("Overview"))
    }

    private var header: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: 16) {
                authorityCopy
                Spacer()
                readinessStatus
            }
            VStack(alignment: .leading, spacing: 12) {
                authorityCopy
                readinessStatus
            }
        }
    }

    private var metrics: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 180), spacing: 12)], spacing: 12) {
            MetricCard(
                title: AppText.localized("Mappings"),
                value: store.status.map { String($0.mappingCount) } ?? AppText.localized("Not available"),
                detail: store.status.map { AppText.enabledMappings($0.enabledCount) }
                    ?? AppText.localized("Remap service unavailable")
            )
            MetricCard(
                title: AppText.localized("Revision"),
                value: store.status.map { String($0.revision) } ?? AppText.localized("Not available"),
                detail: AppText.localized("Saved mapping version")
            )
            MetricCard(
                title: AppText.localized("System DNS"),
                value: resolverValue,
                detail: resolverDetail
            )
        }
    }

    private var mappings: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text(AppText.localized("Mappings"))
                    .font(.title2.weight(.semibold))
                Spacer()
                Button(AppText.localized("New Mapping")) {
                    presentation.createMapping()
                }
                .disabled(!store.canMutateMappings)
                .accessibilityHint(AppText.localized("Opens the mapping editor"))
            }
            if store.authorityState != .ready {
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
                .frame(maxWidth: .infinity, minHeight: 190)
            } else if visibleMappings.isEmpty {
                ContentUnavailableView {
                    Label(AppText.localized("No mappings yet"), systemImage: "arrow.triangle.branch")
                } description: {
                    Text(AppText.localized("Map a hostname to an address or routed service."))
                } actions: {
                    Button(AppText.localized("Create Mapping")) {
                        presentation.createMapping()
                    }
                    .disabled(!store.canMutateMappings)
                    .accessibilityHint(AppText.localized("Opens the mapping editor"))
                }
                .frame(maxWidth: .infinity, minHeight: 190)
            } else {
                VStack(spacing: 0) {
                    ForEach(visibleMappings.prefix(5)) { mapping in
                        Button {
                            presentation.edit(mapping)
                        } label: {
                            MappingSummaryRow(
                                mapping: mapping,
                                accessibilityHint: AppText.localized("Opens this mapping in the editor")
                            )
                        }
                        .buttonStyle(.plain)
                        if mapping.id != visibleMappings.prefix(5).last?.id {
                            Divider()
                        }
                    }
                }
                .padding(.horizontal, 14)
                .background(.background.secondary, in: .rect(cornerRadius: 12))
            }
        }
    }

    private var visibleMappings: [RemapMapping] {
        showDisabledMappings ? store.mappings : store.mappings.filter(\.enabled)
    }

    private var authorityTitle: String {
        switch store.authorityState {
        case .connecting: AppText.localized("Connecting to Remap")
        case .ready where store.isSystemReady: AppText.localized("Names go where you point them")
        case .ready: AppText.localized("Routing needs attention")
        case .unavailable: AppText.localized("Remap isn't responding")
        }
    }

    private var authorityDetail: String {
        switch store.authorityState {
        case .connecting: AppText.localized("Checking Remap and your Mac's network settings.")
        case .ready where store.isSystemReady:
            AppText.localized("Remap and your Mac's network settings are ready.")
        case .ready:
            AppText.localized("Your mappings are available, but at least one routing component is not ready.")
        case .unavailable:
            AppText.localized("Remap isn't responding. Your mappings are still saved.")
        }
    }

    private var resolverDetail: String {
        switch store.resolverState {
        case .checking: AppText.localized("Inspecting native state")
        case let .active(resolver): AppText.ownedResolverServices(resolver.remapServiceIDs.count)
        case .inactive: AppText.localized("macOS resolver unchanged")
        case .unavailable: AppText.localized("Inspection failed")
        }
    }

    private var resolverValue: String {
        switch store.resolverState {
        case .checking: AppText.localized("Checking")
        case .active: AppText.localized("Active")
        case .inactive: AppText.localized("Inactive")
        case .unavailable: AppText.localized("Unavailable")
        }
    }

    private var authorityCopy: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(authorityTitle)
                .font(.largeTitle.weight(.semibold))
                .fixedSize(horizontal: false, vertical: true)
            Text(authorityDetail)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private var readinessStatus: some View {
        StatusPill(
            title: store.isSystemReady ? AppText.localized("Ready") : AppText.localized("Needs attention"),
            symbol: store.isSystemReady ? "checkmark.circle.fill" : "exclamationmark.circle.fill",
            color: store.isSystemReady ? .green : .orange,
            accessibilityLabel: AppText.localized("Remap system status"),
            accessibilityHint: AppText.localized("Summarizes Remap and macOS network readiness")
        )
    }
}

private struct MetricCard: View {
    let title: String
    let value: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(title)
                .font(.caption.weight(.medium))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.title2.monospacedDigit().weight(.semibold))
            Text(detail)
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(title)
        .accessibilityValue(value)
        .accessibilityHint(detail)
    }
}

struct StatusPill: View {
    let title: String
    let symbol: String
    let color: Color
    let accessibilityLabel: String
    let accessibilityHint: String

    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorSchemeContrast) private var colorSchemeContrast

    var body: some View {
        let presentation = AccessibilityPresentation(
            reduceMotion: reduceMotion,
            increasedContrast: colorSchemeContrast == .increased,
            differentiateWithoutColor: differentiateWithoutColor
        )
        Label(title, systemImage: symbol)
            .font(.callout.weight(.medium))
            .foregroundStyle(color)
            .padding(.horizontal, 11)
            .padding(.vertical, 6)
            .background(color.opacity(presentation.statusFillOpacity), in: .capsule)
            .overlay {
                Capsule()
                    .stroke(
                        color.opacity(presentation.statusBorderOpacity),
                        lineWidth: presentation.statusBorderWidth
                    )
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(accessibilityLabel)
            .accessibilityValue(title)
            .accessibilityHint(accessibilityHint)
            .respectsReducedMotion()
    }
}
