import SwiftUI

struct SystemView: View {
    let store: RemapStore

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 24) {
                Text(AppText.localized("System"))
                    .font(.largeTitle.weight(.semibold))
                    .accessibilityAddTraits(.isHeader)
                Text(AppText.localized(
                    "The system status Remap can check without exposing your private mappings."
                ))
                .foregroundStyle(.secondary)
                stateCard
                boundaries
            }
            .padding(28)
            .frame(maxWidth: 760, alignment: .leading)
        }
        .navigationTitle(AppText.localized("System"))
    }

    private var stateCard: some View {
        Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 14) {
            systemRow(
                AppText.localized("Remap service"),
                authorityValue,
                authoritySymbol,
                AppText.localized("Connection to the Remap background service")
            )
            Divider()
            systemRow(
                AppText.localized("macOS DNS"),
                resolverValue,
                resolverSymbol,
                AppText.localized("Native resolver configuration owned by Remap")
            )
            Divider()
            systemRow(
                AppText.localized("DNS listener"),
                dnsValue,
                dnsSymbol,
                AppText.localized("Authenticated UDP and TCP DNS runtime identity")
            )
            Divider()
            systemRow(
                AppText.localized("HTTP gateway"),
                gatewayValue,
                gatewaySymbol,
                AppText.localized("Authenticated local HTTP gateway runtime identity")
            )
            Divider()
            systemRow(
                AppText.localized("Service version"),
                store.status?.daemonVersion ?? AppText.localized("Unavailable"),
                "shippingbox",
                AppText.localized("Version reported by the running Remap service")
            )
        }
        .padding(18)
        .background(.background.secondary, in: .rect(cornerRadius: 12))
    }

    private var boundaries: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(AppText.localized("Source-build resolver boundary"))
                .font(.title2.weight(.semibold))
                .accessibilityAddTraits(.isHeader)
            Text(AppText.localized("Source builds support one ordinary macOS resolver scope."))
                .foregroundStyle(.secondary)
            Text(AppText.localized("Remap refuses VPN or split DNS when it cannot preserve the configuration."))
                .foregroundStyle(.secondary)
            Text(AppText.localized("Use the entitled DNS System Extension for multiple resolver scopes."))
                .foregroundStyle(.secondary)
            Text(AppText.localized("Remap has no telemetry and sends no registry data to Agenxy."))
                .foregroundStyle(.secondary)
        }
    }

    private var authorityValue: String {
        switch store.authorityState {
        case .connecting: AppText.localized("Connecting")
        case .ready: AppText.localized("Connected")
        case .unavailable: AppText.localized("Unavailable")
        }
    }

    private var authoritySymbol: String {
        store.authorityState == .ready ? "checkmark.circle.fill" : "exclamationmark.circle.fill"
    }

    private var resolverValue: String {
        switch store.resolverState {
        case .checking: AppText.localized("Checking")
        case .active: AppText.localized("Active on loopback")
        case .inactive: AppText.localized("Inactive")
        case .unavailable: AppText.localized("Unavailable")
        }
    }

    private var resolverSymbol: String {
        if case .active = store.resolverState {
            return "checkmark.circle.fill"
        }
        return "circle"
    }

    private var gatewayValue: String {
        switch store.gatewayState {
        case .checking: AppText.localized("Checking")
        case .authenticated: AppText.localized("Authenticated on loopback")
        case .unavailable: AppText.localized("Identity unavailable")
        }
    }

    private var gatewaySymbol: String {
        store.gatewayState == .authenticated ? "checkmark.circle.fill" : "circle"
    }

    private var dnsValue: String {
        switch store.dnsState {
        case .checking: AppText.localized("Checking UDP and TCP")
        case .authenticated: AppText.localized("Authenticated over UDP and TCP")
        case .unavailable: AppText.localized("Identity unavailable")
        }
    }

    private var dnsSymbol: String {
        store.dnsState == .authenticated ? "checkmark.circle.fill" : "circle"
    }

    private func systemRow(
        _ label: String,
        _ value: String,
        _ symbol: String,
        _ hint: String
    ) -> some View {
        GridRow {
            Text(label)
                .foregroundStyle(.secondary)
                .gridColumnAlignment(.trailing)
            Label(value, systemImage: symbol)
                .textSelection(.enabled)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(value)
        .accessibilityHint(hint)
    }
}
