import SwiftUI

struct SettingsView: View {
    @AppStorage("show-disabled-mappings") private var showDisabledMappings = true

    var body: some View {
        Form {
            Section(AppText.localized("Mappings")) {
                Toggle(AppText.localized("Show disabled mappings"), isOn: $showDisabledMappings)
                Text(AppText.localized("Disabled mappings remain stored but do not affect resolution."))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Section(AppText.localized("Privacy")) {
                LabeledContent(AppText.localized("Telemetry"), value: AppText.localized("None"))
                LabeledContent(AppText.localized("Account"), value: AppText.localized("Not required"))
                LabeledContent(
                    AppText.localized("Agenxy cloud dependency"),
                    value: AppText.localized("None")
                )
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 420, idealWidth: 480)
        .padding(.vertical, 12)
    }
}
