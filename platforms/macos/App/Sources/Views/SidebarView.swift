import SwiftUI

struct SidebarView: View {
    @Binding var selection: AppSection

    var body: some View {
        List(AppSection.allCases, selection: $selection) { section in
            Label(section.title, systemImage: section.symbol)
                .tag(section)
                .accessibilityHint(AppText.localized("Shows this section"))
        }
        .listStyle(.sidebar)
        .navigationTitle(AppText.localized("Remap"))
        .frame(minWidth: 190)
    }
}
