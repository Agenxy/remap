import AppKit
import SwiftUI

@main
struct RemapApp: App {
    @NSApplicationDelegateAdaptor(RemapAppDelegate.self) private var appDelegate
    @State private var presentation = AppPresentation()
    @State private var store = RemapStore()

    var body: some Scene {
        WindowGroup(AppText.localized("Remap"), id: "main") {
            ContentView(store: store, presentation: presentation)
                .frame(minWidth: 780, minHeight: 520)
        }
        .defaultSize(width: 980, height: 680)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button(AppText.localized("New Mapping")) {
                    presentation.createMapping()
                }
                .keyboardShortcut("n", modifiers: .command)
                .disabled(!store.canMutateMappings)
            }
            CommandGroup(after: .sidebar) {
                Button(AppText.localized("Refresh")) {
                    Task { await store.refresh() }
                }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(store.isRefreshing)
            }
            CommandMenu(AppText.localized("Navigation")) {
                ForEach(AppSection.allCases) { section in
                    Button(section.title) {
                        presentation.navigate(to: section)
                    }
                    .keyboardShortcut(section.keyboardShortcut, modifiers: .command)
                }
            }
        }

        Settings {
            SettingsView()
        }
    }
}

final class RemapAppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }
}
