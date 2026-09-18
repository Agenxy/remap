import Foundation
@testable import RemapInstallKit
import Testing

@Test
func nativeEffectAdapterKeepsAJobLaunchdReloadedFromItsPublishedPlist() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-restart")
    try fixture.launchd.reloadFromPublishedPlists()
    let context = try InstallTransitionContext(
        operation: .install,
        current: fixture.manifest,
        previous: nil
    )
    try await fixture.effects.reconcile(.serviceRunning, context: context)
    try await fixture.effects.verify(.serviceRunning, context: context)
    #expect(fixture.launchd.bootoutCount == 0)
    let status = try fixture.installer.status()
    let everyServiceLoaded = status.services.allSatisfy(\.loaded)
    #expect(everyServiceLoaded)
}
