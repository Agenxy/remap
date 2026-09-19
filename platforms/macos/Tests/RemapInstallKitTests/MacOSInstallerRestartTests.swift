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

@Test
func nativeEffectAdapterRefusesAPublishedPlistWhoseBytesAreNotTheGenerations() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-tampering")
    try fixture.launchd.reloadFromPublishedPlists()
    // Same path, same program, other contents: a job that is not ours.
    let published = fixture.rootURL.appending(
        path: "Library/LaunchDaemons/\(MacOSLaunchdServiceKind.daemon.label).plist"
    )
    let attributes = try FileManager.default.attributesOfItem(atPath: published.path)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: published.path)
    var bytes = try Data(contentsOf: published)
    bytes.append(Data("<!-- other arguments -->".utf8))
    try bytes.write(to: published)
    try FileManager.default.setAttributes(
        [.posixPermissions: attributes[.posixPermissions] ?? 0o444],
        ofItemAtPath: published.path
    )
    let context = try InstallTransitionContext(
        operation: .install,
        current: fixture.manifest,
        previous: nil
    )
    await #expect(throws: InstallError.self) {
        try await fixture.effects.reconcile(.serviceRunning, context: context)
    }
    #expect(fixture.launchd.bootoutCount == 0)
}
