import Foundation
@testable import RemapInstallKit
import Testing

@Test
func nativeUpdateRestoresOrdinaryDnsBeforeReplacingServicesAndPreloadsTheNewPlan() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-safe-handoff")
    let update = try fixture.updatePackage(
        generationID: "native-safe-handoff-update",
        productVersion: "1.0.1"
    )
    fixture.launchd.selectGeneration(update.manifest.generationID)
    let context = try InstallTransitionContext(
        operation: .update,
        current: update.manifest,
        previous: fixture.manifest
    )
    let staging = try fixture.layout.generations.stage(
        update.manifest,
        from: update.source,
        transactionID: "safe-handoff-stage"
    )
    try fixture.layout.generations.publish(staging, manifest: update.manifest)

    try await fixture.effects.reconcile(.serviceRunning, context: context)
    let afterServiceSwitch = try fixture.resolver.observation()
    #expect(!afterServiceSwitch.recordPresent)
    #expect(afterServiceSwitch.remapServiceIDs.isEmpty)

    try await fixture.effects.reconcile(.dnsActive, context: context)
    #expect(fixture.resolver.eventSnapshot().suffix(3) == [
        "restore-ordinary-dns",
        "publish-plan-before-dns",
        "activate-dns"
    ])
    let active = try fixture.resolver.observation()
    #expect(active.activeRecord)
    #expect(active.remapServiceIDs == ["test-service"])
}

@Test
func rejectedUpdatePlanNeverPointsTheMacAtDormantRemapDns() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-rejected-plan")
    let update = try fixture.updatePackage(
        generationID: "native-rejected-plan-update",
        productVersion: "1.0.1"
    )
    fixture.launchd.selectGeneration(update.manifest.generationID)
    let context = try InstallTransitionContext(
        operation: .update,
        current: update.manifest,
        previous: fixture.manifest
    )
    let staging = try fixture.layout.generations.stage(
        update.manifest,
        from: update.source,
        transactionID: "rejected-plan-stage"
    )
    try fixture.layout.generations.publish(staging, manifest: update.manifest)

    try await fixture.effects.reconcile(.serviceRunning, context: context)
    fixture.resolver.failNextActivation()
    await #expect(throws: InstallError.integrity("prepared resolver plan was rejected")) {
        try await fixture.effects.reconcile(.dnsActive, context: context)
    }

    let observation = try fixture.resolver.observation()
    #expect(observation.phase == .prepared)
    #expect(observation.remapServiceIDs.isEmpty)
    #expect(fixture.resolver.eventSnapshot().last == "publish-plan-before-dns")
}

@Test
func updateWaitsForLaunchdToFinishAnAsynchronousBootout() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-delayed-bootout")
    let update = try fixture.updatePackage(
        generationID: "native-delayed-bootout-update",
        productVersion: "1.0.1"
    )
    fixture.launchd.selectGeneration(update.manifest.generationID)
    fixture.launchd.delayEveryBootoutObservation(by: 3)
    let context = try InstallTransitionContext(
        operation: .update,
        current: update.manifest,
        previous: fixture.manifest
    )
    let staging = try fixture.layout.generations.stage(
        update.manifest,
        from: update.source,
        transactionID: "delayed-bootout-stage"
    )
    try fixture.layout.generations.publish(staging, manifest: update.manifest)

    try await fixture.effects.reconcile(.serviceRunning, context: context)
    try await fixture.effects.verify(.serviceRunning, context: context)

    #expect(fixture.launchd.bootoutCount == 2)
}
