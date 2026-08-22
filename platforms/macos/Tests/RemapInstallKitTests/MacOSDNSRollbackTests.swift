import Darwin
@testable import RemapInstallKit
import Testing

@Test
func nativeUpdateRollbackRestoresThePriorActiveDNSGeneration() async throws {
    let fixture = try MacOSInstallerFixture()
    try await fixture.install(transactionID: "install-before-dns-rollback")
    let update = try fixture.updatePackage(
        generationID: "rejected-dns-generation",
        productVersion: "1.0.1"
    )
    let staging = try fixture.layout.generations.stage(
        update.manifest,
        from: update.source,
        transactionID: "rejected-dns-update"
    )
    try fixture.layout.generations.publish(staging, manifest: update.manifest)
    fixture.resolver.setObservation(MacOSResolverObservation(
        ownerUID: UInt32(geteuid()),
        productVersion: update.manifest.productVersion,
        phase: .active,
        configuredServiceIDs: ["test-service"],
        remapServiceIDs: ["test-service"]
    ))
    let context = try InstallTransitionContext(
        operation: .update,
        current: update.manifest,
        previous: fixture.manifest
    )

    try await fixture.effects.reconcile(.dnsRestored, context: context)
    try await fixture.effects.verify(.dnsRestored, context: context)

    let observation = try fixture.resolver.observation()
    #expect(observation.activeRecord)
    #expect(observation.productVersion == fixture.manifest.productVersion)
    #expect(observation.remapServiceIDs == ["test-service"])
    #expect(fixture.resolver.eventSnapshot().suffix(3) == [
        "restore-ordinary-dns",
        "publish-plan-before-dns",
        "activate-dns"
    ])
}
