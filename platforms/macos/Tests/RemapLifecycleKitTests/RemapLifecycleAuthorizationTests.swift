import Foundation
import RemapInstallKit
@testable import RemapLifecycleKit
import Testing

@Test
func lifecycleConfigurationRoundTripsCanonically() throws {
    let configuration = try fixtureConfiguration()
    let data = try configuration.canonicalData()

    #expect(try RemapLifecycleServiceConfiguration.decodeCanonical(data) == configuration)
    #expect(data.count < RemapLifecycleServiceConfiguration.maximumByteCount)
}

@Test
func lifecycleConfigurationRejectsAHelperSignedByAnotherRoot() throws {
    let app = try fixtureIdentity(
        identifier: "org.agenxy.Remap",
        certificate: "a"
    )
    let helper = try fixtureIdentity(
        identifier: "org.agenxy.Remap.installer-service",
        certificate: "b"
    )

    #expect(throws: InstallError.self) {
        _ = try RemapLifecycleServiceConfiguration(
            ownerUID: 501,
            app: app,
            bootstrap: fixtureIdentity(
                identifier: "org.agenxy.Remap.installer-bootstrap",
                certificate: "a"
            ),
            helper: helper,
            sourceManifestDigest: InstallDigest(String(repeating: "d", count: 64)),
            sourcePackageRoot: InstallAbsolutePath(
                "/Library/Application Support/Agenxy/Remap/Installer/Sources/d"
            )
        )
    }
}

@Test
func lifecycleConfigurationRejectsAConfiguredSourceOutsideItsDigestBoundRoot() throws {
    #expect(throws: InstallError.self) {
        _ = try RemapLifecycleServiceConfiguration(
            ownerUID: 501,
            app: fixtureIdentity(identifier: "org.agenxy.Remap", certificate: "a"),
            bootstrap: fixtureIdentity(
                identifier: "org.agenxy.Remap.installer-bootstrap",
                certificate: "a"
            ),
            helper: fixtureIdentity(
                identifier: "org.agenxy.Remap.installer-service",
                certificate: "a"
            ),
            sourceManifestDigest: InstallDigest(String(repeating: "d", count: 64)),
            sourcePackageRoot: InstallAbsolutePath("/private/tmp/foreign")
        )
    }
}

@Test
func lifecycleCallerRequiresTheExactUIDAndCDHash() throws {
    let configuration = try fixtureConfiguration()
    let checker = FixtureCodeIdentityChecker(
        current: configuration.helper,
        peer: configuration.app
    )
    let authenticator = RemapLifecycleCallerAuthenticator(
        configuration: configuration,
        checker: checker
    )

    try authenticator.authorizeService()
    try authenticator.authorizeCaller(effectiveUID: 501, processID: 42)
    #expect(throws: InstallError.self) {
        try authenticator.authorizeCaller(effectiveUID: 502, processID: 42)
    }

    let foreign = try fixtureIdentity(
        identifier: "org.agenxy.Remap",
        certificate: "a",
        cdHash: "c"
    )
    let rejected = RemapLifecycleCallerAuthenticator(
        configuration: configuration,
        checker: FixtureCodeIdentityChecker(
            current: configuration.helper,
            peer: foreign
        )
    )
    #expect(throws: InstallError.self) {
        try rejected.authorizeCaller(effectiveUID: 501, processID: 42)
    }

    let repair = try RemapLifecycleCallerAuthenticator(
        configuration: configuration,
        checker: FixtureCodeIdentityChecker(
            current: fixtureIdentity(
                identifier: "org.agenxy.Remap.installer-bootstrap",
                certificate: "a",
                cdHash: "c"
            ),
            peer: configuration.app
        )
    )
    try repair.authorizeBootstrapRepair()

    let foreignRepair = try RemapLifecycleCallerAuthenticator(
        configuration: configuration,
        checker: FixtureCodeIdentityChecker(
            current: fixtureIdentity(
                identifier: "org.agenxy.Remap.installer-bootstrap",
                certificate: "b",
                cdHash: "c"
            ),
            peer: configuration.app
        )
    )
    #expect(throws: InstallError.self) {
        try foreignRepair.authorizeBootstrapRepair()
    }
}

@Test
func lifecycleCallerAcceptsOnlyTheConfiguredLocallySignedClient() throws {
    let client = try fixtureIdentity(
        identifier: "org.agenxy.Remap.lifecycle-cli",
        certificate: "a",
        cdHash: "c"
    )
    let configuration = try fixtureConfiguration(client: client)
    let authenticator = RemapLifecycleCallerAuthenticator(
        configuration: configuration,
        checker: FixtureCodeIdentityChecker(current: configuration.helper, peer: client)
    )

    try authenticator.authorizeCaller(effectiveUID: 501, processID: 42)

    let wrongCertificate = try fixtureIdentity(
        identifier: "org.agenxy.Remap.lifecycle-cli",
        certificate: "b",
        cdHash: "c"
    )
    let rejected = RemapLifecycleCallerAuthenticator(
        configuration: configuration,
        checker: FixtureCodeIdentityChecker(current: configuration.helper, peer: wrongCertificate)
    )
    #expect(throws: InstallError.self) {
        try rejected.authorizeCaller(effectiveUID: 501, processID: 42)
    }
}

@Test
func lifecycleConfigurationRejectsAClientSignedByAnotherRoot() throws {
    #expect(throws: InstallError.self) {
        _ = try fixtureConfiguration(client: fixtureIdentity(
            identifier: "org.agenxy.Remap.lifecycle-cli",
            certificate: "b"
        ))
    }
}

private struct FixtureCodeIdentityChecker: RemapLifecycleCodeIdentityChecking {
    let current: RemapLifecycleCodeIdentity
    let peer: RemapLifecycleCodeIdentity

    func currentIdentity() -> RemapLifecycleCodeIdentity {
        current
    }

    func identity(processID _: pid_t) -> RemapLifecycleCodeIdentity {
        peer
    }

    func identity(fileDescriptor _: Int32) -> RemapLifecycleCodeIdentity {
        current
    }
}

private func fixtureConfiguration(
    client: RemapLifecycleCodeIdentity? = nil
) throws -> RemapLifecycleServiceConfiguration {
    try RemapLifecycleServiceConfiguration(
        ownerUID: 501,
        app: fixtureIdentity(identifier: "org.agenxy.Remap", certificate: "a"),
        client: client,
        bootstrap: fixtureIdentity(
            identifier: "org.agenxy.Remap.installer-bootstrap",
            certificate: "a"
        ),
        helper: fixtureIdentity(
            identifier: "org.agenxy.Remap.installer-service",
            certificate: "a",
            cdHash: "b"
        ),
        sourceManifestDigest: InstallDigest(String(repeating: "d", count: 64)),
        sourcePackageRoot: InstallAbsolutePath(
            "/Library/Application Support/Agenxy/Remap/Installer/Sources/"
                + String(repeating: "d", count: 64)
        )
    )
}

private func fixtureIdentity(
    identifier: String,
    certificate: Character,
    cdHash: Character = "a"
) throws -> RemapLifecycleCodeIdentity {
    try RemapLifecycleCodeIdentity(
        identifier: identifier,
        certificateSHA256: InstallDigest(String(repeating: certificate, count: 64)),
        cdHash: String(repeating: cdHash, count: 40)
    )
}
