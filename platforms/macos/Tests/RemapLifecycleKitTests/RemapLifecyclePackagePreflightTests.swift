import RemapInstallKit
@testable import RemapLifecycleKit
import Synchronization
import Testing

@Test
func packagePreflightAcceptsAnAbsentProductRoot() throws {
    try RemapLifecyclePackagePreflight(exists: { _ in false }).validateCleanInstall()
}

@Test
func packagePreflightFinishesApprovedPortableCleanupBeforeInspection() throws {
    let residuePresent = Mutex(true)
    try RemapLifecyclePackagePreflight(
        exists: { _ in residuePresent.withLock { $0 } },
        recoverCleanup: { residuePresent.withLock { $0 = false } }
    ).validateCleanInstall()
    #expect(!residuePresent.withLock { $0 })
}

@Test
func packagePreflightRecognizesEveryValidatedHistoricalOrganisationMode() {
    #expect(
        RemapLifecyclePackagePreflight.recoverableOrganisationModes
            == [0o700, 0o711, 0o755]
    )
    #expect(
        RemapLifecyclePackagePreflight.recoverableProductModes
            == [0o700, 0o711]
    )
}

@Test
func packagePreflightRejectsPartialAuthorityBeforePayloadMutation() throws {
    #expect(throws: InstallError.self) {
        try RemapLifecyclePackagePreflight(
            exists: { path in
                path.description.contains("PrivilegedHelperTools")
            }
        ).validateCleanInstall()
    }
}

@Test
func packagePreflightAcceptsOnlyCompletelyValidatedExistingAuthority() throws {
    let events = Mutex<[String]>([])
    try RemapLifecyclePackagePreflight(
        exists: { _ in true },
        validateExisting: {
            events.withLock { $0.append("validated") }
        },
        migrateExisting: {
            events.withLock { $0.append("migrated") }
        }
    ).validateCleanInstall()

    #expect(events.withLock { $0 } == ["validated", "migrated"])
}

@Test
func packagePreflightNeverMigratesPartialOrUnvalidatedAuthority() {
    let migrationCount = Mutex(0)
    #expect(throws: InstallError.self) {
        try RemapLifecyclePackagePreflight(
            exists: { path in path.description.contains("PrivilegedHelperTools") },
            migrateExisting: { migrationCount.withLock { $0 += 1 } }
        ).validateCleanInstall()
    }
    #expect(migrationCount.withLock { $0 } == 0)
}

@Test
func packagePreflightRejectsUnvalidatedExistingAuthority() {
    #expect(throws: InstallError.self) {
        try RemapLifecyclePackagePreflight(exists: { _ in true })
            .validateCleanInstall()
    }
}

@Test
func packagePreflightChecksOnlyTheThreeFixedAuthorityRoots() throws {
    let observed = Mutex<[String]>([])
    try RemapLifecyclePackagePreflight(
        exists: { path in
            observed.withLock { $0.append(path.description) }
            return false
        }
    ).validateCleanInstall()

    #expect(
        observed.withLock { $0 } == [
            "Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service",
            "Library/LaunchDaemons/org.agenxy.Remap.installer-service.plist",
            "Library/Application Support/Agenxy/Remap"
        ]
    )
}
