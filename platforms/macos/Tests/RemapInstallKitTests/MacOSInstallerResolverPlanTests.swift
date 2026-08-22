@testable import RemapInstallKit
import Testing

@Test
func installerResolverPlanAcceptsTheDataPlaneMaximum() throws {
    let addresses = ["192.0.2.1", "198.51.100.2", "2001:db8::3", "2001:db8::4"]
    let plan = try MacOSInstallerResolverPlan(serviceCount: 1, upstreamAddresses: addresses)

    #expect(plan.schemaVersion == 1)
    #expect(plan.serviceCount == 1)
    #expect(plan.upstreams == ["192.0.2.1:53", "198.51.100.2:53", "[2001:db8::3]:53", "[2001:db8::4]:53"])
}

@Test
func installerResolverPlanRejectsMoreThanTheDataPlaneMaximum() {
    let addresses = ["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"]

    #expect(throws: InstallError.integrity("the native resolver plan exceeds remapd's four-upstream limit")) {
        try MacOSInstallerResolverPlan(serviceCount: 1, upstreamAddresses: addresses)
    }
}

@Test
func installerResolverPlanRejectsAnEmptyUpstreamSet() {
    #expect(throws: InstallError.integrity("the native resolver plan has no upstreams")) {
        try MacOSInstallerResolverPlan(serviceCount: 1, upstreamAddresses: [])
    }
}
