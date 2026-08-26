@testable import RemapInstall
import RemapInstallKit
import Testing

@Test
func installerUserPresenceRequiresMatchingPreviewAndAuthentication() async throws {
    let token = try InstallApprovalToken(String(repeating: "a", count: 64))
    try await RemapInstallUserPresence.authorize(
        reviewedToken: token,
        expectedToken: token,
        evaluate: { true }
    )

    await #expect(throws: InstallError.approval(
        "macOS user authentication did not approve this installer change"
    )) {
        try await RemapInstallUserPresence.authorize(
            reviewedToken: token,
            expectedToken: token,
            evaluate: { false }
        )
    }
    await #expect(throws: InstallError.approval(
        "macOS user authentication did not approve this installer change"
    )) {
        try await RemapInstallUserPresence.authorize(
            reviewedToken: token,
            expectedToken: token,
            evaluate: { throw TestInstallerPresenceError() }
        )
    }
}

@Test
func installerUserPresenceRejectsAStaleTokenBeforeAuthentication() async throws {
    let reviewed = try InstallApprovalToken(String(repeating: "a", count: 64))
    let current = try InstallApprovalToken(String(repeating: "b", count: 64))
    await #expect(throws: InstallError.approval(
        "the approved preview is stale or does not match this operation"
    )) {
        try await RemapInstallUserPresence.authorize(
            reviewedToken: reviewed,
            expectedToken: current,
            evaluate: { throw TestInstallerPresenceError() }
        )
    }
}

private struct TestInstallerPresenceError: Error {}
