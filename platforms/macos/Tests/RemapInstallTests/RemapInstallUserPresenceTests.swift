import LocalAuthentication
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

@Test
func installerUserPresenceSaysWhyTheDialogEndedWithoutApproval() async throws {
    let token = try InstallApprovalToken(String(repeating: "a", count: 64))
    await #expect(throws: InstallError.approval(
        "macOS user authentication did not approve this installer change"
            + " (the prompt was cancelled)"
    )) {
        try await RemapInstallUserPresence.authorize(
            reviewedToken: token,
            expectedToken: token,
            evaluate: { throw LAError(.userCancel) }
        )
    }
    #expect(RemapInstallUserPresence.reason(for: LAError(.notInteractive))
        == "no interactive session could show the prompt")
}

@Test
func installerUserPresenceIsPutToTheInvokingUserOnlyUnderSudoAsRoot() {
    #expect(RemapInstallUserPresence.invokingUser(euid: 0, environment: ["SUDO_UID": "501"]) == 501)
    #expect(RemapInstallUserPresence.invokingUser(euid: 501, environment: ["SUDO_UID": "501"]) == nil)
    #expect(RemapInstallUserPresence.invokingUser(euid: 0, environment: [:]) == nil)
    #expect(RemapInstallUserPresence.invokingUser(euid: 0, environment: ["SUDO_UID": "0"]) == nil)
    #expect(RemapInstallUserPresence.invokingUser(euid: 0, environment: ["SUDO_UID": "the maintainer"]) == nil)
}
