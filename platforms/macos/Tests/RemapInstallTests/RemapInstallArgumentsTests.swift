@testable import RemapInstall
import RemapInstallKit
import Testing

@Test
func mutationRequiresTheExactTypedApprovalFlag() throws {
    let token = String(repeating: "a", count: 64)
    let invocation = try RemapInstallArguments.parse([
        "install",
        "--package-root", "/private/package",
        "--manifest-sha256", String(repeating: "b", count: 64),
        "--source-uid", "501",
        "--approval-token", token,
        "--json"
    ])

    guard case let .install(_, _, sourceUID, approvalToken, transactionID) = invocation.command else {
        Issue.record("install arguments did not produce the typed install command")
        return
    }
    #expect(invocation.json)
    #expect(sourceUID == 501)
    let expectedToken = try InstallApprovalToken(token)
    #expect(approvalToken == expectedToken)
    #expect(transactionID == nil)
}

@Test
func mutationRejectsMissingOrNoncanonicalApprovalTokens() {
    let base = [
        "update",
        "--package-root", "/private/package",
        "--manifest-sha256", String(repeating: "b", count: 64),
        "--source-uid", "501"
    ]
    #expect(throws: InstallError.unsupported(
        "update requires --approval-token from its exact preview"
    )) {
        try RemapInstallArguments.parse(base)
    }
    #expect(throws: InstallError.unsupported(
        "update requires a canonical lowercase SHA-256 --approval-token"
    )) {
        try RemapInstallArguments.parse(base + [
            "--approval-token", String(repeating: "A", count: 64)
        ])
    }
}

@Test
func recoveryHasAnExplicitPreviewAndApprovalHandshake() throws {
    #expect(
        try RemapInstallArguments.parse(["preview", "recover", "--all"]).command
            == .previewRecoverAll
    )
    let token = try InstallApprovalToken(String(repeating: "c", count: 64))
    #expect(
        try RemapInstallArguments.parse([
            "recover", "--all", "--approval-token", token.description
        ]).command == .recoverAll(approvalToken: token)
    )
    #expect(throws: InstallError.unsupported(
        "recover requires --approval-token from its exact preview"
    )) {
        try RemapInstallArguments.parse(["recover", "--all"])
    }
}

@Test
func bootstrapRecoveryHasASeparateTypedApprovalHandshake() throws {
    #expect(
        try RemapInstallArguments.parse(["preview", "recover-bootstrap-helpers"]).command
            == .previewRecoverBootstrapHelpers
    )
    let token = try InstallApprovalToken(String(repeating: "d", count: 64))
    #expect(
        try RemapInstallArguments.parse([
            "recover-bootstrap-helpers", "--approval-token", token.description
        ]).command == .recoverBootstrapHelpers(approvalToken: token)
    )
    #expect(throws: InstallError.unsupported(
        "recover-bootstrap-helpers requires --approval-token from its exact preview"
    )) {
        try RemapInstallArguments.parse(["recover-bootstrap-helpers"])
    }
}
