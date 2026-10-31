// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import RemapInstallKit
@testable import RemapLifecycleCLI
import Testing

@Test
func lifecycleCommandParserAcceptsTheDocumentedSurface() throws {
    #expect(try RemapLifecycleCLICommand.parse(["remap-lifecycle", "status"]) == .status(json: false))
    #expect(try RemapLifecycleCLICommand.parse(["remap-lifecycle", "--json", "recover"]) == .recover(json: true))
    #expect(try RemapLifecycleCLICommand.parse(["remap-lifecycle", "uninstall", "--json"]) == .uninstall(json: true))
    #expect(try RemapLifecycleCLICommand.parse(["remap-lifecycle", "--help"]) == .help)
}

@Test
func lifecycleCommandParserRejectsAmbiguousOrUnknownInput() {
    #expect(throws: RemapLifecycleCLIError.self) {
        try RemapLifecycleCLICommand.parse(["remap-lifecycle"])
    }
    #expect(throws: RemapLifecycleCLIError.self) {
        try RemapLifecycleCLICommand.parse(["remap-lifecycle", "status", "recover"])
    }
    #expect(throws: RemapLifecycleCLIError.self) {
        try RemapLifecycleCLICommand.parse(["remap-lifecycle", "delete"])
    }
    #expect(throws: RemapLifecycleCLIError.self) {
        try RemapLifecycleCLICommand.parse(["remap-lifecycle", "status", "--json", "--json"])
    }
}

@Test
func lifecycleApprovalRequiresAnInteractiveTerminal() throws {
    try RemapLifecycleCLIApproval.requireInteractive(true)
    #expect(throws: RemapLifecycleCLIError.approval(
        "mutating lifecycle commands require an interactive terminal"
    )) {
        try RemapLifecycleCLIApproval.requireInteractive(false)
    }
}

@Test
func lifecycleUserPresenceFailsClosed() async throws {
    try await RemapLifecycleUserPresence.authorize(evaluate: { true })
    await #expect(throws: RemapLifecycleCLIError.self) {
        try await RemapLifecycleUserPresence.authorize(evaluate: { false })
    }
    await #expect(throws: RemapLifecycleCLIError.self) {
        try await RemapLifecycleUserPresence.authorize(evaluate: {
            throw TestPresenceError()
        })
    }
}

private struct TestPresenceError: Error {}

@Test
func lifecycleOutputRemovesTerminalControls() {
    #expect(plain("safe\u{1B}[31m\ntext") == "safe?[31m?text")
    #expect(RemapLifecycleCLIOutput.help.contains("remap system status"))
    #expect(!RemapLifecycleCLIOutput.help.contains("--yes"))
    #expect(RemapLifecycleCLIOutput.help.contains("piped use cannot authorize"))
}

@Test
func lifecycleJSONErrorIsCanonicalAndBounded() throws {
    let data = try RemapLifecycleCLIErrorDocument.data(
        for: RemapLifecycleCLIError.approval("approval did not match")
    )
    let text = try #require(String(data: data, encoding: .utf8))

    let expected = #"{"error":{"category":"approval","hint":"Request a fresh preview and approve through "#
        + #"macOS authentication.","#
        + #""message":"approval did not match","retryable":false},"ok":false,"schemaVersion":1}"#
        + "\n"
    #expect(text == expected)
    #expect(data.count < 1024)
}

@Test
func lifecycleStatusNamesARehearsalInstallAndNothingElse() throws {
    func status(packageKind: String?) throws -> MacOSInstallerStatus {
        let kind = packageKind.map { #","packageKind":"\#($0)""# } ?? ""
        let document = """
        {"schemaVersion":1,"activeGenerationID":"0.2.0-abc",\
        "generations":[{"generationID":"0.2.0-abc","productVersion":"0.2.0"\(kind)},\
        {"generationID":"0.1.9-def","productVersion":"0.1.9"}],\
        "transactions":[],"services":[],\
        "dns":{"active":true,"configuredServiceCount":1,"effectiveRemapServiceCount":1}}
        """
        return try JSONDecoder().decode(MacOSInstallerStatus.self, from: Data(document.utf8))
    }
    let rehearsal = try RemapLifecycleCLIOutput.status(status(packageKind: "rehearsal"))
    #expect(rehearsal.contains("Remap is installed (0.2.0-abc).\nPackage: rehearsal install, not a release\n"))
    let development = try RemapLifecycleCLIOutput.status(status(packageKind: "development"))
    #expect(development.contains("Package: development install"))
    let release = try RemapLifecycleCLIOutput.status(status(packageKind: nil))
    #expect(!release.contains("Package:"))
    #expect(release.contains("Remap is installed (0.2.0-abc).\nGenerations: 2"))
}
