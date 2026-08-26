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
