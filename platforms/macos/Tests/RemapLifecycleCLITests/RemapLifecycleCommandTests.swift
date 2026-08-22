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
func lifecycleApprovalIsExactAndDefaultDeny() throws {
    let token = try InstallApprovalToken(String(repeating: "a", count: 64))

    try RemapLifecycleCLIApproval.validate(
        "approve aaaaaaaaaaaa",
        token: token,
        interactive: true
    )
    try RemapLifecycleCLIApproval.validate(
        token.description,
        token: token,
        interactive: false
    )
    for rejected in [nil, "", "yes", "approve", "approve aaaaaaaaaaa", token.description + " "] {
        #expect(throws: RemapLifecycleCLIError.self) {
            try RemapLifecycleCLIApproval.validate(
                rejected,
                token: token,
                interactive: false
            )
        }
    }
}

@Test
func lifecycleOutputRemovesTerminalControls() {
    #expect(plain("safe\u{1B}[31m\ntext") == "safe?[31m?text")
    #expect(RemapLifecycleCLIOutput.help.contains("remap system status"))
    #expect(!RemapLifecycleCLIOutput.help.contains("--yes"))
}

@Test
func lifecycleJSONErrorIsCanonicalAndBounded() throws {
    let data = try RemapLifecycleCLIErrorDocument.data(
        for: RemapLifecycleCLIError.approval("approval did not match")
    )
    let text = try #require(String(data: data, encoding: .utf8))

    let expected = #"{"error":{"category":"approval","hint":"Request a fresh preview and approve the exact token.","#
        + #""message":"approval did not match","retryable":false},"ok":false,"schemaVersion":1}"#
        + "\n"
    #expect(text == expected)
    #expect(data.count < 1024)
}
