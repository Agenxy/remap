import Foundation
@testable import RemapControlKit
import Testing

@Test
func validateCommandCarriesAnExplicitLandingPath() throws {
    let command = RemapControlCommand.validate(
        pattern: "site.test",
        target: "http://127.0.0.1/",
        hostPolicy: .useUpstream,
        landing: "/page"
    )
    let encoded = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(command)) as? [String: Any])
    #expect(encoded["landing"] as? String == "/page")
}

@Test
func previewsAndReceiptsRetainWarningsAndLandingEffects() throws {
    let before: [String: Any] = [
        "pattern": "site.test", "target": "http://127.0.0.1/", "target_kind": "http",
        "host_policy": "use-upstream", "enabled": true, "updated_revision": 7, "landing": "/old"
    ]
    var after = before
    after["landing"] = "/new"
    let effect: [String: Any] = ["pattern": "site.test", "action": "updated", "before": before, "after": after]
    let preview: [String: Any] = [
        "base_revision": 7, "will_change": true, "effects": [effect],
        "warnings": ["Use preserve-client for virtual hosts."]
    ]
    let decoded = try JSONDecoder().decode(RemapPreview.self, from: JSONSerialization.data(withJSONObject: preview))
    #expect(decoded.effects.first?.before?.landing == "/old")
    #expect(decoded.effects.first?.after?.landing == "/new")
    #expect(decoded.warnings == ["Use preserve-client for virtual hosts."])

    let receipt: [String: Any] = [
        "operation_id": "4df4bb55-93bb-4f99-9707-9761f6a69364", "previous_revision": 7,
        "revision": 8, "changed": true, "effects": [effect], "warnings": ["An advisory."]
    ]
    let saved = try JSONDecoder().decode(RemapApplyReceipt.self, from: JSONSerialization.data(withJSONObject: receipt))
    #expect(saved.effects == decoded.effects)
    #expect(saved.warnings == ["An advisory."])
}

@Test
func oldPreviewAndReceiptWithoutWarningsStillDecode() throws {
    let preview = Data(#"{"base_revision":7,"will_change":false,"effects":[]}"#.utf8)
    let receipt = Data(#"{"operation_id":"id","previous_revision":7,"revision":7,"changed":false,"effects":[]}"#.utf8)
    #expect(try JSONDecoder().decode(RemapPreview.self, from: preview).warnings == nil)
    #expect(try JSONDecoder().decode(RemapApplyReceipt.self, from: receipt).warnings == nil)
}
