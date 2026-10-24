import Foundation
@testable import RemapApp
@testable import RemapControlKit
import Testing

@Test
func clearingLandingDeliberatelyOmitsItFromTheSet() throws {
    var draft = try MappingDraft(mapping: mappingWithLanding("/page"))
    draft.landing = ""
    let encoded = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(draft.change)) as? [String: Any])

    #expect(encoded["kind"] as? String == "set")
    #expect(encoded["landing"] == nil)
    #expect(encoded["target"] as? String == "http://127.0.0.1:8792/")
}

@Test
func legacyMappingWithoutLandingRemainsEditable() throws {
    let mapping = try mappingWithLanding(nil)
    let draft = MappingDraft(mapping: mapping)

    #expect(mapping.landing == nil)
    #expect(draft.landing.isEmpty)
    #expect(draft.hostPolicy == .useUpstream)
}

private func mappingWithLanding(_ landing: String?) throws -> RemapMapping {
    var fields: [String: Any] = [
        "pattern": "site.test",
        "target": "http://127.0.0.1:8792/",
        "target_kind": "http",
        "host_policy": "use-upstream",
        "enabled": true,
        "updated_revision": 7
    ]
    if let landing {
        fields["landing"] = landing
    }
    return try JSONDecoder().decode(RemapMapping.self, from: JSONSerialization.data(withJSONObject: fields))
}
