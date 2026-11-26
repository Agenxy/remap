// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapApp
@testable import RemapControlKit
import Testing

@Test
func reviewLandingRoundTripPreservesTheWireField() throws {
    let payload = Data(#"""
    {"pattern":"site.test","target":"http://127.0.0.1:8792/","target_kind":"http",
     "host_policy":"use-upstream","enabled":true,"updated_revision":7,
     "landing":"/ops/scorecard/?token=A%2Fb"}
    """#.utf8)
    let mapping = try JSONDecoder().decode(RemapMapping.self, from: payload)
    let draft = MappingDraft(mapping: mapping)
    let change = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(draft.change)) as? [String: Any])
    let saved = try #require(JSONSerialization.jsonObject(with: JSONEncoder().encode(mapping)) as? [String: Any])

    #expect(change["landing"] as? String == "/ops/scorecard/?token=A%2Fb")
    #expect(saved["landing"] as? String == "/ops/scorecard/?token=A%2Fb")
    #expect(change["pattern"] as? String == mapping.pattern)
    #expect(change["host_policy"] as? String == "use-upstream")
}
