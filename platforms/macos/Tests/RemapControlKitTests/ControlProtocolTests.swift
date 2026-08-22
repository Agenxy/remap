import Foundation
@testable import RemapControlKit
import Testing

@Test
func statusCommandUsesExactRustWireShape() throws {
    let request = ControlRequest(
        protocol: remapControlProtocolVersion,
        requestID: "request-1",
        surface: "native-app",
        clientVersion: "0.1.0",
        command: .status
    )
    let frame = try ControlFrame.encode(request)
    let length = try ControlFrame.declaredLength(frame.prefix(4))
    let value = try #require(
        JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any]
    )
    let command = try #require(value["command"] as? [String: Any])
    #expect(length == frame.count - 4)
    #expect(value["protocol"] as? String == "remap.control/v1")
    #expect(value["request_id"] as? String == "request-1")
    #expect(value["surface"] as? String == "native-app")
    #expect(command.count == 1)
    #expect(command["kind"] as? String == "status")
}

@Test
func healthChallengeCommandUsesBoundedRustWireShape() throws {
    let nonce = "00112233445566778899aabbccddeeff"
    let request = ControlRequest(
        protocol: remapControlProtocolVersion,
        requestID: "request-health",
        surface: "native-app",
        clientVersion: "0.1.0",
        command: .healthChallenge(nonce: nonce)
    )
    let frame = try ControlFrame.encode(request)
    let value = try #require(
        JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any]
    )
    let command = try #require(value["command"] as? [String: Any])
    #expect(command["kind"] as? String == "health_challenge")
    #expect(command["nonce"] as? String == nonce)
}

@Test
func applyCommandPreservesIdempotencyAndMutationScope() throws {
    let request = ControlRequest(
        protocol: remapControlProtocolVersion,
        requestID: "request-2",
        surface: "native-app",
        clientVersion: "0.1.0",
        command: .apply(
            expectedRevision: 41,
            operationID: "8efe5887-7f19-453f-aa79-eaeba2852955",
            changes: [
                .set(
                    pattern: "remap.test",
                    target: "http://127.0.0.1:4270/",
                    hostPolicy: .useUpstream,
                    enabled: true
                )
            ]
        )
    )
    let frame = try ControlFrame.encode(request)
    let value = try #require(
        JSONSerialization.jsonObject(with: frame.dropFirst(4)) as? [String: Any]
    )
    let command = try #require(value["command"] as? [String: Any])
    let changes = try #require(command["changes"] as? [[String: Any]])
    #expect(command["kind"] as? String == "apply")
    #expect(command["expected_revision"] as? NSNumber == 41)
    #expect(command["operation_id"] as? String == "8efe5887-7f19-453f-aa79-eaeba2852955")
    #expect(changes.first?["pattern"] as? String == "remap.test")
    #expect(changes.first?["host_policy"] as? String == "use-upstream")
}

@Test
func responseDecoderKeepsCompleteMappingShape() throws {
    let payload = Data(
        #"""
        {
          "protocol":"remap.control/v1",
          "request_id":"request-3",
          "result":{
            "kind":"list",
            "value":{
              "revision":3,
              "mappings":[{
                "pattern":"remap.test",
                "target":"http://127.0.0.1:4270/",
                "target_kind":"http",
                "host_policy":"use-upstream",
                "enabled":true,
                "updated_revision":3
              }],
              "next_cursor":null
            }
          }
        }
        """#.utf8
    )
    let response = try ControlFrame.decodeResponse(payload)
    guard case let .list(page) = response.result else {
        Issue.record("expected a mapping page")
        return
    }
    #expect(page.revision == 3)
    #expect(page.mappings.first?.pattern == "remap.test")
    #expect(page.mappings.first?.target == "http://127.0.0.1:4270/")
    #expect(page.mappings.first?.hostPolicy == .useUpstream)
}

@Test
func frameDecoderRejectsOversizedPayloadBeforeAllocation() {
    var value = UInt32(remapMaximumControlFrameBytes + 1).bigEndian
    let prefix = withUnsafeBytes(of: &value) { Data($0) }
    #expect(throws: RemapDiagnostic.self) {
        _ = try ControlFrame.declaredLength(prefix)
    }
}

@Test
func runtimeChallengeRejectsWrongVersionOrProofShape() throws {
    let client = RemapControlClient(socketPath: "/tmp/not-used.sock", clientVersion: "0.1.0")
    let valid = RemapHealthChallengeResponse(
        instanceID: "12b4ed60-49a6-4df1-ad2a-673c0c3fd071",
        daemonVersion: "0.1.0",
        dnsProof: String(repeating: "a", count: 64),
        httpProof: String(repeating: "b", count: 64)
    )
    let challenge = try client.validateRuntimeChallenge(
        valid,
        nonce: "00112233445566778899aabbccddeeff"
    )
    #expect(challenge.daemonVersion == "0.1.0")

    let wrongVersion = RemapHealthChallengeResponse(
        instanceID: valid.instanceID,
        daemonVersion: "0.2.0",
        dnsProof: valid.dnsProof,
        httpProof: valid.httpProof
    )
    #expect(throws: RemapDiagnostic.self) {
        _ = try client.validateRuntimeChallenge(wrongVersion, nonce: challenge.nonce)
    }

    let malformedProof = RemapHealthChallengeResponse(
        instanceID: valid.instanceID,
        daemonVersion: valid.daemonVersion,
        dnsProof: String(repeating: "A", count: 64),
        httpProof: valid.httpProof
    )
    #expect(throws: RemapDiagnostic.self) {
        _ = try client.validateRuntimeChallenge(malformedProof, nonce: challenge.nonce)
    }
}

@Test
func missingAuthorityFailsWithoutFifteenSecondUiStall() async throws {
    let suffix = UUID().uuidString.prefix(8).lowercased()
    let socket = URL(filePath: "/tmp/remap-\(suffix).sock")
    let client = RemapControlClient(socketPath: socket.path, clientVersion: "test")
    let started = monotonicTestTime()
    do {
        _ = try await client.execute(.status)
        Issue.record("a missing control socket unexpectedly answered")
    } catch let diagnostic as RemapDiagnostic {
        #expect(diagnostic.code == "E_DAEMON_UNAVAILABLE")
    }
    #expect(monotonicTestElapsed(since: started) < 1_000_000_000)
}

@Test
func cancelledControlReadinessChecksCompleteWithoutContinuationLeaks() async {
    let started = monotonicTestTime()
    let checks = (0 ..< 64).map { _ in
        let socket = FileManager.default.temporaryDirectory
            .appending(path: "remap-\(UUID().uuidString.lowercased()).sock")
        let client = RemapControlClient(socketPath: socket.path, clientVersion: "test")
        return Task {
            do {
                _ = try await client.execute(.status)
                return ControlReadinessOutcome.unexpectedSuccess
            } catch is CancellationError {
                return .cancelled
            } catch let diagnostic as RemapDiagnostic {
                return .diagnostic(diagnostic.code)
            } catch {
                return .unexpectedFailure
            }
        }
    }

    checks.forEach { $0.cancel() }
    var outcomes: [ControlReadinessOutcome] = []
    for check in checks {
        let outcome = await check.value
        outcomes.append(outcome)
    }

    #expect(
        outcomes.allSatisfy { outcome in
            outcome == .cancelled || outcome == .diagnostic("E_DAEMON_UNAVAILABLE")
        }
    )
    #expect(monotonicTestElapsed(since: started) < 1_000_000_000)
}

private enum ControlReadinessOutcome: Equatable {
    case cancelled
    case diagnostic(String)
    case unexpectedFailure
    case unexpectedSuccess
}
