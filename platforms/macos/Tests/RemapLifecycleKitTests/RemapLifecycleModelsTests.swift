import Foundation
import RemapInstallKit
@testable import RemapLifecycleKit
import Testing

@Test
func lifecycleRequestRoundTripsThroughTheBoundedWireContract() throws {
    let request = try RemapLifecycleRequest(
        action: .previewInstall,
        packageRoot: "/Users/example/Library/Application Support/Remap/package",
        manifestDigest: InstallDigest(String(repeating: "a", count: 64))
    )

    let encoded = try RemapLifecycleCoding.encodeRequest(request)
    #expect(try RemapLifecycleCoding.decodeRequest(encoded) == request)
    #expect(encoded.count < RemapLifecycleXPC.maximumRequestByteCount)
}

@Test
func configuredLifecycleSourceRequestsOmitUserControlledPackagePaths() throws {
    let preview = try RemapLifecycleRequest(action: .previewInstall)
    let install = try RemapLifecycleRequest(
        action: .install,
        approvalToken: InstallApprovalToken(String(repeating: "a", count: 64))
    )

    #expect(preview.packageRoot == nil)
    #expect(preview.manifestDigest == nil)
    #expect(install.packageRoot == nil)
    #expect(install.manifestDigest == nil)
}

@Test
func lifecycleRequestRejectsFieldsThatDoNotBelongToItsAction() throws {
    #expect(throws: InstallError.self) {
        _ = try RemapLifecycleRequest(
            action: .status,
            packageRoot: "/tmp/foreign"
        )
    }
}

@Test
func lifecycleFailureRoundTripsAsOneUnambiguousPayload() throws {
    let diagnostic = RemapLifecycleDiagnostic(
        category: .approval,
        message: "The approved state changed.",
        hint: "Refresh the exact preview.",
        retryable: true
    )
    let response = RemapLifecycleResponse.failure(
        action: .install,
        diagnostic: diagnostic
    )

    let encoded = try RemapLifecycleCoding.encodeResponse(response)
    #expect(try RemapLifecycleCoding.decodeResponse(encoded) == response)
}

@Test
func lifecycleDecoderRejectsAnOversizedRequestBeforeParsing() {
    let oversized = Data(
        repeating: 0x41,
        count: RemapLifecycleXPC.maximumRequestByteCount + 1
    )

    #expect(throws: InstallError.self) {
        _ = try RemapLifecycleCoding.decodeRequest(oversized)
    }
}

@Test
func lifecycleClientRejectsAMismatchedResponseAction() async throws {
    let request = try RemapLifecycleRequest(action: .status)
    let response = RemapLifecycleResponse.failure(
        action: .previewRecover,
        diagnostic: RemapLifecycleDiagnostic(
            category: .integrity,
            message: "fixture",
            hint: "fixture",
            retryable: false
        )
    )
    let data = try RemapLifecycleCoding.encodeResponse(response)
    let client = RemapLifecycleClient { _ in data }

    await #expect(throws: InstallError.self) {
        _ = try await client.execute(request)
    }
}

@Test
func lifecycleResponseRejectsAPayloadForAnotherAction() throws {
    #expect(throws: InstallError.self) {
        _ = try RemapLifecycleResponse.success(
            action: .previewRecover,
            mutation: RemapLifecycleMutationResult(
                generationID: "fixture",
                transactionID: "fixture"
            )
        )
    }
}

@Test
func lifecycleClientSurfacesTypedRemoteDiagnostics() async throws {
    let request = try RemapLifecycleRequest(action: .status)
    let diagnostic = RemapLifecycleDiagnostic(
        category: .authority,
        message: "The exact app identity was rejected.",
        hint: "Repair Remap.",
        retryable: false
    )
    let response = RemapLifecycleResponse.failure(
        action: .status,
        diagnostic: diagnostic
    )
    let data = try RemapLifecycleCoding.encodeResponse(response)
    let client = RemapLifecycleClient { _ in data }

    await #expect(throws: RemapLifecycleRemoteError(diagnostic: diagnostic)) {
        _ = try await client.execute(request)
    }
}
