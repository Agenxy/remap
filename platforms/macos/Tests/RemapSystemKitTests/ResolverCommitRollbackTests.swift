// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
@testable import RemapSystemKit
import Testing

private let wifi = "wifi"
private let staleVerification = ResolverError.preferences("verify the effective DNS configuration")
private let refusedCommit = ResolverError.preferences("commit and apply DNS preferences")

/// Activated, then suspended: the record is prepared and Wi-Fi is back at
/// its captured prior configuration, as after a safe bypass.
private func preparedMac() throws -> ActivatedMac {
    let mac = try ActivatedMac()
    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: true)
    #expect(mac.store.current?.payload.phase == .prepared)
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    return mac
}

@Test
func committingAPreparedActivationPointsTheServiceAtRemapAndRecordsItActive() throws {
    let mac = try preparedMac()

    let active = try mac.configurator.commitPrepared()

    #expect(active.payload.phase == .active)
    #expect(mac.store.current == active)
    #expect(try mac.network.loopbackServiceIDs() == [wifi])
    #expect(try mac.network.snapshot().globalServers == [loopbackResolver])
}

@Test
func aCommitThatCannotBeVerifiedIsRestoredAndReturnsToPrepared() throws {
    let mac = try preparedMac()
    mac.network.update { $0.faults = [.verificationStale] }

    #expect(throws: staleVerification) { try mac.configurator.commitPrepared() }

    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)
}

@Test
func aRestoreThatFailsAfterAFailedCommitIsReportedAndTheRecordStaysActive() throws {
    let mac = try preparedMac()
    mac.network.update { $0.faults = [.verificationStale] }
    // The commit succeeds; the restore that follows the failed verification does not.
    mac.network.refuseCommit(2)

    #expect(throws: refusedCommit) { try mac.configurator.commitPrepared() }

    #expect(try mac.network.loopbackServiceIDs() == [wifi])
    #expect(mac.store.current?.payload.phase == .active)
}

@Test
func deactivationRestoresAServiceAFailedCommitCouldNotRestore() throws {
    let mac = try preparedMac()
    mac.network.update { $0.faults = [.verificationStale] }
    mac.network.refuseCommit(2)
    _ = try? mac.configurator.commitPrepared()
    mac.network.update { state in
        state.faults = []
        state.refusedCommitAttempts = []
    }

    try mac.configurator.restoreOrdinaryDNS(retainPreparedRecord: false)

    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.network.service(wifi)?.persisted == nil)
    #expect(mac.store.current == nil)
}

@Test
func theRecordIsActiveBeforeAnyServicePointsAtRemap() throws {
    let mac = try preparedMac()
    let commits = mac.network.commitCount
    mac.store.failWrite(1)

    #expect(throws: ResolverError.secureStorage("replace the activation record atomically")) {
        try mac.configurator.commitPrepared()
    }

    #expect(mac.network.commitCount == commits)
    #expect(try mac.network.loopbackServiceIDs().isEmpty)
    #expect(mac.store.current?.payload.phase == .prepared)
}
