// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
@testable import RemapSystemKit
import Testing

// ADR-0036. The owner turning Remap DNS off on purpose leaves a small
// root-owned record, so status tells it apart from a fallback and from DNS
// that was never activated.

private let turnedOffAt: UInt64 = 1_793_409_600_000

private func payload(command: String = remapSystemDeactivateCommand) -> DNSTurnedOffPayload {
    DNSTurnedOffPayload(
        turnedOffAtMilliseconds: turnedOffAt,
        command: command,
        ownerUID: 501,
        productVersion: "0.2.0"
    )
}

private func ownedDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory
        .appendingPathComponent("remap-turned-off-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
        at: directory,
        withIntermediateDirectories: false,
        attributes: [.posixPermissions: 0o700]
    )
    return directory
}

@Test
func theTurnedOffRecordHasAStableCanonicalForm() throws {
    // `remapd` verifies these exact bytes (crates/remapd/src/native_dns.rs).
    let encoded = try CanonicalJSON.encoder.encode(DNSTurnedOffRecord(payload: payload()))
    #expect(String(data: encoded, encoding: .utf8) == #"""
    {"payload":{"command":"remap-system deactivate","ownerUID":501,"productVersion":"0.2.0",\#
    "schemaVersion":1,"turnedOffAtMilliseconds":1793409600000},\#
    "sha256":"e36ff5314b7d49cfec7182148bf33cebc66dc6ae4a66b2f3609128a2f103f24a"}
    """#)
}

@Test
func turningDNSOffRecordsWhenHowAndHowToTurnItBackOn() throws {
    let directory = try ownedDirectory()
    let store = DNSTurnedOffStore(directory: directory, ownerUID: geteuid())
    #expect(try store.read() == nil)

    let activation = try healingRecord()
    let turnOff = recordTurnOff(
        command: remapSystemDeactivateCommand,
        activation: activation,
        at: Date(timeIntervalSince1970: TimeInterval(turnedOffAt) / 1000),
        store: store
    )

    #expect(turnOff.recordError == nil)
    let read = try #require(try store.read()?.payload)
    #expect(read == turnOff.payload)
    #expect(read.statusLine == "turned off by the owner at 2026-10-31T01:20Z (`remap-system deactivate`)")
    #expect(read.turnOnCommand == "sudo '/Library/Application Support/Agenxy/Remap/Install/current/libexec/"
        + "remap-system' activate --owner-uid 501 --product-version 0.2.0 "
        + "--system-socket /var/run/org.agenxy.Remap.system.sock")
    var information = stat()
    #expect(lstat(store.recordURL.path, &information) == 0)
    #expect(information.st_mode & 0o777 == 0o644)

    try store.clear()
    #expect(try store.read() == nil)
    try store.clear()
}

@Test
func anUntrustworthyTurnedOffRecordIsRefused() throws {
    let directory = try ownedDirectory()
    let store = DNSTurnedOffStore(directory: directory, ownerUID: geteuid())
    #expect(throws: ResolverError.invalidTurnedOffRecord) {
        try store.write(payload(command: "rm -rf /"))
    }
    try store.write(payload())
    let original = try Data(contentsOf: store.recordURL)
    let tampered = try #require(String(data: original, encoding: .utf8))
        .replacingOccurrences(of: "501", with: "502")
    try Data(tampered.utf8).write(to: store.recordURL)
    #expect(chmod(store.recordURL.path, 0o644) == 0)
    #expect(throws: ResolverError.invalidTurnedOffRecord) { try store.read() }

    try original.write(to: store.recordURL)
    #expect(chmod(store.recordURL.path, 0o666) == 0)
    #expect(throws: ResolverError.secureStorage("verify the root-owned DNS turned-off record")) {
        try store.read()
    }

    try FileManager.default.removeItem(at: store.recordURL)
    let elsewhere = directory.appendingPathComponent("elsewhere.json")
    try original.write(to: elsewhere)
    try FileManager.default.createSymbolicLink(at: store.recordURL, withDestinationURL: elsewhere)
    #expect(throws: ResolverError.secureStorage("verify the root-owned DNS turned-off record")) {
        try store.read()
    }
    #expect(throws: ResolverError.notRoot) {
        try DNSTurnedOffStore(directory: directory, ownerUID: geteuid() &+ 1).write(payload())
    }
}

@Test
func statusTellsOnFallbackOffOnPurposeAndNeverActivatedApart() throws {
    let active = try healingRecord()
    let prepared = try healingRecord(phase: .prepared)
    let armed = NativeResolverStatus(record: active, bypass: nil, bypassError: nil, turnedOff: payload())
    #expect(armed.stateLines().first == "Native DNS is active")
    #expect(armed.turnedOff == nil)
    let fallback = NativeResolverStatus(record: prepared, bypass: nil, bypassError: nil)
    #expect(fallback.stateLines().first?.contains("falling back to ordinary DNS on its own") == true)
    let off = NativeResolverStatus(record: nil, bypass: nil, bypassError: nil, turnedOff: payload())
    #expect(off.stateLines().first
        == "Native DNS is turned off by the owner at 2026-10-31T01:20Z (`remap-system deactivate`)")
    #expect(off.stateLines().last?.contains("activate --owner-uid 501") == true)
    let never = NativeResolverStatus(record: nil, bypass: nil, bypassError: nil)
    #expect(never.stateLines() == ["Native DNS is not activated"])

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let object = try #require(
        JSONSerialization.jsonObject(with: encoder.encode(off)) as? [String: Any]
    )
    #expect(Set(object.keys) == ["dnsTurnedOff"])
    let turnedOff = try #require(object["dnsTurnedOff"] as? [String: Any])
    #expect(turnedOff["command"] as? String == "remap-system deactivate")
    #expect(turnedOff["turnedOffAtMilliseconds"] as? UInt64 == turnedOffAt)
    #expect(try String(data: encoder.encode(never), encoding: .utf8) == "null")
}
