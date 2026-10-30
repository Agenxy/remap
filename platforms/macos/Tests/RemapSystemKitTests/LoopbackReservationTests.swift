// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
@testable import RemapSystemKit
import Synchronization
import Testing

@Test
func reservationsAcceptOnlyCanonicalAddressesInTheReservedRange() {
    for text in ["127.77.0.1", "127.77.0.255", "127.77.1.0", "127.77.255.254"] {
        #expect(LoopbackReservation(text)?.description == text)
    }
    for text in [
        "127.77.0.0", "127.77.255.255", "127.78.0.1", "127.0.0.1", "10.77.0.1",
        "127.077.0.1", "127.77.0", "127.77.0.1.2", "127.77.0.256", "127.77..1", "", " 127.77.0.1"
    ] {
        #expect(LoopbackReservation(text) == nil, "\(text)")
    }
}

@Test
func aChangeRemovesOnlyWhatThisSupervisorAdded() throws {
    let (first, second, third, foreign) = try (
        reservation("127.77.0.1"), reservation("127.77.0.2"),
        reservation("127.77.0.3"), reservation("127.77.0.9")
    )
    let change = loopbackReservationChange(
        desired: [first, second, foreign],
        owned: [second, third],
        present: [second, third, foreign]
    )
    #expect(change.add == [first])
    #expect(change.remove == [third])
    // An alias another tool placed is neither removed nor adopted.
    #expect(change.owned == [first, second])
}

@Test
func theDaemonsAnswerIsRefusedWholeWhenAnyPartIsInvalid() throws {
    let valid = ResolverSystemResult(activationID: nil, activeGeneration: nil, loopbackReservations: ["127.77.0.1"])
    #expect(try loopbackReservations(from: valid).map(\.description) == ["127.77.0.1"])
    let refusals: [[String]?] = [
        nil,
        ["127.77.0.1", "127.0.0.1"],
        ["127.77.0.1", "127.77.0.1"],
        (1 ... 257).map { "127.77.1.\($0 % 255)" }
    ]
    for texts in refusals {
        let result = ResolverSystemResult(activationID: nil, activeGeneration: nil, loopbackReservations: texts)
        #expect(throws: LoopbackReservationError.invalidReservations) {
            _ = try loopbackReservations(from: result)
        }
    }
}

@Test
func theKeeperFollowsTheDaemonAndReleasesWithoutAnActivation() throws {
    let fixture = try KeeperFixture()
    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.1", "127.77.0.2"] }
    #expect(fixture.keeper.reconcile() == .held(2))
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.1", "127.77.0.2"])
    #expect(try fixture.store.read() == fixture.interface.present)

    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.2"] }
    #expect(fixture.keeper.reconcile() == .held(1))
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.2"])

    try fixture.removeActivation()
    #expect(fixture.keeper.reconcile() == .held(0))
    #expect(fixture.interface.aliases.isEmpty)
    #expect(!FileManager.default.fileExists(atPath: fixture.store.recordURL.path))
}

@Test
func anUnreachableDaemonKeepsTheCurrentAliases() throws {
    let fixture = try KeeperFixture()
    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.1"] }
    #expect(fixture.keeper.reconcile() == .held(1))
    fixture.daemon.update { $0.refusesEverything = true }
    #expect(fixture.keeper.reconcile() == .unchanged("E_LOOPBACK_AUTHORITY_UNAVAILABLE"))
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.1"])
}

@Test
func anInterruptedAddIsRecordedFirstAndFinishedNextTime() throws {
    let fixture = try KeeperFixture()
    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.1", "127.77.0.2"] }
    try fixture.interface.refuse(reservation("127.77.0.2"))
    #expect(fixture.keeper.reconcile() == .unchanged("E_LOOPBACK_INTERFACE"))
    // Both were recorded before either was added, so neither can be orphaned.
    #expect(try fixture.store.read().map(\.description).sorted() == ["127.77.0.1", "127.77.0.2"])

    fixture.interface.refuse(nil)
    #expect(fixture.keeper.reconcile() == .held(2))
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.1", "127.77.0.2"])
}

@Test
func releasingRemovesEveryOwnedAliasAndNoOther() throws {
    let fixture = try KeeperFixture()
    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.1"] }
    _ = fixture.keeper.reconcile()
    try fixture.interface.add(reservation("127.77.0.9"))
    try LoopbackReservationKeeper.releaseAll(interface: fixture.interface, store: fixture.store)
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.9"])
    #expect(try fixture.store.read().isEmpty)
}

@Test
func aDamagedRecordIsRefusedRatherThanGuessedAt() throws {
    let fixture = try KeeperFixture()
    try Data(#"{"reservations":["127.0.0.1"],"version":1}"#.utf8).write(to: fixture.store.recordURL)
    #expect(chmod(fixture.store.recordURL.path, 0o600) == 0)
    #expect(throws: LoopbackReservationError.invalidRecord) { _ = try fixture.store.read() }
    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.1"] }
    #expect(fixture.keeper.reconcile() == .unchanged("E_LOOPBACK_RECORD"))
    #expect(fixture.interface.aliases.isEmpty)
}

@Test
func theRequestHasItsWireKind() throws {
    let request = ResolverSystemRequest(requestID: UUID(), command: .loopbackReservations)
    let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(request)) as? [String: Any]
    let command = object?["command"] as? [String: Any]
    #expect(command?["kind"] as? String == "loopback_reservations")
    #expect(command?.count == 1)
}

@Test
func theAliasControlsAreTheValuesDarwinsHeadersDefine() {
    // SIOCAIFADDR and SIOCDIFADDR from <sys/sockio.h>, measured on macOS 27.
    #expect(addAlias == 0x8040_691A)
    #expect(deleteAddress == 0x8020_6919)
}

private func reservation(_ text: String) throws -> LoopbackReservation {
    try #require(LoopbackReservation(text))
}

private struct KeeperFixture {
    let directory: URL
    let daemon = ResolverTestDaemon()
    let interface = TestLoopbackInterface()
    let store: LoopbackReservationStore
    let keeper: LoopbackReservationKeeper

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("remap-loopback-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
        let activation = ActivationStore(directory: directory)
        try Data("{}".utf8).write(to: activation.recordURL)
        store = LoopbackReservationStore(directory: directory, ownerUID: geteuid())
        keeper = LoopbackReservationKeeper(
            channel: daemon,
            interface: interface,
            store: store,
            activation: activation,
            observe: { _ in }
        )
    }

    func removeActivation() throws {
        try FileManager.default.removeItem(at: ActivationStore(directory: directory).recordURL)
    }
}

/// `lo0` as the keeper sees it, so the reconciliation can be driven without
/// root. Only the boundary is replaced; every decision is the product's.
private final class TestLoopbackInterface: LoopbackInterface, Sendable {
    private let state = Mutex<(present: Set<LoopbackReservation>, refused: LoopbackReservation?)>(([], nil))

    var present: Set<LoopbackReservation> {
        state.withLock { $0.present }
    }

    var aliases: [LoopbackReservation] {
        present.sorted()
    }

    func refuse(_ reservation: LoopbackReservation?) {
        state.withLock { $0.refused = reservation }
    }

    func presentReservations() throws -> Set<LoopbackReservation> {
        present
    }

    func add(_ reservation: LoopbackReservation) throws {
        try state.withLock {
            guard $0.refused != reservation else { throw LoopbackReservationError.interface("add") }
            $0.present.insert(reservation)
        }
    }

    func remove(_ reservation: LoopbackReservation) throws {
        state.withLock { _ = $0.present.remove(reservation) }
    }
}
