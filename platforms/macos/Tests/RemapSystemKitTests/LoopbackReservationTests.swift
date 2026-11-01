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
    #expect(fixture.keeper.reconcile() == .held(aliases: 2, listenersUnheld: 0))
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.1", "127.77.0.2"])
    #expect(try fixture.store.read() == fixture.interface.present)

    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.2"] }
    #expect(fixture.keeper.reconcile() == .held(aliases: 1, listenersUnheld: 0))
    #expect(fixture.interface.aliases.map(\.description) == ["127.77.0.2"])

    try fixture.removeActivation()
    #expect(fixture.keeper.reconcile() == .held(aliases: 0, listenersUnheld: 0))
    #expect(fixture.interface.aliases.isEmpty)
    #expect(!FileManager.default.fileExists(atPath: fixture.store.recordURL.path))
}

@Test
func anUnreachableDaemonKeepsTheCurrentAliases() throws {
    let fixture = try KeeperFixture()
    fixture.daemon.update { $0.loopbackReservations = ["127.77.0.1"] }
    #expect(fixture.keeper.reconcile() == .held(aliases: 1, listenersUnheld: 0))
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
    #expect(fixture.keeper.reconcile() == .held(aliases: 2, listenersUnheld: 0))
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

@Test
func unheldListenersOnHeldAliasesAreCreatedAndHandedOver() throws {
    let fixture = try KeeperFixture()
    let ssh = LoopbackListener(address: "127.77.0.1", port: 22)
    let kassette = LoopbackListener(address: "127.77.0.1", port: 7443)
    fixture.daemon.update {
        $0.loopbackReservations = ["127.77.0.1"]
        $0.unheldListeners = [ssh, kassette]
    }
    #expect(fixture.keeper.reconcile() == .held(aliases: 1, listenersUnheld: 0))
    #expect(fixture.listenerFactory.created == [ssh, kassette])
    // One descriptor travelled with each listener, and root kept none open.
    #expect(fixture.daemon.snapshot().adoptedDescriptorCounts == [2])
    #expect(fixture.listenerFactory.openDescriptors == 0)
}

@Test
func aPortRootCannotBindStaysUnheldWithoutSpinning() throws {
    let fixture = try KeeperFixture()
    let taken = LoopbackListener(address: "127.77.0.1", port: 8080)
    fixture.daemon.update {
        $0.loopbackReservations = ["127.77.0.1"]
        $0.unheldListeners = [taken]
    }
    fixture.listenerFactory.refuse(taken)
    #expect(fixture.keeper.reconcile() == .held(aliases: 1, listenersUnheld: 1))
    #expect(fixture.daemon.snapshot().adoptedDescriptorCounts.isEmpty)
}

@Test
func anUnheldListenerOutsideTheRangeRefusesTheWholeList() throws {
    let result = ResolverSystemResult(
        activationID: nil,
        activeGeneration: nil,
        loopbackReservations: ["127.77.0.1"],
        unheldListeners: [LoopbackListener(address: "127.0.0.1", port: 22)]
    )
    #expect(throws: LoopbackReservationError.invalidReservations) {
        _ = try unheldListeners(from: result, within: [reservation("127.77.0.1")])
    }
}

private func reservation(_ text: String) throws -> LoopbackReservation {
    try #require(LoopbackReservation(text))
}

private struct KeeperFixture {
    let directory: URL
    let daemon = ResolverTestDaemon()
    let interface = TestLoopbackInterface()
    let listenerFactory = TestListenerFactory()
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
            listeners: listenerFactory,
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

/// Root's socket factory, with real descriptors the keeper must close.
private final class TestListenerFactory: LoopbackListenerFactory, Sendable {
    private struct State {
        var created: [LoopbackListener] = []
        var open: Set<Int32> = []
        var refused: LoopbackListener?
    }

    private let state = Mutex(State())

    var created: [LoopbackListener] {
        state.withLock { $0.created }
    }

    /// Descriptors this factory made that are still open in this process.
    var openDescriptors: Int {
        state.withLock { $0.open.count(where: { fcntl($0, F_GETFD) != -1 }) }
    }

    func refuse(_ listener: LoopbackListener) {
        state.withLock { $0.refused = listener }
    }

    func listen(on listener: LoopbackListener) throws -> Int32 {
        try state.withLock {
            guard $0.refused != listener else { throw LoopbackReservationError.interface("listen") }
            let descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC)
            guard descriptor >= 0 else { throw LoopbackReservationError.interface("open") }
            $0.created.append(listener)
            $0.open.insert(descriptor)
            return descriptor
        }
    }
}
