// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation

/// Holds the `lo0` aliases that peer-machine names answer with (ADR-0033).
///
/// It runs beside the resolver supervisor and never shares its failure
/// handling: nothing here can bypass, suspend or restore DNS. Reservations
/// are held while a DNS activation exists, including while DNS is suspended,
/// so a flap never drops open connections. With no activation, every owned
/// alias is released. When the daemon cannot answer, the current aliases are
/// kept, never guessed at.
public final class LoopbackReservationKeeper: Sendable {
    private let channel: any ResolverSystemExchanging
    private let interface: any LoopbackInterface
    private let store: LoopbackReservationStore
    private let listeners: any LoopbackListenerFactory
    private let activation: ActivationStore
    private let interval: Duration
    private let observe: @Sendable (LoopbackReservationOutcome) -> Void

    public init(
        channel: any ResolverSystemExchanging,
        interface: any LoopbackInterface = DarwinLoopbackInterface(),
        store: LoopbackReservationStore = .standard,
        listeners: any LoopbackListenerFactory = DarwinLoopbackListenerFactory(),
        activation: ActivationStore = .standard,
        interval: Duration = .seconds(5),
        observe: @escaping @Sendable (LoopbackReservationOutcome) -> Void
    ) {
        self.channel = channel
        self.interface = interface
        self.store = store
        self.listeners = listeners
        self.activation = activation
        self.interval = interval
        self.observe = observe
    }

    public func run() async {
        var last: LoopbackReservationOutcome?
        while !Task.isCancelled {
            let outcome = reconcile()
            if outcome != last {
                observe(outcome)
                last = outcome
            }
            try? await Task.sleep(for: interval)
        }
    }

    /// One reconciliation; exposed so a single pass can be driven directly.
    public func reconcile() -> LoopbackReservationOutcome {
        var answer: ResolverSystemResult?
        let desired: Set<LoopbackReservation>
        if activation.exists() {
            do {
                let result = try channel.exchange(.loopbackReservations)
                desired = try loopbackReservations(from: result)
                answer = result
            } catch let error as LoopbackReservationError {
                return .unchanged(error.code)
            } catch {
                return .unchanged("E_LOOPBACK_AUTHORITY_UNAVAILABLE")
            }
        } else {
            desired = []
        }
        let change: LoopbackReservationChange
        do {
            change = try apply(desired: desired, interface: interface, store: store, activation: activation)
        } catch let error as LoopbackReservationError {
            return .unchanged(error.code)
        } catch {
            return .unchanged("E_LOOPBACK_RECORD")
        }
        guard let answer else { return .held(aliases: change.owned.count, listenersUnheld: 0) }
        let unheld = handOverListeners(answer, on: desired.intersection(present(after: change)))
        return .held(aliases: change.owned.count, listenersUnheld: unheld)
    }

    /// The aliases now on `lo0` that this pass may bind on: the ones it owns,
    /// plus any already present that the daemon asked for.
    private func present(after change: LoopbackReservationChange) -> Set<LoopbackReservation> {
        (try? interface.presentReservations()) ?? change.owned
    }

    /// Binds every unheld listener the daemon names on an alias this Mac holds
    /// and hands the sockets over, a page at a time. Returns how many remain
    /// unheld. A page that makes no progress ends the pass, so a port another
    /// account already holds cannot spin the loop.
    private func handOverListeners(_ first: ResolverSystemResult, on aliases: Set<LoopbackReservation>) -> Int {
        var answer = first
        for _ in 0 ..< maximumListenerPagesPerPass {
            guard let pending = try? unheldListeners(from: answer, within: aliases), !pending.isEmpty else {
                return 0
            }
            let created = pending.compactMap { listener in
                (try? listeners.listen(on: listener)).map { (listener, $0) }
            }
            guard !created.isEmpty else { return pending.count }
            defer { created.forEach { close($0.1) } }
            guard let next = try? channel.exchange(
                .adoptListeners(created.map(\.0)),
                passing: created.map(\.1)
            ), next.unheldListeners != answer.unheldListeners else {
                return pending.count
            }
            answer = next
        }
        return (try? unheldListeners(from: answer, within: aliases).count) ?? 0
    }

    /// Removes every alias this supervisor added. Deactivation and uninstall
    /// call it directly, so no alias outlives the activation that needed it.
    public static func releaseAll(
        interface: any LoopbackInterface = DarwinLoopbackInterface(),
        store: LoopbackReservationStore = .standard
    ) throws {
        _ = try apply(desired: [], interface: interface, store: store)
    }
}

/// What one reconciliation left in place, for the supervisor's log.
public enum LoopbackReservationOutcome: Equatable, Sendable {
    /// The supervisor holds this many aliases; this many listeners the
    /// daemon asked for are still not held by it.
    case held(aliases: Int, listenersUnheld: Int)
    /// Nothing changed, for this stable reason.
    case unchanged(String)
}

/// Records an address before adding it and forgets it only after removing
/// it, so a crash between the two never leaves an alias nobody owns.
///
/// Every caller serialises on the store's lock. `activation`, when given, is
/// re-read under that lock: deactivation removes the activation record before
/// it releases, so a pass that started earlier releases too instead of adding
/// back what deactivation just removed.
@discardableResult
func apply(
    desired: Set<LoopbackReservation>,
    interface: any LoopbackInterface,
    store: LoopbackReservationStore,
    activation: ActivationStore? = nil
) throws -> LoopbackReservationChange {
    try store.withLock {
        let desired = activation.map { $0.exists() } ?? true ? desired : []
        return try applyLocked(desired: desired, interface: interface, store: store)
    }
}

private func applyLocked(
    desired: Set<LoopbackReservation>,
    interface: any LoopbackInterface,
    store: LoopbackReservationStore
) throws -> LoopbackReservationChange {
    let owned = try store.read()
    let change = try loopbackReservationChange(
        desired: desired,
        owned: owned,
        present: interface.presentReservations()
    )
    guard !change.isEmpty || change.owned != owned else { return change }
    try store.write(owned.union(change.add))
    for reservation in change.add {
        try interface.add(reservation)
    }
    for reservation in change.remove {
        try interface.remove(reservation)
    }
    try store.write(change.owned)
    return change
}

/// The most listener pages one pass hands over: 16 × 64 covers every port
/// of the 256 names the daemon may hold at 4 ports each, and more on later
/// passes.
private let maximumListenerPagesPerPass = 16

/// Decodes the daemon's unheld listeners, refusing the whole list when any
/// entry is outside the reserved range, port zero, or beyond one exchange.
/// Entries on an alias this Mac does not hold are left for a later pass.
func unheldListeners(
    from result: ResolverSystemResult,
    within aliases: Set<LoopbackReservation>
) throws -> [LoopbackListener] {
    let listeners = result.unheldListeners ?? []
    guard listeners.count <= maximumListenersPerExchange else {
        throw LoopbackReservationError.invalidReservations
    }
    for listener in listeners {
        guard LoopbackReservation(listener.address) != nil, listener.port != 0 else {
            throw LoopbackReservationError.invalidReservations
        }
    }
    return listeners.filter { LoopbackReservation($0.address).map(aliases.contains) ?? false }
}
