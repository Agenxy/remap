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
    private let activation: ActivationStore
    private let interval: Duration
    private let observe: @Sendable (LoopbackReservationOutcome) -> Void

    public init(
        channel: any ResolverSystemExchanging,
        interface: any LoopbackInterface = DarwinLoopbackInterface(),
        store: LoopbackReservationStore = .standard,
        activation: ActivationStore = .standard,
        interval: Duration = .seconds(5),
        observe: @escaping @Sendable (LoopbackReservationOutcome) -> Void
    ) {
        self.channel = channel
        self.interface = interface
        self.store = store
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
        let desired: Set<LoopbackReservation>
        if activation.exists() {
            do {
                desired = try loopbackReservations(from: channel.exchange(.loopbackReservations))
            } catch let error as LoopbackReservationError {
                return .unchanged(error.code)
            } catch {
                return .unchanged("E_LOOPBACK_AUTHORITY_UNAVAILABLE")
            }
        } else {
            desired = []
        }
        do {
            let change = try apply(desired: desired, interface: interface, store: store)
            return .held(change.owned.count)
        } catch let error as LoopbackReservationError {
            return .unchanged(error.code)
        } catch {
            return .unchanged("E_LOOPBACK_RECORD")
        }
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
    /// The supervisor holds exactly this many aliases.
    case held(Int)
    /// Nothing changed, for this stable reason.
    case unchanged(String)
}

/// Records an address before adding it and forgets it only after removing
/// it, so a crash between the two never leaves an alias nobody owns.
@discardableResult
func apply(
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
