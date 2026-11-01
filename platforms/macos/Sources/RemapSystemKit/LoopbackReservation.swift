// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// One address in the range ADR-0033 reserves for peer-machine names,
/// `127.77.0.0/16` without its network and broadcast addresses. The root
/// supervisor never adds or removes an address outside it.
public struct LoopbackReservation: Hashable, Comparable, Sendable, CustomStringConvertible {
    /// The address in host byte order.
    public let value: UInt32

    static let network: UInt32 = 0x7F4D_0000
    static let mask: UInt32 = 0xFFFF_0000

    /// Parses a canonical dotted quad inside the reserved range, or nil.
    public init?(_ text: String) {
        let parts = text.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var value: UInt32 = 0
        for part in parts {
            guard let octet = UInt8(part), String(octet) == part else { return nil }
            value = value << 8 | UInt32(octet)
        }
        self.init(value: value)
    }

    init?(value: UInt32) {
        guard value & Self.mask == Self.network,
              value != Self.network,
              value != Self.network | ~Self.mask
        else {
            return nil
        }
        self.value = value
    }

    public var description: String {
        [24, 16, 8, 0].map { String((value >> UInt32($0)) & 0xFF) }.joined(separator: ".")
    }

    public static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.value < rhs.value
    }
}

/// The most reservations the daemon may ask for, matching its mapping cap.
public let maximumLoopbackReservations = 256

/// What one reconciliation must do to `lo0`.
public struct LoopbackReservationChange: Equatable, Sendable {
    public let add: [LoopbackReservation]
    public let remove: [LoopbackReservation]
    /// What the supervisor owns once the change is applied.
    public let owned: Set<LoopbackReservation>

    public var isEmpty: Bool {
        add.isEmpty && remove.isEmpty
    }
}

/// Decides a reconciliation. Only addresses this supervisor added are ever
/// removed, so an alias another tool placed in the range is left alone, and
/// an address already present is neither added again nor adopted.
public func loopbackReservationChange(
    desired: Set<LoopbackReservation>,
    owned: Set<LoopbackReservation>,
    present: Set<LoopbackReservation>
) -> LoopbackReservationChange {
    let add = desired.subtracting(present).sorted()
    let remove = owned.subtracting(desired).intersection(present).sorted()
    let kept = owned.intersection(desired).intersection(present)
    return LoopbackReservationChange(add: add, remove: remove, owned: kept.union(add))
}

/// Decodes the daemon's answer, refusing all of it when any part is invalid.
public func loopbackReservations(from result: ResolverSystemResult) throws -> Set<LoopbackReservation> {
    guard let texts = result.loopbackReservations,
          texts.count <= maximumLoopbackReservations
    else {
        throw LoopbackReservationError.invalidReservations
    }
    var reservations = Set<LoopbackReservation>()
    for text in texts {
        guard let reservation = LoopbackReservation(text), reservations.insert(reservation).inserted else {
            throw LoopbackReservationError.invalidReservations
        }
    }
    return reservations
}

/// The loopback interface's aliases inside the reserved range.
public protocol LoopbackInterface: Sendable {
    func presentReservations() throws -> Set<LoopbackReservation>
    func add(_ reservation: LoopbackReservation) throws
    func remove(_ reservation: LoopbackReservation) throws
}

/// Stable failures of loopback reservation. None of them changes DNS.
public enum LoopbackReservationError: Error, Equatable, CustomStringConvertible {
    case invalidReservations
    case interface(String)
    case invalidRecord

    public var code: String {
        switch self {
        case .invalidReservations: "E_LOOPBACK_RESERVATIONS_INVALID"
        case .interface: "E_LOOPBACK_INTERFACE"
        case .invalidRecord: "E_LOOPBACK_RECORD"
        }
    }

    public var description: String {
        switch self {
        case .invalidReservations:
            "The Remap authority returned loopback reservations outside 127.77.0.0/16 or beyond its limit."
        case let .interface(operation):
            "macOS refused to \(operation) on the loopback interface."
        case .invalidRecord:
            "The root-owned loopback reservation record is damaged."
        }
    }
}
