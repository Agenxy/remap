// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation

/// `lo0` aliases through the BSD socket ioctls macOS uses for `ifconfig lo0
/// alias`. Each reservation is a host address with an all-ones mask.
public struct DarwinLoopbackInterface: LoopbackInterface {
    public init() {}

    public func presentReservations() throws -> Set<LoopbackReservation> {
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else {
            throw LoopbackReservationError.interface("list its addresses")
        }
        defer { freeifaddrs(head) }
        var present = Set<LoopbackReservation>()
        var cursor = head
        while let entry = cursor?.pointee {
            cursor = entry.ifa_next
            guard String(cString: entry.ifa_name) == loopbackName,
                  let address = entry.ifa_addr,
                  address.pointee.sa_family == UInt8(AF_INET)
            else {
                continue
            }
            let value = address.withMemoryRebound(to: sockaddr_in.self, capacity: 1) {
                UInt32(bigEndian: $0.pointee.sin_addr.s_addr)
            }
            if let reservation = LoopbackReservation(value: value) {
                present.insert(reservation)
            }
        }
        return present
    }

    public func add(_ reservation: LoopbackReservation) throws {
        var request = ifaliasreq()
        setName(&request.ifra_name)
        request.ifra_addr = socketAddress(reservation.value)
        request.ifra_mask = socketAddress(UInt32.max)
        try control(addAlias, &request, operation: "add \(reservation)")
    }

    public func remove(_ reservation: LoopbackReservation) throws {
        var request = ifreq()
        setName(&request.ifr_name)
        request.ifr_ifru.ifru_addr = socketAddress(reservation.value)
        try control(deleteAddress, &request, operation: "remove \(reservation)")
    }

    private func control(_ command: UInt, _ request: inout some Any, operation: String) throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else {
            throw LoopbackReservationError.interface(operation)
        }
        defer { close(descriptor) }
        let status = withUnsafeMutablePointer(to: &request) { ioctl(descriptor, command, $0) }
        guard status == 0 else {
            throw LoopbackReservationError.interface(operation)
        }
    }
}

private let loopbackName = "lo0"

/// `_IOW('i', 26, struct ifaliasreq)`, which Swift does not import.
let addAlias = writeControl(number: 26, size: MemoryLayout<ifaliasreq>.size)
/// `_IOW('i', 25, struct ifreq)`.
let deleteAddress = writeControl(number: 25, size: MemoryLayout<ifreq>.size)

private func writeControl(number: UInt, size: Int) -> UInt {
    let inbound: UInt = 0x8000_0000
    let parameterMask: UInt = 0x1FFF
    return inbound | (UInt(size) & parameterMask) << 16 | UInt(UInt8(ascii: "i")) << 8 | number
}

private func setName(_ name: inout some Any) {
    withUnsafeMutableBytes(of: &name) { bytes in
        bytes.initializeMemory(as: UInt8.self, repeating: 0)
        for (index, byte) in loopbackName.utf8.enumerated() {
            bytes[index] = byte
        }
    }
}

private func socketAddress(_ value: UInt32) -> sockaddr {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_addr = in_addr(s_addr: value.bigEndian)
    return withUnsafeBytes(of: &address) { $0.load(as: sockaddr.self) }
}

/// Creates the listening sockets peer-machine names need. Root creates them
/// because only root may bind a port below 1024 on a specific address, and
/// because creating them the moment the alias exists leaves no window in which
/// another account could bind the address first (ADR-0033 amendment).
public protocol LoopbackListenerFactory: Sendable {
    /// A listening TCP socket bound to exactly this address and port.
    func listen(on listener: LoopbackListener) throws -> Int32
}

public struct DarwinLoopbackListenerFactory: LoopbackListenerFactory {
    public init() {}

    public func listen(on listener: LoopbackListener) throws -> Int32 {
        guard let reservation = LoopbackReservation(listener.address), listener.port != 0 else {
            throw LoopbackReservationError.invalidReservations
        }
        let operation = "listen on \(listener.address):\(listener.port)"
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw LoopbackReservationError.interface(operation) }
        do {
            var enabled: Int32 = 1
            // SO_REUSEADDR lets root bind this one address beside a wildcard
            // listener, such as Remote Login's sshd on *:22, measured on macOS
            // 27.2; connections to the alias then reach this socket.
            guard fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0,
                  setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0
            else {
                throw LoopbackReservationError.interface(operation)
            }
            var address = sockaddr_in()
            address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
            address.sin_family = sa_family_t(AF_INET)
            address.sin_port = listener.port.bigEndian
            address.sin_addr = in_addr(s_addr: reservation.value.bigEndian)
            let bound = withUnsafePointer(to: &address) { pointer in
                pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard bound == 0, Darwin.listen(descriptor, listenBacklog) == 0 else {
                throw LoopbackReservationError.interface(operation)
            }
            return descriptor
        } catch {
            close(descriptor)
            throw error
        }
    }
}

private let listenBacklog: Int32 = 128
