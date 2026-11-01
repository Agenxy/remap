// SPDX-License-Identifier: GPL-3.0-or-later
import Foundation
import RemapSystemKit

struct MacOSResolverObservation: Equatable, Sendable {
    let ownerUID: UInt32?
    let productVersion: String?
    let phase: ActivationPhase?
    let configuredServiceIDs: [String]
    let remapServiceIDs: [String]
    /// The owner's deliberate turn-off, while no activation exists (ADR-0036).
    var turnedOff: DNSTurnedOffPayload?

    var recordPresent: Bool {
        phase != nil
    }

    var activeRecord: Bool {
        phase == .active
    }
}

protocol MacOSResolverControlling: Sendable {
    func observation() throws -> MacOSResolverObservation
    func activate(
        configuration: MacOSInstallConfiguration,
        productVersion: String,
        systemSocketPath: String
    ) async throws
    func deactivate() throws
}

struct NativeMacOSResolverController: MacOSResolverControlling, Sendable {
    private let resolver = SystemResolver()
    private let store: ActivationStore

    init(store: ActivationStore = .standard) {
        self.store = store
    }

    func observation() throws -> MacOSResolverObservation {
        let record = try resolver.activeRecord(store: store)
        let system = try resolver.observe()
        return MacOSResolverObservation(
            ownerUID: record?.payload.ownerUID,
            productVersion: record?.payload.productVersion,
            phase: record?.payload.phase,
            configuredServiceIDs: record?.payload.services.map(\.serviceID).sorted() ?? [],
            remapServiceIDs: system.remapServiceIDs,
            // A diagnostic record never decides whether status can be read.
            turnedOff: record == nil ? (try? DNSTurnedOffStore(directory: store.directory).read())?.payload : nil
        )
    }

    func activate(
        configuration: MacOSInstallConfiguration,
        productVersion: String,
        systemSocketPath: String
    ) async throws {
        _ = try await resolver.activate(
            ownerUID: configuration.ownerUID,
            productVersion: productVersion,
            systemSocketPath: systemSocketPath,
            store: store
        )
    }

    func deactivate() throws {
        try resolver.deactivate(store: store)
    }
}
