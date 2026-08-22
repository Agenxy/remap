import Foundation

/// Production macOS adapter for launchd, SystemConfiguration, and authenticated runtime effects.
public struct MacOSInstallSystemEffectAdapter: InstallSystemEffectAdapting, Sendable {
    private let images: any MacOSGenerationImageLoading
    private let launchd: any MacOSLaunchdControlling
    private let resolver: any MacOSResolverControlling
    private let runtime: any MacOSRuntimeHealthChecking
    private let resolverReadiness: MacOSResolverReadinessVerifier

    public init(layout: MacOSInstallLayout) {
        images = MacOSGenerationImageStore(layout: layout)
        launchd = NativeMacOSLaunchdController()
        resolver = NativeMacOSResolverController()
        runtime = NativeMacOSRuntimeHealthChecker()
        resolverReadiness = MacOSResolverReadinessVerifier()
    }

    init(
        images: any MacOSGenerationImageLoading,
        launchd: any MacOSLaunchdControlling,
        resolver: any MacOSResolverControlling,
        runtime: any MacOSRuntimeHealthChecking,
        resolverReadiness: MacOSResolverReadinessVerifier = MacOSResolverReadinessVerifier()
    ) {
        self.images = images
        self.launchd = launchd
        self.resolver = resolver
        self.runtime = runtime
        self.resolverReadiness = resolverReadiness
    }

    public func reconcile(
        _ effect: InstallSystemEffect,
        context: InstallTransitionContext
    ) async throws {
        switch effect {
        case .serviceRunning:
            // During an update, restore ordinary DNS before replacing either
            // launchd job. The new daemon starts with a dormant forwarding
            // plan, so leaving macOS pointed at loopback during this handoff
            // would interrupt public DNS.
            if context.previous != nil {
                try await reconcileDNS(desired: nil, context: context)
            }
            try await reconcileServices(desired: images.load(context.current), context: context)
        case .priorServiceRestored:
            // Rollback must never point macOS at loopback while exchanging a
            // failed generation for the prior one. Restore ordinary DNS first,
            // then start the prior daemon; the following `.dnsRestored` step
            // re-enables Remap only after that daemon has proved authority.
            try await reconcileDNS(desired: nil, context: context)
            try await reconcileServices(
                desired: context.previous.map { try images.load($0) },
                context: context
            )
        case .serviceStopped:
            try await reconcileServices(desired: nil, context: context)
        case .dnsActive:
            try await reconcileDNS(desired: context.current, context: context)
        case .dnsRestored:
            // An update rollback restores the exact prior DNS owner only after
            // `.priorServiceRestored` has authenticated that daemon. Fresh
            // install rollback and uninstall have no prior generation, so they
            // continue to restore the machine's ordinary resolvers.
            try await reconcileDNS(desired: context.previous, context: context)
        case .installationAccepted:
            return
        }
    }

    public func verify(
        _ effect: InstallSystemEffect,
        context: InstallTransitionContext
    ) async throws {
        switch effect {
        case .serviceRunning:
            let image = try images.load(context.current)
            try verifyServices(image)
            _ = try await runtime.wait(
                configuration: image.configuration,
                productVersion: context.current.productVersion,
                requirement: .authority
            )
        case .priorServiceRestored:
            try await verifyPriorService(context)
        case .serviceStopped:
            try verifyServices(nil)
            let image = try images.load(context.current)
            _ = try await runtime.wait(
                configuration: image.configuration,
                productVersion: context.current.productVersion,
                requirement: .unavailable
            )
        case .dnsActive:
            try verifyDNS(desired: context.current)
            let image = try images.load(context.current)
            _ = try await runtime.wait(
                configuration: image.configuration,
                productVersion: context.current.productVersion,
                requirement: .dns
            )
        case .dnsRestored:
            try await verifyRestoredDNS(context)
        case .installationAccepted:
            let image = try images.load(context.current)
            _ = try await runtime.wait(
                configuration: image.configuration,
                productVersion: context.current.productVersion,
                requirement: .ready
            )
            // SystemConfiguration and its dynamic store settle independently
            // from the authenticated listeners. Listener identity alone is
            // therefore insufficient: accept only after macOS has repeatedly
            // reported the exact intended Remap DNS configuration.
            let configuration = image.configuration
            try await resolverReadiness.wait {
                try dnsMatchesExactly(context.current, configuration: configuration)
            }
        }
    }

    private func reconcileServices(
        desired: MacOSGenerationImage?,
        context: InstallTransitionContext
    ) async throws {
        let allowed = try allowedServiceImages(context)
        for kind in MacOSLaunchdServiceKind.allCases {
            let intended = desired?.services.first { $0.kind == kind }
            let observation = try launchd.observation(label: kind.label)
            if case let .loaded(plistPath, programPath) = observation {
                let identity = MacOSServiceIdentity(plistPath: plistPath, programPath: programPath)
                if identity == intended.map(MacOSServiceIdentity.init) {
                    continue
                }
                guard allowed.contains(identity) else {
                    throw InstallError.collision("launchd service \(kind.label)")
                }
                try launchd.bootout(label: kind.label)
                try await waitForServiceToUnload(kind, departing: identity)
            }
            if let intended {
                try launchd.bootstrap(plistPath: intended.plistPath)
                try launchd.enable(label: kind.label)
                // Both admitted plists require RunAtLoad and KeepAlive. Bootstrap
                // therefore starts the service. An immediate `kickstart -k`
                // needlessly kills that fresh process and can consume launchd's
                // five-second throttle window before acceptance observes it.
            }
        }
    }

    private func waitForServiceToUnload(
        _ kind: MacOSLaunchdServiceKind,
        departing: MacOSServiceIdentity
    ) async throws {
        for attempt in 0 ... 50 {
            switch try launchd.observation(label: kind.label) {
            case .missing:
                return
            case let .loaded(plistPath, programPath):
                let observed = MacOSServiceIdentity(
                    plistPath: plistPath,
                    programPath: programPath
                )
                guard observed == departing else {
                    throw InstallError.collision("launchd service \(kind.label)")
                }
            }
            guard attempt < 50 else { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        throw InstallError.integrity("launchd did not unload \(kind.label) within five seconds")
    }

    private func verifyServices(_ desired: MacOSGenerationImage?) throws {
        for kind in MacOSLaunchdServiceKind.allCases {
            let intended = desired?.services.first { $0.kind == kind }
            let observation = try launchd.observation(label: kind.label)
            switch (observation, intended) {
            case (.missing, nil):
                continue
            case let (.loaded(plistPath, programPath), .some(service))
                where plistPath == service.plistPath && programPath == service.programPath:
                continue
            default:
                throw InstallError.integrity("launchd service \(kind.label) does not match the intended generation")
            }
        }
    }

    private func verifyPriorService(_ context: InstallTransitionContext) async throws {
        guard let previous = context.previous else {
            try verifyServices(nil)
            let current = try images.load(context.current)
            _ = try await runtime.wait(
                configuration: current.configuration,
                productVersion: context.current.productVersion,
                requirement: .unavailable
            )
            return
        }
        let image = try images.load(previous)
        try verifyServices(image)
        _ = try await runtime.wait(
            configuration: image.configuration,
            productVersion: previous.productVersion,
            requirement: .authority
        )
    }

    private func verifyRestoredDNS(_ context: InstallTransitionContext) async throws {
        try verifyDNS(desired: context.previous)
        guard let previous = context.previous else { return }
        let image = try images.load(previous)
        _ = try await runtime.wait(
            configuration: image.configuration,
            productVersion: previous.productVersion,
            requirement: .dns
        )
        let configuration = image.configuration
        try await resolverReadiness.wait {
            try dnsMatchesExactly(previous, configuration: configuration)
        }
    }

    private func allowedServiceImages(_ context: InstallTransitionContext) throws -> Set<MacOSServiceIdentity> {
        let current = try images.load(context.current).services
        let previous = try context.previous.map { try images.load($0).services } ?? []
        return Set((current + previous).map(MacOSServiceIdentity.init))
    }

    private func reconcileDNS(
        desired: InstallManifest?,
        context: InstallTransitionContext
    ) async throws {
        let status = try resolver.observation()
        try verifyResolverConsistency(status)
        let desiredImage = try desired.map { try images.load($0) }
        let alreadyDesired = desired.flatMap { manifest in
            desiredImage.map { matches(status, manifest: manifest, configuration: $0.configuration) }
        } ?? false
        if alreadyDesired {
            return
        }
        if status.recordPresent {
            guard let identity = resolverIdentity(status),
                  try allowedDNSStates(context).contains(identity)
            else {
                throw InstallError.collision("native DNS activation record")
            }
            try resolver.deactivate()
        }
        if let desired, let desiredImage {
            try await resolver.activate(
                configuration: desiredImage.configuration,
                productVersion: desired.productVersion
            )
        }
    }

    private func verifyDNS(desired: InstallManifest?) throws {
        let status = try resolver.observation()
        try verifyResolverConsistency(status)
        guard let desired else {
            guard !status.recordPresent, status.remapServiceIDs.isEmpty else {
                throw InstallError.integrity("system DNS still contains a Remap activation")
            }
            return
        }
        let image = try images.load(desired)
        guard matches(status, manifest: desired, configuration: image.configuration) else {
            throw InstallError.integrity("system DNS does not match the intended Remap generation")
        }
    }

    private func dnsMatchesExactly(
        _ desired: InstallManifest,
        configuration: MacOSInstallConfiguration
    ) throws -> Bool {
        let status = try resolver.observation()
        return matches(status, manifest: desired, configuration: configuration)
    }

    private func allowedDNSStates(_ context: InstallTransitionContext) throws -> Set<MacOSResolverIdentity> {
        var identities = try [dnsIdentity(context.current)]
        if let previous = context.previous {
            try identities.append(dnsIdentity(previous))
        }
        return Set(identities)
    }

    private func dnsIdentity(_ manifest: InstallManifest) throws -> MacOSResolverIdentity {
        let configuration = try images.load(manifest).configuration
        return MacOSResolverIdentity(ownerUID: configuration.ownerUID, productVersion: manifest.productVersion)
    }

    private func resolverIdentity(_ status: MacOSResolverObservation) -> MacOSResolverIdentity? {
        guard let ownerUID = status.ownerUID, let productVersion = status.productVersion else {
            return nil
        }
        return MacOSResolverIdentity(ownerUID: ownerUID, productVersion: productVersion)
    }

    private func matches(
        _ status: MacOSResolverObservation,
        manifest: InstallManifest,
        configuration: MacOSInstallConfiguration
    ) -> Bool {
        status.activeRecord
            && status.ownerUID == configuration.ownerUID
            && status.productVersion == manifest.productVersion
            && status.configuredServiceIDs == status.remapServiceIDs
            && !status.remapServiceIDs.isEmpty
    }

    private func verifyResolverConsistency(_ status: MacOSResolverObservation) throws {
        let hasIdentity = status.ownerUID != nil && status.productVersion != nil
        let effectiveStateIsRecoverable = status.remapServiceIDs.isEmpty
            || status.configuredServiceIDs == status.remapServiceIDs
        guard status.recordPresent == hasIdentity,
              status.recordPresent || status.configuredServiceIDs.isEmpty,
              status.recordPresent || status.remapServiceIDs.isEmpty,
              effectiveStateIsRecoverable
        else {
            throw InstallError.integrity("the native DNS record and effective resolver state disagree")
        }
    }
}

private struct MacOSServiceIdentity: Equatable, Hashable, Sendable {
    let plistPath: InstallAbsolutePath
    let programPath: InstallAbsolutePath

    init(plistPath: InstallAbsolutePath, programPath: InstallAbsolutePath) {
        self.plistPath = plistPath
        self.programPath = programPath
    }

    init(_ image: MacOSLaunchdServiceImage) {
        plistPath = image.plistPath
        programPath = image.programPath
    }
}

private struct MacOSResolverIdentity: Equatable, Hashable, Sendable {
    let ownerUID: UInt32
    let productVersion: String
}
