import Darwin
import Foundation
import RemapInstallKit
import RemapLifecycleKit

struct PortableLifecycleAuthorityInstaller: Sendable {
    private let files: PortableAuthorityFiles
    private let publications: PortableAuthorityPublicationStore
    private let service: PortableLifecycleServiceController

    init(
        runner: PortableCommandRunner = PortableCommandRunner(),
        files: PortableAuthorityFiles = .production()
    ) {
        self.files = files
        publications = PortableAuthorityPublicationStore(files: files)
        service = PortableLifecycleServiceController(runner: runner)
    }

    func install(
        prepared: PortablePreparedProduct,
        activeGenerationID: String?
    ) throws -> PortableLifecycleAuthorityTransaction {
        let lock = try PortableAuthorityLock.acquire(files: files)
        try recoverExisting(activeGenerationID: activeGenerationID)
        try validateExistingAuthority()
        let previousConfiguration: RemapLifecycleServiceConfiguration? = if files.exists(
            PortableLifecyclePaths.configuration
        ) {
            try RemapLifecycleServiceConfiguration.production()
        } else {
            nil
        }
        let configuration = try configuration(prepared)
        let retainedSources = Set(
            [
                previousConfiguration?.sourceManifestDigest,
                configuration.sourceManifestDigest
            ].compactMap(\.self)
        )
        try MacOSPortableSourcePurge.purgeDetachedSources(retaining: retainedSources)
        let sourceChanged = previousConfiguration?.sourcePackageRoot
            != configuration.sourcePackageRoot
        let previousSource: RemapLifecycleServiceConfiguration? = sourceChanged
            ? previousConfiguration
            : nil
        let contents = try publicationContents(
            prepared: prepared,
            configuration: configuration
        )
        let wasLoaded = try service.isLoaded()
        let transactionID = UUID().uuidString.lowercased()
        var journal: PortableAuthorityJournal
        do {
            journal = try publications.prepare(
                transactionID: transactionID,
                generationID: prepared.sourcePackage.generationID,
                previousServiceWasLoaded: wasLoaded,
                previousSourceRoot: previousSource?.sourcePackageRoot.description,
                previousSourceManifestDigest: previousSource?.sourceManifestDigest,
                contents: contents
            )
            if wasLoaded {
                try service.bootout()
            }
            journal = try publications.publish(
                journal,
                index: 0,
                phase: .helperPublished
            )
            journal = try publications.publish(
                journal,
                index: 1,
                phase: .configurationPublished
            )
            journal = try publications.publish(
                journal,
                index: 2,
                phase: .plistPublished
            )
            try validateInstalledAuthority(configuration: configuration)
            try service.bootstrap()
            try service.requireLoaded()
            journal = try publications.advance(journal, to: .serviceLoaded)
        } catch {
            try settleFailedPreparation(primary: error)
        }
        return PortableLifecycleAuthorityTransaction(
            journal: journal,
            lock: lock,
            publications: publications,
            service: service
        )
    }

    private func recoverExisting(activeGenerationID: String?) throws {
        guard var journal = try publications.load() else { return }
        if journal.phase == .productCommitted || activeGenerationID == journal.generationID {
            if journal.phase != .productCommitted {
                journal = try publications.advance(journal, to: .productCommitted)
            }
            try publications.validateCommit(journal)
            try validateInstalledAuthority(configuration: nil)
            if try service.isLoaded() {
                try service.bootout()
            }
            try service.bootstrap()
            try service.requireLoaded()
            try publications.commit(journal)
            return
        }
        try restorePreviousAuthority(journal)
    }

    private func settleFailedPreparation(primary: any Error) throws -> Never {
        do {
            if let journal = try publications.load() {
                try restorePreviousAuthority(journal)
            }
        } catch {
            throw InstallError.transaction(
                primary: String(describing: primary),
                recovery: String(describing: error)
            )
        }
        throw primary
    }

    private func restorePreviousAuthority(_ journal: PortableAuthorityJournal) throws {
        try publications.validateRollback(journal)
        if try service.isLoaded() {
            try service.bootout()
        }
        try publications.rollback(journal)
        if journal.previousServiceWasLoaded {
            try service.bootstrap()
            try service.requireLoaded()
        }
        try publications.finishRollback()
    }

    private func configuration(
        _ prepared: PortablePreparedProduct
    ) throws -> RemapLifecycleServiceConfiguration {
        try RemapLifecycleServiceConfiguration(
            ownerUID: prepared.ownerUID,
            app: prepared.appIdentity,
            client: prepared.clientIdentity,
            bootstrap: prepared.bootstrapIdentity,
            helper: prepared.serviceIdentity,
            sourceManifestDigest: prepared.sourcePackage.manifestDigest,
            sourcePackageRoot: InstallAbsolutePath(prepared.sourcePackage.rootPath)
        )
    }

    private func publicationContents(
        prepared: PortablePreparedProduct,
        configuration: RemapLifecycleServiceConfiguration
    ) throws -> [Data] {
        let helper = try PortableAuthoritySourceReader.read(prepared.servicePath)
        let configurationData = try configuration.canonicalData()
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: RemapLifecycleBootstrapper.launchdDocument,
            format: .xml,
            options: 0
        )
        return [helper, configurationData, plistData]
    }

    private func validateExistingAuthority() throws {
        let paths = PortableLifecyclePaths.orderedPublications.map(\.path)
        let presence = paths.map(files.exists)
        guard presence.allSatisfy({ !$0 }) || presence.allSatisfy(\.self) else {
            throw InstallError.collision("partial Remap lifecycle service authority")
        }
        guard presence.allSatisfy(\.self) else { return }
        try validateInstalledAuthority(configuration: nil)
    }

    private func validateInstalledAuthority(
        configuration expected: RemapLifecycleServiceConfiguration?
    ) throws {
        let configuration = try RemapLifecycleServiceConfiguration.production()
        if let expected, configuration != expected {
            throw InstallError.integrity("the installed lifecycle configuration is not exact")
        }
        let helper = try PortableCodeIdentityChecker.identity(
            path: PortableLifecyclePaths.helper
        )
        guard helper == configuration.helper else {
            throw InstallError.integrity("the installed lifecycle service identity is not exact")
        }
        _ = try MacOSInstallSourcePackage(
            rootPath: configuration.sourcePackageRoot.description,
            expectedManifestDigest: configuration.sourceManifestDigest.description,
            sourceUID: 0
        )
        try RemapLifecycleBootstrapper.production(
            configuration: configuration
        ).validateInstalledAuthority()
    }
}

final class PortableLifecycleAuthorityTransaction {
    private var journal: PortableAuthorityJournal
    private var lock: PortableAuthorityLock?
    private let publications: PortableAuthorityPublicationStore
    private let service: PortableLifecycleServiceController
    private var completed = false

    init(
        journal: PortableAuthorityJournal,
        lock: PortableAuthorityLock,
        publications: PortableAuthorityPublicationStore,
        service: PortableLifecycleServiceController
    ) {
        self.journal = journal
        self.lock = lock
        self.publications = publications
        self.service = service
    }

    func markProductCommitted() throws {
        guard !completed else {
            throw InstallError.journal("the lifecycle authority transaction already settled")
        }
        journal = try publications.advance(journal, to: .productCommitted)
    }

    func commit() throws {
        guard !completed else { return }
        try service.requireLoaded()
        try publications.commit(journal)
        completed = true
        lock = nil
    }

    func settleAfterFailure() throws {
        guard !completed else { return }
        if journal.phase == .productCommitted {
            if try !(service.isLoaded()) {
                try service.bootstrap()
            }
            try service.requireLoaded()
            try publications.commit(journal)
        } else {
            try publications.validateRollback(journal)
            if try service.isLoaded() {
                try service.bootout()
            }
            try publications.rollback(journal)
            if journal.previousServiceWasLoaded {
                try service.bootstrap()
                try service.requireLoaded()
            }
            try publications.finishRollback()
        }
        completed = true
        lock = nil
    }
}

struct PortableLifecycleServiceController: Sendable {
    private let runner: PortableCommandRunner

    init(runner: PortableCommandRunner) {
        self.runner = runner
    }

    func isLoaded() throws -> Bool {
        let result = try runner.run(
            executable: "/bin/launchctl",
            arguments: ["print", "system/\(MacOSInstallerServiceLaunchd.label)"]
        )
        if result.exitStatus == 113 {
            return false
        }
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem("inspect the lifecycle service", result.exitStatus)
        }
        return true
    }

    func bootout() throws {
        let result = try runner.run(
            executable: "/bin/launchctl",
            arguments: ["bootout", "system/\(MacOSInstallerServiceLaunchd.label)"]
        )
        guard result.exitStatus == 0 || result.exitStatus == 113 else {
            throw InstallError.operatingSystem("stop the lifecycle service", result.exitStatus)
        }
    }

    func bootstrap() throws {
        let result = try runner.run(
            executable: "/bin/launchctl",
            arguments: ["bootstrap", "system", PortableLifecyclePaths.plist]
        )
        guard result.exitStatus == 0 else {
            throw InstallError.operatingSystem("start the lifecycle service", result.exitStatus)
        }
    }

    func requireLoaded() throws {
        for _ in 0 ..< 20 {
            if try isLoaded() {
                return
            }
            usleep(50000)
        }
        throw InstallError.integrity("the lifecycle service did not stay loaded")
    }
}
