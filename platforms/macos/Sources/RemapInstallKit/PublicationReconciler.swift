import Foundation

struct PublicationReconciler: Sendable {
    let store: PublicationStore
    let validateManifest: @Sendable (InstallManifest) throws -> Void

    init(
        store: PublicationStore,
        validateManifest: @escaping @Sendable (InstallManifest) throws -> Void = { _ in }
    ) {
        self.store = store
        self.validateManifest = validateManifest
    }

    func install(_ context: InstallTransitionContext, transactionID: String) throws {
        try validate(context)
        let previous = publicationsByPath(context.previous?.publications ?? [])
        let current = publicationsByPath(context.current.publications)
        for publication in installOrder(context.current.publications) {
            try store.publish(
                publication,
                replacing: previous[publication.path],
                transactionID: transactionID
            )
        }
        for publication in removalOrder(previous.values.filter { current[$0.path] == nil }) {
            try store.unpublish(publication)
        }
        try verifyInstalled(context)
    }

    func restorePrevious(_ context: InstallTransitionContext, transactionID: String) throws {
        try validate(context)
        let previous = publicationsByPath(context.previous?.publications ?? [])
        let current = publicationsByPath(context.current.publications)
        for publication in installOrder(Array(previous.values)) {
            try store.publish(
                publication,
                replacing: current[publication.path],
                transactionID: rollbackTransactionID(transactionID)
            )
        }
        for publication in removalOrder(current.values.filter { previous[$0.path] == nil }) {
            try store.unpublish(publication)
        }
        try verifyRestored(context)
    }

    func removeCurrent(_ context: InstallTransitionContext) throws {
        try validate(context)
        for publication in removalOrder(context.current.publications) {
            try store.unpublish(publication)
        }
        try verifyRemoved(context.current.publications)
    }

    func requireCurrentOwned(_ context: InstallTransitionContext) throws {
        try validate(context)
        for publication in context.current.publications {
            guard try acceptableInstalledClassification(store.classify(publication), for: publication) else {
                throw InstallError.collision(publication.path.description)
            }
        }
    }

    func requireInstallable(_ context: InstallTransitionContext) throws {
        try validate(context)
        let previous = publicationsByPath(context.previous?.publications ?? [])
        for publication in previous.values {
            guard try acceptableInstalledClassification(store.classify(publication), for: publication) else {
                throw InstallError.collision(publication.path.description)
            }
        }
        for publication in context.current.publications where previous[publication.path] == nil {
            let classification = try store.classify(publication)
            guard classification == .missing ||
                (publication.kind == .directory && classification == .compatible)
            else {
                throw InstallError.collision(publication.path.description)
            }
        }
    }

    private func verifyInstalled(_ context: InstallTransitionContext) throws {
        let current = publicationsByPath(context.current.publications)
        for publication in current.values {
            guard try acceptableInstalledClassification(store.classify(publication), for: publication) else {
                throw InstallError.integrity("publication \(publication.path) was not installed exactly")
            }
        }
        let previous = publicationsByPath(context.previous?.publications ?? [])
        try verifyMissing(previous.values.filter { current[$0.path] == nil })
    }

    private func validate(_ context: InstallTransitionContext) throws {
        try validateManifest(context.current)
        if let previous = context.previous {
            try validateManifest(previous)
        }
    }

    private func verifyRestored(_ context: InstallTransitionContext) throws {
        let previous = publicationsByPath(context.previous?.publications ?? [])
        for publication in previous.values {
            guard try acceptableInstalledClassification(store.classify(publication), for: publication) else {
                throw InstallError.integrity("publication \(publication.path) was not restored exactly")
            }
        }
        let current = publicationsByPath(context.current.publications)
        try verifyMissing(current.values.filter { previous[$0.path] == nil })
    }

    private func verifyRemoved(_ publications: [InstallPublication]) throws {
        try verifyMissing(publications)
    }

    private func verifyMissing(_ publications: some Sequence<InstallPublication>) throws {
        for publication in publications {
            let classification = try store.classify(publication)
            guard classification == .missing ||
                (publication.kind == .directory && classification == .compatible)
            else {
                throw InstallError.collision(publication.path.description)
            }
        }
    }

    private func publicationsByPath(
        _ publications: [InstallPublication]
    ) -> [InstallRelativePath: InstallPublication] {
        Dictionary(uniqueKeysWithValues: publications.map { ($0.path, $0) })
    }

    private func rollbackTransactionID(_ transactionID: String) -> String {
        "rollback-\(InstallDigest.hash(Data(transactionID.utf8)).value)"
    }

    private func acceptableInstalledClassification(
        _ classification: PublicationClassification,
        for publication: InstallPublication
    ) -> Bool {
        classification == .owned ||
            (publication.kind == .directory && classification == .compatible)
    }

    private func installOrder(_ publications: [InstallPublication]) -> [InstallPublication] {
        publications.sorted { left, right in
            if left.kind == .directory, right.kind != .directory {
                return true
            }
            if left.kind != .directory, right.kind == .directory {
                return false
            }
            let hasDifferentDepth = left.path.components.count != right.path.components.count
            if left.kind == .directory, hasDifferentDepth {
                return left.path.components.count < right.path.components.count
            }
            return left.path < right.path
        }
    }

    private func removalOrder(_ publications: some Sequence<InstallPublication>) -> [InstallPublication] {
        publications.sorted { left, right in
            if left.kind == .directory, right.kind != .directory {
                return false
            }
            if left.kind != .directory, right.kind == .directory {
                return true
            }
            let hasDifferentDepth = left.path.components.count != right.path.components.count
            if left.kind == .directory, hasDifferentDepth {
                return left.path.components.count > right.path.components.count
            }
            return left.path > right.path
        }
    }
}
