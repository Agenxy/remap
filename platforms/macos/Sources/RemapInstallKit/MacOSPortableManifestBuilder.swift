import Foundation

enum MacOSPortableManifestBuilder {
    static func generationID(
        productVersion: String,
        entries: [InstallEntry],
        account: MacOSAccount,
        ownerUID: UInt32,
        dataDirectory: String,
        upstreams: [String]
    ) throws -> String {
        let placeholder = MacOSPortableProductContract.generationPlaceholder
        let launchd = try MacOSPortableLaunchd.documents(
            generationID: placeholder,
            account: account,
            ownerUID: ownerUID,
            dataDirectory: dataDirectory,
            upstreams: upstreams
        )
        let seed: [String: Any] = try [
            "accountName": account.userName,
            "entries": jsonObjects(entries),
            "groupName": account.groupName,
            "launchd": launchd,
            "publicationContract": publicationDocuments(generationID: placeholder),
            "productVersion": productVersion
        ]
        let data = try JSONSerialization.data(
            withJSONObject: seed,
            options: [.sortedKeys, .withoutEscapingSlashes]
        )
        return productVersion + "-" + InstallDigest.hash(data).description
    }

    static func publications(
        generationID: String,
        entries: [InstallEntry]
    ) throws -> [InstallPublication] {
        var publications = try directoryPaths.map {
            try InstallPublication(
                path: InstallRelativePath($0),
                generationID: generationID
            )
        }
        try publications.append(contentsOf: symlinkTargets(generationID: generationID).map { path, target in
            try InstallPublication(
                path: InstallRelativePath(path),
                target: InstallSymlinkTarget(target),
                generationID: generationID
            )
        })
        for service in MacOSLaunchdServiceKind.allCases {
            let entryPath = try InstallRelativePath(service.plistEntry)
            guard let entry = entries.first(where: { $0.path == entryPath }) else {
                throw InstallError.invalidManifest(
                    "the portable image has no launchd entry for \(service.label)"
                )
            }
            guard let digest = entry.sha256, let byteCount = entry.byteCount else {
                throw InstallError.invalidManifest(
                    "the portable launchd entry is not a regular file for \(service.label)"
                )
            }
            try publications.append(
                InstallPublication(
                    path: InstallRelativePath("Library/LaunchDaemons/\(service.label).plist"),
                    source: InstallRelativePath(
                        "\(MacOSInstallLayout.installerBase)/Generations/\(generationID)/\(service.plistEntry)"
                    ),
                    sha256: digest,
                    byteCount: byteCount,
                    generationID: generationID
                )
            )
        }
        return publications.sorted { $0.path < $1.path }
    }

    private static func publicationDocuments(generationID: String) -> [[String: Any]] {
        var documents = directoryPaths.map {
            [
                "generationID": generationID,
                "groupGID": 0,
                "kind": "directory",
                "mode": 0o755,
                "ownerUID": 0,
                "path": $0
            ] as [String: Any]
        }
        documents.append(contentsOf: symlinkTargets(generationID: generationID).map { path, target in
            [
                "generationID": generationID,
                "kind": "symbolicLink",
                "path": path,
                "target": target
            ]
        })
        documents.append(contentsOf: MacOSLaunchdServiceKind.allCases.map { service in
            [
                "generationID": generationID,
                "groupGID": 0,
                "kind": "regularFile",
                "mode": 0o444,
                "ownerUID": 0,
                "path": "Library/LaunchDaemons/\(service.label).plist",
                "source": "\(MacOSInstallLayout.installerBase)/Generations/\(generationID)/\(service.plistEntry)"
            ] as [String: Any]
        })
        return documents.sorted { left, right in
            (left["path"] as? String ?? "") < (right["path"] as? String ?? "")
        }
    }

    private static func jsonObjects(_ values: some Encodable) throws -> Any {
        let data = try InstallCanonicalJSON.encoder.encode(values)
        return try JSONSerialization.jsonObject(with: data)
    }

    private static func symlinkTargets(generationID: String) -> [(String, String)] {
        let current = "/\(MacOSInstallLayout.installerBase)/current"
        var targets = [
            ("Applications/Remap.app", current + "/app/Remap.app"),
            (
                "\(MacOSInstallLayout.installerBase)/current",
                "/\(MacOSInstallLayout.installerBase)/Generations/\(generationID)"
            ),
            ("usr/local/bin/remap", current + "/bin/remap"),
            (
                "usr/local/share/bash-completion/completions/remap",
                current + "/share/completions/remap.bash"
            ),
            (
                "usr/local/share/fish/vendor_completions.d/remap.fish",
                current + "/share/completions/remap.fish"
            ),
            ("usr/local/share/licenses/remap/LICENSE", current + "/share/licenses/remap/LICENSE"),
            ("usr/local/share/licenses/remap/NOTICE", current + "/share/licenses/remap/NOTICE"),
            ("usr/local/share/zsh/site-functions/_remap", current + "/share/completions/remap.zsh")
        ]
        targets.append(contentsOf: MacOSPortableProductContract.manpageNames.map {
            ("usr/local/share/man/man1/\($0)", current + "/share/man/man1/\($0)")
        })
        return targets.sorted { $0.0 < $1.0 }
    }

    private static let directoryPaths = [
        "usr/local",
        "usr/local/bin",
        "usr/local/share",
        "usr/local/share/bash-completion",
        "usr/local/share/bash-completion/completions",
        "usr/local/share/fish",
        "usr/local/share/fish/vendor_completions.d",
        "usr/local/share/licenses",
        "usr/local/share/licenses/remap",
        "usr/local/share/man",
        "usr/local/share/man/man1",
        "usr/local/share/zsh",
        "usr/local/share/zsh/site-functions"
    ]
}
