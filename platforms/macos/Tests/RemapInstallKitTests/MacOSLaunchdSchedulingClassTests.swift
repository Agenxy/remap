// SPDX-License-Identifier: GPL-3.0-or-later
import Darwin
import Foundation
@testable import RemapInstallKit
import Testing

/// ADR-0030: the daemon and the resolver supervisor sit in the system DNS
/// path, so neither may run in launchd's Background band.
@Test
func generatedDaemonAndResolverDefinitionsAreInteractive() throws {
    let scope = try SchedulingScope()
    let documents = try MacOSPortableLaunchd.documents(
        generationID: "test",
        account: scope.account,
        ownerUID: scope.configuration.ownerUID,
        dataDirectory: scope.configuration.dataDirectory.value,
        upstreams: ["192.0.2.53:53"]
    )
    #expect(Set(documents.keys) == Set(MacOSLaunchdServiceKind.allCases.map(\.label)))
    for kind in MacOSLaunchdServiceKind.allCases {
        let document = try #require(documents[kind.label])
        #expect(document["ProcessType"] as? String == "Interactive")
        // What the generator writes is what a new generation must carry.
        try MacOSLaunchdPropertyList.validate(
            PropertyListSerialization.data(fromPropertyList: document, format: .xml, options: 0),
            kind: kind,
            configuration: scope.configuration,
            account: scope.account,
            programPath: scope.program(kind)
        )
    }
}

@Test
func aNewGenerationAcceptsOnlyTheInteractiveSchedulingClass() throws {
    let scope = try SchedulingScope()
    for kind in MacOSLaunchdServiceKind.allCases {
        try scope.validate(kind, processType: "Interactive", scheduling: .generated)
        for refused in ["Background", "Standard", "Adaptive", "interactive", "", nil] as [String?] {
            #expect(throws: InstallError.self, "\(kind) \(String(describing: refused))") {
                try scope.validate(kind, processType: refused, scheduling: .generated)
            }
        }
    }
}

@Test
func anInstalledGenerationMayAlsoCarryOnlyTheLegacyBackgroundClass() throws {
    let scope = try SchedulingScope()
    for kind in MacOSLaunchdServiceKind.allCases {
        try scope.validate(kind, processType: "Interactive", scheduling: .installed)
        try scope.validate(kind, processType: "Background", scheduling: .installed)
        for refused in ["Standard", "Adaptive", "background", "Background ", "", nil] as [String?] {
            #expect(throws: InstallError.self, "\(kind) \(String(describing: refused))") {
                try scope.validate(kind, processType: refused, scheduling: .installed)
            }
        }
    }
}

@Test
func theSchedulingRefusalSaysWhatItRefused() throws {
    let scope = try SchedulingScope()
    #expect(throws: InstallError.invalidManifest(
        "the launchd scheduling class is not one Remap declares"
    )) {
        try scope.validate(.daemon, processType: "Background", scheduling: .generated)
    }
}

private struct SchedulingScope {
    let account: MacOSAccount
    let configuration: MacOSInstallConfiguration

    init() throws {
        let ownerUID = UInt32(getuid())
        account = try MacOSAccountLookup.account(for: ownerUID)
        let dataDirectory = account.homeDirectory.value + "/Library/Application Support/org.Agenxy.Remap"
        configuration = try MacOSInstallConfiguration(
            ownerUID: ownerUID,
            dataDirectory: InstallAbsolutePath(dataDirectory),
            controlSocket: InstallAbsolutePath(dataDirectory + "/control.sock"),
            signingCertificateSHA256: InstallDigest.hash(Data("certificate".utf8))
        )
    }

    func program(_ kind: MacOSLaunchdServiceKind) throws -> InstallAbsolutePath {
        try InstallAbsolutePath("/\(MacOSInstallLayout.installerBase)/Generations/test/\(kind.programEntry)")
    }

    /// Validates the fake definition for `kind` with `ProcessType` replaced,
    /// or removed when `processType` is nil.
    func validate(
        _ kind: MacOSLaunchdServiceKind,
        processType: String?,
        scheduling: MacOSLaunchdSchedulingAdmission
    ) throws {
        let program = try program(kind)
        let data = switch kind {
        case .daemon:
            try daemonPlist(configuration: configuration, program: program.value)
        case .resolver:
            try resolverPlist(configuration: configuration, program: program.value)
        }
        var document = try #require(
            PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any]
        )
        document["ProcessType"] = processType
        try MacOSLaunchdPropertyList.validate(
            PropertyListSerialization.data(fromPropertyList: document, format: .xml, options: 0),
            kind: kind,
            configuration: configuration,
            account: account,
            programPath: program,
            scheduling: scheduling
        )
    }
}
