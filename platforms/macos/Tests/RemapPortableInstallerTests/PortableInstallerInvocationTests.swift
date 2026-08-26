import Foundation
@testable import RemapPortableInstaller
import Testing

@Test
func portableInvocationAcceptsAnExistingPrivateTemporaryPackage() throws {
    let path = "/private/tmp/remap-invocation-\(UUID().uuidString.lowercased()).pkg"
    #expect(FileManager.default.createFile(atPath: path, contents: Data()))
    defer { try? FileManager.default.removeItem(atPath: path) }

    _ = try PortableInstallerInvocation(
        arguments: [
            "/private/tmp/package/Scripts/preinstall",
            path,
            "/",
            "/"
        ],
        environment: [
            "SCRIPT_NAME": "preinstall",
            "INSTALL_PKG_SESSION_ID": PortableInstallerInvocation.packageIdentifier,
            "DSTROOT": "/",
            "DSTVOLUME": "/",
            "PACKAGE_PATH": path
        ]
    )
}

@Test
func portableInvocationRejectsLexicallyNoncanonicalPackagePaths() {
    for path in ["relative.pkg", "/private/tmp/../foreign.pkg", "/private//tmp/pkg"] {
        #expect(throws: Error.self) {
            _ = try PortableInstallerInvocation(
                arguments: ["/private/tmp/package/Scripts/preinstall"],
                environment: [
                    "SCRIPT_NAME": "preinstall",
                    "INSTALL_PKG_SESSION_ID": PortableInstallerInvocation.packageIdentifier,
                    "DSTROOT": "/",
                    "DSTVOLUME": "/",
                    "PACKAGE_PATH": path
                ]
            )
        }
    }
}
