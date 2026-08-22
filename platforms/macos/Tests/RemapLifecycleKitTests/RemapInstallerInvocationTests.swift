import RemapInstallKit
@testable import RemapLifecycleKit
import Testing

@Test
func installerInvocationAcceptsTheClassicPackageScriptArguments() throws {
    let invocation = try RemapInstallerInvocation(
        arguments: [
            "/private/tmp/package/Scripts/preinstall",
            "/private/tmp/Remap.pkg",
            "/",
            "/"
        ],
        environment: packageEnvironment(script: "preinstall")
    )

    #expect(invocation.script == .preinstall)
    #expect(invocation.argumentCount == 4)
}

@Test
func installerInvocationAcceptsBoundedOperatingSystemExtensions() throws {
    let invocation = try RemapInstallerInvocation(
        arguments: [
            "/private/tmp/package/Scripts/postinstall",
            "/private/tmp/Remap.pkg",
            "/",
            "/",
            "apple-packagekit-extension"
        ],
        environment: packageEnvironment(script: "postinstall")
    )

    #expect(invocation.script == .postinstall)
    #expect(invocation.argumentCount == 5)
}

@Test(arguments: [
    ["/private/tmp/package/Scripts/foreign"],
    Array(repeating: "argument", count: RemapInstallerInvocation.maximumArgumentCount + 1),
    [String(repeating: "a", count: RemapInstallerInvocation.maximumArgumentByteCount + 1)]
])
func installerInvocationRejectsMalformedArguments(_ arguments: [String]) {
    #expect(throws: InstallError.self) {
        _ = try RemapInstallerInvocation(
            arguments: arguments,
            environment: packageEnvironment(script: "preinstall")
        )
    }
}

@Test(arguments: [
    ("SCRIPT_NAME", "postinstall"),
    ("INSTALL_PKG_SESSION_ID", "org.example.Foreign"),
    ("DSTROOT", "/Volumes/Foreign"),
    ("DSTVOLUME", "/Volumes/Foreign"),
    ("PACKAGE_PATH", "relative/Remap.pkg"),
    ("PACKAGE_PATH", "/private/tmp/../foreign.pkg")
])
func installerInvocationRejectsMismatchedPackageAuthority(
    key: String,
    value: String
) {
    var environment = packageEnvironment(script: "preinstall")
    environment[key] = value

    #expect(throws: InstallError.self) {
        _ = try RemapInstallerInvocation(
            arguments: ["/private/tmp/package/Scripts/preinstall"],
            environment: environment
        )
    }
}

private func packageEnvironment(script: String) -> [String: String] {
    [
        "SCRIPT_NAME": script,
        "INSTALL_PKG_SESSION_ID": RemapInstallerInvocation.packageIdentifier,
        "DSTROOT": "/",
        "DSTVOLUME": "/",
        "PACKAGE_PATH": "/private/tmp/Remap.pkg"
    ]
}
