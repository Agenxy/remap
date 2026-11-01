// SPDX-License-Identifier: GPL-3.0-or-later
// swift-tools-version: 6.2

import PackageDescription

let strictSwift: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .unsafeFlags(["-warnings-as-errors"])
]

/// A helper's `Info.plist` sits beside its sources and is not one of them.
let embeddedInfoPlistSource = ["Info.plist"]

/// Embeds a helper's `Info.plist` in its executable's `__TEXT,__info_plist`
/// section. A bare executable has no bundle, so without one macOS names the
/// helper in a prompt by its file name, and code signing has no identifier of
/// the product's choosing to bind (ADR-0034).
func embeddedInfoPlist(_ target: String) -> LinkerSetting {
    .unsafeFlags([
        "-Xlinker", "-sectcreate",
        "-Xlinker", "__TEXT",
        "-Xlinker", "__info_plist",
        "-Xlinker", "\(Context.packageDirectory)/Sources/\(target)/Info.plist"
    ])
}

let package = Package(
    name: "RemapMac",
    platforms: [.macOS(.v15)],
    products: [
        .library(name: "RemapControlKit", targets: ["RemapControlKit"]),
        .library(name: "RemapInstallKit", targets: ["RemapInstallKit"]),
        .library(name: "RemapLifecycleKit", targets: ["RemapLifecycleKit"]),
        .library(name: "RemapSystemKit", targets: ["RemapSystemKit"]),
        .executable(name: "remap-install", targets: ["RemapInstall"]),
        .executable(name: "remap-installer-bootstrap", targets: ["RemapInstallerBootstrap"]),
        .executable(name: "remap-installer-service", targets: ["RemapInstallerService"]),
        .executable(name: "remap-lifecycle", targets: ["RemapLifecycleCLI"]),
        .executable(name: "remap-portable-installer", targets: ["RemapPortableInstaller"]),
        .executable(name: "remap-release-key", targets: ["RemapReleaseKey"]),
        .executable(name: "remap-release-xar-signer", targets: ["RemapReleaseXARSigner"]),
        .executable(name: "remap-resolver", targets: ["RemapResolver"]),
        .executable(name: "remap-system", targets: ["RemapSystem"]),
        .executable(name: "Remap", targets: ["RemapApp"])
    ],
    targets: [
        .target(
            name: "RemapControlKit",
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("Network")]
        ),
        .target(
            name: "RemapInstallKit",
            dependencies: ["RemapControlKit", "RemapSystemKit"],
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("Security")
            ]
        ),
        .target(
            name: "RemapLifecycleKit",
            dependencies: ["RemapInstallKit"],
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("Security")]
        ),
        .target(
            name: "RemapSystemKit",
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("Network"),
                .linkedFramework("SystemConfiguration")
            ]
        ),
        .executableTarget(
            name: "RemapInstall",
            dependencies: ["RemapInstallKit", "RemapSystemKit"],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                embeddedInfoPlist("RemapInstall")
            ]
        ),
        .executableTarget(
            name: "RemapInstallerBootstrap",
            dependencies: ["RemapInstallKit", "RemapLifecycleKit"],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [embeddedInfoPlist("RemapInstallerBootstrap")]
        ),
        .executableTarget(
            name: "RemapInstallerService",
            dependencies: ["RemapLifecycleKit"],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [embeddedInfoPlist("RemapInstallerService")]
        ),
        .executableTarget(
            name: "RemapLifecycleCLI",
            dependencies: ["RemapLifecycleKit"],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                embeddedInfoPlist("RemapLifecycleCLI")
            ]
        ),
        .executableTarget(
            name: "RemapPortableInstaller",
            dependencies: [
                "RemapControlKit",
                "RemapInstallKit",
                "RemapLifecycleKit",
                "RemapSystemKit"
            ],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("Security"),
                embeddedInfoPlist("RemapPortableInstaller")
            ]
        ),
        .executableTarget(
            name: "RemapResolver",
            dependencies: ["RemapSystemKit"],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("OSLog"),
                embeddedInfoPlist("RemapResolver")
            ]
        ),
        .executableTarget(
            name: "RemapReleaseKey",
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
                embeddedInfoPlist("RemapReleaseKey")
            ]
        ),
        .executableTarget(
            name: "RemapReleaseXARSigner",
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("Security"),
                embeddedInfoPlist("RemapReleaseXARSigner")
            ]
        ),
        .executableTarget(
            name: "RemapSystem",
            dependencies: ["RemapSystemKit"],
            exclude: embeddedInfoPlistSource,
            swiftSettings: strictSwift,
            linkerSettings: [embeddedInfoPlist("RemapSystem")]
        ),
        .executableTarget(
            name: "RemapApp",
            dependencies: ["RemapControlKit", "RemapLifecycleKit", "RemapSystemKit"],
            path: "App",
            exclude: ["Assets"],
            sources: ["Sources"],
            resources: [.process("Resources")],
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("SwiftUI")]
        ),
        .testTarget(
            name: "RemapControlKitTests",
            dependencies: ["RemapControlKit"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapAppTests",
            dependencies: ["RemapApp", "RemapControlKit", "RemapSystemKit"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapInstallKitTests",
            dependencies: ["RemapInstallKit"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapInstallTests",
            dependencies: ["RemapInstall"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapLifecycleKitTests",
            dependencies: ["RemapLifecycleKit"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapLifecycleCLITests",
            dependencies: ["RemapLifecycleCLI"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapPortableInstallerTests",
            dependencies: ["RemapPortableInstaller", "RemapSystemKit"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapReleaseKeyTests",
            dependencies: ["RemapReleaseKey"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapReleaseXARSignerTests",
            dependencies: ["RemapReleaseXARSigner"],
            swiftSettings: strictSwift
        ),
        .testTarget(
            name: "RemapSystemKitTests",
            dependencies: ["RemapSystemKit"],
            swiftSettings: strictSwift
        )
    ]
)
