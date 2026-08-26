// swift-tools-version: 6.2

import PackageDescription

let strictSwift: [SwiftSetting] = [
    .swiftLanguageMode(.v6),
    .unsafeFlags(["-warnings-as-errors"])
]

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
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("LocalAuthentication")]
        ),
        .executableTarget(
            name: "RemapInstallerBootstrap",
            dependencies: ["RemapInstallKit", "RemapLifecycleKit"],
            swiftSettings: strictSwift
        ),
        .executableTarget(
            name: "RemapInstallerService",
            dependencies: ["RemapLifecycleKit"],
            swiftSettings: strictSwift
        ),
        .executableTarget(
            name: "RemapLifecycleCLI",
            dependencies: ["RemapLifecycleKit"],
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("LocalAuthentication")]
        ),
        .executableTarget(
            name: "RemapPortableInstaller",
            dependencies: [
                "RemapControlKit",
                "RemapInstallKit",
                "RemapLifecycleKit",
                "RemapSystemKit"
            ],
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("Security")]
        ),
        .executableTarget(
            name: "RemapResolver",
            dependencies: ["RemapSystemKit"],
            swiftSettings: strictSwift,
            linkerSettings: [.linkedFramework("OSLog")]
        ),
        .executableTarget(
            name: "RemapReleaseXARSigner",
            swiftSettings: strictSwift,
            linkerSettings: [
                .linkedFramework("CryptoKit"),
                .linkedFramework("Security")
            ]
        ),
        .executableTarget(
            name: "RemapSystem",
            dependencies: ["RemapSystemKit"],
            swiftSettings: strictSwift
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
            dependencies: ["RemapPortableInstaller"],
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
