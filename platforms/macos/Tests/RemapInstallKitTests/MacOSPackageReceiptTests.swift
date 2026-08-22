import Foundation
@testable import RemapInstallKit
import Synchronization
import Testing

@Test
func packageReceiptReadsOneExactPortableInstallerReceipt() throws {
    let store = MacOSPackageReceiptStore(runner: ReceiptRunner { command in
        #expect(command == .info)
        return try MacOSPackageReceiptResult(
            exitStatus: 0,
            output: receiptData(version: "0.2.0")
        )
    })

    #expect(try store.version() == "0.2.0")
}

@Test
func packageReceiptAcceptsMacOSRootInstallLocationEncoding() throws {
    let store = MacOSPackageReceiptStore(runner: ReceiptRunner { _ in
        try MacOSPackageReceiptResult(
            exitStatus: 0,
            output: receiptData(installLocation: "", version: "0.2.0")
        )
    })

    #expect(try store.version() == "0.2.0")
}

@Test
func packageReceiptRejectsNonRootInstallLocation() throws {
    let store = MacOSPackageReceiptStore(runner: ReceiptRunner { _ in
        try MacOSPackageReceiptResult(
            exitStatus: 0,
            output: receiptData(installLocation: "/tmp", version: "0.2.0")
        )
    })

    #expect(throws: InstallError.self) {
        _ = try store.version()
    }
}

@Test
func packageReceiptRejectsAnotherIdentifier() throws {
    let store = MacOSPackageReceiptStore(runner: ReceiptRunner { _ in
        try MacOSPackageReceiptResult(
            exitStatus: 0,
            output: receiptData(
                identifier: "org.example.Foreign",
                version: "0.2.0"
            )
        )
    })

    #expect(throws: InstallError.self) {
        _ = try store.version()
    }
}

@Test
func packageReceiptForgetRequiresTheReviewedVersionAndVerifiesRemoval() throws {
    let present = Mutex(true)
    let commands = Mutex<[MacOSPackageReceiptCommand]>([])
    let store = MacOSPackageReceiptStore(runner: ReceiptRunner { command in
        commands.withLock { $0.append(command) }
        switch command {
        case .info:
            return try present.withLock { isPresent in
                let data = isPresent
                    ? try receiptData(version: "0.2.0")
                    : Data(MacOSPackageReceiptStore.missingReceiptMessage.utf8)
                return MacOSPackageReceiptResult(
                    exitStatus: isPresent ? 0 : 1,
                    output: data
                )
            }
        case .forget:
            present.withLock { $0 = false }
            return MacOSPackageReceiptResult(exitStatus: 0, output: Data("forgot\n".utf8))
        }
    })

    try store.forget(expectedVersion: "0.2.0")
    #expect(commands.withLock { $0 } == [.info, .forget, .info])
}

@Test
func packageReceiptNeverForgetsAnUnreviewedReceipt() throws {
    let forgetCount = Mutex(0)
    let store = MacOSPackageReceiptStore(runner: ReceiptRunner { command in
        if command == .forget {
            forgetCount.withLock { $0 += 1 }
        }
        return try MacOSPackageReceiptResult(
            exitStatus: 0,
            output: receiptData(version: "0.2.1")
        )
    })

    #expect(throws: InstallError.self) {
        try store.forget(expectedVersion: "0.2.0")
    }
    #expect(forgetCount.withLock { $0 } == 0)
}

private struct ReceiptRunner: MacOSPackageReceiptRunning, Sendable {
    let operation: @Sendable (MacOSPackageReceiptCommand) throws -> MacOSPackageReceiptResult

    func run(_ command: MacOSPackageReceiptCommand) throws -> MacOSPackageReceiptResult {
        try operation(command)
    }
}

private func receiptData(
    identifier: String = MacOSPackageReceiptStore.identifier,
    installLocation: String = "/",
    version: String
) throws -> Data {
    try PropertyListSerialization.data(
        fromPropertyList: [
            "install-location": installLocation,
            "install-time": 1_786_900_000,
            "pkg-version": version,
            "pkgid": identifier,
            "receipt-plist-version": 1,
            "volume": "/"
        ],
        format: .xml,
        options: 0
    )
}
