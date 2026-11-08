// SPDX-License-Identifier: GPL-3.0-or-later
import CryptoKit
import Darwin
import Foundation
@testable import RemapReleaseKey

/// A private directory and `/usr/bin/ssh-keygen`, the verifier every Remap consumer runs.
struct SSHToolFixture {
    let directory: URL

    init() throws {
        directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("remap-release-key-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
    }

    func remove() {
        try? FileManager.default.removeItem(at: directory)
    }

    func write(_ data: Data, named name: String) throws -> URL {
        let url = directory.appendingPathComponent(name)
        try data.write(to: url, options: [.withoutOverwriting])
        return url
    }

    @discardableResult
    func sshKeygen(_ arguments: [String], input: URL? = nil) throws -> (status: Int32, output: Data) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
        process.arguments = arguments
        process.currentDirectoryURL = directory
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.standardInput = try input.map { try FileHandle(forReadingFrom: $0) } ?? FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (process.terminationStatus, data)
    }

    /// Whether ssh-keygen accepts `signature` over `message` for the `remap-release` principal.
    func verifies(
        signature: Data,
        message: Data,
        namespace: String,
        publicKeyLine: String
    ) throws -> Bool {
        let name = UUID().uuidString
        let signers = try write(Data("remap-release \(publicKeyLine)\n".utf8), named: "\(name).signers")
        let signatureURL = try write(signature, named: "\(name).sig")
        let messageURL = try write(message, named: "\(name).message")
        let result = try sshKeygen(
            ["-Y", "verify", "-f", signers.path, "-I", "remap-release", "-n", namespace, "-s", signatureURL.path],
            input: messageURL
        )
        return result.status == 0
    }
}

/// Reads the SSH wire format back, so a test can take an ssh-keygen signature apart.
struct SSHReader {
    private var remaining: Data

    init(_ data: Data) {
        remaining = data
    }

    var isEmpty: Bool {
        remaining.isEmpty
    }

    mutating func bytes(_ count: Int) throws -> Data {
        guard remaining.count >= count else {
            throw ReleaseKeyError.input("truncated SSH wire data")
        }
        let value = Data(remaining.prefix(count))
        remaining = Data(remaining.dropFirst(count))
        return value
    }

    mutating func uint32() throws -> UInt32 {
        try bytes(4).reduce(0) { ($0 << 8) | UInt32($1) }
    }

    mutating func string() throws -> Data {
        try bytes(Int(uint32()))
    }

    /// The unsigned 32-byte big-endian value of a P-256 `mpint`.
    mutating func scalar() throws -> Data {
        let value = try Data(string().drop { $0 == 0 })
        return Data(repeating: 0, count: 32 - value.count) + value
    }
}

func armoredBlob(_ armor: Data) throws -> Data {
    let lines = String(decoding: armor, as: UTF8.self).split(separator: "\n").map(String.init)
    guard lines.first == SSHSignature.beginLine, lines.last == SSHSignature.endLine,
          let blob = Data(base64Encoded: lines.dropFirst().dropLast().joined())
    else {
        throw ReleaseKeyError.input("not an armoured SSH signature")
    }
    return blob
}
