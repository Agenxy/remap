import Foundation

enum ControlFrame {
    static func encode(_ request: ControlRequest) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let payload = try encoder.encode(request)
        guard payload.count <= remapMaximumControlFrameBytes else {
            throw transportDiagnostic(
                code: "E_CONTROL_FRAME",
                message: "the local-control request exceeds the one MiB limit",
                retryable: false
            )
        }
        guard let count = UInt32(exactly: payload.count) else {
            throw transportDiagnostic(
                code: "E_CONTROL_FRAME",
                message: "the local-control request length cannot be represented",
                retryable: false
            )
        }
        var bigEndianCount = count.bigEndian
        var frame = withUnsafeBytes(of: &bigEndianCount) { Data($0) }
        frame.append(payload)
        return frame
    }

    static func declaredLength(_ prefix: Data) throws -> Int {
        guard prefix.count == MemoryLayout<UInt32>.size else {
            throw transportDiagnostic(
                code: "E_CONTROL_PROTOCOL",
                message: "the daemon returned an incomplete frame length",
                retryable: true
            )
        }
        let value = prefix.reduce(UInt32.zero) { result, byte in
            (result << 8) | UInt32(byte)
        }
        let length = Int(value)
        guard length <= remapMaximumControlFrameBytes else {
            throw transportDiagnostic(
                code: "E_CONTROL_PROTOCOL",
                message: "the daemon response exceeds the one MiB limit",
                retryable: false
            )
        }
        return length
    }

    static func decodeResponse(_ payload: Data) throws -> ControlResponse {
        do {
            return try JSONDecoder().decode(ControlResponse.self, from: payload)
        } catch {
            throw transportDiagnostic(
                code: "E_CONTROL_PROTOCOL",
                message: "the daemon returned an invalid local-control response",
                retryable: false
            )
        }
    }
}

func transportDiagnostic(
    code: String,
    message: String,
    hint: String? = nil,
    retryable: Bool,
    context: [String: String] = [:]
) -> RemapDiagnostic {
    RemapDiagnostic(
        code: code,
        message: message,
        hint: hint,
        retryable: retryable,
        context: context
    )
}
