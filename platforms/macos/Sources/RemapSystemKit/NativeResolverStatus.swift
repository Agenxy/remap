import Foundation

/// `remap-system status` data. The activation record's `payload` and `sha256`
/// keys are unchanged, so existing readers keep working; the last resolver
/// bypass is an added key, and the data stays `null` when there is neither an
/// activation nor any bypass evidence.
public struct NativeResolverStatus: Encodable, Sendable {
    public let record: ActivationRecord?
    public let bypass: ResolverBypassPayload?
    public let bypassError: String?

    public init(record: ActivationRecord?, bypassStore: ResolverBypassStore) {
        let bypass: ResolverBypassPayload?
        let bypassError: String?
        do {
            bypass = try bypassStore.read()?.payload
            bypassError = nil
        } catch {
            // The diagnostic record never decides whether status can report
            // the activation; an unreadable one is shown, not fatal.
            bypass = nil
            bypassError = String(describing: error)
        }
        self.init(record: record, bypass: bypass, bypassError: bypassError)
    }

    init(record: ActivationRecord?, bypass: ResolverBypassPayload?, bypassError: String?) {
        self.record = record
        self.bypass = bypass
        self.bypassError = bypassError
    }

    enum CodingKeys: String, CodingKey {
        case payload
        case sha256
        case lastResolverBypass
        case lastResolverBypassError
    }

    public func encode(to encoder: Encoder) throws {
        guard record != nil || bypass != nil || bypassError != nil else {
            var container = encoder.singleValueContainer()
            try container.encodeNil()
            return
        }
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(record?.payload, forKey: .payload)
        try container.encodeIfPresent(record?.sha256, forKey: .sha256)
        try container.encodeIfPresent(bypass, forKey: .lastResolverBypass)
        try container.encodeIfPresent(bypassError, forKey: .lastResolverBypassError)
    }

    /// Human lines describing the last fallback, empty when there was none.
    public func bypassLines() -> [String] {
        if let bypassError {
            return ["  Last fallback record unreadable: \(bypassError)"]
        }
        guard let bypass else { return [] }
        var lines = [
            "  Last fallback \(statusTimestamp(bypass.bypassedAtMilliseconds)) \(bypass.outcomeCode)",
            "    Reason      \(bypass.reasonCode), failing since "
                + statusTimestamp(bypass.failingSinceMilliseconds)
        ]
        if let rearmed = bypass.rearmedAtMilliseconds {
            lines.append("    Re-armed    \(statusTimestamp(rearmed))")
        } else {
            lines.append("    Re-armed    not yet; the Mac uses ordinary DNS")
            if let required = bypass.rearmAfterHealthyMilliseconds {
                lines.append(
                    "    Next try    after \(statusDuration(required)) of continuous daemon health"
                )
            }
        }
        if bypass.releasePending, bypass.rearmedAtMilliseconds == nil {
            lines.append("    Release     pending; the next reconciliation retries it")
        }
        return lines
    }
}

private func statusTimestamp(_ milliseconds: UInt64) -> String {
    Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1000).formatted(.iso8601)
}

/// Whole seconds, or milliseconds below one second.
private func statusDuration(_ milliseconds: UInt64) -> String {
    if milliseconds < 1000 {
        return "\(milliseconds) ms"
    }
    let seconds = (milliseconds + 500) / 1000
    return seconds == 1 ? "1 second" : "\(seconds) seconds"
}
