import RemapControlKit

struct MappingDraft: Equatable {
    var pattern = ""
    var target = ""
    var hostPolicy = RemapHostPolicy.useUpstream
    var enabled = true
    var landing = ""

    init() {}

    init(mapping: RemapMapping) {
        pattern = mapping.pattern
        target = mapping.target
        hostPolicy = mapping.hostPolicy
        enabled = mapping.enabled
        landing = mapping.landing ?? ""
    }

    var change: RemapChange {
        .set(
            pattern: pattern,
            target: target,
            hostPolicy: hostPolicy,
            enabled: enabled,
            landing: landing.isEmpty ? nil : landing
        )
    }
}
