"""Exact field sets for Remap's native Linux lifecycle JSON v1 contract."""

SUCCESS_ENVELOPE_KEYS = frozenset({"command", "data", "ok", "schemaVersion"})
ERROR_ENVELOPE_KEYS = frozenset({"command", "error", "ok", "schemaVersion"})
ERROR_DETAIL_KEYS = frozenset({"category", "hint", "message"})
ERROR_CATEGORIES = frozenset(
    {
        "invalid_request",
        "permission_denied",
        "state_conflict",
        "system_error",
        "timeout",
        "unsupported_platform",
    }
)
STATUS_DATA_KEYS = frozenset(
    {
        "activeGenerationID",
        "backend",
        "distribution",
        "hint",
        "installationState",
        "interfaceName",
        "linkCandidates",
        "linkIndex",
        "ownerUID",
        "previousGenerationID",
        "recoveryRequired",
        "resolverEnvironment",
        "schemaVersion",
        "services",
        "stateResidue",
    }
)
PREVIEW_DATA_KEYS = frozenset(
    {
        "approvalToken",
        "backend",
        "effects",
        "generationID",
        "hasEffects",
        "interfaceName",
        "linkIndex",
        "operation",
        "previousGenerationID",
        "publications",
        "resolverEnvironment",
        "schemaVersion",
        "sourceManifestSHA256",
    }
)
RECOVERY_DATA_KEYS = frozenset(
    {
        "approvalToken",
        "bootstrapResidues",
        "effects",
        "generationID",
        "hasEffects",
        "installationPhase",
        "schemaVersion",
        "stateResidue",
    }
)
PUBLICATION_KEYS = frozenset(
    {"action", "nextGenerationID", "path", "previousGenerationID"}
)
SERVICE_KEYS = frozenset({"state", "unit"})
LINK_CANDIDATE_KEYS = frozenset(
    {"backend", "interfaceName", "linkIndex", "selectionState"}
)
DISTRIBUTION_KEYS = frozenset({"id", "versionID"})
