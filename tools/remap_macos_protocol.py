"""Bounded, terminal-safe decoding for the native macOS installer helper."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import cast

GENERATION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
APPROVAL_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
BOOTSTRAP_CDHASH_PATTERN = re.compile(r"[0-9a-f]{40,64}\Z")
BOOTSTRAP_PATH_PATTERN = re.compile(
    r"/Library/PrivilegedHelperTools/org\.agenxy\.Remap\.install\.[0-9a-f]{32}\Z"
)
BOOTSTRAP_STAGE_PATH_PATTERN = re.compile(
    r"/Library/PrivilegedHelperTools/org\.agenxy\.Remap\.install-stage\.[0-9a-f]{32}\Z"
)


@dataclass(frozen=True)
class InstallerStatus:
    """Narrow status facts needed by the unprivileged orchestrator."""

    active_generation_id: str | None
    generation_count: int
    pending_recovery_count: int
    loaded_service_count: int
    service_count: int
    dns_active: bool
    effective_remap_service_count: int


def installer_status(document: dict[str, object]) -> InstallerStatus:
    """Validate the narrow status values used to select lifecycle behavior."""
    data = success_data(document, "status")
    active = data.get("activeGenerationID")
    if active is not None:
        active = generation_id(active)
    generations = _object_list(data, "generations", maximum=32)
    transactions = _object_list(data, "transactions", maximum=4_096)
    services = _object_list(data, "services", maximum=8)
    dns = data.get("dns")
    if not isinstance(dns, dict):
        raise TypeError("the installer returned an invalid DNS status")
    dns_data = cast("dict[str, object]", dns)
    dns_active = dns_data.get("active")
    effective_remap_service_count = dns_data.get("effectiveRemapServiceCount")
    if (
        not isinstance(dns_active, bool)
        or type(effective_remap_service_count) is not int
        or not 0 <= effective_remap_service_count <= 128
    ):
        raise TypeError("the installer returned an invalid DNS status")
    pending = sum(item.get("recoveryRequired") is True for item in transactions)
    loaded = sum(item.get("loaded") is True for item in services)
    return InstallerStatus(
        active_generation_id=active,
        generation_count=len(generations),
        pending_recovery_count=pending,
        loaded_service_count=loaded,
        service_count=len(services),
        dns_active=dns_active,
        effective_remap_service_count=effective_remap_service_count,
    )


def is_exact_update(operation: str, status: InstallerStatus, generation: str) -> bool:
    """Return whether update inputs already identify the active generation."""
    return operation == "update" and generation == status.active_generation_id


def resolver_upstreams(document: dict[str, object]) -> list[str]:
    """Validate sensitive native endpoints without printing or persisting them."""
    data = success_data(document, "resolver-plan")
    raw = data.get("upstreams")
    if not isinstance(raw, list):
        raise TypeError("the native resolver plan must contain one to four upstreams")
    raw_values = cast("list[object]", raw)
    if not 1 <= len(raw_values) <= 4:
        raise RuntimeError(
            "the native resolver plan must contain one to four upstreams"
        )
    values: list[str] = []
    for item in raw_values:
        if not isinstance(item, str) or item in values:
            raise RuntimeError("the native resolver plan contains an invalid endpoint")
        values.append(_resolver_endpoint(item))
    return values


def render_preview(document: dict[str, object]) -> str:
    """Render the exact bounded lifecycle preview for a person in the terminal."""
    data = success_data(document, "preview")
    operation = data.get("operation")
    generation = generation_id(data.get("generationID"))
    changes = data.get("publicationChanges")
    change_details = data.get("publicationChangeDetails")
    effects = data.get("effects")
    recovery = data.get("pendingRecoveryTransactions")
    if (
        data.get("schemaVersion") != 2
        or operation not in {"install", "update", "uninstall"}
        or not isinstance(changes, int)
        or changes < 0
        or not isinstance(change_details, list)
        or not isinstance(effects, list)
        or not isinstance(recovery, list)
    ):
        raise RuntimeError("the native installer returned an invalid preview")
    effect_values = cast("list[object]", effects)
    detail_values = cast("list[object]", change_details)
    recovery_values = cast("list[object]", recovery)
    if (
        len(detail_values) != changes
        or len(detail_values) > 256
        or not 1 <= len(effect_values) <= 16
        or len(recovery_values) > 4_096
    ):
        raise RuntimeError("the native installer returned an invalid preview")
    rendered_changes = [_publication_change(value) for value in detail_values]
    paths = [path for path, _rendered in rendered_changes]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RuntimeError(
            "the native installer returned unordered publication changes"
        )
    safe_effects: list[str] = []
    for effect in effect_values:
        if not isinstance(effect, str) or not effect or len(effect) > 160:
            raise RuntimeError("the native installer returned an invalid effect")
        safe_effects.append(terminal_text(effect))
    lines = [
        f"Preview: {operation} generation {generation}",
        f"  Publication changes: {changes}",
        *(f"    - {rendered}" for _path, rendered in rendered_changes),
        f"  Pending recovery transactions: {len(recovery_values)}",
        "  Effects:",
        *(f"    - {effect}" for effect in safe_effects),
        f"  Approval token: {_approval_token(data)}",
    ]
    return "\n".join(lines)


def render_recovery_preview(document: dict[str, object]) -> str:
    """Render exact bounded crash-recovery scope before any recovery effect."""
    data = success_data(document, "preview-recovery")
    selected, orphans, detached, effects, _transactions = _recovery_scope(data)
    lines = [
        "Recovery preview",
        f"  Selected transactions: {len(selected)}",
        *(f"    - {value}" for value in selected),
        f"  Orphaned staging generations: {len(orphans)}",
        *(f"    - {value}" for value in orphans),
        f"  Detached generations: {len(detached)}",
        *(f"    - {value}" for value in detached),
        "  Effects:",
        *(f"    - {terminal_text(effect)}" for effect in effects),
        f"  Approval token: {_approval_token(data)}",
    ]
    return "\n".join(lines)


def approval_token(document: dict[str, object], command: str) -> str:
    """Return the exact canonical approval token from one validated preview."""
    return _approval_token(success_data(document, command))


def recovery_has_effects(document: dict[str, object]) -> bool:
    """Return whether a validated recovery preview selects any system effect."""
    data = success_data(document, "preview-recovery")
    selected, orphans, detached, effects, transactions = _recovery_scope(data)
    return bool(selected or orphans or detached or effects or transactions)


def render_bootstrap_recovery_preview(document: dict[str, object]) -> str:
    """Render verified bootstrap residue and its independently approved effects."""
    data = success_data(document, "preview-bootstrap-recovery")
    candidates, stages, effects = _bootstrap_recovery_scope(data)
    lines = [
        "Bootstrap-helper recovery preview",
        f"  Direct candidates: {len(candidates)}",
        *(f"    - {rendered}" for _path, rendered in candidates),
        f"  Private staging candidates: {len(stages)}",
        *(f"    - {rendered}" for _path, rendered in stages),
        "  Effects:",
        *(f"    - {terminal_text(effect)}" for effect in effects),
        f"  Approval token: {_approval_token(data)}",
    ]
    return "\n".join(lines)


def bootstrap_recovery_has_effects(document: dict[str, object]) -> bool:
    """Return whether exact inactive bootstrap residue will be removed."""
    data = success_data(document, "preview-bootstrap-recovery")
    _candidates, _stages, effects = _bootstrap_recovery_scope(data)
    return bool(effects)


def _bootstrap_recovery_scope(
    data: dict[str, object],
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[str]]:
    if data.get("schemaVersion") != 3:
        raise RuntimeError(
            "the native installer returned an invalid bootstrap recovery preview"
        )
    _ = _approval_token(data)
    raw_candidates = _object_list(data, "candidates", maximum=32)
    candidates = [_bootstrap_candidate(candidate) for candidate in raw_candidates]
    raw_stages = _object_list(data, "stagingCandidates", maximum=32)
    stages = [_bootstrap_stage(candidate) for candidate in raw_stages]
    if len(candidates) + len(stages) > 32:
        raise RuntimeError(
            "the native installer returned too many bootstrap candidates"
        )
    paths = [path for path, _rendered in candidates]
    stage_paths = [path for path, _rendered in stages]
    if (
        paths != sorted(paths)
        or len(paths) != len(set(paths))
        or stage_paths != sorted(stage_paths)
        or len(stage_paths) != len(set(stage_paths))
    ):
        raise RuntimeError("the native installer returned invalid bootstrap candidates")
    effects = _string_list(data, "effects", maximum=32, maximum_bytes=192)
    expected = [
        f"remove inactive orphan bootstrap helper {path}"
        for path, candidate in zip(paths, raw_candidates, strict=True)
        if candidate.get("activity") == "inactive"
    ]
    expected.extend(
        f"remove private orphan bootstrap stage {path}" for path in stage_paths
    )
    if effects != expected:
        raise RuntimeError("the native installer returned invalid bootstrap effects")
    return candidates, stages, effects


def _bootstrap_stage(value: dict[str, object]) -> tuple[str, str]:
    path = value.get("path")
    attributes = value.get("extendedAttributeNames")
    identity = value.get("fileIdentity")
    staged = value.get("stagedFile")
    if (
        not isinstance(path, str)
        or not BOOTSTRAP_STAGE_PATH_PATTERN.fullmatch(path)
        or attributes not in ([], ["com.apple.provenance"])
        or not isinstance(identity, dict)
        or staged is not None
        and not isinstance(staged, dict)
    ):
        raise RuntimeError(
            "the native installer returned an invalid private bootstrap stage"
        )
    metadata = cast("dict[str, object]", identity)
    mode = value.get("mode")
    if not (
        _bounded_integer(metadata.get("deviceID"), minimum=0, maximum=2**64 - 1)
        and _bounded_integer(metadata.get("fileID"), minimum=1, maximum=2**64 - 1)
        and _bounded_integer(value.get("ownerUID"), minimum=0, maximum=0)
        and _bounded_integer(value.get("groupGID"), minimum=0, maximum=0)
        and mode in {0o700, 0o711}
        and _bounded_integer(value.get("linkCount"), minimum=1, maximum=3)
        and _bounded_integer(value.get("flags"), minimum=0, maximum=0)
    ):
        raise RuntimeError(
            "the native installer returned unsafe private bootstrap metadata"
        )
    file_rendered = "empty"
    if isinstance(staged, dict):
        file_rendered = _bootstrap_staged_file(path, cast("dict[str, object]", staged))
    return path, f"{terminal_text(path)} [root:wheel {mode:04o}, {file_rendered}]"


def _bootstrap_staged_file(stage_path: str, value: dict[str, object]) -> str:
    path = value.get("path")
    identity = value.get("fileIdentity")
    attributes = value.get("extendedAttributeNames")
    sha256 = value.get("sha256")
    if (
        path != f"{stage_path}/candidate"
        or not isinstance(identity, dict)
        or attributes not in ([], ["com.apple.provenance"])
        or not isinstance(sha256, str)
        or not APPROVAL_TOKEN_PATTERN.fullmatch(sha256)
    ):
        raise RuntimeError(
            "the native installer returned an invalid private staged file"
        )
    metadata = cast("dict[str, object]", identity)
    mode = value.get("mode")
    if not (
        _bounded_integer(metadata.get("deviceID"), minimum=0, maximum=2**64 - 1)
        and _bounded_integer(metadata.get("fileID"), minimum=1, maximum=2**64 - 1)
        and _bounded_integer(value.get("ownerUID"), minimum=0, maximum=0)
        and _bounded_integer(value.get("groupGID"), minimum=0, maximum=0)
        and mode in {0o600, 0o400, 0o555}
        and _bounded_integer(value.get("byteCount"), minimum=0, maximum=134_217_728)
        and _bounded_integer(value.get("linkCount"), minimum=1, maximum=1)
        and _bounded_integer(value.get("flags"), minimum=0, maximum=0)
    ):
        raise RuntimeError(
            "the native installer returned unsafe private staged-file metadata"
        )
    return f"candidate {value['byteCount']} bytes mode {mode:04o} SHA-256 {sha256}"


def _bootstrap_candidate(value: dict[str, object]) -> tuple[str, str]:
    path = value.get("path")
    code_validity = value.get("codeValidity")
    identifier = value.get("codeIdentifier")
    cdhash = value.get("cdHash")
    sha256 = value.get("sha256")
    activity = value.get("activity")
    attributes = value.get("extendedAttributeNames")
    identity = value.get("fileIdentity")
    if (
        not isinstance(path, str)
        or not BOOTSTRAP_PATH_PATTERN.fullmatch(path)
        or code_validity not in {"invalid", "verified"}
        or not isinstance(sha256, str)
        or not APPROVAL_TOKEN_PATTERN.fullmatch(sha256)
        or activity not in {"active", "current", "inactive"}
        or not isinstance(attributes, list)
        or attributes not in ([], ["com.apple.provenance"])
        or not isinstance(identity, dict)
    ):
        raise RuntimeError(
            "the native installer returned an invalid bootstrap candidate"
        )
    if code_validity == "verified":
        if (
            identifier != "org.agenxy.Remap.install-bootstrap"
            or not isinstance(cdhash, str)
            or not BOOTSTRAP_CDHASH_PATTERN.fullmatch(cdhash)
            or len(cdhash) % 2 != 0
        ):
            raise RuntimeError(
                "the native installer returned an invalid bootstrap code identity"
            )
    elif identifier is not None or cdhash is not None:
        raise RuntimeError(
            "the native installer returned an invalid bootstrap code classification"
        )
    metadata = cast("dict[str, object]", identity)
    if not (
        _bounded_integer(metadata.get("deviceID"), minimum=0, maximum=2**64 - 1)
        and _bounded_integer(metadata.get("fileID"), minimum=1, maximum=2**64 - 1)
        and _bounded_integer(value.get("ownerUID"), minimum=0, maximum=0)
        and _bounded_integer(value.get("groupGID"), minimum=0, maximum=0)
        and _bounded_integer(value.get("mode"), minimum=0o555, maximum=0o555)
        and _bounded_integer(value.get("byteCount"), minimum=0, maximum=134_217_728)
        and _bounded_integer(value.get("linkCount"), minimum=1, maximum=1)
        and _bounded_integer(value.get("flags"), minimum=0, maximum=0)
    ):
        raise RuntimeError("the native installer returned unsafe bootstrap metadata")
    code = (
        f"verified CDHash {cdhash}"
        if code_validity == "verified"
        else "invalid code identity"
    )
    rendered = (
        f"{terminal_text(path)} [{activity}], {code}, SHA-256 {sha256}, "
        f"root:wheel 0555, {value['byteCount']} bytes"
    )
    return path, rendered


def _bounded_integer(value: object, *, minimum: int, maximum: int) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and minimum <= value <= maximum
    )


def _recovery_scope(
    data: dict[str, object],
) -> tuple[list[str], list[str], list[str], list[str], list[str]]:
    if data.get("schemaVersion") != 1:
        raise RuntimeError("the native installer returned an invalid recovery preview")
    _ = _approval_token(data)
    requested = data.get("requestedTransactionID")
    if requested is not None:
        _ = _identifier(requested, "requested recovery transaction")
    selected = _identifier_list(data, "selectedTransactionIDs", maximum=4_096)
    orphans = _identifier_list(data, "orphanedStagingTransactionIDs", maximum=4_096)
    detached = _identifier_list(data, "detachedGenerationNames", maximum=64)
    effects = _string_list(data, "effects", maximum=8_258, maximum_bytes=192)
    transactions = _object_list(data, "transactions", maximum=4_096)
    transaction_ids = [_recovery_transaction(value) for value in transactions]
    if (
        transaction_ids != sorted(transaction_ids)
        or len(transaction_ids) != len(set(transaction_ids))
        or not set(selected).issubset(transaction_ids)
    ):
        raise RuntimeError(
            "the native installer returned invalid recovery transactions"
        )
    return selected, orphans, detached, effects, transaction_ids


def _recovery_transaction(value: dict[str, object]) -> str:
    transaction = _identifier(value.get("transactionID"), "recovery transaction")
    operation = value.get("operation")
    phase = value.get("phase")
    previous = value.get("previousGenerationID")
    count = value.get("recordCount")
    digest = value.get("journalHeadDigest")
    valid_count = (
        isinstance(count, int) and not isinstance(count, bool) and 1 <= count <= 4_096
    )
    if (
        operation not in {"install", "update", "uninstall"}
        or not isinstance(phase, str)
        or not IDENTIFIER_PATTERN.fullmatch(phase)
        or not valid_count
    ):
        raise RuntimeError(
            "the native installer returned an invalid recovery transaction"
        )
    _ = generation_id(value.get("generationID"))
    if previous is not None:
        _ = generation_id(previous)
    if not isinstance(digest, str) or not APPROVAL_TOKEN_PATTERN.fullmatch(digest):
        raise RuntimeError(
            "the native installer returned an invalid recovery transaction"
        )
    if not isinstance(value.get("recoveryRequired"), bool):
        raise TypeError("the native installer returned an invalid recovery transaction")
    return transaction


def _identifier(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or value in {".", ".."}
        or not IDENTIFIER_PATTERN.fullmatch(value)
    ):
        raise RuntimeError(f"the native installer returned an invalid {label}")
    return value


def _publication_change(value: object) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise TypeError("the native installer returned an invalid publication change")
    change = cast("dict[str, object]", value)
    path = _relative_public_path(change.get("path"))
    action = change.get("action")
    previous = _optional_generation(change.get("previousGenerationID"))
    following = _optional_generation(change.get("nextGenerationID"))
    if action == "create" and previous is None and following is not None:
        detail = f"create /{terminal_text(path)} -> {terminal_text(following)}"
    elif action == "remove" and previous is not None and following is None:
        detail = f"remove /{terminal_text(path)} <- {terminal_text(previous)}"
    elif action == "replace" and previous is not None and following is not None:
        detail = (
            f"replace /{terminal_text(path)}: "
            f"{terminal_text(previous)} -> {terminal_text(following)}"
        )
    else:
        raise RuntimeError(
            "the native installer returned inconsistent publication ownership"
        )
    return path, detail


def _relative_public_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1_024:
        raise RuntimeError("the native installer returned an invalid publication path")
    components = value.split("/")
    if any(component in {"", ".", ".."} for component in components):
        raise RuntimeError("the native installer returned an invalid publication path")
    return value


def _optional_generation(value: object) -> str | None:
    return None if value is None else generation_id(value)


def _approval_token(data: dict[str, object]) -> str:
    value = data.get("approvalToken")
    if not isinstance(value, str) or not APPROVAL_TOKEN_PATTERN.fullmatch(value):
        raise RuntimeError("the native installer returned an invalid approval token")
    return value


def _identifier_list(data: dict[str, object], key: str, *, maximum: int) -> list[str]:
    values = _string_list(data, key, maximum=maximum, maximum_bytes=128)
    if (
        values != sorted(values)
        or len(values) != len(set(values))
        or any(
            value in {".", ".."} or not IDENTIFIER_PATTERN.fullmatch(value)
            for value in values
        )
    ):
        raise RuntimeError(f"the native installer returned invalid {key}")
    return values


def _string_list(
    data: dict[str, object],
    key: str,
    *,
    maximum: int,
    maximum_bytes: int,
) -> list[str]:
    raw = data.get(key)
    if not isinstance(raw, list):
        raise TypeError(f"the native installer returned invalid {key}")
    values = cast("list[object]", raw)
    if len(values) > maximum:
        raise RuntimeError(f"the native installer returned invalid {key}")
    if not all(
        isinstance(value, str) and value and len(value.encode("utf-8")) <= maximum_bytes
        for value in values
    ):
        raise RuntimeError(f"the native installer returned invalid {key}")
    return cast("list[str]", values)


def installer_error(data: bytes, status: int) -> str:
    """Render a bounded structured helper failure without terminal controls."""
    try:
        document = decode_document(data, "native installer error")
        detail = document.get("error")
        if document.get("ok") is not False or not isinstance(detail, dict):
            raise ValueError
        error_data = cast("dict[str, object]", detail)
        category = error_data.get("category")
        message = error_data.get("message")
        hint = error_data.get("hint")
        if not isinstance(category, str) or not isinstance(message, str):
            raise TypeError
        rendered = f"native installer {category} error: {terminal_text(message)}"
        if isinstance(hint, str):
            rendered += f"\nNext: {terminal_text(hint)}"
        return rendered
    except (TypeError, UnicodeDecodeError, ValueError, RuntimeError):
        return f"native installer exited with status {status} and no valid diagnostic"


def terminal_text(value: str) -> str:
    """Escape control and bidirectional formatting characters for a terminal."""
    return "".join(
        character
        if character.isprintable()
        and character not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        else f"\\u{{{ord(character):04x}}}"
        for character in value
    )


def decode_document(data: bytes, label: str) -> dict[str, object]:
    """Decode one bounded JSON object after its caller enforces the byte limit."""
    try:
        value = cast("object", json.loads(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} was not valid bounded JSON") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} was not a JSON object")
    return cast("dict[str, object]", value)


def success_data(document: dict[str, object], command: str) -> dict[str, object]:
    """Validate one successful helper envelope and return its data object."""
    data = document.get("data")
    if (
        document.get("schemaVersion") != 1
        or document.get("ok") is not True
        or document.get("command") != command
        or not isinstance(data, dict)
    ):
        raise RuntimeError(
            f"the native installer returned an invalid {command} envelope"
        )
    return cast("dict[str, object]", data)


def generation_id(value: object) -> str:
    """Validate one filesystem-safe native generation identity."""
    if not isinstance(value, str) or not GENERATION_PATTERN.fullmatch(value):
        raise RuntimeError(
            "the native installer returned an invalid generation identity"
        )
    return value


def _resolver_endpoint(value: str) -> str:
    if value.startswith("["):
        closing = value.find("]")
        if closing < 2 or value[closing + 1 :] != ":53":
            raise RuntimeError(
                "the native resolver plan contains an invalid IPv6 endpoint"
            )
        address_text = value[1:closing]
    else:
        address_text, separator, port = value.rpartition(":")
        if not separator or port != "53":
            raise RuntimeError(
                "the native resolver plan contains an invalid IPv4 endpoint"
            )
    address = ipaddress.ip_address(address_text)
    if address.is_loopback or address.is_unspecified or address.is_multicast:
        raise RuntimeError("the native resolver plan contains an unsafe address")
    rendered = f"[{address}]:53" if address.version == 6 else f"{address}:53"
    if rendered != value:
        raise RuntimeError("the native resolver endpoint is not canonical")
    return rendered


def _object_list(
    data: dict[str, object], key: str, *, maximum: int
) -> list[dict[str, object]]:
    value = data.get(key)
    if not isinstance(value, list):
        raise TypeError(f"the native installer returned an invalid {key} collection")
    objects = cast("list[object]", value)
    if len(objects) > maximum:
        raise RuntimeError(f"the native installer returned an invalid {key} collection")
    if not all(isinstance(item, dict) for item in objects):
        raise RuntimeError(f"the native installer returned malformed {key} entries")
    return cast("list[dict[str, object]]", objects)
