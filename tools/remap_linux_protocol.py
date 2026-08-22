"""Bounded, terminal-safe decoding for the native Linux lifecycle helper."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast

from tools.remap_linux_schema import (
    DISTRIBUTION_KEYS,
    ERROR_CATEGORIES,
    ERROR_DETAIL_KEYS,
    ERROR_ENVELOPE_KEYS,
    LINK_CANDIDATE_KEYS,
    PREVIEW_DATA_KEYS,
    PUBLICATION_KEYS,
    RECOVERY_DATA_KEYS,
    SERVICE_KEYS,
    STATUS_DATA_KEYS,
    SUCCESS_ENVELOPE_KEYS,
)

APPROVAL_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
GENERATION_PATTERN = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
INTERFACE_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,64}\Z")
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
BOOTSTRAP_DIRECTORY_PATTERN = re.compile(r"/run/remap-bootstrap-[0-9a-f]{32}\Z")
BOOTSTRAP_HELPER_NAME = "remap-linux-system"
MAX_BOOTSTRAP_RESIDUES = 32
MAX_BOOTSTRAP_HELPER_BYTES = 128 * 1024 * 1024
MAX_XATTR_BYTES = 64 * 1024
LINUX_STATE_DIRECTORY = "/var/lib/remap-system"
MAX_STATE_RESIDUE_BYTES = 64 * 1024
STATE_RESIDUE_NAMES = frozenset(
    {
        ".installation.lock",
        ".installation.new",
        ".resolver-activation.lock",
        ".resolver-activation.new",
    }
)
ALLOWED_BOOTSTRAP_XATTRS = frozenset(
    {"security.evm", "security.ima", "security.selinux"}
)
LINK_SELECTION_STATES = frozenset(
    {"inactive", "supported_primary", "supported_secondary", "unsupported"}
)


@dataclass(frozen=True)
class LinkCandidate:
    """One native link that can be selected explicitly for installation."""

    link_index: int
    interface_name: str
    backend: str
    selection_state: str


@dataclass(frozen=True)
class LinuxStatus:
    """Narrow native facts used to select an exact lifecycle request."""

    active_generation_id: str | None
    previous_generation_id: str | None
    link_index: int | None
    owner_uid: int | None
    recovery_required: bool
    installation_state: str
    backend: str | None
    interface_name: str | None
    link_candidates: tuple[LinkCandidate, ...]
    hint: str | None
    distribution_id: str
    distribution_version: str
    resolver_environment: str
    state_residue: LifecycleStateResidue | None = None


@dataclass(frozen=True)
class BootstrapXattr:
    """Bounded identity of one allowlisted Linux extended attribute."""

    name: str
    byte_length: int
    digest: str


@dataclass(frozen=True)
class BootstrapDirectory:
    """Exact root-owned crash-residue directory identity."""

    path: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    xattrs: tuple[BootstrapXattr, ...]


@dataclass(frozen=True)
class BootstrapHelper:
    """Exact immutable helper identity nested in a crash residue."""

    path: str
    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    links: int
    byte_length: int
    sha256: str
    xattrs: tuple[BootstrapXattr, ...]


@dataclass(frozen=True)
class BootstrapResidue:
    """One exact native cleanup candidate bound by recovery approval."""

    directory: BootstrapDirectory
    helper: BootstrapHelper | None


@dataclass(frozen=True)
class StateResidueEntry:
    """Exact interrupted lifecycle state file authorized for removal."""

    path: str
    byte_length: int
    digest: str


@dataclass(frozen=True)
class LifecycleStateResidue:
    """Typed bounded residue inside Remap's native lifecycle state directory."""

    directory: str
    remove_directory: bool
    entries: tuple[StateResidueEntry, ...]


def lifecycle_status(
    document: dict[str, object], command: str = "status"
) -> LinuxStatus:
    """Validate native installation, recovery, link, and backend status."""
    data = success_data(document, command)
    _require_exact_keys(data, STATUS_DATA_KEYS, f"{command} status")
    if data.get("schemaVersion") != 1:
        raise RuntimeError("the Linux helper returned an unsupported status schema")
    active = _optional_generation(data.get("activeGenerationID"))
    previous = _optional_generation(data.get("previousGenerationID"))
    link = _optional_u32(data.get("linkIndex"), "link index")
    owner = _optional_u32(data.get("ownerUID"), "owner UID")
    recovery = data.get("recoveryRequired")
    state = data.get("installationState")
    backend = _optional_identifier(data.get("backend"), "resolver backend")
    interface = _optional_interface(data.get("interfaceName"))
    distribution_id, distribution_version = _distribution(data.get("distribution"))
    resolver_environment = _safe_identifier(
        data.get("resolverEnvironment"), "resolver environment"
    )
    _services(data)
    candidates = _link_candidates(data)
    state_residue = _state_residue(data.get("stateResidue"))
    raw_hint = data.get("hint")
    hint = (
        None if raw_hint is None else _safe_text(raw_hint, "status hint", maximum=512)
    )
    if not isinstance(state, str):
        raise TypeError("the Linux helper returned an invalid installation state")
    if (
        not isinstance(recovery, bool)
        or state not in {"absent", "active", "recovery_required"}
        or (
            state == "absent"
            and any(value is not None for value in (active, link, owner))
        )
        or (state == "active" and any(value is None for value in (active, link, owner)))
        or recovery != (state == "recovery_required")
        or state_residue is not None
        and not recovery
    ):
        raise RuntimeError("the Linux helper returned inconsistent lifecycle status")
    return LinuxStatus(
        active_generation_id=active,
        previous_generation_id=previous,
        link_index=link,
        owner_uid=owner,
        recovery_required=recovery,
        installation_state=state,
        backend=backend,
        interface_name=interface,
        link_candidates=candidates,
        hint=hint,
        distribution_id=distribution_id,
        distribution_version=distribution_version,
        resolver_environment=resolver_environment,
        state_residue=state_residue,
    )


def render_status(status: LinuxStatus) -> str:
    """Render privacy-safe native platform and lifecycle preflight facts."""
    lines = [
        "Linux native preflight",
        (
            "  Distribution: "
            + f"{terminal_text(status.distribution_id)} "
            + terminal_text(status.distribution_version)
        ),
        f"  Resolver environment: {terminal_text(status.resolver_environment)}",
        f"  Installation state: {status.installation_state}",
    ]
    if status.link_index is not None:
        lines.append(
            "  Selected link: "
            + f"{status.link_index} ({status.interface_name or 'unknown'}, "
            + f"{status.backend or 'unknown'})"
        )
    if status.link_candidates:
        lines.append("  Native link candidates:")
        lines.extend(
            "    - "
            + f"{candidate.link_index} ({terminal_text(candidate.interface_name)}, "
            + f"{terminal_text(candidate.backend)}, "
            + f"{terminal_text(candidate.selection_state)})"
            for candidate in status.link_candidates
        )
    if status.hint is not None:
        lines.append(f"  Next: {terminal_text(status.hint)}")
    lines.extend(_render_state_residue(status.state_residue))
    return "\n".join(lines)


def render_preview(document: dict[str, object]) -> str:
    """Render the complete bounded lifecycle preview without terminal controls."""
    data = success_data(document, "preview")
    _require_exact_keys(data, PREVIEW_DATA_KEYS, "lifecycle preview")
    operation = data.get("operation")
    generation = _optional_generation(data.get("generationID"))
    previous = _optional_generation(data.get("previousGenerationID"))
    link = _u32(data.get("linkIndex"), "link index")
    interface = _interface(data.get("interfaceName"))
    backend = _safe_identifier(data.get("backend"), "resolver backend")
    source_manifest = _preview_source_manifest(data, operation)
    environment = _safe_identifier(
        data.get("resolverEnvironment"), "resolver environment"
    )
    publications = _publications(data)
    effects = _effects(data)
    has_effects = data.get("hasEffects")
    if (
        data.get("schemaVersion") != 1
        or operation not in {"install", "update", "uninstall"}
        or not isinstance(has_effects, bool)
        or (operation in {"install", "update"} and generation is None)
        or (operation == "uninstall" and generation is not None)
        or has_effects != bool(publications or effects)
    ):
        raise RuntimeError("the Linux helper returned an invalid lifecycle preview")
    lines = [
        f"Linux {operation} preview",
        f"  Generation: {generation or 'none'}",
        f"  Previous generation: {previous or 'none'}",
        f"  Link: {link} ({terminal_text(interface)})",
        f"  Resolver: {terminal_text(environment)} via {terminal_text(backend)}",
        f"  Reviewed source manifest SHA-256: {source_manifest or 'none'}",
        f"  Public path changes: {len(publications)}",
        *(f"    - {rendered}" for _path, rendered in publications),
        "  Effects:",
        *(f"    - {terminal_text(effect)}" for effect in effects),
        f"  Approval token: {_approval_token(data)}",
    ]
    return "\n".join(lines)


def render_recovery_preview(document: dict[str, object]) -> str:
    """Render every native recovery effect before asking for approval."""
    data = success_data(document, "preview-recovery")
    _require_exact_keys(data, RECOVERY_DATA_KEYS, "recovery preview")
    phase = _optional_identifier(data.get("installationPhase"), "install phase")
    generation = _optional_generation(data.get("generationID"))
    residues = _bootstrap_residues(data.get("bootstrapResidues"))
    state_residue = _state_residue(data.get("stateResidue"))
    effects = _effects(data)
    cleanup_effects = _recovery_cleanup_effects(residues, state_residue)
    has_effects = data.get("hasEffects")
    if (
        data.get("schemaVersion") != 1
        or not isinstance(has_effects, bool)
        or has_effects != bool(effects)
        or bool(residues)
        and not has_effects
        or state_residue is not None
        and not has_effects
        or cleanup_effects
        and effects[-len(cleanup_effects) :] != cleanup_effects
    ):
        raise RuntimeError("the Linux helper returned an invalid recovery preview")
    lines = [
        "Linux recovery preview",
        f"  Installation phase: {phase or 'none'}",
        f"  Generation: {generation or 'none'}",
        f"  Verified bootstrap crash residues: {len(residues)}",
        *(line for residue in residues for line in _render_bootstrap_residue(residue)),
        *_render_state_residue(state_residue),
        "  Effects:",
        *(f"    - {terminal_text(effect)}" for effect in effects),
        f"  Approval token: {_approval_token(data)}",
    ]
    return "\n".join(lines)


def preview_has_effects(document: dict[str, object]) -> bool:
    """Return the validated native has-effects classification."""
    data = success_data(document, "preview")
    _ = render_preview(document)
    value = data.get("hasEffects")
    if not isinstance(value, bool):
        raise TypeError("the Linux helper returned an invalid effect classification")
    return value


def preview_operation(document: dict[str, object]) -> str:
    """Return the validated lifecycle operation named by a preview."""
    data = success_data(document, "preview")
    _ = render_preview(document)
    value = data.get("operation")
    if not isinstance(value, str):
        raise TypeError("the Linux helper returned an invalid lifecycle operation")
    return value


def recovery_has_effects(document: dict[str, object]) -> bool:
    """Return the validated native recovery effect classification."""
    data = success_data(document, "preview-recovery")
    _ = render_recovery_preview(document)
    value = data.get("hasEffects")
    if not isinstance(value, bool):
        raise TypeError("the Linux helper returned an invalid effect classification")
    return value


def approval_token(document: dict[str, object], command: str) -> str:
    """Return one validated canonical state-bound approval token."""
    return _approval_token(success_data(document, command))


def source_manifest_sha256(document: dict[str, object]) -> str | None:
    """Return the validated source digest independently bound by the preview."""
    data = success_data(document, "preview")
    operation = data.get("operation")
    if not isinstance(operation, str):
        raise TypeError("the Linux helper returned an invalid lifecycle operation")
    _ = render_preview(document)
    return _preview_source_manifest(data, operation)


def preview_identity(document: dict[str, object]) -> tuple[str, int]:
    """Return the validated next generation and resolver link for a preview."""
    data = success_data(document, "preview")
    _ = render_preview(document)
    generation = _generation(data.get("generationID"))
    return generation, _u32(data.get("linkIndex"), "link index")


def installed_publication_paths(document: dict[str, object]) -> tuple[str, ...]:
    """Return exact create/repoint paths from a validated lifecycle preview."""
    return _publication_paths_for_actions(document, frozenset({"create", "repoint"}))


def removed_publication_paths(document: dict[str, object]) -> tuple[str, ...]:
    """Return exact removal paths from a validated lifecycle preview."""
    return _publication_paths_for_actions(document, frozenset({"remove"}))


def helper_error(data: bytes, status: int) -> str:
    """Render a bounded structured native failure without terminal controls."""
    try:
        document = decode_document(data, "native Linux helper error")
        _require_exact_keys(document, ERROR_ENVELOPE_KEYS, "error envelope")
        detail = document.get("error")
        if (
            document.get("schemaVersion") != 1
            or document.get("ok") is not False
            or not isinstance(detail, dict)
        ):
            raise ValueError
        error = cast("dict[str, object]", detail)
        _require_exact_keys(error, ERROR_DETAIL_KEYS, "error detail")
        _ = _safe_identifier(document.get("command"), "error command")
        category = _safe_identifier(error.get("category"), "error category")
        if category not in ERROR_CATEGORIES:
            raise ValueError
        message = _safe_text(error.get("message"), "error message", maximum=512)
        hint = error.get("hint")
        rendered = (
            f"native Linux {terminal_text(category)} error: {terminal_text(message)}"
        )
        if hint is not None:
            rendered += "\nNext: " + terminal_text(
                _safe_text(hint, "error hint", maximum=512)
            )
        return rendered
    except (TypeError, UnicodeDecodeError, ValueError, RuntimeError):
        return (
            f"native Linux helper exited with status {status} and no valid diagnostic"
        )


def decode_document(data: bytes, label: str) -> dict[str, object]:
    """Decode one JSON object after the caller enforces the byte bound."""
    try:
        value = cast("object", json.loads(data))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"{label} was not valid bounded JSON") from error
    if not isinstance(value, dict):
        raise TypeError(f"{label} was not a JSON object")
    return cast("dict[str, object]", value)


def success_data(document: dict[str, object], command: str) -> dict[str, object]:
    """Validate one successful helper envelope and return its data object."""
    _require_exact_keys(document, SUCCESS_ENVELOPE_KEYS, f"{command} envelope")
    data = document.get("data")
    if (
        document.get("schemaVersion") != 1
        or document.get("ok") is not True
        or document.get("command") != command
        or not isinstance(data, dict)
    ):
        raise RuntimeError(f"the Linux helper returned an invalid {command} envelope")
    return cast("dict[str, object]", data)


def terminal_text(value: str) -> str:
    """Escape control and bidirectional formatting characters for a terminal."""
    return "".join(
        character
        if character.isprintable()
        and character not in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
        else f"\\u{{{ord(character):04x}}}"
        for character in value
    )


def _publications(data: dict[str, object]) -> list[tuple[str, str]]:
    raw = data.get("publications")
    if not isinstance(raw, list):
        raise TypeError("the Linux helper returned invalid publication changes")
    values = cast("list[object]", raw)
    if len(values) > 64:
        raise RuntimeError("the Linux helper returned invalid publication changes")
    changes = [_publication(value) for value in values]
    paths = [path for path, _rendered in changes]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RuntimeError("the Linux helper returned unordered publication changes")
    return changes


def _publication_paths_for_actions(
    document: dict[str, object], actions: frozenset[str]
) -> tuple[str, ...]:
    _ = render_preview(document)
    raw = success_data(document, "preview").get("publications")
    if not isinstance(raw, list):
        raise TypeError("the Linux helper returned invalid publication changes")
    values = cast("list[object]", raw)
    selected: list[str] = []
    for value in values:
        if not isinstance(value, dict):
            raise TypeError("the Linux helper returned an invalid publication change")
        change = cast("dict[str, object]", value)
        if change.get("action") in actions:
            selected.append(_absolute_path(change.get("path")))
    return tuple(selected)


def _publication(value: object) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise TypeError("the Linux helper returned an invalid publication change")
    change = cast("dict[str, object]", value)
    _require_exact_keys(change, PUBLICATION_KEYS, "publication change")
    path = _absolute_path(change.get("path"))
    action = change.get("action")
    previous = _optional_generation(change.get("previousGenerationID"))
    following = _optional_generation(change.get("nextGenerationID"))
    if action == "create" and previous is None and following is not None:
        rendered = f"create {terminal_text(path)} -> {following}"
    elif action == "remove" and previous is not None and following is None:
        rendered = f"remove {terminal_text(path)} <- {previous}"
    elif action == "repoint" and previous is not None and following is not None:
        rendered = f"repoint {terminal_text(path)}: {previous} -> {following}"
    else:
        raise RuntimeError(
            "the Linux helper returned inconsistent publication ownership"
        )
    return path, rendered


def _bootstrap_residues(value: object) -> tuple[BootstrapResidue, ...]:
    if not isinstance(value, list):
        raise TypeError("the Linux helper returned invalid bootstrap residues")
    values = cast("list[object]", value)
    if len(values) > MAX_BOOTSTRAP_RESIDUES:
        raise TypeError("the Linux helper returned invalid bootstrap residues")
    residues = tuple(_bootstrap_residue(item) for item in values)
    paths = [residue.directory.path for residue in residues]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        raise RuntimeError("the Linux helper returned unordered bootstrap residues")
    return residues


def _bootstrap_residue(value: object) -> BootstrapResidue:
    residue = _object(value, "bootstrap residue")
    _require_exact_keys(
        residue, frozenset({"directory", "helper"}), "bootstrap residue"
    )
    directory = _bootstrap_directory(residue.get("directory"))
    raw_helper = residue.get("helper")
    helper = (
        None
        if raw_helper is None
        else _bootstrap_helper(raw_helper, directory.path, directory.device)
    )
    return BootstrapResidue(directory=directory, helper=helper)


def _bootstrap_directory(value: object) -> BootstrapDirectory:
    directory = _object(value, "bootstrap directory")
    _require_exact_keys(
        directory,
        frozenset(
            {"device", "inode", "mode", "ownerGid", "ownerUid", "path", "xattrs"}
        ),
        "bootstrap directory",
    )
    path = _bootstrap_directory_path(directory.get("path"))
    device = _bounded_integer(directory.get("device"), "device", 0, 2**64 - 1)
    inode = _bounded_integer(directory.get("inode"), "inode", 1, 2**64 - 1)
    mode = _bounded_integer(directory.get("mode"), "mode", 0, 0o7777)
    owner_uid = _bounded_integer(directory.get("ownerUid"), "owner UID", 0, 2**32 - 1)
    owner_gid = _bounded_integer(directory.get("ownerGid"), "owner GID", 0, 2**32 - 1)
    xattrs = _bootstrap_xattrs(directory.get("xattrs"))
    if mode != 0o711 or owner_uid != 0 or owner_gid != 0:
        raise RuntimeError("the Linux helper returned an unsafe bootstrap directory")
    return BootstrapDirectory(
        path=path,
        device=device,
        inode=inode,
        mode=mode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        xattrs=xattrs,
    )


def _bootstrap_helper(
    value: object, directory_path: str, directory_device: int
) -> BootstrapHelper:
    helper = _object(value, "bootstrap helper")
    _require_exact_keys(
        helper,
        frozenset(
            {
                "byteLength",
                "device",
                "inode",
                "links",
                "mode",
                "ownerGid",
                "ownerUid",
                "path",
                "sha256",
                "xattrs",
            }
        ),
        "bootstrap helper",
    )
    path = _absolute_path(helper.get("path"))
    device = _bounded_integer(helper.get("device"), "device", 0, 2**64 - 1)
    inode = _bounded_integer(helper.get("inode"), "inode", 1, 2**64 - 1)
    mode = _bounded_integer(helper.get("mode"), "mode", 0, 0o7777)
    owner_uid = _bounded_integer(helper.get("ownerUid"), "owner UID", 0, 2**32 - 1)
    owner_gid = _bounded_integer(helper.get("ownerGid"), "owner GID", 0, 2**32 - 1)
    links = _bounded_integer(helper.get("links"), "link count", 0, 2**64 - 1)
    byte_length = _bounded_integer(
        helper.get("byteLength"),
        "helper byte length",
        1,
        MAX_BOOTSTRAP_HELPER_BYTES,
    )
    sha256 = helper.get("sha256")
    xattrs = _bootstrap_xattrs(helper.get("xattrs"))
    expected_path = f"{directory_path}/{BOOTSTRAP_HELPER_NAME}"
    if (
        path != expected_path
        or device != directory_device
        or mode != 0o555
        or owner_uid != 0
        or owner_gid != 0
        or links != 1
        or not isinstance(sha256, str)
        or not SHA256_PATTERN.fullmatch(sha256)
    ):
        raise RuntimeError("the Linux helper returned an unsafe bootstrap helper")
    return BootstrapHelper(
        path=path,
        device=device,
        inode=inode,
        mode=mode,
        owner_uid=owner_uid,
        owner_gid=owner_gid,
        links=links,
        byte_length=byte_length,
        sha256=sha256,
        xattrs=xattrs,
    )


def _bootstrap_xattrs(value: object) -> tuple[BootstrapXattr, ...]:
    if not isinstance(value, list):
        raise TypeError("the Linux helper returned invalid bootstrap xattrs")
    values = cast("list[object]", value)
    if len(values) > len(ALLOWED_BOOTSTRAP_XATTRS):
        raise TypeError("the Linux helper returned invalid bootstrap xattrs")
    attributes = tuple(_bootstrap_xattr(item) for item in values)
    names = [attribute.name for attribute in attributes]
    if (
        names != sorted(names)
        or len(names) != len(set(names))
        or not set(names) <= ALLOWED_BOOTSTRAP_XATTRS
    ):
        raise RuntimeError("the Linux helper returned unsafe bootstrap xattrs")
    return attributes


def _bootstrap_xattr(value: object) -> BootstrapXattr:
    attribute = _object(value, "bootstrap xattr")
    _require_exact_keys(
        attribute,
        frozenset({"byteLength", "digest", "name"}),
        "bootstrap xattr",
    )
    name = _safe_identifier(attribute.get("name"), "bootstrap xattr name")
    byte_length = _bounded_integer(
        attribute.get("byteLength"), "xattr byte length", 0, MAX_XATTR_BYTES
    )
    digest = _digest_octets(attribute.get("digest"), "xattr digest")
    return BootstrapXattr(name=name, byte_length=byte_length, digest=digest)


def _state_residue(value: object) -> LifecycleStateResidue | None:
    if value is None:
        return None
    residue = _object(value, "lifecycle state residue")
    _require_exact_keys(
        residue,
        frozenset({"directory", "entries", "removeDirectory"}),
        "lifecycle state residue",
    )
    directory = _absolute_path(residue.get("directory"))
    remove_directory = residue.get("removeDirectory")
    raw_entries = residue.get("entries")
    if (
        directory != LINUX_STATE_DIRECTORY
        or not isinstance(remove_directory, bool)
        or not isinstance(raw_entries, list)
    ):
        raise RuntimeError("the Linux helper returned invalid lifecycle state residue")
    values = cast("list[object]", raw_entries)
    if len(values) > len(STATE_RESIDUE_NAMES):
        raise RuntimeError("the Linux helper returned invalid lifecycle state residue")
    entries = tuple(_state_residue_entry(item, directory) for item in values)
    paths = [entry.path for entry in entries]
    names = [entry.path.rsplit("/", 1)[-1] for entry in entries]
    if (
        paths != sorted(paths)
        or len(paths) != len(set(paths))
        or not entries
        and not remove_directory
        or not remove_directory
        and any(not name.endswith(".new") for name in names)
        or any(
            name.endswith(".lock") and entry.byte_length != 0
            for name, entry in zip(names, entries, strict=True)
        )
    ):
        raise RuntimeError("the Linux helper returned invalid lifecycle state residue")
    return LifecycleStateResidue(
        directory=directory,
        remove_directory=remove_directory,
        entries=entries,
    )


def _state_residue_entry(value: object, directory: str) -> StateResidueEntry:
    entry = _object(value, "lifecycle state residue entry")
    _require_exact_keys(
        entry,
        frozenset({"byteLength", "digest", "path"}),
        "lifecycle state residue entry",
    )
    path = _absolute_path(entry.get("path"))
    name = path.removeprefix(f"{directory}/")
    byte_length = _bounded_integer(
        entry.get("byteLength"),
        "lifecycle state byte length",
        0,
        MAX_STATE_RESIDUE_BYTES,
    )
    digest = _digest_octets(entry.get("digest"), "lifecycle state digest")
    if name not in STATE_RESIDUE_NAMES or path != f"{directory}/{name}":
        raise RuntimeError("the Linux helper returned unsafe lifecycle state residue")
    return StateResidueEntry(path=path, byte_length=byte_length, digest=digest)


def _render_bootstrap_residue(residue: BootstrapResidue) -> tuple[str, ...]:
    directory = residue.directory
    lines = [
        f"    - Directory: {terminal_text(directory.path)}",
        "      Identity: "
        + f"device {directory.device}, inode {directory.inode}, mode {directory.mode:04o}, "
        + f"owner {directory.owner_uid}:{directory.owner_gid}",
        *_render_bootstrap_xattrs(directory.xattrs, "      Directory xattrs"),
    ]
    helper = residue.helper
    if helper is None:
        lines.append("      Helper: none (verified empty crash directory)")
    else:
        lines.extend(
            (
                f"      Helper: {terminal_text(helper.path)}",
                "      Helper identity: "
                + f"device {helper.device}, inode {helper.inode}, mode {helper.mode:04o}, "
                + f"owner {helper.owner_uid}:{helper.owner_gid}, links {helper.links}, "
                + f"bytes {helper.byte_length}",
                f"      Helper SHA-256: {helper.sha256}",
                *_render_bootstrap_xattrs(helper.xattrs, "      Helper xattrs"),
            )
        )
    return tuple(lines)


def _render_bootstrap_xattrs(
    attributes: tuple[BootstrapXattr, ...], label: str
) -> tuple[str, ...]:
    if not attributes:
        return (f"{label}: none",)
    return tuple(
        f"{label}: {attribute.name}, bytes {attribute.byte_length}, "
        + f"SHA-256 {attribute.digest}"
        for attribute in attributes
    )


def _render_state_residue(
    residue: LifecycleStateResidue | None,
) -> tuple[str, ...]:
    if residue is None:
        return ("  Verified interrupted lifecycle state: none",)
    lines = [
        "  Verified interrupted lifecycle state:",
        f"    Directory: {residue.directory}",
        f"    Remove directory: {'yes' if residue.remove_directory else 'no'}",
        f"    Entries: {len(residue.entries)}",
    ]
    lines.extend(
        f"      - {entry.path}, bytes {entry.byte_length}, SHA-256 {entry.digest}"
        for entry in residue.entries
    )
    return tuple(lines)


def _recovery_cleanup_effects(
    residues: tuple[BootstrapResidue, ...],
    state_residue: LifecycleStateResidue | None,
) -> list[str]:
    effects: list[str] = []
    for residue in residues:
        if residue.helper is not None:
            effects.append(f"remove verified bootstrap helper {residue.helper.path}")
        effects.append(f"remove verified bootstrap directory {residue.directory.path}")
    if state_residue is not None:
        effects.append(
            "remove verified interrupted lifecycle state from "
            + state_residue.directory
        )
    return effects


def _effects(data: dict[str, object]) -> list[str]:
    raw = data.get("effects")
    if not isinstance(raw, list):
        raise TypeError("the Linux helper returned invalid lifecycle effects")
    values = cast("list[object]", raw)
    if len(values) > 256:
        raise RuntimeError("the Linux helper returned invalid lifecycle effects")
    effects = [_safe_text(value, "lifecycle effect", maximum=256) for value in values]
    if len(effects) != len(set(effects)):
        raise RuntimeError("the Linux helper returned duplicate lifecycle effects")
    return effects


def _services(data: dict[str, object]) -> None:
    raw = data.get("services")
    if not isinstance(raw, list):
        raise TypeError("the Linux helper returned invalid service status")
    values = cast("list[object]", raw)
    if len(values) > 16:
        raise RuntimeError("the Linux helper returned invalid service status")
    services: list[str] = []
    for item in values:
        if not isinstance(item, dict):
            raise TypeError("the Linux helper returned invalid service status")
        service = cast("dict[str, object]", item)
        _require_exact_keys(service, SERVICE_KEYS, "service status")
        unit = _safe_identifier(service.get("unit"), "systemd unit")
        _ = _safe_identifier(service.get("state"), "systemd unit state")
        services.append(unit)
    if services != sorted(services) or len(services) != len(set(services)):
        raise RuntimeError("the Linux helper returned unordered service status")


def _link_candidates(data: dict[str, object]) -> tuple[LinkCandidate, ...]:
    raw = data.get("linkCandidates")
    if not isinstance(raw, list):
        raise TypeError("the Linux helper returned invalid link candidates")
    values = cast("list[object]", raw)
    if len(values) > 4_096:
        raise RuntimeError("the Linux helper returned invalid link candidates")
    indexes: list[int] = []
    candidates: list[LinkCandidate] = []
    for item in values:
        if not isinstance(item, dict):
            raise TypeError("the Linux helper returned invalid link candidates")
        candidate = cast("dict[str, object]", item)
        _require_exact_keys(candidate, LINK_CANDIDATE_KEYS, "link candidate")
        index = _u32(candidate.get("linkIndex"), "candidate link index")
        interface = _interface(candidate.get("interfaceName"))
        backend = _safe_identifier(
            candidate.get("backend"), "candidate resolver backend"
        )
        state = _safe_identifier(
            candidate.get("selectionState"), "candidate selection state"
        )
        if state not in LINK_SELECTION_STATES:
            raise RuntimeError(
                "the Linux helper returned an invalid candidate selection state"
            )
        indexes.append(index)
        candidates.append(LinkCandidate(index, interface, backend, state))
    if indexes != sorted(indexes) or len(indexes) != len(set(indexes)):
        raise RuntimeError("the Linux helper returned unordered link candidates")
    return tuple(candidates)


def _distribution(value: object) -> tuple[str, str]:
    if not isinstance(value, dict):
        raise TypeError("the Linux helper returned invalid distribution status")
    distribution = cast("dict[str, object]", value)
    _require_exact_keys(distribution, DISTRIBUTION_KEYS, "distribution")
    return (
        _safe_identifier(distribution.get("id"), "distribution identifier"),
        _safe_identifier(distribution.get("versionID"), "distribution version"),
    )


def _approval_token(data: dict[str, object]) -> str:
    value = data.get("approvalToken")
    if not isinstance(value, str) or not APPROVAL_TOKEN_PATTERN.fullmatch(value):
        raise RuntimeError("the Linux helper returned an invalid approval token")
    return value


def _preview_source_manifest(data: dict[str, object], operation: object) -> str | None:
    value = data.get("sourceManifestSHA256")
    if operation in {"install", "update"}:
        if not isinstance(value, str) or not SHA256_PATTERN.fullmatch(value):
            raise RuntimeError(
                "the Linux helper returned an invalid source manifest digest"
            )
        return value
    if operation == "uninstall" and value is None:
        return None
    raise RuntimeError("the Linux helper returned an invalid source manifest digest")


def _absolute_path(value: object) -> str:
    path = _safe_text(value, "publication path", maximum=1_024)
    components = path.split("/")
    if (
        not path.startswith("/")
        or path != "/"
        and (
            path.endswith("/")
            or any(part in {"", ".", ".."} for part in components[1:])
        )
    ):
        raise RuntimeError("the Linux helper returned an unsafe publication path")
    return path


def _bootstrap_directory_path(value: object) -> str:
    path = _absolute_path(value)
    if not BOOTSTRAP_DIRECTORY_PATTERN.fullmatch(path):
        raise RuntimeError("the Linux helper returned an unsafe bootstrap path")
    return path


def _object(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"the Linux helper returned an invalid {label}")
    return cast("dict[str, object]", value)


def _require_exact_keys(
    value: dict[str, object], expected: frozenset[str], label: str
) -> None:
    if frozenset(value) != expected:
        raise RuntimeError(f"the Linux helper returned an incompatible {label}")


def _bounded_integer(value: object, label: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise RuntimeError(f"the Linux helper returned an invalid {label}")
    return value


def _digest_octets(value: object, label: str) -> str:
    if not isinstance(value, list):
        raise TypeError(f"the Linux helper returned an invalid {label}")
    values = cast("list[object]", value)
    if len(values) != 32:
        raise RuntimeError(f"the Linux helper returned an invalid {label}")
    return bytes(
        _bounded_integer(item, f"{label} byte", 0, 255) for item in values
    ).hex()


def _generation(value: object) -> str:
    if not isinstance(value, str) or not GENERATION_PATTERN.fullmatch(value):
        raise RuntimeError("the Linux helper returned an invalid generation identity")
    return value


def _optional_generation(value: object) -> str | None:
    return None if value is None else _generation(value)


def _interface(value: object) -> str:
    if not isinstance(value, str) or not INTERFACE_PATTERN.fullmatch(value):
        raise RuntimeError("the Linux helper returned an invalid interface name")
    return value


def _optional_interface(value: object) -> str | None:
    return None if value is None else _interface(value)


def _safe_identifier(value: object, label: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_PATTERN.fullmatch(value):
        raise RuntimeError(f"the Linux helper returned an invalid {label}")
    return value


def _optional_identifier(value: object, label: str) -> str | None:
    return None if value is None else _safe_identifier(value, label)


def _safe_text(value: object, label: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value.encode("utf-8")) > maximum:
        raise RuntimeError(f"the Linux helper returned an invalid {label}")
    return value


def _u32(value: object, label: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 1 <= value <= 4_294_967_295
    ):
        raise RuntimeError(f"the Linux helper returned an invalid {label}")
    return value


def _optional_u32(value: object, label: str) -> int | None:
    return None if value is None else _u32(value, label)
