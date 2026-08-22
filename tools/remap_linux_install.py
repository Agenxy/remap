"""Build and orchestrate Remap's native Linux source lifecycle."""

from __future__ import annotations

import grp
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from tools.remap_lifecycle_approval import confirm_approval
from tools.remap_linux_bootstrap import (
    BOOTSTRAP_HELPER_NAME,
    SUDO,
    TrustedHelper,
    bootstrap_helper,
    capture_trusted_helper,
    open_verified_helper,
    verify_bootstrap_environment,
    verify_pinned_helper,
    verify_root_owned_ancestry,
)
from tools.remap_linux_protocol import (
    LinuxStatus,
    approval_token,
    decode_document,
    helper_error,
    installed_publication_paths,
    lifecycle_status,
    preview_has_effects,
    preview_identity,
    preview_operation,
    recovery_has_effects,
    removed_publication_paths,
    render_preview,
    render_recovery_preview,
    render_status,
    source_manifest_sha256,
    terminal_text,
)
from tools.remap_linux_sources import PinnedSourceManifest, pin_source_manifest

SYSTEM_CLI = Path("/usr/bin/remap")
SYSTEM_PRODUCT_ROOT = Path("/usr/libexec/remap")
SYSTEM_GENERATION_ROOT = Path("/usr/libexec/remap/generations")
SYSTEM_CURRENT = Path("/usr/libexec/remap/current")
SYSTEM_STATE = Path("/var/lib/remap-system")
SYSTEM_MAN_DIRECTORY = Path("/usr/share/man/man1")
SYSTEM_POLICY_DIRECTORY = Path("/usr/share/doc/remap")
SYSTEM_COMPLETIONS = {
    "bash": Path("/usr/share/bash-completion/completions/remap"),
    "fish": Path("/usr/share/fish/vendor_completions.d/remap.fish"),
    "zsh": Path("/usr/share/zsh/site-functions/_remap"),
}
SYSTEM_UNITS = tuple(
    Path("/etc/systemd/system") / name
    for name in (
        "remap-resolver.service",
        "remapd-dns-tcp.socket",
        "remapd-dns-udp.socket",
        "remapd-http.socket",
        "remapd.service",
    )
)
MANPAGE_NAMES = (
    "remap-apply.1",
    "remap-completions.1",
    "remap-daemon.1",
    "remap-disable.1",
    "remap-doctor.1",
    "remap-enable.1",
    "remap-get.1",
    "remap-list.1",
    "remap-manpage.1",
    "remap-manpages.1",
    "remap-mcp.1",
    "remap-preview.1",
    "remap-remove.1",
    "remap-resolve.1",
    "remap-set.1",
    "remap-status.1",
    "remap-system-recover.1",
    "remap-system-status.1",
    "remap-system-uninstall.1",
    "remap-system.1",
    "remap-validate.1",
    "remap.1",
)
MAX_HELPER_OUTPUT_BYTES = 1_048_576
HELPER_TIMEOUT_SECONDS = 120


@dataclass(frozen=True)
class NativeAccount:
    """The invoking non-root account represented by a host-wide install."""

    name: str
    group: str
    uid: int


@dataclass(frozen=True)
class LinuxBuild:
    """Owner-only source inputs consumed by the native root helper."""

    cli: Path
    daemon: Path
    helper: Path
    assets: Path


def require_linux() -> None:
    """Reject Linux lifecycle work on unsupported hosts."""
    if sys.platform != "linux":
        raise RuntimeError("native Linux installation is available only on Linux")


def require_linux_bootstrap() -> None:
    """Check the narrow source-bootstrap prerequisites without changing state."""
    require_linux()
    verify_bootstrap_environment()
    _ = native_account()


def native_account() -> NativeAccount:
    """Return the real non-root account that will own host-wide Remap state."""
    uid = os.getuid()
    if uid == 0:
        raise RuntimeError(
            "run the native Linux workflow from a non-root account; it requests "
            + "administrator authorization at the native helper boundary"
        )
    account = pwd.getpwuid(uid)
    group = grp.getgrgid(account.pw_gid)
    if not account.pw_name or not group.gr_name:
        raise RuntimeError("the invoking Linux account has no canonical name or group")
    return NativeAccount(name=account.pw_name, group=group.gr_name, uid=uid)


def require_public_command_slot() -> None:
    """Reject a shell path that would hide the native Linux command."""
    selected = shutil.which("remap")
    if selected is None or Path(selected) == SYSTEM_CLI:
        return
    raise RuntimeError(
        f"PATH currently selects {terminal_text(selected)}, which would shadow "
        + f"{SYSTEM_CLI}. "
        + "Remove that CLI-only installation with 'make uninstall-cli' or place "
        + "/usr/bin first, then retry. No system state changed."
    )


def configured_link(status: LinuxStatus | None = None) -> int:
    """Parse one explicit Linux resolver-link index from the public workflow."""
    raw = os.environ.get("REMAP_LINUX_LINK", "")
    primary = (
        tuple(
            candidate
            for candidate in status.link_candidates
            if candidate.selection_state == "supported_primary"
        )
        if status is not None
        else ()
    )
    if not raw and len(primary) == 1:
        return primary[0].link_index
    try:
        value = int(raw, 10)
    except ValueError as error:
        raise RuntimeError(_link_selection_error(status)) from error
    if not 1 <= value <= 4_294_967_295 or str(value) != raw:
        raise RuntimeError(_link_selection_error(status))
    if (
        status is not None
        and status.link_candidates
        and value not in {candidate.link_index for candidate in status.link_candidates}
    ):
        raise RuntimeError(_link_selection_error(status))
    return value


def build_native_products(root: Path, staging: Path) -> LinuxBuild:
    """Build and stage every owner-only input consumed by a Linux generation."""
    _run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "remap",
            "-p",
            "remapd",
            "-p",
            "remap-linux-system",
        ),
        root,
    )
    release = _cargo_target_directory(root) / "release"
    products = staging / "products"
    products.mkdir(mode=0o700)
    cli = _copy_source(release / "remap", products / "remap")
    daemon = _copy_source(release / "remapd", products / "remapd")
    helper = _copy_source(
        release / "remap-linux-system",
        products / "remap-linux-system",
    )
    assets = products / "assets"
    assets.mkdir(mode=0o700)
    manpages = assets / "manpages"
    _run((str(cli), "manpages", str(manpages)), root)
    if tuple(path.name for path in sorted(manpages.glob("*.1"))) != MANPAGE_NAMES:
        raise RuntimeError("the CLI did not generate its exact 22-page manual family")
    for path in manpages.iterdir():
        path.chmod(0o400)
    for shell in ("bash", "fish", "zsh"):
        _write_output((str(cli), "completions", shell), assets / f"remap.{shell}", root)
    _copy_asset(root / "LICENSE", assets / "LICENSE")
    _copy_asset(root / "NOTICE", assets / "NOTICE")
    _run((str(cli), "--version"), root)
    return LinuxBuild(cli=cli, daemon=daemon, helper=helper, assets=assets)


def build_native_helper(root: Path, staging: Path) -> Path:
    """Build only the reviewed root helper used for status and removal."""
    _run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "remap-linux-system",
        ),
        root,
    )
    return _copy_source(
        _cargo_target_directory(root) / "release/remap-linux-system",
        staging / "remap-linux-system",
    )


def _cargo_target_directory(root: Path) -> Path:
    """Resolve Cargo's configured output root without assuming repo-local state."""
    configured = os.environ.get("CARGO_TARGET_DIR")
    if configured is None:
        return root / "target"
    if not configured or "\x00" in configured:
        raise RuntimeError("CARGO_TARGET_DIR must identify one non-empty path")
    candidate = Path(configured)
    return candidate if candidate.is_absolute() else root / candidate


def install_or_update(root: Path, version: str, operation: str) -> None:
    """Preview, approve, commit, and independently verify one Linux generation."""
    require_linux_bootstrap()
    if operation not in {"install", "update"}:
        raise ValueError("native Linux lifecycle operation must be install or update")
    require_public_command_slot()
    account = native_account()
    with tempfile.TemporaryDirectory(prefix="remap-linux-source-") as directory:
        build = build_native_products(root, Path(directory))
        authorize_administrator(root)
        with (
            pin_source_manifest(
                cli=build.cli,
                daemon=build.daemon,
                helper=build.helper,
                assets=build.assets,
                manpage_names=MANPAGE_NAMES,
                owner_uid=account.uid,
            ) as sources,
            bootstrap_helper(root, build.helper, account.uid) as bootstrap,
        ):
            status = lifecycle_status(
                helper_json(root, bootstrap, ("status",), source_manifest=sources)
            )
            print(render_status(status))
            _require_recovered_state(status)
            link = _operation_link(operation, status)
            arguments = _install_arguments(build, account, link, sources.sha256)
            helper = _selected_helper(status, bootstrap)
            preview = helper_json(
                root,
                helper,
                ("preview", operation, *arguments),
                source_manifest=sources,
            )
            print(render_preview(preview))
            if preview_operation(preview) != operation:
                raise RuntimeError(
                    "the native Linux preview operation differs from the request"
                )
            if source_manifest_sha256(preview) != sources.sha256:
                raise RuntimeError(
                    "the native Linux preview differs from the reviewed source manifest"
                )
            generation, preview_link = preview_identity(preview)
            if not preview_has_effects(preview):
                final = lifecycle_status(
                    helper_json(root, bootstrap, ("status",), source_manifest=sources)
                )
                if (
                    final.installation_state != "active"
                    or final.recovery_required
                    or final.active_generation_id != generation
                    or final.link_index != preview_link
                    or final.state_residue is not None
                ):
                    raise RuntimeError(
                        "the native Linux state changed after the no-op preview; "
                        + "request a fresh lifecycle preview"
                    )
                verify_installed_product(root, version, final)
                print(
                    "Remap already matches the reviewed Linux generation. No state changed."
                )
                return
            token = confirm_approval(approval_token(preview, "preview"), operation)
            committed = helper_json(
                root,
                helper,
                (operation, *arguments, "--approval-token", token),
                source_manifest=sources,
            )
            _ = lifecycle_status(committed, operation)
            final = lifecycle_status(
                helper_json(root, bootstrap, ("status",), source_manifest=sources)
            )
            if (
                final.active_generation_id != generation
                or final.link_index != preview_link
            ):
                raise RuntimeError(
                    "the committed Linux generation differs from the approved preview"
                )
            verify_installed_product(
                root, version, final, installed_publication_paths(preview)
            )
    print(f"{operation.capitalize()} committed and verified on Linux.")


def recover(root: Path) -> None:
    """Preview and explicitly converge interrupted Linux lifecycle state."""
    require_linux_bootstrap()
    with tempfile.TemporaryDirectory(prefix="remap-linux-recover-") as directory:
        source = build_native_helper(root, Path(directory))
        authorize_administrator(root)
        with bootstrap_helper(root, source, native_account().uid) as bootstrap:
            status = lifecycle_status(helper_json(root, bootstrap, ("status",)))
            print(render_status(status))
            if not status.recovery_required:
                print("No Linux lifecycle recovery is required. No state changed.")
                return
            preview = helper_json(root, bootstrap, ("preview", "recover", "--all"))
            print(render_recovery_preview(preview))
            if not recovery_has_effects(preview):
                raise RuntimeError("native Linux recovery omitted its required effects")
            token = confirm_approval(
                approval_token(preview, "preview-recovery"), "recover"
            )
            committed = helper_json(
                root,
                bootstrap,
                ("recover", "--all", "--approval-token", token),
            )
            _ = lifecycle_status(committed, "recover")
            final = lifecycle_status(helper_json(root, bootstrap, ("status",)))
            if final.recovery_required:
                raise RuntimeError(
                    "native Linux recovery left unfinished lifecycle state"
                )
    print("Linux lifecycle recovery completed and was independently verified.")


def uninstall(root: Path) -> None:
    """Preview, remove, and verify only native Linux manifest-owned state."""
    require_linux_bootstrap()
    with tempfile.TemporaryDirectory(prefix="remap-linux-remove-") as directory:
        source = build_native_helper(root, Path(directory))
        authorize_administrator(root)
        with bootstrap_helper(root, source, native_account().uid) as bootstrap:
            status = lifecycle_status(helper_json(root, bootstrap, ("status",)))
            print(render_status(status))
            _require_recovered_state(status)
            if status.active_generation_id is None:
                verify_uninstalled(status)
                print("Remap is not installed. User mappings were not changed.")
                return
            preview = helper_json(root, bootstrap, ("preview", "uninstall"))
            print(render_preview(preview))
            if preview_operation(preview) != "uninstall":
                raise RuntimeError(
                    "the native Linux preview operation differs from the request"
                )
            removed_paths = removed_publication_paths(preview)
            token = confirm_approval(approval_token(preview, "preview"), "uninstall")
            committed = helper_json(
                root, bootstrap, ("uninstall", "--approval-token", token)
            )
            _ = lifecycle_status(committed, "uninstall")
            final = lifecycle_status(helper_json(root, bootstrap, ("status",)))
            verify_uninstalled(final, removed_paths)
    print("Remap was removed, resolver state was restored, and mappings remain.")


def authorize_administrator(root: Path) -> None:
    """Acquire one visible, time-limited sudo authorization ticket."""
    _run((str(SUDO), "-v"), root)


def _selected_helper(status: LinuxStatus, bootstrap: TrustedHelper) -> TrustedHelper:
    generation = status.active_generation_id
    if generation is None:
        return bootstrap
    installed_path = SYSTEM_GENERATION_ROOT / generation / BOOTSTRAP_HELPER_NAME
    verify_root_owned_ancestry(installed_path.parent)
    installed = capture_trusted_helper(
        installed_path, expected_digest=None, expected_mode=0o755
    )
    if installed.identity.digest == bootstrap.identity.digest:
        return installed
    print(
        "The installed generation uses a different native helper; this source "
        + "workflow will use the newly reviewed root-owned bootstrap helper."
    )
    return bootstrap


def helper_json(
    root: Path,
    helper: object,
    arguments: Sequence[str],
    *,
    source_manifest: PinnedSourceManifest | None = None,
) -> dict[str, object]:
    """Run one bounded structured native-root helper exchange."""
    if not isinstance(helper, TrustedHelper):
        raise TypeError(
            "native Linux helper execution requires a pinned trusted helper"
        )
    if source_manifest is not None:
        source_manifest.verify()
    with open_verified_helper(helper):
        command = (
            str(SUDO),
            "-n",
            "--",
            str(helper.path),
            *arguments,
            "--json",
        )
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            try:
                result = subprocess.run(
                    command,
                    cwd=root,
                    stdout=output,
                    stderr=errors,
                    check=False,
                    timeout=HELPER_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired as error:
                message = (
                    "the native Linux helper timed out; the outcome is unknown and "
                    "must be inspected with 'make recover'"
                )
                raise RuntimeError(message) from error
            verify_pinned_helper(helper)
            if source_manifest is not None:
                source_manifest.verify()
            stdout = _bounded_file(output, "Linux helper output")
            stderr = _bounded_file(errors, "Linux helper diagnostic")
    if result.returncode != 0:
        raise RuntimeError(helper_error(stderr, result.returncode))
    if stderr:
        raise RuntimeError("the native Linux helper wrote an unexpected diagnostic")
    return decode_document(stdout, "native Linux helper result")


def verify_installed_product(
    root: Path,
    version: str,
    status: LinuxStatus,
    expected_publications: Sequence[str] = (),
) -> None:
    """Prove command discovery, assets, and authenticated native runtime health."""
    if status.active_generation_id is None or status.recovery_required:
        raise RuntimeError("native Linux status does not identify a healthy generation")
    if not SYSTEM_CLI.is_file() or not os.access(SYSTEM_CLI, os.X_OK):
        raise RuntimeError("the Linux transaction did not publish /usr/bin/remap")
    if _capture((str(SYSTEM_CLI), "--version"), root) != f"remap {version}":
        raise RuntimeError("the installed Linux command reports the wrong version")
    selected = shutil.which("remap", path="/usr/bin:/bin:/usr/sbin:/sbin")
    if selected != str(SYSTEM_CLI):
        raise RuntimeError("a clean Linux shell does not select /usr/bin/remap")
    for publication in expected_publications:
        path = Path(publication)
        if not path.exists() and not path.is_symlink():
            raise RuntimeError(
                f"the Linux transaction did not publish the approved path {path}"
            )
    verify_installed_assets(root)
    verify_doctor(_json_command((str(SYSTEM_CLI), "--json", "doctor"), root), version)


def verify_installed_assets(root: Path) -> None:
    """Compare installed manuals, completions, and policy text byte for byte."""
    with tempfile.TemporaryDirectory(prefix="remap-linux-assets-") as directory:
        destination = Path(directory)
        manpages = destination / "manpages"
        _run((str(SYSTEM_CLI), "manpages", str(manpages)), root)
        for name in MANPAGE_NAMES:
            _require_exact(manpages / name, SYSTEM_MAN_DIRECTORY / name)
        for shell, installed in SYSTEM_COMPLETIONS.items():
            expected = destination / f"remap.{shell}"
            _write_output((str(SYSTEM_CLI), "completions", shell), expected, root)
            _require_exact(expected, installed)
    _require_exact(root / "LICENSE", SYSTEM_POLICY_DIRECTORY / "LICENSE")
    _require_exact(root / "NOTICE", SYSTEM_POLICY_DIRECTORY / "NOTICE")


def verify_uninstalled(
    status: LinuxStatus, expected_absent: Sequence[str] = ()
) -> None:
    """Require every manifest-owned Linux lifecycle artifact to be absent."""
    if status.active_generation_id is not None or status.recovery_required:
        raise RuntimeError("native Linux uninstall left active or recoverable state")
    paths = (
        SYSTEM_CLI,
        SYSTEM_CURRENT,
        SYSTEM_GENERATION_ROOT,
        SYSTEM_PRODUCT_ROOT,
        SYSTEM_STATE,
        SYSTEM_POLICY_DIRECTORY,
        SYSTEM_POLICY_DIRECTORY / "LICENSE",
        SYSTEM_POLICY_DIRECTORY / "NOTICE",
        *(SYSTEM_MAN_DIRECTORY / name for name in MANPAGE_NAMES),
        *SYSTEM_COMPLETIONS.values(),
        *SYSTEM_UNITS,
        *(Path(path) for path in expected_absent),
    )
    for path in paths:
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"native Linux uninstall left the owned path {path}")


def _operation_link(operation: str, status: LinuxStatus) -> int:
    if operation == "install":
        if status.active_generation_id is not None:
            raise RuntimeError("Remap is already installed; run 'make update' instead")
        return configured_link(status)
    if status.active_generation_id is None or status.link_index is None:
        raise RuntimeError("Remap is not installed; run 'make install' instead")
    return status.link_index


def _require_recovered_state(status: LinuxStatus) -> None:
    if status.recovery_required:
        raise RuntimeError(
            "Remap has unfinished Linux lifecycle work. Run 'make recover', "
            + "review its separate preview, approve it, and retry."
        )


def _link_selection_error(status: LinuxStatus | None) -> str:
    message = (
        "Remap could not select one unambiguous native DNS link. Set "
        + "REMAP_LINUX_LINK to the numeric interface index shown below, for example "
        + "REMAP_LINUX_LINK=2 make install."
    )
    if status is None:
        return message
    if status.link_candidates:
        candidates = ", ".join(
            f"{item.link_index} ({terminal_text(item.interface_name)}, "
            + f"{terminal_text(item.backend)}, {terminal_text(item.selection_state)})"
            for item in status.link_candidates
        )
        message += f" Native candidates: {candidates}."
    if status.hint is not None:
        message += f" Next: {terminal_text(status.hint)}"
    return message


def _install_arguments(
    build: LinuxBuild, account: NativeAccount, link: int, source_manifest: str
) -> tuple[str, ...]:
    return (
        "--remap-source",
        str(build.cli.resolve(strict=True)),
        "--remapd-source",
        str(build.daemon.resolve(strict=True)),
        "--system-source",
        str(build.helper.resolve(strict=True)),
        "--assets-source",
        str(build.assets.resolve(strict=True)),
        "--source-manifest-sha256",
        source_manifest,
        "--account",
        account.name,
        "--group",
        account.group,
        "--owner-uid",
        str(account.uid),
        "--link",
        str(link),
    )


def _copy_source(source: Path, destination: Path) -> Path:
    if not source.is_file() or not os.access(source, os.X_OK):
        raise RuntimeError(f"the native Linux build did not produce {source}")
    _ = shutil.copyfile(source, destination)
    destination.chmod(0o500)
    return destination


def _copy_asset(source: Path, destination: Path) -> None:
    _ = shutil.copyfile(source, destination)
    destination.chmod(0o400)


def _write_output(arguments: Sequence[str], destination: Path, root: Path) -> None:
    with destination.open("xb") as output:
        _ = subprocess.run(arguments, cwd=root, stdout=output, check=True)
    destination.chmod(0o400)


def _require_exact(expected: Path, installed: Path) -> None:
    if not installed.is_file():
        raise RuntimeError(f"the native Linux install did not publish {installed}")
    if expected.read_bytes() != installed.read_bytes():
        raise RuntimeError(f"the installed Linux asset differs from {expected.name}")


def verify_doctor(document: dict[str, object], version: str) -> None:
    """Require the installed CLI to prove complete authenticated readiness."""
    result = document.get("result")
    if not isinstance(result, dict):
        raise TypeError("the installed Linux doctor omitted its result")
    data = cast("dict[str, object]", result)
    if (
        document.get("schema") != "remap.cli/v1"
        or document.get("ok") is not True
        or document.get("command") != "doctor"
        or data.get("version") != version
        or data.get("native_install") is not True
        or data.get("dns_listener") is not True
        or data.get("http_gateway") is not True
        or data.get("telemetry") != "none"
        or not isinstance(data.get("revision"), int)
        or isinstance(data.get("revision"), bool)
    ):
        raise RuntimeError("the installed Linux runtime did not prove full readiness")


def _bounded_file(handle: BinaryIO, label: str) -> bytes:
    _ = handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError(f"{label} exceeded {MAX_HELPER_OUTPUT_BYTES} bytes")
    _ = handle.seek(0)
    return handle.read()


def _capture(arguments: Sequence[str], root: Path) -> str:
    result = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    if len(result.stdout.encode("utf-8")) > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError("native Linux command output exceeded its bound")
    return result.stdout.strip()


def _json_command(arguments: Sequence[str], root: Path) -> dict[str, object]:
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        result = subprocess.run(
            arguments,
            cwd=root,
            stdout=output,
            stderr=errors,
            check=False,
            timeout=HELPER_TIMEOUT_SECONDS,
        )
        stdout = _bounded_file(output, "installed command output")
        stderr = _bounded_file(errors, "installed command diagnostic")
    if result.returncode != 0:
        raise RuntimeError(
            f"the installed command exited with status {result.returncode}: "
            + stderr.decode("utf-8", errors="replace")
        )
    if stderr:
        raise RuntimeError("the installed command wrote an unexpected diagnostic")
    return decode_document(stdout, "installed command result")


def _run(arguments: Sequence[str], root: Path) -> None:
    _ = subprocess.run(arguments, cwd=root, check=True)
