"""Build and orchestrate Remap's transactional native macOS source install."""

from __future__ import annotations

import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, cast

from tools.remap_app import build as build_native_app
from tools.remap_app import verify as verify_native_app
from tools.remap_freshness import verify_selected_xcode
from tools.remap_lifecycle_approval import confirm_approval
from tools.remap_macos_artifact import (
    expected_macos_sdk,
    normalize_macos_sdk_metadata,
)
from tools.remap_macos_bootstrap import (
    BOOTSTRAP_IDENTIFIER,
    bootstrap_helper,
)
from tools.remap_macos_protocol import (
    InstallerStatus,
    approval_token,
    bootstrap_recovery_has_effects,
    decode_document,
    installer_error,
    installer_status,
    is_exact_update,
    recovery_has_effects,
    render_bootstrap_recovery_preview,
    render_preview,
    render_recovery_preview,
    resolver_upstreams,
    terminal_text,
)
from tools.remap_macos_signing import (
    LocalCodeSigningIdentity,
    ensure_local_codesigning_identity,
    sign_path,
    sign_paths,
)
from tools.remap_native_package import (
    DAEMON_LABEL,
    GENERATIONS_ROOT,
    INSTALL_ROOT,
    MANPAGE_NAMES,
    RESOLVER_LABEL,
    NativePackage,
    NativeProductFiles,
    assemble,
)

SYSTEM_CLI = Path("/usr/local/bin/remap")
SYSTEM_APP = Path("/Applications/Remap.app")
SYSTEM_MAN_DIRECTORY = Path("/usr/local/share/man/man1")
SYSTEM_POLICY_DIRECTORY = Path("/usr/local/share/licenses/remap")
SYSTEM_COMPLETIONS = {
    "bash": Path("/usr/local/share/bash-completion/completions/remap"),
    "fish": Path("/usr/local/share/fish/vendor_completions.d/remap.fish"),
    "zsh": Path("/usr/local/share/zsh/site-functions/_remap"),
}
SYSTEM_PUBLIC_DIRECTORIES = (
    Path("/usr/local"),
    Path("/usr/local/bin"),
    Path("/usr/local/share"),
    Path("/usr/local/share/bash-completion"),
    Path("/usr/local/share/bash-completion/completions"),
    Path("/usr/local/share/fish"),
    Path("/usr/local/share/fish/vendor_completions.d"),
    Path("/usr/local/share/licenses"),
    SYSTEM_POLICY_DIRECTORY,
    Path("/usr/local/share/man"),
    SYSTEM_MAN_DIRECTORY,
    Path("/usr/local/share/zsh"),
    Path("/usr/local/share/zsh/site-functions"),
)
MAX_HELPER_OUTPUT_BYTES = 1_048_576
HELPER_TIMEOUT_SECONDS = 120
CDHASH_PATTERN = re.compile(r"[0-9a-f]{40,64}\Z")


@dataclass(frozen=True)
class NativeBuild:
    """Reviewed, durably self-signed inputs for one package generation."""

    files: NativeProductFiles
    installer_cdhash: str
    installer_bootstrap: Path | None = None
    installer_bootstrap_cdhash: str | None = None
    installer_service: Path | None = None
    installer_service_cdhash: str | None = None


def require_macos() -> None:
    """Reject native lifecycle work on unsupported hosts."""
    if sys.platform != "darwin":
        raise RuntimeError("native source installation is currently available on macOS")


def require_public_command_slot() -> None:
    """Fail before mutation when another command would shadow the native CLI."""
    selected = shutil.which("remap")
    if selected is None or Path(selected) == SYSTEM_CLI:
        return
    safe = terminal_text(selected)
    detail = f"PATH currently selects {safe}, which would shadow {SYSTEM_CLI}. "
    action = (
        "Remove that CLI-only installation with 'make uninstall-cli' or place "
        + "/usr/local/bin first, then retry. No system state changed."
    )
    raise RuntimeError(detail + action)


def native_user() -> pwd.struct_passwd:
    """Return the real non-root account that will own the Remap authority."""
    account = pwd.getpwuid(os.getuid())
    if account.pw_uid == 0 or not account.pw_name or not account.pw_dir:
        raise RuntimeError("native installation requires a real non-root account")
    return account


def build_native_products(root: Path, version: str, staging: Path) -> NativeBuild:
    """Build, sign, and generate every input consumed by the native package."""
    verify_selected_xcode()
    signing_identity = ensure_local_codesigning_identity()
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
        ),
        root=root,
    )
    _run(
        (
            "xcrun",
            "swift",
            "build",
            "--configuration",
            "release",
            "--package-path",
            "platforms/macos",
        ),
        root=root,
    )
    swift_bin = Path(
        _capture(
            (
                "xcrun",
                "swift",
                "build",
                "--show-bin-path",
                "--configuration",
                "release",
                "--package-path",
                "platforms/macos",
            ),
            root=root,
        )
    )
    swift_executables = tuple(
        swift_bin / name
        for name in (
            "remap-install",
            "remap-installer-service",
            "remap-installer-bootstrap",
            "remap-resolver",
            "remap-system",
        )
    )
    normalize_macos_sdk_metadata(
        swift_executables,
        expected_sdk=expected_macos_sdk(root),
        minimum_macos="15.0",
    )
    products = staging / "products"
    products.mkdir(mode=0o700)
    signing_directory = products / "signing"
    signing_directory.mkdir(mode=0o700)
    cli_staging = _unsigned_copy(
        root / "target/release/remap",
        signing_directory / "cli",
    )
    daemon_staging = _unsigned_copy(
        root / "target/release/remapd",
        signing_directory / "daemon",
    )
    installer_staging = _unsigned_copy(
        swift_bin / "remap-install",
        signing_directory / "install-bootstrap",
    )
    installer_service_staging = _unsigned_copy(
        swift_bin / "remap-installer-service",
        signing_directory / "installer-service",
    )
    installer_bootstrap_staging = _unsigned_copy(
        swift_bin / "remap-installer-bootstrap",
        signing_directory / "installer-bootstrap",
    )
    resolver_staging = _unsigned_copy(
        swift_bin / "remap-resolver",
        signing_directory / "resolver",
    )
    system_staging = _unsigned_copy(
        swift_bin / "remap-system",
        signing_directory / "system",
    )
    app = build_native_app(
        root,
        version,
        release=True,
        signing_identity=signing_identity,
        sign=False,
    )
    sign_paths(
        (
            cli_staging,
            daemon_staging,
            installer_staging,
            installer_bootstrap_staging,
            installer_service_staging,
            resolver_staging,
            system_staging,
            app,
        ),
        signing_identity,
        identifier_prefix="org.agenxy.Remap.",
    )
    cli = _finalize_signed_copy(cli_staging, products / "remap", "org.agenxy.Remap.cli")
    daemon = _finalize_signed_copy(
        daemon_staging, products / "remapd", "org.agenxy.Remap.daemon"
    )
    installer = _finalize_signed_copy(
        installer_staging, products / "remap-install", BOOTSTRAP_IDENTIFIER
    )
    installer_service = _finalize_signed_copy(
        installer_service_staging,
        products / "remap-installer-service",
        "org.agenxy.Remap.installer-service",
    )
    installer_bootstrap = _finalize_signed_copy(
        installer_bootstrap_staging,
        products / "remap-installer-bootstrap",
        "org.agenxy.Remap.installer-bootstrap",
    )
    resolver = _finalize_signed_copy(
        resolver_staging, products / "remap-resolver", "org.agenxy.Remap.resolver"
    )
    system_tool = _finalize_signed_copy(
        system_staging, products / "remap-system", "org.agenxy.Remap.system"
    )
    verify_native_app(root, app, signing_identity)
    manpages = products / "manpages"
    _run((str(cli), "manpages", str(manpages)), root=root)
    if len(tuple(manpages.glob("*.1"))) != 22:
        raise RuntimeError("the CLI did not generate its complete 22-page manual")
    completions = {
        shell: _write_output(
            (str(cli), "completions", shell),
            products / f"remap.{shell}",
            root,
        )
        for shell in ("bash", "fish", "zsh")
    }
    files = NativeProductFiles(
        app=app,
        cli=cli,
        daemon=daemon,
        installer=installer,
        resolver=resolver,
        system_tool=system_tool,
        manpages=manpages,
        completions=completions,
        license=root / "LICENSE",
        notice=root / "NOTICE",
        signing_certificate_sha256=signing_identity.sha256.lower(),
    )
    _run((str(cli), "--version"), root=root)
    return NativeBuild(
        files=files,
        installer_cdhash=_verified_code_identity(installer)[1],
        installer_bootstrap=installer_bootstrap,
        installer_bootstrap_cdhash=_verified_code_identity(installer_bootstrap)[1],
        installer_service=installer_service,
        installer_service_cdhash=_verified_code_identity(installer_service)[1],
    )


def build_installer(root: Path, staging: Path) -> tuple[Path, str]:
    """Build only the reviewed recovery helper needed for removal."""
    verify_selected_xcode()
    signing_identity = ensure_local_codesigning_identity()
    _run(
        (
            "xcrun",
            "swift",
            "build",
            "--configuration",
            "release",
            "--package-path",
            "platforms/macos",
            "--product",
            "remap-install",
        ),
        root=root,
    )
    swift_bin = Path(
        _capture(
            (
                "xcrun",
                "swift",
                "build",
                "--show-bin-path",
                "--configuration",
                "release",
                "--package-path",
                "platforms/macos",
            ),
            root=root,
        )
    )
    normalize_macos_sdk_metadata(
        (swift_bin / "remap-install",),
        expected_sdk=expected_macos_sdk(root),
        minimum_macos="15.0",
    )
    helper = _signed_copy(
        swift_bin / "remap-install",
        staging / "remap-install",
        BOOTSTRAP_IDENTIFIER,
        signing_identity,
    )
    return helper, _verified_code_identity(helper)[1]


def install_or_update(root: Path, version: str, operation: str) -> None:
    """Preview, commit, and independently verify install or update."""
    require_macos()
    if operation not in {"install", "update"}:
        raise ValueError("native lifecycle operation must be install or update")
    require_public_command_slot()
    account = native_user()
    with tempfile.TemporaryDirectory(prefix="remap-native-source-") as directory:
        workspace = Path(directory)
        build = build_native_products(root, version, workspace)
        authorize_administrator(root)
        with bootstrap_helper(
            root, build.files.installer, build.installer_cdhash
        ) as bootstrap:
            status = installer_status(helper_json(root, bootstrap, ("status",)))
            helper = _selected_helper(root, bootstrap, build.installer_cdhash, status)
            _require_recovered_state(status)
            _require_operation_state(operation, status)
            upstreams = resolver_upstreams(
                helper_json(root, helper, ("resolver-plan",))
            )
            package_root = workspace / "package"
            package_root.mkdir(mode=0o700)
            data_directory = _private_data_path(account)
            package = assemble(
                package_root,
                build.files,
                product_version=version,
                account_name=account.pw_name,
                owner_uid=account.pw_uid,
                group_name=_group_name(account.pw_gid),
                data_directory=data_directory,
                upstreams=upstreams,
                previous_generation_id=status.active_generation_id,
            )
            if is_exact_update(operation, status, package.generation_id):
                verify_installed_product(root, version, data_directory)
                message = (
                    "Remap is already the exact reviewed generation; "
                    + "no Remap product state changed."
                )
                print(message)
                return
            arguments = _package_arguments(package, account.pw_uid)
            preview = helper_json(root, helper, ("preview", operation, *arguments))
            print(render_preview(preview))
            approved = confirm_approval(approval_token(preview, "preview"), operation)
            _ensure_private_data_directory(account, data_directory)
            transaction_id = f"{operation}-{uuid.uuid4()}"
            try:
                _ = helper_json(
                    root,
                    helper,
                    (
                        operation,
                        *arguments,
                        "--approval-token",
                        approved,
                        "--transaction",
                        transaction_id,
                    ),
                )
            except RuntimeError as error:
                raise RuntimeError(
                    f"{error}\nRecovery transaction: {transaction_id}"
                ) from error
            final = installer_status(helper_json(root, bootstrap, ("status",)))
            if final.active_generation_id != package.generation_id:
                raise RuntimeError(
                    "the committed generation is not the active generation"
                )
            verify_installed_product(root, version, data_directory)
            message = (
                f"{operation.capitalize()} committed and verified generation"
                f" {package.generation_id}."
            )
            print(message)


def uninstall(root: Path) -> None:
    """Preview, remove, and verify only the manifest-owned native installation."""
    require_macos()
    with tempfile.TemporaryDirectory(prefix="remap-native-remove-") as directory:
        staging = Path(directory)
        helper_source, expected_cdhash = build_installer(root, staging)
        authorize_administrator(root)
        with bootstrap_helper(root, helper_source, expected_cdhash) as bootstrap:
            status = installer_status(helper_json(root, bootstrap, ("status",)))
            helper = _selected_helper(root, bootstrap, expected_cdhash, status)
            _require_recovered_state(status)
            generation = status.active_generation_id
            if generation is None:
                verify_uninstalled(status)
                print("Remap is not installed. User mappings were not changed.")
                return
            preview = helper_json(
                root,
                helper,
                ("preview", "uninstall", "--generation", generation),
            )
            print(render_preview(preview))
            approved = confirm_approval(approval_token(preview, "preview"), "uninstall")
            transaction_id = f"uninstall-{uuid.uuid4()}"
            try:
                _ = helper_json(
                    root,
                    helper,
                    (
                        "uninstall",
                        "--generation",
                        generation,
                        "--approval-token",
                        approved,
                        "--transaction",
                        transaction_id,
                    ),
                )
            except RuntimeError as error:
                raise RuntimeError(
                    f"{error}\nRecovery transaction: {transaction_id}"
                ) from error
            final = installer_status(helper_json(root, bootstrap, ("status",)))
            verify_uninstalled(final)
    print("Remap was removed, DNS was restored, and user mappings were preserved.")


def recover(root: Path) -> None:
    """Preview, approve, and converge interrupted native lifecycle state."""
    require_macos()
    with tempfile.TemporaryDirectory(prefix="remap-native-recover-") as directory:
        staging = Path(directory)
        helper_source, expected_cdhash = build_installer(root, staging)
        authorize_administrator(root)
        with bootstrap_helper(root, helper_source, expected_cdhash) as bootstrap:
            status = installer_status(helper_json(root, bootstrap, ("status",)))
            helper = _selected_helper(root, bootstrap, expected_cdhash, status)
            preview = helper_json(root, helper, ("preview", "recover", "--all"))
            print(render_recovery_preview(preview))
            if recovery_has_effects(preview):
                approved = confirm_approval(
                    approval_token(preview, "preview-recovery"), "recover"
                )
                _ = helper_json(
                    root,
                    helper,
                    ("recover", "--all", "--approval-token", approved),
                )
                final = installer_status(helper_json(root, bootstrap, ("status",)))
                if final.pending_recovery_count != 0:
                    raise RuntimeError("native recovery left unfinished transactions")
                remaining = helper_json(
                    root,
                    bootstrap,
                    ("preview", "recover", "--all"),
                )
                if recovery_has_effects(remaining):
                    raise RuntimeError(
                        "native recovery left recoverable system effects"
                    )
            else:
                print("No lifecycle recovery is required.")
            bootstrap_preview = helper_json(
                root,
                bootstrap,
                ("preview", "recover-bootstrap-helpers"),
            )
            print(render_bootstrap_recovery_preview(bootstrap_preview))
            if bootstrap_recovery_has_effects(bootstrap_preview):
                bootstrap_approval = confirm_approval(
                    approval_token(
                        bootstrap_preview,
                        "preview-bootstrap-recovery",
                    ),
                    "recover bootstrap helpers",
                )
                _ = helper_json(
                    root,
                    bootstrap,
                    (
                        "recover-bootstrap-helpers",
                        "--approval-token",
                        bootstrap_approval,
                    ),
                )
                bootstrap_remaining = helper_json(
                    root,
                    bootstrap,
                    ("preview", "recover-bootstrap-helpers"),
                )
                if bootstrap_recovery_has_effects(bootstrap_remaining):
                    raise RuntimeError(
                        "native recovery left removable bootstrap helper residue"
                    )
    print("Native recovery completed and was independently verified.")


def verify_generated_package_contract(root: Path, version: str) -> None:
    """Run Swift's production package validator on a real generated image."""
    require_macos()
    account = native_user()
    with tempfile.TemporaryDirectory(prefix="remap-package-contract-") as directory:
        workspace = Path(directory)
        build = build_native_products(root, version, workspace)
        package_root = workspace / "package"
        package_root.mkdir(mode=0o700)
        package = assemble(
            package_root,
            build.files,
            product_version=version,
            account_name=account.pw_name,
            owner_uid=account.pw_uid,
            group_name=_group_name(account.pw_gid),
            data_directory=Path(account.pw_dir)
            / "Library/Application Support/org.Agenxy.Remap",
            upstreams=["192.0.2.53:53"],
            previous_generation_id=None,
        )
        environment = os.environ.copy()
        environment.update(
            {
                "REMAP_GENERATED_PACKAGE_ROOT": str(package.root),
                "REMAP_GENERATED_MANIFEST_SHA256": package.manifest_digest,
                "REMAP_GENERATED_SOURCE_UID": str(account.pw_uid),
            }
        )
        _run(
            (
                "xcrun",
                "swift",
                "test",
                "--package-path",
                "platforms/macos",
                "--filter",
                "pythonGeneratedPackageMatchesTheNativeProductionContract",
            ),
            root=root,
            environment=environment,
        )


def authorize_administrator(root: Path) -> None:
    """Acquire one visible, time-limited administrator authorization."""
    try:
        _run(("/usr/bin/sudo", "-v"), root=root)
    except subprocess.TimeoutExpired as error:
        message = (
            "administrator authentication did not complete within the bounded "
            "two-minute window; retry the lifecycle command and authenticate "
            "locally when macOS prompts. No privileged Remap state changed."
        )
        raise RuntimeError(message) from error


def verify_installed_product(root: Path, version: str, data_directory: Path) -> None:
    """Prove clean-shell discovery and the authenticated installed runtime."""
    if not SYSTEM_CLI.is_file() or not os.access(SYSTEM_CLI, os.X_OK):
        raise RuntimeError(
            "the native transaction did not publish /usr/local/bin/remap"
        )
    actual_version = _capture((str(SYSTEM_CLI), "--version"), root=root)
    if actual_version != f"remap {version}":
        raise RuntimeError("the installed command reports the wrong product version")
    if not SYSTEM_APP.is_dir():
        raise RuntimeError(
            "the native transaction did not publish /Applications/Remap.app"
        )
    app_identifier, _app_cdhash = _verified_code_identity(SYSTEM_APP)
    if app_identifier != "org.agenxy.Remap":
        raise RuntimeError("the installed app reports the wrong product identity")
    verify_installed_assets(root)
    clean_path = "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    selected = shutil.which("remap", path=clean_path)
    if selected != str(SYSTEM_CLI):
        raise RuntimeError("a clean shell does not select /usr/local/bin/remap")
    document = _json_command(
        (
            str(SYSTEM_CLI),
            "--json",
            "--data-dir",
            str(data_directory),
            "doctor",
        ),
        root=root,
    )
    result = document.get("result")
    result_data = (
        cast("dict[str, object]", result) if isinstance(result, dict) else None
    )
    if (
        document.get("ok") is not True
        or result_data is None
        or result_data.get("version") != version
        or result_data.get("native_install") is not True
        or result_data.get("dns_listener") is not True
        or result_data.get("http_gateway") is not True
    ):
        raise RuntimeError(
            "the installed command did not authenticate the complete runtime"
        )


def verify_installed_assets(root: Path) -> None:
    """Prove documentation, completions, and policy texts as the invoking user."""
    with tempfile.TemporaryDirectory(prefix="remap-installed-assets-") as directory:
        generated = Path(directory)
        generated_man = generated / "man1"
        _ = _capture(
            (str(SYSTEM_CLI), "manpages", str(generated_man)),
            root=root,
        )
        expected_manpages = sorted(generated_man.glob("remap*.1"))
        installed_manpages = sorted(SYSTEM_MAN_DIRECTORY.glob("remap*.1"))
        if not expected_manpages or [path.name for path in expected_manpages] != [
            path.name for path in installed_manpages
        ]:
            raise RuntimeError(
                "the installed manual-page family is incomplete or stale"
            )
        for expected in expected_manpages:
            require_readable_exact(expected, SYSTEM_MAN_DIRECTORY / expected.name)
        for shell, installed in SYSTEM_COMPLETIONS.items():
            expected = _write_output(
                (str(SYSTEM_CLI), "completions", shell),
                generated / f"remap.{shell}",
                root,
            )
            require_readable_exact(expected, installed)
        for name in ("LICENSE", "NOTICE"):
            require_readable_exact(root / name, SYSTEM_POLICY_DIRECTORY / name)
    environment = os.environ.copy()
    environment.update(
        {
            "MANPATH": str(SYSTEM_MAN_DIRECTORY.parent),
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }
    )
    location = _capture(
        ("/usr/bin/man", "-w", "remap"),
        root=root,
        environment=environment,
    )
    if Path(location) != SYSTEM_MAN_DIRECTORY / "remap.1":
        raise RuntimeError("man does not discover the installed remap(1) page")


def require_readable_exact(expected: Path, installed: Path) -> None:
    """Require one installed regular file to be readable and byte-identical."""
    if not installed.is_file() or not os.access(installed, os.R_OK):
        raise RuntimeError(f"the installed asset is not readable: {installed}")
    if installed.read_bytes() != expected.read_bytes():
        raise RuntimeError(f"the installed asset differs from its build: {installed}")


def _selected_helper(
    root: Path,
    bootstrap: Path,
    expected_cdhash: str,
    status: InstallerStatus,
) -> Path:
    generation = status.active_generation_id
    if generation is None:
        return bootstrap
    installed = GENERATIONS_ROOT / generation / "libexec/remap-install"
    try:
        identifier, actual_cdhash = _verified_code_identity(
            installed, privileged=True, root=root
        )
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        return bootstrap
    if identifier == BOOTSTRAP_IDENTIFIER and actual_cdhash == expected_cdhash:
        return installed
    return bootstrap


def helper_json(
    root: Path, helper: Path, arguments: Sequence[str]
) -> dict[str, object]:
    command = (
        "/usr/bin/sudo",
        "-n",
        str(helper),
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
                "the native installer timed out; the outcome is unknown and "
                + "journal recovery is required"
            )
            raise RuntimeError(message) from error
        stdout = _bounded_file(output, "installer output")
        stderr = _bounded_file(errors, "installer diagnostic")
    if result.returncode != 0:
        raise RuntimeError(installer_error(stderr, result.returncode))
    if stderr:
        raise RuntimeError(
            "the native installer wrote an unexpected success diagnostic"
        )
    return decode_document(stdout, "native installer result")


def _package_arguments(package: NativePackage, source_uid: int) -> tuple[str, ...]:
    return (
        "--package-root",
        str(package.root.resolve(strict=True)),
        "--manifest-sha256",
        package.manifest_digest,
        "--source-uid",
        str(source_uid),
    )


def _require_operation_state(operation: str, status: InstallerStatus) -> None:
    if operation == "install" and status.active_generation_id is not None:
        raise RuntimeError("Remap is already installed; run 'make update' instead")
    if operation == "update" and status.active_generation_id is None:
        raise RuntimeError("Remap is not installed; run 'make install' instead")


def _require_recovered_state(status: InstallerStatus) -> None:
    if status.pending_recovery_count != 0:
        raise RuntimeError(
            "Remap has an unfinished native lifecycle transaction. "
            + "Run 'make recover' to preview and approve recovery before retrying."
        )


def _private_data_path(account: pwd.struct_passwd) -> Path:
    """Return the manifest-bound data path without creating product state."""
    return Path(account.pw_dir) / "Library/Application Support/org.Agenxy.Remap"


def _ensure_private_data_directory(account: pwd.struct_passwd, path: Path) -> None:
    """Create the private data root only after explicit product approval."""
    if path != _private_data_path(account):
        raise RuntimeError("the approved native data directory changed identity")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    information = path.lstat()
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != account.pw_uid
        or stat.S_IMODE(information.st_mode) != 0o700
    ):
        raise RuntimeError(
            "the native data directory is not a private user-owned directory"
        )


def _group_name(group_id: int) -> str:
    import grp

    value = grp.getgrgid(group_id).gr_name
    if not value:
        raise RuntimeError("the native account has no group name")
    return value


def verify_uninstalled(status: InstallerStatus) -> None:
    """Require the native product and every manifest-owned artifact to be absent."""
    if (
        status.active_generation_id is not None
        or status.generation_count != 0
        or status.pending_recovery_count != 0
        or status.loaded_service_count != 0
        or status.dns_active
        or status.effective_remap_service_count != 0
    ):
        raise RuntimeError("native uninstall left active or recoverable system state")
    public_paths = (
        SYSTEM_CLI,
        SYSTEM_APP,
        SYSTEM_POLICY_DIRECTORY / "LICENSE",
        SYSTEM_POLICY_DIRECTORY / "NOTICE",
        *(SYSTEM_MAN_DIRECTORY / name for name in MANPAGE_NAMES),
        *SYSTEM_COMPLETIONS.values(),
        Path(f"/Library/LaunchDaemons/{DAEMON_LABEL}.plist"),
        Path(f"/Library/LaunchDaemons/{RESOLVER_LABEL}.plist"),
        INSTALL_ROOT / "current",
    )
    for path in public_paths:
        if path.exists() or path.is_symlink():
            raise RuntimeError(f"native uninstall left the manifest-owned path {path}")
    for directory in SYSTEM_PUBLIC_DIRECTORIES:
        marker = directory / ".remap-owned-directory"
        if marker.exists() or marker.is_symlink():
            raise RuntimeError(
                f"native uninstall left directory ownership at {directory}"
            )
    if INSTALL_ROOT.exists() or INSTALL_ROOT.is_symlink():
        raise RuntimeError("native uninstall left the private installer topology")


def _signed_copy(
    source: Path,
    destination: Path,
    identifier: str,
    signing_identity: LocalCodeSigningIdentity,
) -> Path:
    if not source.is_file() or not os.access(source, os.X_OK):
        raise RuntimeError(f"the native build did not produce {source}")
    _ = shutil.copyfile(source, destination)
    os.chmod(destination, 0o500)
    _ = sign_path(destination, signing_identity, identifier)
    actual_identifier, _cdhash = _verified_code_identity(destination)
    if actual_identifier != identifier:
        raise RuntimeError(
            f"the signed native product has the wrong identity: {destination}"
        )
    return destination


def _unsigned_copy(source: Path, destination: Path) -> Path:
    if not source.is_file() or not os.access(source, os.X_OK):
        raise RuntimeError(f"the native build did not produce {source}")
    _ = shutil.copyfile(source, destination)
    os.chmod(destination, 0o500)
    return destination


def _finalize_signed_copy(source: Path, destination: Path, identifier: str) -> Path:
    _ = source.replace(destination)
    actual_identifier, _cdhash = _verified_code_identity(destination)
    if actual_identifier != identifier:
        raise RuntimeError(
            f"the signed native product has the wrong identity: {destination}"
        )
    return destination


def _verified_code_identity(
    path: Path,
    *,
    privileged: bool = False,
    root: Path | None = None,
) -> tuple[str, str]:
    prefix = ("/usr/bin/sudo", "-n") if privileged else ()
    working_root = root or path.parent
    _run(
        (*prefix, "/usr/bin/codesign", "--verify", "--strict", str(path)),
        root=working_root,
    )
    details = _capture(
        (*prefix, "/usr/bin/codesign", "-d", "--verbose=4", str(path)),
        root=working_root,
        include_standard_error=True,
    )
    values = {
        key: value
        for line in details.splitlines()
        if "=" in line
        for key, value in [line.split("=", maxsplit=1)]
    }
    identifier = values.get("Identifier")
    cdhash = values.get("CDHash")
    if not identifier or not cdhash or not CDHASH_PATTERN.fullmatch(cdhash):
        raise RuntimeError(f"codesign did not report a stable identity for {path}")
    return identifier, cdhash


def _bounded_file(handle: BinaryIO, label: str) -> bytes:
    _ = handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError(f"{label} exceeded one MiB")
    _ = handle.seek(0)
    return handle.read()


def _json_command(arguments: Sequence[str], *, root: Path) -> dict[str, object]:
    result = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=False,
        timeout=10,
    )
    if len(result.stdout) > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError("the command returned more than one MiB")
    return decode_document(result.stdout, "command result")


def _write_output(arguments: Sequence[str], destination: Path, root: Path) -> Path:
    with destination.open("wb") as output:
        _ = subprocess.run(arguments, cwd=root, stdout=output, check=True, timeout=30)
    os.chmod(destination, 0o400)
    return destination


def _capture(
    arguments: Sequence[str],
    *,
    root: Path,
    include_standard_error: bool = False,
    environment: dict[str, str] | None = None,
) -> str:
    result = subprocess.run(
        arguments,
        cwd=root,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + (result.stderr if include_standard_error else "")
    if len(output.encode("utf-8")) > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError("the native tool returned more than one MiB")
    return output.strip()


def _run(
    arguments: Sequence[str],
    *,
    root: Path,
    environment: dict[str, str] | None = None,
) -> None:
    _ = subprocess.run(
        arguments,
        cwd=root,
        env=environment,
        check=True,
        timeout=HELPER_TIMEOUT_SECONDS,
    )
