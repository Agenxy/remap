"""Native Apple Installer bootstrap package for Remap's lifecycle service."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from tools.remap_macos_installer_signing import (
    LocalInstallerSigningIdentity,
    sign_package,
)
from tools.remap_macos_signing import (
    LocalCodeSigningIdentity,
    verify_local_signature,
)
from tools.remap_native_package import (
    NativePackage,
    has_extended_acl,
    list_extended_attributes,
)

PACKAGE_IDENTIFIER = "org.agenxy.Remap.InstallerBootstrap"
APP_IDENTIFIER = "org.agenxy.Remap"
BOOTSTRAP_IDENTIFIER = "org.agenxy.Remap.installer-bootstrap"
SERVICE_IDENTIFIER = "org.agenxy.Remap.installer-service"
SERVICE_PROGRAM = Path("/Library/PrivilegedHelperTools") / SERVICE_IDENTIFIER
SERVICE_PLIST = Path("/Library/LaunchDaemons") / f"{SERVICE_IDENTIFIER}.plist"
SERVICE_CONFIGURATION = (
    Path("/Library/Application Support/Agenxy/Remap/Installer") / "service-v1.json"
)
SERVICE_SOURCES = Path("/Library/Application Support/Agenxy/Remap/Installer/Sources")
AGENXY_DIRECTORY_MODE = 0o755
REMAP_DIRECTORY_MODE = 0o711
INSTALLER_DIRECTORY_MODE = 0o700


@dataclass(frozen=True)
class InstallerBootstrapInputs:
    """Exact signed inputs admitted to the bootstrap package."""

    app: Path
    bootstrap: Path
    service: Path
    owner_uid: int
    product_version: str
    code_identity: LocalCodeSigningIdentity
    installer_identity: LocalInstallerSigningIdentity
    source_package: NativePackage


def build_package(
    inputs: InstallerBootstrapInputs,
    output: Path,
) -> Path:
    """Build, sign, and verify one no-shell native bootstrap package."""
    _validate_inputs(inputs)
    if output.exists() or output.is_symlink():
        raise RuntimeError(f"refusing to overwrite Installer package {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="remap-bootstrap-package-") as directory:
        workspace = Path(directory)
        os.chmod(workspace, 0o700)
        payload = workspace / "payload"
        scripts = workspace / "scripts"
        payload.mkdir(mode=0o700)
        scripts.mkdir(mode=0o700)
        app_cdhash = verify_local_signature(
            inputs.app,
            inputs.code_identity,
            APP_IDENTIFIER,
        )
        bootstrap_cdhash = verify_local_signature(
            inputs.bootstrap,
            inputs.code_identity,
            BOOTSTRAP_IDENTIFIER,
        )
        service_cdhash = verify_local_signature(
            inputs.service,
            inputs.code_identity,
            SERVICE_IDENTIFIER,
        )
        _assemble_payload(
            payload,
            inputs=inputs,
            app_cdhash=app_cdhash,
            bootstrap_cdhash=bootstrap_cdhash,
            service_cdhash=service_cdhash,
        )
        for script_name in ("preinstall", "postinstall"):
            _copy_unique(inputs.bootstrap, scripts / script_name, mode=0o555)
        _verify_staged_tree(payload)
        _verify_staged_tree(scripts)
        unsigned = workspace / "unsigned.pkg"
        _run(
            (
                "/usr/bin/pkgbuild",
                "--root",
                str(payload),
                "--scripts",
                str(scripts),
                "--identifier",
                PACKAGE_IDENTIFIER,
                "--version",
                inputs.product_version,
                "--install-location",
                "/",
                "--ownership",
                "recommended",
                str(unsigned),
            ),
            environment={**os.environ, "COPYFILE_DISABLE": "1"},
        )
        _verify_package(unsigned, inputs)
        _verify_expanded_package(unsigned, workspace / "verified", inputs)
        sign_package(unsigned, output, inputs.installer_identity)
    return output


def service_configuration_document(
    *,
    owner_uid: int,
    app_cdhash: str,
    bootstrap_cdhash: str,
    service_cdhash: str,
    source_package: NativePackage,
    signing_certificate_sha256: str,
) -> dict[str, object]:
    """Return the canonical Swift-compatible service authority document."""
    identity = signing_certificate_sha256.lower()
    return {
        "app": {
            "cdHash": app_cdhash,
            "certificateSHA256": identity,
            "identifier": APP_IDENTIFIER,
        },
        "bootstrap": {
            "cdHash": bootstrap_cdhash,
            "certificateSHA256": identity,
            "identifier": BOOTSTRAP_IDENTIFIER,
        },
        "helper": {
            "cdHash": service_cdhash,
            "certificateSHA256": identity,
            "identifier": SERVICE_IDENTIFIER,
        },
        "ownerUID": owner_uid,
        "schemaVersion": 1,
        "sourceManifestDigest": source_package.manifest_digest,
        "sourcePackageRoot": str(source_package_path(source_package.manifest_digest)),
    }


def source_package_path(manifest_digest: str) -> Path:
    """Return the one root-owned path bound to an exact source manifest."""
    if re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None:
        raise RuntimeError("the lifecycle source manifest digest is malformed")
    return SERVICE_SOURCES / manifest_digest


def launchd_document() -> dict[str, object]:
    """Match RemapLifecycleBootstrapper.launchdDocument exactly."""
    return {
        "HardResourceLimits": {"Core": 0, "NumberOfFiles": 128},
        "Label": SERVICE_IDENTIFIER,
        "MachServices": {SERVICE_IDENTIFIER: True},
        "ProcessType": "Interactive",
        "ProgramArguments": [str(SERVICE_PROGRAM)],
        "SoftResourceLimits": {"NumberOfFiles": 128},
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "ThrottleInterval": 5,
        "Umask": 0o077,
    }


def _assemble_payload(
    payload: Path,
    *,
    inputs: InstallerBootstrapInputs,
    app_cdhash: str,
    bootstrap_cdhash: str,
    service_cdhash: str,
) -> None:
    helper = _payload_path(payload, SERVICE_PROGRAM)
    plist = _payload_path(payload, SERVICE_PLIST)
    configuration = _payload_path(payload, SERVICE_CONFIGURATION)
    source = _payload_path(
        payload,
        source_package_path(inputs.source_package.manifest_digest),
    )
    prepare_lifecycle_parent_chain(payload, helper.parent, private_leaf=False)
    prepare_lifecycle_parent_chain(payload, plist.parent, private_leaf=False)
    prepare_lifecycle_parent_chain(payload, configuration.parent, private_leaf=True)
    prepare_lifecycle_parent_chain(payload, source.parent, private_leaf=True)
    _copy_unique(inputs.service, helper, mode=0o555)
    stage_source_package(inputs.source_package, source)
    _ = plist.write_bytes(plistlib.dumps(launchd_document(), fmt=plistlib.FMT_BINARY))
    os.chmod(plist, 0o644)
    document = service_configuration_document(
        owner_uid=inputs.owner_uid,
        app_cdhash=app_cdhash,
        bootstrap_cdhash=bootstrap_cdhash,
        service_cdhash=service_cdhash,
        source_package=inputs.source_package,
        signing_certificate_sha256=inputs.code_identity.sha256,
    )
    _ = configuration.write_bytes(
        json.dumps(
            document,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    os.chmod(configuration, 0o400)


def prepare_lifecycle_parent_chain(
    payload: Path,
    parent: Path,
    *,
    private_leaf: bool,
) -> None:
    """Create one package payload path with native-topology-compatible modes."""
    current = payload
    relative = parent.relative_to(payload)
    for component in relative.parts:
        current /= component
        if not current.exists():
            current.mkdir(mode=0o755)
    if private_leaf:
        os.chmod(parent, INSTALLER_DIRECTORY_MODE)
        remap_root = _payload_path(
            payload,
            Path("/Library/Application Support/Agenxy/Remap"),
        )
        agenxy_root = remap_root.parent
        os.chmod(agenxy_root, AGENXY_DIRECTORY_MODE)
        os.chmod(remap_root, REMAP_DIRECTORY_MODE)


def _payload_path(payload: Path, absolute: Path) -> Path:
    if not absolute.is_absolute():
        raise RuntimeError("Installer payload paths must be absolute")
    return payload.joinpath(*absolute.parts[1:])


def _copy_unique(source: Path, destination: Path, *, mode: int) -> None:
    status = source.lstat()
    if not source.is_file() or source.is_symlink() or status.st_nlink != 1:
        raise RuntimeError(f"Installer input is not one unique regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        shutil.copyfileobj(input_file, output_file, length=1_048_576)
    os.chmod(destination, mode)


def stage_source_package(package: NativePackage, destination: Path) -> None:
    manifest = package.manifest.read_bytes()
    if hashlib.sha256(manifest).hexdigest() != package.manifest_digest:
        raise RuntimeError("the lifecycle source manifest does not match its digest")
    _copy_package_directory(package.root, destination, root=True)


def _copy_package_directory(source: Path, destination: Path, *, root: bool) -> None:
    information = source.lstat()
    expected_mode = 0o700 if root else 0o500
    if (
        not stat.S_ISDIR(information.st_mode)
        or source.is_symlink()
        or stat.S_IMODE(information.st_mode) != expected_mode
    ):
        raise RuntimeError(f"lifecycle source package directory is unsafe: {source}")
    destination.mkdir(mode=0o700)
    for child in sorted(source.iterdir(), key=lambda path: path.name):
        target = destination / child.name
        status = child.lstat()
        if stat.S_ISDIR(status.st_mode):
            _copy_package_directory(child, target, root=False)
            continue
        if not stat.S_ISREG(status.st_mode) or status.st_nlink != 1:
            raise RuntimeError(f"lifecycle source package node is unsafe: {child}")
        mode = stat.S_IMODE(status.st_mode)
        if mode not in {0o400, 0o500}:
            raise RuntimeError(f"lifecycle source package file mode is unsafe: {child}")
        _copy_unique(child, target, mode=mode)
    os.chmod(destination, expected_mode)


def _validate_inputs(inputs: InstallerBootstrapInputs) -> None:
    if inputs.owner_uid <= 0:
        raise RuntimeError("Installer bootstrap requires a non-root owner UID")
    if not inputs.product_version or len(inputs.product_version.encode()) > 128:
        raise RuntimeError("Installer bootstrap product version is malformed")
    for path in (inputs.app, inputs.bootstrap, inputs.service):
        if not path.is_absolute() or not path.exists() or path.is_symlink():
            raise RuntimeError(f"Installer bootstrap input is unsafe: {path}")
    if not inputs.source_package.root.is_absolute():
        raise RuntimeError("Installer source package root must be absolute")


def _verify_staged_tree(root: Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        information = path.lstat()
        directory = stat.S_ISDIR(information.st_mode)
        if not directory and not stat.S_ISREG(information.st_mode):
            raise RuntimeError(
                f"Installer package staging contains an unsafe node: {path}"
            )
        if path.name.startswith("._") or information.st_flags != 0:
            raise RuntimeError(
                f"Installer package staging contains foreign metadata: {path}"
            )
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        if directory:
            flags |= os.O_DIRECTORY
        descriptor = os.open(path, flags)
        try:
            attributes = set(list_extended_attributes(descriptor, path))
            if attributes - {"com.apple.provenance"}:
                raise RuntimeError(
                    f"Installer package staging contains unexpected xattrs: {path}"
                )
            if has_extended_acl(descriptor, path):
                raise RuntimeError(f"Installer package staging contains an ACL: {path}")
        finally:
            os.close(descriptor)


def _verify_package(package: Path, inputs: InstallerBootstrapInputs) -> None:
    result = _capture(("/usr/sbin/pkgutil", "--payload-files", str(package)))
    files = {
        line.removeprefix("./")
        for line in result.splitlines()
        if line.removeprefix("./")
    }
    for path in files:
        name = Path(path).name
        if not name.startswith("._"):
            continue
        base = str(Path(path).with_name(name.removeprefix("._")))
        if base not in files:
            raise RuntimeError("the Installer package has an orphaned metadata sidecar")
    required = {
        str(SERVICE_PROGRAM).lstrip("/"),
        str(SERVICE_PLIST).lstrip("/"),
        str(SERVICE_CONFIGURATION).lstrip("/"),
        str(
            source_package_path(inputs.source_package.manifest_digest) / "manifest.json"
        ).lstrip("/"),
    }
    if not required.issubset(files):
        raise RuntimeError("the Installer package omits a required lifecycle file")
    if len(package.name.encode()) > 255 or not inputs.product_version:
        raise RuntimeError("the Installer package identity is malformed")


def _verify_expanded_package(
    package: Path,
    destination: Path,
    inputs: InstallerBootstrapInputs,
) -> None:
    _run(("/usr/sbin/pkgutil", "--expand-full", str(package), str(destination)))
    if any(path.name.startswith("._") for path in destination.rglob("*")):
        raise RuntimeError("the expanded Installer package contains a metadata file")
    expected_bootstrap_digest = _file_digest(inputs.bootstrap)
    for name in ("preinstall", "postinstall"):
        script = destination / "Scripts" / name
        if _file_digest(script) != expected_bootstrap_digest:
            raise RuntimeError(
                "the Installer package changed its native lifecycle script"
            )
        _ = verify_local_signature(
            script,
            inputs.code_identity,
            BOOTSTRAP_IDENTIFIER,
        )
    source = _payload_path(
        destination / "Payload",
        source_package_path(inputs.source_package.manifest_digest),
    )
    if _file_digest(source / "manifest.json") != inputs.source_package.manifest_digest:
        raise RuntimeError("the Installer package changed its source manifest")
    configuration = _payload_path(destination / "Payload", SERVICE_CONFIGURATION)
    decoded_value = cast(object, json.loads(configuration.read_bytes()))
    if not isinstance(decoded_value, dict):
        raise TypeError("the Installer package configuration is malformed")
    decoded = cast(dict[str, object], decoded_value)
    if decoded.get("sourceManifestDigest") != inputs.source_package.manifest_digest:
        raise RuntimeError(
            "the Installer package configuration changed source identity"
        )
    if decoded.get("sourcePackageRoot") != str(
        source_package_path(inputs.source_package.manifest_digest)
    ):
        raise RuntimeError(
            "the Installer package configuration changed source location"
        )
    plist = _payload_path(destination / "Payload", SERVICE_PLIST)
    if plistlib.loads(plist.read_bytes()) != launchd_document():
        raise RuntimeError(
            "the Installer package changed its launchd service definition"
        )
    expanded_payload = destination / "Payload"
    expected_directories = {
        Path("/Library/Application Support/Agenxy"): AGENXY_DIRECTORY_MODE,
        Path("/Library/Application Support/Agenxy/Remap"): REMAP_DIRECTORY_MODE,
        Path(
            "/Library/Application Support/Agenxy/Remap/Installer"
        ): INSTALLER_DIRECTORY_MODE,
    }
    for path, expected_mode in expected_directories.items():
        actual = _payload_path(expanded_payload, path).stat().st_mode
        if stat.S_IMODE(actual) != expected_mode:
            raise RuntimeError(
                f"the Installer package changed the lifecycle directory mode for {path}"
            )


def _file_digest(path: Path) -> str:
    information = path.lstat()
    if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
        raise RuntimeError(f"the Installer package file is unsafe: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _capture(arguments: tuple[str, ...]) -> str:
    return _run_result(arguments).stdout


def _run(
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str] | None = None,
) -> None:
    _ = _run_result(arguments, environment=environment)


def _run_result(
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as error:
        standard_error = cast(str | None, error.stderr)
        standard_output = cast(str | None, error.stdout)
        detail = (standard_error or standard_output or "").strip()
        raise RuntimeError(
            f"{Path(arguments[0]).name} failed while building the native Installer package: {detail}"
        ) from error
