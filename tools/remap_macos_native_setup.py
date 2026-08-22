"""Build Remap's native Apple Installer product from exact reviewed inputs."""

from __future__ import annotations

import grp
import ipaddress
import json
import os
import pwd
import re
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import cast

from tools.remap_macos_install import NativeBuild, build_native_products, require_macos
from tools.remap_macos_installer_package import (
    InstallerBootstrapInputs,
    build_package,
)
from tools.remap_macos_installer_signing import ensure_local_installer_identity
from tools.remap_macos_signing import ensure_local_codesigning_identity
from tools.remap_native_package import CURRENT_ROOT, GENERATIONS_ROOT, assemble

MAXIMUM_PLAN_BYTES = 65_536


def build_setup_package(root: Path, product_version: str, output: Path) -> Path:
    """Build one self-signed, no-shell Apple Installer package."""
    require_macos()
    account = _native_user()
    with tempfile.TemporaryDirectory(prefix="remap-native-setup-") as directory:
        workspace = Path(directory)
        os.chmod(workspace, 0o700)
        build = build_native_products(root, product_version, workspace)
        bootstrap, service = _required_lifecycle_products(build)
        package_root = workspace / "source"
        package_root.mkdir(mode=0o700)
        source_package = assemble(
            package_root,
            build.files,
            product_version=product_version,
            account_name=account.pw_name,
            owner_uid=account.pw_uid,
            group_name=_group_name(account.pw_gid),
            data_directory=_private_data_path(account),
            upstreams=resolver_upstreams_from_tool(build.files.system_tool, root),
            previous_generation_id=installed_generation_id(),
        )
        return build_package(
            InstallerBootstrapInputs(
                app=build.files.app,
                bootstrap=bootstrap,
                service=service,
                owner_uid=account.pw_uid,
                product_version=product_version,
                code_identity=ensure_local_codesigning_identity(),
                installer_identity=ensure_local_installer_identity(),
                source_package=source_package,
            ),
            output,
        )


def _required_lifecycle_products(build: NativeBuild) -> tuple[Path, Path]:
    if build.installer_bootstrap is None or build.installer_service is None:
        raise RuntimeError("the native build omitted the lifecycle bootstrap products")
    return build.installer_bootstrap, build.installer_service


def resolver_upstreams_from_tool(system_tool: Path, root: Path) -> list[str]:
    result = subprocess.run(
        (str(system_tool), "plan", "--json"),
        cwd=root,
        check=True,
        capture_output=True,
        timeout=10,
    )
    if len(result.stdout) > MAXIMUM_PLAN_BYTES:
        raise RuntimeError("the native resolver plan exceeds its response bound")
    decoded = cast(object, json.loads(result.stdout))
    if not isinstance(decoded, dict):
        raise TypeError("the native resolver plan envelope is malformed")
    document = cast(dict[str, object], decoded)
    if set(document) != {"command", "data", "ok"}:
        raise RuntimeError("the native resolver plan envelope is malformed")
    data = document.get("data")
    if document.get("ok") is not True or document.get("command") != "plan":
        raise RuntimeError("the native resolver plan did not succeed")
    if not isinstance(data, dict):
        raise TypeError("the native resolver plan payload is malformed")
    data_document = cast(dict[str, object], data)
    upstreams = data_document.get("upstreams")
    if not isinstance(upstreams, list):
        raise TypeError("the native resolver plan has an unsafe upstream set")
    upstream_values = cast(list[object], upstreams)
    if not 1 <= len(upstream_values) <= 4 or any(
        not isinstance(value, str) or not value for value in upstream_values
    ):
        raise RuntimeError("the native resolver plan has an unsafe upstream set")
    rendered: list[str] = []
    for raw_value in upstream_values:
        try:
            address = ipaddress.ip_address(cast(str, raw_value))
        except ValueError as error:
            raise RuntimeError(
                "the native resolver plan has an unsafe upstream set"
            ) from error
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise RuntimeError("the native resolver plan has an unsafe upstream set")
        endpoint = (
            f"[{address.compressed}]:53" if address.version == 6 else f"{address}:53"
        )
        if endpoint in rendered:
            raise RuntimeError("the native resolver plan has duplicate upstreams")
        rendered.append(endpoint)
    return rendered


def installed_generation_id(current: Path = CURRENT_ROOT) -> str | None:
    """Return the exact root-owned generation selected by the native install."""
    try:
        information = current.lstat()
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISLNK(information.st_mode)
        or information.st_uid != 0
        or information.st_gid != 0
    ):
        raise RuntimeError("the installed generation pointer has unsafe metadata")
    target = Path(os.readlink(current))
    if not target.is_absolute() or target.parent != GENERATIONS_ROOT:
        raise RuntimeError("the installed generation pointer has an unsafe target")
    generation_id = target.name
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,190}", generation_id) is None:
        raise RuntimeError("the installed generation identifier is malformed")
    return generation_id


def _native_user() -> pwd.struct_passwd:
    account = pwd.getpwuid(os.getuid())
    if account.pw_uid == 0 or not account.pw_name or not account.pw_dir:
        raise RuntimeError("native setup requires a real non-root account")
    return account


def _group_name(group_id: int) -> str:
    name = grp.getgrgid(group_id).gr_name
    if not name:
        raise RuntimeError("the native account has no group name")
    return name


def _private_data_path(account: pwd.struct_passwd) -> Path:
    return Path(account.pw_dir) / "Library/Application Support/org.Agenxy.Remap"
