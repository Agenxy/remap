"""Install only a root-pinned copy of a verified Remap macOS package."""

from __future__ import annotations

import re
import stat
import subprocess
import uuid
from pathlib import Path

from tools.remap_macos_portable_package import verify_detached_package_signature
from tools.remap_macos_release_installer_signing import verify_package_signature

STAGING_PARENT = Path("/private/var/tmp")
STAGING_PREFIX = "org.agenxy.Remap.install-"


def install_verified_package(root: Path, package: Path, signature: Path) -> None:
    """Reverify exact root-owned bytes before invoking Apple's installer."""
    public_key = (root / "docs/release/remap-release-signing-key.pub").read_text(
        encoding="utf-8"
    )
    installer_certificate = root / "docs/release/remap-release-installer.pem"
    verify_detached_package_signature(package, signature, public_key=public_key)
    verify_package_signature(package, installer_certificate)
    staging = STAGING_PARENT / f"{STAGING_PREFIX}{uuid.uuid4()}"
    staged_package = staging / "Remap.pkg"
    try:
        _run(("/usr/bin/sudo", "/bin/mkdir", "-m", "0755", str(staging)))
        _run(
            (
                "/usr/bin/sudo",
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "0444",
                str(package),
                str(staged_package),
            )
        )
        verify_staging(staging, staged_package)
        verify_detached_package_signature(
            staged_package,
            signature,
            public_key=public_key,
            expected_package_owner_uid=0,
        )
        verify_package_signature(staged_package, installer_certificate)
        verify_staging(staging, staged_package)
        _run(
            (
                "/usr/bin/sudo",
                "/usr/sbin/installer",
                "-pkg",
                str(staged_package),
                "-target",
                "/",
            )
        )
    finally:
        _cleanup(staging, staged_package)


def verify_staging(directory: Path, package: Path) -> None:
    if (
        directory.parent != STAGING_PARENT
        or re.fullmatch(rf"{re.escape(STAGING_PREFIX)}[0-9a-f-]{{36}}", directory.name)
        is None
    ):
        raise RuntimeError("the Remap package staging path is malformed")
    directory_status = directory.lstat()
    package_status = package.lstat()
    if (
        not stat.S_ISDIR(directory_status.st_mode)
        or directory_status.st_uid != 0
        or directory_status.st_gid != 0
        or stat.S_IMODE(directory_status.st_mode) != 0o755
        or directory_status.st_nlink < 2
        or not stat.S_ISREG(package_status.st_mode)
        or package_status.st_uid != 0
        or package_status.st_gid != 0
        or stat.S_IMODE(package_status.st_mode) != 0o444
        or package_status.st_nlink != 1
        or package_status.st_size <= 0
    ):
        raise RuntimeError("the root-owned Remap package staging area is unsafe")


def _cleanup(directory: Path, package: Path) -> None:
    if directory.parent != STAGING_PARENT or not directory.name.startswith(
        STAGING_PREFIX
    ):
        return
    if package.exists() and not package.is_symlink():
        _run(("/usr/bin/sudo", "/bin/unlink", str(package)), check=False)
    if directory.exists() and not directory.is_symlink():
        _run(("/usr/bin/sudo", "/bin/rmdir", str(directory)), check=False)


def _run(arguments: tuple[str, ...], *, check: bool = True) -> None:
    _ = subprocess.run(arguments, check=check, timeout=300)
