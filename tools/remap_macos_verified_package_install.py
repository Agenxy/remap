# SPDX-License-Identifier: GPL-3.0-or-later
"""Install only a root-pinned copy of a verified Remap macOS package."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import uuid
from pathlib import Path

from tools.remap_lifecycle_approval import administrator_command
from tools.remap_macos_portable_package import verify_detached_package_signature
from tools.remap_macos_release_installer_signing import verify_package_signature
from tools.remap_release_signing import (
    DEVELOPMENT_PACKAGE_VARIABLE,
    RELEASE_PIN,
    PackageKind,
    is_development_marked,
    pinned_public_key,
)

STAGING_PARENT = Path("/private/var/tmp")
STAGING_PREFIX = "org.agenxy.Remap.install-"


def install_verified_package(root: Path, package: Path, signature: Path) -> None:
    """Reverify exact root-owned bytes before invoking Apple's installer."""
    kind = selected_package_kind(root, package)
    public_key = pinned_public_key(root, kind)
    development = kind is PackageKind.DEVELOPMENT
    installer_certificate = root / "docs/release/remap-release-installer.pem"
    # A development package carries no Apple installer signature, because producing one
    # needs a key in a keychain and a person to release it. Apple's installer accepts an
    # unsigned package, unlike one signed by a certificate the machine does not trust,
    # which it refuses in preflight. What still has to hold is the detached signature over
    # the exact root-owned bytes, checked below against its own kind's pin either way.
    verify_detached_package_signature(package, signature, public_key=public_key)
    if development:
        print(
            "Installing a development package: no Apple installer signature, and a "
            + "signing key held in a file rather than in hardware."
        )
    else:
        verify_package_signature(package, installer_certificate)
    staging = STAGING_PARENT / f"{STAGING_PREFIX}{uuid.uuid4()}"
    staged_package = staging / "Remap.pkg"
    try:
        _run(_administrator("/bin/mkdir", "-m", "0755", str(staging)))
        _run(
            _administrator(
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
        if not development:
            verify_package_signature(staged_package, installer_certificate)
        verify_staging(staging, staged_package)
        _run(
            _administrator(
                "/usr/sbin/installer", "-pkg", str(staged_package), "-target", "/"
            )
        )
    finally:
        _cleanup(staging, staged_package)


def selected_package_kind(root: Path, package: Path) -> PackageKind:
    """A development package only on request; otherwise the release pin, which must be real.

    Each kind verifies against its own pin. The release pin is refused while it still
    carries the development marker, because a key held in a file would then pass as the
    release key.
    """
    if os.environ.get(DEVELOPMENT_PACKAGE_VARIABLE):
        return PackageKind.DEVELOPMENT
    if package.name.endswith("-development.pkg"):
        raise RuntimeError(
            f"{package.name} is a development package, which proves only that its bytes "
            + "came from the machine that built it. Set "
            + f"{DEVELOPMENT_PACKAGE_VARIABLE}=1 to install one deliberately."
        )
    if is_development_marked(pinned_public_key(root, PackageKind.RELEASE)):
        raise RuntimeError(
            f"the release pin {RELEASE_PIN} is still the development key, so no package "
            + "can be verified as a release. Set "
            + f"{DEVELOPMENT_PACKAGE_VARIABLE}=1 to install a development package."
        )
    return PackageKind.RELEASE


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
        _run(_administrator("/bin/unlink", str(package)), check=False)
    if directory.exists() and not directory.is_symlink():
        _run(_administrator("/bin/rmdir", str(directory)), check=False)


def _administrator(*command: str) -> tuple[str, ...]:
    # sudo asks once per ticket, so the first of these is normally the one that asks.
    return administrator_command("install-package", *command)


def _run(arguments: tuple[str, ...], *, check: bool = True) -> None:
    _ = subprocess.run(arguments, check=check, timeout=300)
