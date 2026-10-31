# SPDX-License-Identifier: GPL-3.0-or-later
"""Install only a root-pinned copy of a verified Remap macOS package."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import uuid
from pathlib import Path

from tools.remap_macos_portable_package import verify_detached_package_signature
from tools.remap_macos_release_installer_signing import verify_package_signature
from tools.remap_release_signing import (
    DEVELOPMENT_PACKAGE_VARIABLE,
    REHEARSAL_KEY_MARKER,
    REHEARSAL_PACKAGE_VARIABLE,
    REHEARSAL_PIN,
    RELEASE_PIN,
    PackageKind,
    fingerprint,
    is_development_marked,
    is_rehearsal_marked,
    pinned_public_key,
    revoked_fingerprints,
)

# What is printed before an unsigned kind is handed to Apple's installer.
INSTALL_NOTES = {
    PackageKind.DEVELOPMENT: (
        "Installing a development package: no Apple installer signature, and a "
        + "signing key held in a file rather than in hardware."
    ),
    PackageKind.REHEARSAL: (
        "Installing a rehearsal package, not a release: it is verified against the "
        + "rehearsal pin, carries no Apple installer signature, and a production "
        + "release replaces it as an ordinary update. Do not keep it as a release."
    ),
}

STAGING_PARENT = Path("/private/var/tmp")
STAGING_PREFIX = "org.agenxy.Remap.install-"


def install_verified_package(root: Path, package: Path, signature: Path) -> None:
    """Reverify exact root-owned bytes before invoking Apple's installer."""
    kind = selected_package_kind(root, package)
    public_key = pinned_public_key(root, kind)
    # Only a release carries an Apple installer signature.
    unsigned = kind is not PackageKind.RELEASE
    installer_certificate = root / "docs/release/remap-release-installer.pem"
    # A development or rehearsal package carries no Apple installer signature, because
    # producing one needs a key in a keychain and a person to release it. Apple's
    # installer accepts an unsigned package, unlike one signed by a certificate the machine
    # does not trust, which it refuses in preflight. What still has to hold is the
    # detached signature over the exact root-owned bytes, checked below against its own
    # kind's pin either way.
    verify_detached_package_signature(package, signature, public_key=public_key)
    if unsigned:
        print(INSTALL_NOTES[kind])
    else:
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
        if not unsigned:
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


def selected_package_kind(root: Path, package: Path) -> PackageKind:
    """A development or rehearsal package only on request; otherwise a real release pin.

    Each kind verifies against its own pin. A rehearsal is never installed as a release:
    its file name says what it is, and it is accepted only when asked for by name. The
    release pin is refused while it carries either non-release marker, because another
    kind's key would then pass as the release key.
    """
    development = bool(os.environ.get(DEVELOPMENT_PACKAGE_VARIABLE))
    rehearsal = bool(os.environ.get(REHEARSAL_PACKAGE_VARIABLE))
    if development and rehearsal:
        raise RuntimeError(
            f"{DEVELOPMENT_PACKAGE_VARIABLE} and {REHEARSAL_PACKAGE_VARIABLE} select two "
            + "kinds of package at once; a package is exactly one kind"
        )
    if rehearsal:
        return _rehearsal_kind(root, package)
    if development:
        return PackageKind.DEVELOPMENT
    if package.name.endswith("-development.pkg"):
        raise RuntimeError(
            f"{package.name} is a development package, which proves only that its bytes "
            + "came from the machine that built it. Set "
            + f"{DEVELOPMENT_PACKAGE_VARIABLE}=1 to install one deliberately."
        )
    if package.name.endswith("-rehearsal.pkg"):
        raise RuntimeError(
            f"{package.name} is a rehearsal package, and a rehearsal is never installed "
            + f"as a release. Set {REHEARSAL_PACKAGE_VARIABLE}=1 to install it as the "
            + "rehearsal it is."
        )
    release = pinned_public_key(root, PackageKind.RELEASE)
    for marked, other in (
        (is_development_marked(release), "development"),
        (is_rehearsal_marked(release), "rehearsal"),
    ):
        if marked:
            raise RuntimeError(
                f"the release pin {RELEASE_PIN} is still the {other} key, so no "
                + "package can be verified as a release"
            )
    return PackageKind.RELEASE


def _rehearsal_kind(root: Path, package: Path) -> PackageKind:
    if not package.name.endswith("-rehearsal.pkg"):
        raise RuntimeError(
            f"{REHEARSAL_PACKAGE_VARIABLE}=1 installs only a package named "
            + f"Remap-<version>-<arch>-rehearsal.pkg, and {package.name} is not one"
        )
    pin = pinned_public_key(root, PackageKind.REHEARSAL)
    if not is_rehearsal_marked(pin) or is_development_marked(pin):
        raise RuntimeError(
            f"the rehearsal pin {REHEARSAL_PIN} must carry {REHEARSAL_KEY_MARKER}, and "
            + "only that marker"
        )
    if fingerprint(pin) in revoked_fingerprints(root):
        raise RuntimeError(
            f"the rehearsal pin {REHEARSAL_PIN} is revoked; nothing it signed is installed"
        )
    return PackageKind.REHEARSAL


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
