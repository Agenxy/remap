# SPDX-License-Identifier: GPL-3.0-or-later
"""Metadata normalization and member validation for native macOS packages."""

from __future__ import annotations

import os
import stat
import subprocess
import time
import uuid
from pathlib import Path, PurePosixPath

MAXIMUM_PAYLOAD_LISTING_BYTES = 4_194_304
NORMALIZED_PACKAGE_MTIME = 946_684_800

# Extended attributes the kernel owns, which userspace cannot remove.
#
# macOS 27 stamps `com.apple.provenance` on every file as it is created, including one
# written by a plain shell redirection. `xattr -c` reports success and leaves it in
# place, and so does `sudo xattr -c`. Requiring its absence is therefore a condition no
# file can satisfy, which made packaging impossible rather than careful. Apple's own
# `pkgbuild` takes the same view: it emits `write: Permission denied` for these and
# still produces a correct package. Every other extended attribute must still be gone,
# because those carry quarantine flags, editor state and Finder metadata that have no
# business in a distributed payload.
PLATFORM_OWNED_EXTENDED_ATTRIBUTES = frozenset({"com.apple.provenance"})


def removable_extended_attributes(names: str) -> tuple[str, ...]:
    """The attributes in `xattr` output that userspace is able to clear."""
    return tuple(
        name
        for name in (line.strip() for line in names.splitlines())
        if name and name not in PLATFORM_OWNED_EXTENDED_ATTRIBUTES
    )


def normalize_package_timestamps(root: Path) -> None:
    """Give every pkgbuild input one stable metadata timestamp."""
    paths = (root, *root.rglob("*"))
    for path in paths:
        information = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISREG(information.st_mode) or stat.S_ISDIR(information.st_mode)
        ):
            raise RuntimeError(f"portable package timestamp input is unsafe: {path}")
    for path in paths:
        os.utime(
            path,
            (NORMALIZED_PACKAGE_MTIME, NORMALIZED_PACKAGE_MTIME),
            follow_symlinks=False,
        )


def normalize_package_extended_attributes(root: Path) -> None:
    """Remove inherited extended attributes from verified pkgbuild inputs."""
    paths = (root, *root.rglob("*"))
    for path in paths:
        information = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISREG(information.st_mode) or stat.S_ISDIR(information.st_mode)
        ):
            raise RuntimeError(
                f"portable package extended-attribute input is unsafe: {path}"
            )
    _clear_extended_attributes(root, paths)


def _clear_extended_attributes(root: Path, paths: tuple[Path, ...]) -> None:
    label = f"org.agenxy.remap.package-xattr.{uuid.uuid4().hex}"
    result = subprocess.run(
        (
            "/bin/launchctl",
            "submit",
            "-l",
            label,
            "--",
            "/usr/bin/xattr",
            "-cr",
            str(root),
        ),
        cwd=root.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        raise RuntimeError("launchd could not normalize package metadata")
    deadline = time.monotonic() + 30
    retained: tuple[tuple[Path, str], ...] = ()
    try:
        while time.monotonic() < deadline:
            retained = _retained_extended_attributes(paths, root=root.parent)
            if not retained:
                return
            time.sleep(0.05)
    finally:
        _ = subprocess.run(
            ("/bin/launchctl", "remove", label),
            cwd=root.parent,
            check=False,
            capture_output=True,
            timeout=30,
        )
    retained = _retained_extended_attributes(paths, root=root.parent)
    if not retained:
        return
    path, attributes = retained[0]
    relative = path.relative_to(root)
    raise RuntimeError(
        "portable package input retains extended attributes at "
        + f"{relative}: {attributes}"
    )


def _retained_extended_attributes(
    paths: tuple[Path, ...], *, root: Path
) -> tuple[tuple[Path, str], ...]:
    retained: list[tuple[Path, str]] = []
    for path in paths:
        removable = removable_extended_attributes(_extended_attributes(path, root=root))
        if removable:
            retained.append((path, " ".join(removable)))
    return tuple(retained)


def _extended_attributes(path: Path, *, root: Path) -> str:
    result = subprocess.run(
        ("/usr/bin/xattr", str(path)),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout.strip()


def verify_payload_member_names(listing: str) -> None:
    """Reject ambiguous members, and orphan AppleDouble members, before expansion.

    An AppleDouble `._x` member is how the payload carries `x`'s extended attributes.
    macOS 27 stamps `com.apple.provenance` on every file it creates and does not allow
    its removal, so pkgbuild emits one of these beside every file and directory; that is
    measured, not assumed, and on extraction the installer decodes them back into
    attributes rather than leaving `._` files on disk. Refusing them outright therefore
    refuses every package this platform can build.

    What stays refused is an AppleDouble member with no counterpart, since that is a
    file smuggled into the payload under a name the installer treats as metadata, and
    one appearing anywhere but the final path component.
    """
    encoded = listing.encode("utf-8")
    if not listing or len(encoded) > MAXIMUM_PAYLOAD_LISTING_BYTES:
        raise RuntimeError("portable package payload listing has an unsafe size")
    members = {member for member in listing.splitlines() if member}
    for member in listing.splitlines():
        if member == ".":
            continue
        if not member.startswith("./") or any(
            ord(character) < 32 for character in member
        ):
            raise RuntimeError(
                f"portable package payload has an unsafe member: {member!r}"
            )
        relative = member[2:]
        path = PurePosixPath(relative)
        if (
            not relative
            or path.is_absolute()
            or path.as_posix() != relative
            or ".." in path.parts
            or any(part.startswith("._") for part in path.parts[:-1])
        ):
            raise RuntimeError(
                f"portable package payload has an unsafe member: {member!r}"
            )
        final = path.parts[-1]
        if final.startswith("._"):
            counterpart = path.parent / final[2:]
            if final == "._" or f"./{counterpart.as_posix()}" not in members:
                raise RuntimeError(
                    "portable package payload has an AppleDouble member with no "
                    + f"counterpart: {member!r}"
                )
