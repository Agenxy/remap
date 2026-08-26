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


def normalize_package_timestamps(root: Path) -> None:
    """Give every pkgbuild input one stable metadata timestamp."""
    paths = (root, *root.rglob("*"))
    for path in paths:
        information = path.lstat()
        if path.is_symlink() or not (
            stat.S_ISREG(information.st_mode) or stat.S_ISDIR(information.st_mode)
        ):
            raise RuntimeError(f"portable package timestamp input is unsafe: {path}")
    _set_timestamps_without_inherited_attributes(root, paths)


def _set_timestamps_without_inherited_attributes(
    root: Path, paths: tuple[Path, ...]
) -> None:
    reference = root.parent / f".{root.name}.timestamp.{uuid.uuid4().hex}"
    with reference.open("xb") as output_file:
        _ = output_file.write(b"remap-package-timestamp\n")
        output_file.flush()
        os.fsync(output_file.fileno())
    os.utime(reference, (NORMALIZED_PACKAGE_MTIME, NORMALIZED_PACKAGE_MTIME))
    label = f"org.agenxy.remap.package-timestamp.{uuid.uuid4().hex}"
    result = subprocess.run(
        (
            "/bin/launchctl",
            "submit",
            "-l",
            label,
            "--",
            "/bin/zsh",
            "-c",
            '/usr/bin/find "$1" -exec /usr/bin/touch -h -r "$2" {} +; '
            + "/bin/sleep 300",
            "remap-package-timestamp",
            str(root),
            str(reference),
        ),
        cwd=root.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0 or result.stdout or result.stderr:
        reference.unlink()
        raise RuntimeError("launchd could not normalize package timestamps")
    deadline = time.monotonic() + 30
    try:
        while time.monotonic() < deadline:
            if all(
                path.stat().st_mtime_ns == NORMALIZED_PACKAGE_MTIME * 10**9
                for path in paths
            ):
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
        reference.unlink()
    raise RuntimeError("launchd did not normalize package timestamps")


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
        attributes = _extended_attributes(path, root=root)
        if attributes:
            retained.append((path, attributes))
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
    """Reject ambiguous or AppleDouble members before package expansion."""
    encoded = listing.encode("utf-8")
    if not listing or len(encoded) > MAXIMUM_PAYLOAD_LISTING_BYTES:
        raise RuntimeError("portable package payload listing has an unsafe size")
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
            or any(part.startswith("._") for part in path.parts)
        ):
            raise RuntimeError(
                f"portable package payload has an unsafe member: {member!r}"
            )
