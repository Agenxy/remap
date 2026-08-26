"""Atomic publication and safe opening of bounded Remap release artifacts."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path
from typing import BinaryIO

MAXIMUM_FILE_BYTES = 134_217_728
MAXIMUM_SIGNATURE_BYTES = 16_384


def publish_release_artifacts(
    *,
    package: Path,
    signature: Path,
    output: Path,
    output_signature: Path,
) -> None:
    """Publish the package/signature pair without overwriting another artifact."""
    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        published.append(
            (
                output,
                _copy_release_artifact(
                    package, output, maximum_bytes=MAXIMUM_FILE_BYTES * 2
                ),
            )
        )
        published.append(
            (
                output_signature,
                _copy_release_artifact(
                    signature,
                    output_signature,
                    maximum_bytes=MAXIMUM_SIGNATURE_BYTES,
                ),
            )
        )
    except BaseException:
        cleanup_errors: list[str] = []
        for path, identity in reversed(published):
            try:
                _unlink_same_inode(path, identity)
            except OSError as error:
                cleanup_errors.append(f"{path}: {error}")
        if cleanup_errors:
            raise RuntimeError(
                "release publication failed and exact cleanup also failed: "
                + "; ".join(cleanup_errors)
            )
        raise


def verify_release_artifact(path: Path, *, maximum_bytes: int) -> None:
    information = path.lstat()
    if (
        path.is_symlink()
        or not path.is_file()
        or information.st_nlink != 1
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) & 0o022
        or information.st_size <= 0
        or information.st_size > maximum_bytes
    ):
        raise RuntimeError(f"release artifact has unsafe metadata: {path}")


def open_release_artifact(
    path: Path,
    *,
    maximum_bytes: int,
    expected_owner_uid: int | None = None,
) -> BinaryIO:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_nlink != 1
            or information.st_uid
            != (os.getuid() if expected_owner_uid is None else expected_owner_uid)
            or stat.S_IMODE(information.st_mode) & 0o022
            or information.st_size <= 0
            or information.st_size > maximum_bytes
        ):
            raise RuntimeError(f"release artifact has unsafe metadata: {path}")
        return os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise


def _copy_release_artifact(
    source: Path,
    destination: Path,
    *,
    maximum_bytes: int,
) -> tuple[int, int]:
    verify_release_artifact(source, maximum_bytes=maximum_bytes)
    identity: tuple[int, int] | None = None
    try:
        with source.open("rb") as input_file, destination.open("xb") as output_file:
            information = os.fstat(output_file.fileno())
            identity = information.st_dev, information.st_ino
            shutil.copyfileobj(input_file, output_file, length=1_048_576)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.chmod(destination, 0o444)
        verify_release_artifact(destination, maximum_bytes=maximum_bytes)
        if _sha256(source) != _sha256(destination):
            raise RuntimeError(
                f"release artifact changed while publishing {destination}"
            )
        return identity
    except BaseException:
        if identity is not None:
            try:
                _unlink_same_inode(destination, identity)
            except FileNotFoundError:
                pass
            except OSError as error:
                raise RuntimeError(
                    f"release publication failed and exact cleanup failed: {error}"
                ) from error
        raise


def _unlink_same_inode(path: Path, identity: tuple[int, int]) -> None:
    information = path.lstat()
    if (information.st_dev, information.st_ino) != identity:
        raise OSError(f"release artifact identity changed before cleanup: {path}")
    path.unlink()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()
