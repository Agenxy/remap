"""Descriptor-pinned Linux generation source manifest."""

from __future__ import annotations

import hashlib
import os
import struct
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from tools.remap_linux_bootstrap import (
    FileIdentity,
    file_identity,
    require_path_matches_descriptor,
)

SOURCE_MANIFEST_DOMAIN = b"remap.linux-source-manifest/v1\0"
EXPECTED_SOURCE_COUNT = 30


class DigestWriter(Protocol):
    """Minimal hashlib surface used by the streaming manifest encoder."""

    def update(self, data: bytes, /) -> None: ...


@dataclass(frozen=True)
class SourceSpec:
    """One exact source path and its immutable generation identity."""

    logical_path: str
    path: Path
    source_mode: int
    installed_mode: int


@dataclass(frozen=True)
class PinnedSource:
    """One source held open with its reviewed identity."""

    spec: SourceSpec
    descriptor: int
    identity: FileIdentity


@dataclass(frozen=True)
class PinnedSourceManifest:
    """All generation inputs held open across preview, approval, and commit."""

    sources: tuple[PinnedSource, ...]
    sha256: str

    def verify(self) -> None:
        """Reject path, metadata, xattr, or byte drift from the approved manifest."""
        for source in self.sources:
            verification = _open_descriptor_rooted(source.spec.path)
            try:
                if file_identity(verification) != source.identity:
                    raise RuntimeError(
                        "a reviewed Linux generation source path changed: "
                        + source.spec.logical_path
                    )
            finally:
                os.close(verification)
            require_path_matches_descriptor(source.spec.path, source.descriptor)
            if file_identity(source.descriptor) != source.identity:
                raise RuntimeError(
                    "a reviewed Linux generation source changed during lifecycle work: "
                    + source.spec.logical_path
                )


@contextmanager
def pin_source_manifest(
    *,
    cli: Path,
    daemon: Path,
    helper: Path,
    assets: Path,
    manpage_names: Sequence[str],
    owner_uid: int,
) -> Generator[PinnedSourceManifest, None, None]:
    """Open, validate, digest, and hold every exact generation source."""
    specs = _source_specs(cli, daemon, helper, assets, manpage_names)
    if len(specs) != EXPECTED_SOURCE_COUNT:
        raise RuntimeError("the Linux source manifest does not contain 30 artifacts")
    opened: list[PinnedSource] = []
    try:
        for spec in specs:
            descriptor = _open_descriptor_rooted(spec.path)
            try:
                identity = _review_source(spec, descriptor, owner_uid)
            except BaseException:
                os.close(descriptor)
                raise
            opened.append(PinnedSource(spec, descriptor, identity))
        manifest = PinnedSourceManifest(
            sources=tuple(opened), sha256=_digest_pinned_sources(opened)
        )
        manifest.verify()
        yield manifest
    finally:
        for source in reversed(opened):
            os.close(source.descriptor)


def source_manifest_digest(
    sources: Sequence[tuple[str, int, bytes]],
) -> str:
    """Compute the language-neutral v1 digest for fixtures and interoperability."""
    ordered = tuple(sorted(sources, key=lambda source: source[0]))
    digest = hashlib.sha256()
    digest.update(SOURCE_MANIFEST_DOMAIN)
    digest.update(struct.pack("<Q", len(ordered)))
    for logical_path, mode, content in ordered:
        encoded_path = logical_path.encode("utf-8")
        digest.update(struct.pack("<Q", len(encoded_path)))
        digest.update(encoded_path)
        digest.update(struct.pack("<I", mode))
        digest.update(struct.pack("<Q", len(content)))
        digest.update(content)
    return digest.hexdigest()


def _source_specs(
    cli: Path,
    daemon: Path,
    helper: Path,
    assets: Path,
    manpage_names: Sequence[str],
) -> tuple[SourceSpec, ...]:
    specs = [
        SourceSpec("remap", cli, 0o500, 0o755),
        SourceSpec("remapd", daemon, 0o500, 0o755),
        SourceSpec("remap-linux-system", helper, 0o500, 0o755),
        SourceSpec("LICENSE", assets / "LICENSE", 0o400, 0o644),
        SourceSpec("NOTICE", assets / "NOTICE", 0o400, 0o644),
        *(
            SourceSpec(
                f"share/man/man1/{name}",
                assets / "manpages" / name,
                0o400,
                0o644,
            )
            for name in manpage_names
        ),
        *(
            SourceSpec(
                f"share/completions/remap.{shell}",
                assets / f"remap.{shell}",
                0o400,
                0o644,
            )
            for shell in ("bash", "fish", "zsh")
        ),
    ]
    specs.sort(key=lambda spec: spec.logical_path)
    logical_paths = tuple(spec.logical_path for spec in specs)
    if len(logical_paths) != len(set(logical_paths)):
        raise RuntimeError("the Linux source manifest contains duplicate paths")
    return tuple(specs)


def _review_source(spec: SourceSpec, descriptor: int, owner_uid: int) -> FileIdentity:
    identity = file_identity(descriptor)
    require_path_matches_descriptor(spec.path, descriptor)
    if (
        identity.owner_uid != owner_uid
        or identity.links != 1
        or identity.mode != spec.source_mode
        or identity.xattrs
    ):
        raise RuntimeError(
            "a Linux generation source has unsafe ownership or metadata: "
            + spec.logical_path
        )
    return identity


def _open_descriptor_rooted(path: Path) -> int:
    if not path.is_absolute() or not path.name:
        raise RuntimeError("a Linux source path is not canonical and absolute")
    directory = os.open(
        path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    try:
        for component in path.parts[1:-1]:
            following = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory,
            )
            os.close(directory)
            directory = following
        return os.open(
            path.name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
    finally:
        os.close(directory)


def _digest_pinned_sources(sources: Sequence[PinnedSource]) -> str:
    digest = hashlib.sha256()
    digest.update(SOURCE_MANIFEST_DOMAIN)
    digest.update(struct.pack("<Q", len(sources)))
    for source in sources:
        encoded_path = source.spec.logical_path.encode("utf-8")
        digest.update(struct.pack("<Q", len(encoded_path)))
        digest.update(encoded_path)
        digest.update(struct.pack("<I", source.spec.installed_mode))
        digest.update(struct.pack("<Q", source.identity.size))
        _update_from_descriptor(digest, source.descriptor)
    return digest.hexdigest()


def _update_from_descriptor(digest: DigestWriter, descriptor: int) -> None:
    offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        _ = os.lseek(descriptor, offset, os.SEEK_SET)
