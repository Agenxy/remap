"""Pure, deterministic models for Remap release evidence."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import cast

ARTIFACT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}")
BUFFER_BYTES = 1_048_576
MAXIMUM_ARTIFACTS = 64
SHA256_HEX_LENGTH = 64


@dataclass(frozen=True)
class ArtifactSpec:
    """One explicit release artifact with a portable public name."""

    name: str
    path: Path

    @classmethod
    def parse(cls, value: str) -> ArtifactSpec:
        """Parse NAME=PATH without allowing path syntax in the public name."""
        name, separator, raw_path = value.partition("=")
        if not separator or not ARTIFACT_NAME.fullmatch(name) or not raw_path:
            raise ValueError(
                "artifact must be NAME=PATH with a portable one-segment name"
            )
        expanded = Path(raw_path).expanduser()
        lexical = Path(os.path.abspath(expanded))
        return cls(name=name, path=lexical)


@dataclass(frozen=True)
class ArtifactDigest:
    """Stable content identity for one immutable regular file."""

    name: str
    byte_count: int
    sha256: str

    def document(self) -> dict[str, object]:
        """Render the canonical public manifest entry."""
        return {
            "byteCount": self.byte_count,
            "name": self.name,
            "sha256": self.sha256,
        }


def artifact_reference(digest: ArtifactDigest) -> str:
    """Return a content-addressed identity for one final artifact file."""
    return f"urn:sha256:{digest.sha256}"


def verify_sbom_artifacts(
    components: list[object],
    dependencies: list[object],
    product_reference: str,
    digests: tuple[ArtifactDigest, ...],
) -> None:
    """Bind exactly one final-artifact component and product edge per digest."""
    expected = {artifact_reference(digest): digest for digest in digests}
    if len(expected) != len(digests):
        raise ValueError("release artifacts must have unique content identities")
    artifacts: dict[str, dict[str, object]] = {}
    for value in components:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component must be an object")
        component = cast("dict[str, object]", value)
        reference = component.get("bom-ref")
        if not isinstance(reference, str) or not _is_artifact_component(component):
            continue
        if reference in artifacts:
            raise ValueError("release SBOM artifact components are duplicated")
        artifacts[reference] = component
    if set(artifacts) != set(expected):
        raise ValueError(
            "release SBOM artifact component set is incomplete or unexpected"
        )
    for reference, digest in expected.items():
        component = artifacts[reference]
        if (
            component.get("type") != "file"
            or component.get("name") != digest.name
            or component.get("hashes") != [{"alg": "SHA-256", "content": digest.sha256}]
        ):
            raise ValueError(
                f"release SBOM artifact component is invalid: {digest.name}"
            )
        properties = component.get("properties")
        if not isinstance(properties, list):
            raise TypeError("release SBOM artifact properties must be an array")
        property_values = _component_property_values(cast("list[object]", properties))
        if property_values.get("org.agenxy.remap:evidence-class") != [
            "artifact-observed"
        ] or property_values.get("org.agenxy.remap:artifact-byte-count") != [
            str(digest.byte_count)
        ]:
            raise ValueError(
                f"release SBOM artifact evidence is invalid: {digest.name}"
            )
    product_edges: list[str] | None = None
    for value in dependencies:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX dependency must be an object")
        dependency = cast("dict[str, object]", value)
        if dependency.get("ref") != product_reference:
            continue
        raw_edges = dependency.get("dependsOn")
        if not isinstance(raw_edges, list) or not all(
            isinstance(edge, str) for edge in cast("list[object]", raw_edges)
        ):
            raise TypeError("CycloneDX product dependencies must be a string array")
        product_edges = cast("list[str]", raw_edges)
        break
    if product_edges is None or product_edges != sorted(set(product_edges)):
        raise ValueError("release SBOM product dependencies are ambiguous")
    if set(expected) - set(product_edges):
        raise ValueError("release SBOM product omits a final-artifact dependency")


def _is_artifact_component(component: dict[str, object]) -> bool:
    reference = component.get("bom-ref")
    if isinstance(reference, str) and reference.startswith("urn:sha256:"):
        return True
    properties = component.get("properties")
    return isinstance(properties, list) and any(
        isinstance(value, dict)
        and cast("dict[str, object]", value).get("name")
        == "org.agenxy.remap:artifact-byte-count"
        for value in cast("list[object]", properties)
    )


def _component_property_values(properties: list[object]) -> dict[str, list[object]]:
    values: dict[str, list[object]] = {}
    for value in properties:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component property must be an object")
        property_value = cast("dict[str, object]", value)
        name = property_value.get("name")
        if not isinstance(name, str) or "value" not in property_value:
            raise TypeError("CycloneDX component property is incomplete")
        values.setdefault(name, []).append(property_value["value"])
    return values


def validate_specs(specs: tuple[ArtifactSpec, ...]) -> None:
    """Reject ambiguous, missing, linked, or non-file artifact inputs."""
    if not 1 <= len(specs) <= MAXIMUM_ARTIFACTS:
        raise ValueError(f"provide between 1 and {MAXIMUM_ARTIFACTS} artifacts")
    names = [spec.name for spec in specs]
    if len(names) != len(set(names)):
        raise ValueError("artifact names must be unique")
    paths = [spec.path for spec in specs]
    if len(paths) != len(set(paths)):
        raise ValueError("artifact paths must be unique")
    for spec in specs:
        information = spec.path.lstat()
        if (
            not stat.S_ISREG(information.st_mode)
            or spec.path.is_symlink()
            or information.st_nlink != 1
        ):
            raise ValueError(f"artifact {spec.name} must be an unlinked regular file")


def digest_artifact(spec: ArtifactSpec) -> ArtifactDigest:
    """Hash an artifact through a no-follow descriptor and reject races."""
    flags = os.O_RDONLY | os.O_CLOEXEC
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(spec.path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError(f"artifact {spec.name} must be an unlinked regular file")
        digest = hashlib.sha256()
        byte_count = 0
        while block := os.read(descriptor, BUFFER_BYTES):
            digest.update(block)
            byte_count += len(block)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    current = spec.path.lstat()
    identities = {file_identity(value) for value in (before, after, current)}
    if len(identities) != 1 or byte_count != before.st_size:
        raise RuntimeError(f"artifact {spec.name} changed while it was hashed")
    return ArtifactDigest(spec.name, before.st_size, digest.hexdigest())


def sha256_file(path: Path) -> str:
    """Hash one evidence or material file without loading it into memory."""
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(BUFFER_BYTES):
            digest.update(block)
    return digest.hexdigest()


def file_identity(information: os.stat_result) -> tuple[int, ...]:
    """Bind every mutable inode property relevant to artifact hashing."""
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_gid,
        information.st_nlink,
        information.st_size,
        information.st_mtime_ns,
        information.st_ctime_ns,
    )


def canonical_bytes(value: object) -> bytes:
    """Encode JSON with stable keys, whitespace, Unicode, and a final newline."""
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    ).encode("utf-8")


def canonicalize(value: object) -> object:
    """Recursively sort object keys and semantically unordered JSON arrays."""
    if isinstance(value, dict):
        table = cast("dict[str, object]", value)
        return {key: canonicalize(table[key]) for key in sorted(table)}
    if isinstance(value, list):
        items = [canonicalize(item) for item in cast("list[object]", value)]
        return sorted(items, key=lambda item: canonical_bytes(item))
    return value


def checksum_lines(digests: tuple[ArtifactDigest, ...]) -> bytes:
    """Render portable SHA-256 checksum lines in artifact-name order."""
    text = "".join(
        f"{digest.sha256}  {digest.name}\n"
        for digest in sorted(digests, key=lambda item: item.name)
    )
    return text.encode("utf-8")


def parse_checksums(data: bytes) -> dict[str, str]:
    """Parse the exact restricted SHA256SUMS representation."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("checksum file must be UTF-8") from error
    if not text.endswith("\n"):
        raise ValueError("checksum file must end with a newline")
    checksums: dict[str, str] = {}
    for line in text.splitlines():
        digest, separator, name = line.partition("  ")
        if (
            separator != "  "
            or len(digest) != SHA256_HEX_LENGTH
            or any(character not in "0123456789abcdef" for character in digest)
            or not ARTIFACT_NAME.fullmatch(name)
            or name in checksums
        ):
            raise ValueError("checksum file contains an invalid line")
        checksums[name] = digest
    if not checksums:
        raise ValueError("checksum file contains no artifacts")
    return checksums
