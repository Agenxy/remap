"""Adversarial tests for deterministic, non-claiming release evidence."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Protocol, Self, cast
from unittest import mock

from tools import (
    remap_release_evidence,
    remap_release_inventory,
)
from tools.remap_release_evidence import (
    app_reference,
    complete_sbom,
    create,
    publish_directory_exclusive,
    swift_reference,
    verify,
    verify_sbom,
)
from tools.remap_release_inventory import (
    AppInput,
    AppInventory,
    Captured,
    SwiftInventory,
    SwiftTarget,
)
from tools.remap_release_model import (
    BUFFER_BYTES,
    ArtifactDigest,
    ArtifactSpec,
    canonical_bytes,
    digest_artifact,
    parse_checksums,
    validate_specs,
)


class ReleaseEvidenceTests(unittest.TestCase):
    """Prove determinism, integrity, coverage, and honest negative claims."""

    def test_create_is_deterministic_and_records_release_limits(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-evidence-") as directory:
            root = Path(directory)
            artifact = root / "remap-source.tar.gz"
            _ = artifact.write_bytes(b"deterministic release bytes")
            spec = ArtifactSpec("remap-source.tar.gz", artifact)
            first = root / "first"
            second = root / "second"
            with release_fakes():
                create(first, (spec,))
                create(second, (spec,))
                verify(first, (spec,))

            self.assertEqual(directory_bytes(first), directory_bytes(second))
            manifest = json_object(first / "manifest.json")
            readiness = object_value(manifest, "releaseReadiness")
            self.assertEqual(readiness["sourceTree"], "dirty")
            self.assertEqual(readiness["distribution"], "source-install-only")
            self.assertEqual(
                readiness["ci"], {"status": "unverified", "verified": False}
            )
            self.assertEqual(
                readiness["macOSCodeSignature"],
                {"status": "not-assessed", "verified": False},
            )
            self.assertEqual(
                readiness["macOSLinkedSDKGate"],
                {"status": "not-assessed", "verified": False},
            )
            self.assertEqual(
                readiness["macOSNotarization"],
                {"status": "absent", "verified": False},
            )
            statement = json_object(first / "provenance.intoto.json")
            predicate = object_value(statement, "predicate")
            self.assertEqual(
                predicate["statementAuthentication"],
                {"signaturePresent": False, "verified": False},
            )

    def test_exclusive_publication_preserves_a_raced_output_directory(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-publish-") as directory:
            root = Path(directory)
            staged = root / "staged"
            output = root / "evidence"
            staged.mkdir()
            output.mkdir()
            _ = (staged / "generated").write_bytes(b"generated evidence")
            _ = (output / "foreign").write_bytes(b"foreign state")

            with self.assertRaisesRegex(FileExistsError, "already exists"):
                publish_directory_exclusive(staged, output)

            self.assertEqual((staged / "generated").read_bytes(), b"generated evidence")
            self.assertEqual((output / "foreign").read_bytes(), b"foreign state")

    def test_verification_rejects_artifact_and_evidence_tampering(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-evidence-") as directory:
            root = Path(directory)
            artifact = root / "remap.crate"
            _ = artifact.write_bytes(b"crate")
            spec = ArtifactSpec("remap.crate", artifact)
            evidence = root / "evidence"
            with release_fakes():
                create(evidence, (spec,))
                _ = artifact.write_bytes(b"changed")
                with self.assertRaisesRegex(ValueError, "manifest"):
                    verify(evidence, (spec,))
                _ = artifact.write_bytes(b"crate")
                _ = (evidence / "manifest.json").write_bytes(b"{}\n")
                with self.assertRaisesRegex(ValueError, "digest mismatch"):
                    verify(evidence, (spec,))

    def test_sbom_labels_every_component_evidence_basis(self) -> None:
        document = complete_sbom(
            raw_sbom(),
            swift_fixture(),
            app_fixture(),
            (ArtifactDigest("remap.crate", 5, "5" * 64),),
            "0.1.1",
        )
        verify_sbom(
            document,
            "0.1.1",
            (ArtifactDigest("remap.crate", 5, "5" * 64),),
        )
        self.assertNotIn("serialNumber", document)
        metadata = object_value(document, "metadata")
        self.assertNotIn("timestamp", metadata)
        components = list_value(document, "components")
        classes = {
            cast("str", component["bom-ref"]): evidence_class(component)
            for value in components
            for component in [object_cast(value)]
        }
        self.assertEqual(classes["pkg:cargo/serde@1.0.0"], "lock-declared")
        self.assertEqual(classes["pkg:cargo/remap@0.1.1"], "artifact-observed")
        self.assertEqual(classes[swift_reference("0.1.1")], "manually-declared-swiftpm")
        self.assertEqual(classes[app_reference("0.1.1")], "manually-declared-esbuild")

    def test_sbom_rejects_an_omitted_final_artifact(self) -> None:
        present = ArtifactDigest("remap.crate", 5, "5" * 64)
        missing = ArtifactDigest("remapd.crate", 6, "6" * 64)
        document = complete_sbom(
            raw_sbom(), swift_fixture(), app_fixture(), (present,), "0.1.1"
        )

        with self.assertRaisesRegex(ValueError, "artifact component set"):
            verify_sbom(document, "0.1.1", (present, missing))

    def test_sbom_rejects_substituted_artifact_identity_fields(self) -> None:
        digest = ArtifactDigest("remap.crate", 5, "5" * 64)
        mutations: dict[str, Callable[[dict[str, object]], None]] = {
            "name": lambda component: component.__setitem__("name", "other.crate"),
            "hash": lambda component: component.__setitem__(
                "hashes", [{"alg": "SHA-256", "content": "6" * 64}]
            ),
            "byte count": replace_artifact_byte_count,
        }
        for label, mutate in mutations.items():
            with self.subTest(field=label):
                document = complete_sbom(
                    raw_sbom(), swift_fixture(), app_fixture(), (digest,), "0.1.1"
                )
                component = artifact_component(document, digest)
                mutate(component)
                with self.assertRaisesRegex(ValueError, "artifact"):
                    verify_sbom(document, "0.1.1", (digest,))

    def test_sbom_rejects_an_extra_final_artifact(self) -> None:
        expected = ArtifactDigest("remap.crate", 5, "5" * 64)
        extra = ArtifactDigest("unreviewed.crate", 7, "7" * 64)
        document = complete_sbom(
            raw_sbom(), swift_fixture(), app_fixture(), (expected, extra), "0.1.1"
        )

        with self.assertRaisesRegex(ValueError, "artifact component set"):
            verify_sbom(document, "0.1.1", (expected,))

    def test_sbom_rejects_distinct_artifact_names_with_one_content_identity(
        self,
    ) -> None:
        first = ArtifactDigest("remap.crate", 5, "5" * 64)
        second = ArtifactDigest("remap-copy.crate", 5, "5" * 64)
        document = complete_sbom(
            raw_sbom(), swift_fixture(), app_fixture(), (first,), "0.1.1"
        )

        with self.assertRaisesRegex(ValueError, "unique content identities"):
            verify_sbom(document, "0.1.1", (first, second))

    def test_sbom_rejects_a_missing_product_artifact_edge(self) -> None:
        digest = ArtifactDigest("remap.crate", 5, "5" * 64)
        document = complete_sbom(
            raw_sbom(), swift_fixture(), app_fixture(), (digest,), "0.1.1"
        )
        product = dependency_row(document, "pkg:generic/remap@0.1.1")
        artifact_reference = "urn:sha256:" + digest.sha256
        product["dependsOn"] = [
            value
            for value in list_value(product, "dependsOn")
            if value != artifact_reference
        ]

        with self.assertRaisesRegex(ValueError, "omits a final-artifact"):
            verify_sbom(document, "0.1.1", (digest,))

    def test_sbom_rejects_a_duplicate_product_artifact_edge(self) -> None:
        digest = ArtifactDigest("remap.crate", 5, "5" * 64)
        document = complete_sbom(
            raw_sbom(), swift_fixture(), app_fixture(), (digest,), "0.1.1"
        )
        product = dependency_row(document, "pkg:generic/remap@0.1.1")
        edges = list_value(product, "dependsOn")
        product["dependsOn"] = [*edges, "urn:sha256:" + digest.sha256]

        with self.assertRaisesRegex(ValueError, "dependencies are ambiguous"):
            verify_sbom(document, "0.1.1", (digest,))

    def test_external_swift_packages_fail_closed(self) -> None:
        package = {
            "dependencies": [{"sourceControl": [{"identity": "outside"}]}],
            "name": "RemapMac",
            "targets": [],
        }
        captured = Captured(canonical_bytes(package), b"")
        with (
            tempfile.TemporaryDirectory(prefix="remap-release-swift-") as directory,
            mock.patch.object(
                remap_release_inventory, "capture", return_value=captured
            ),
            mock.patch.object(remap_release_inventory, "verify_selected_xcode"),
            self.assertRaisesRegex(RuntimeError, "advisory scanner"),
        ):
            _ = remap_release_inventory.swift_inventory(
                Path(directory), Path(directory) / "swift.json"
            )

    def test_syft_warnings_are_fatal(self) -> None:
        completed = subprocess.CompletedProcess[bytes](
            args=("syft",), returncode=0, stdout=b"{}", stderr=b"warning\n"
        )
        with (
            mock.patch.object(subprocess, "run", return_value=completed),
            self.assertRaisesRegex(RuntimeError, "release warning"),
        ):
            _ = remap_release_inventory.capture(
                Path.cwd(), ("syft",), warnings_fatal=True
            )

    def test_checksum_parser_rejects_ambiguity(self) -> None:
        digest = "a" * 64
        self.assertEqual(
            parse_checksums(f"{digest}  remap.crate\n".encode()),
            {"remap.crate": digest},
        )
        for invalid in (
            b"",
            f"{digest} remap.crate\n".encode(),
            f"{digest}  ../remap.crate\n".encode(),
            f"{digest}  remap.crate".encode(),
        ):
            with self.assertRaises(ValueError):
                _ = parse_checksums(invalid)

    def test_artifact_symlinks_and_hardlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-links-") as directory:
            root = Path(directory)
            target = root / "target.crate"
            _ = target.write_bytes(b"target")
            linked = root / "linked.crate"
            linked.symlink_to(target)
            spec = ArtifactSpec.parse(f"linked.crate={linked}")
            self.assertEqual(spec.path, linked)
            with self.assertRaisesRegex(ValueError, "unlinked regular file"):
                validate_specs((spec,))
            hardlink = root / "hardlink.crate"
            os.link(target, hardlink)
            with self.assertRaisesRegex(ValueError, "unlinked regular file"):
                validate_specs((ArtifactSpec("hardlink.crate", hardlink),))

    def test_in_place_content_drift_is_rejected_even_if_mtime_is_restored(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-race-") as directory:
            artifact = Path(directory) / "remap.crate"
            _ = artifact.write_bytes(b"a" * (BUFFER_BYTES + 32))
            original = artifact.stat()
            real_read = os.read
            changed = False

            def racing_read(descriptor: int, count: int) -> bytes:
                nonlocal changed
                block = real_read(descriptor, count)
                if not changed and block:
                    changed = True
                    with artifact.open("r+b") as stream:
                        _ = stream.seek(BUFFER_BYTES + 1)
                        _ = stream.write(b"b")
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.utime(
                        artifact,
                        ns=(original.st_atime_ns, original.st_mtime_ns),
                    )
                return block

            with (
                mock.patch.object(os, "read", side_effect=racing_read),
                self.assertRaisesRegex(RuntimeError, "changed while it was hashed"),
            ):
                _ = digest_artifact(ArtifactSpec("remap.crate", artifact))


def release_fakes() -> PatchGroup:
    """Patch external release tools while retaining all filesystem verification."""
    patches = (
        mock.patch.object(remap_release_evidence, "run_dependency_policy"),
        mock.patch.object(
            remap_release_evidence,
            "repository_state",
            return_value={
                "clean": False,
                "revision": "1" * 40,
                "statusSha256": "2" * 64,
                "timing": "observed before evidence generation; not proven as build input",
            },
        ),
        mock.patch.object(
            remap_release_evidence, "swift_inventory", return_value=swift_fixture()
        ),
        mock.patch.object(
            remap_release_evidence, "app_inventory", return_value=app_fixture()
        ),
        mock.patch.object(
            remap_release_evidence,
            "generate_syft_sbom",
            side_effect=fake_generate_syft_sbom,
        ),
        mock.patch.object(
            remap_release_evidence,
            "toolchain_inventory",
            return_value={"syft": "1.51.0"},
        ),
    )
    return PatchGroup(cast("tuple[Patch, ...]", patches))


def fake_generate_syft_sbom(
    root: Path, scan_root: Path, output: Path, version: str
) -> dict[str, object]:
    """Return a fresh mutable SBOM fixture for each generator invocation."""
    _ = (root, scan_root, output, version)
    return raw_sbom()


class Patch(Protocol):
    """The small unittest patcher surface used by PatchGroup."""

    def start(self) -> object:
        """Apply the patch."""

    def stop(self) -> None:
        """Remove the patch."""


class PatchGroup:
    """Small context manager for a fixed group of unittest patches."""

    def __init__(self, patches: tuple[Patch, ...]) -> None:
        self.patches: tuple[Patch, ...] = patches

    def __enter__(self) -> Self:
        for patch in self.patches:
            _ = patch.start()
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: object,
    ) -> None:
        for patch in reversed(self.patches):
            patch.stop()


def raw_sbom() -> dict[str, object]:
    """Return one minimal Syft-shaped CycloneDX fixture."""
    return {
        "bomFormat": "CycloneDX",
        "components": [
            {
                "bom-ref": "pkg:cargo/serde@1.0.0",
                "name": "serde",
                "properties": [
                    {
                        "name": "syft:package:foundBy",
                        "value": "rust-cargo-lock-cataloger",
                    },
                    {"name": "syft:location:0:path", "value": "/materials/Cargo.lock"},
                ],
                "purl": "pkg:cargo/serde@1.0.0",
                "type": "library",
                "version": "1.0.0",
            },
            {
                "bom-ref": "pkg:cargo/remap@0.1.1",
                "name": "remap",
                "properties": [
                    {"name": "syft:location:0:path", "value": "/artifacts/remap.crate"}
                ],
                "purl": "pkg:cargo/remap@0.1.1",
                "type": "application",
                "version": "0.1.1",
            },
        ],
        "dependencies": [
            {"dependsOn": ["pkg:cargo/serde@1.0.0"], "ref": "syft-root"},
            {"dependsOn": [], "ref": "pkg:cargo/remap@0.1.1"},
            {"dependsOn": [], "ref": "pkg:cargo/serde@1.0.0"},
        ],
        "metadata": {
            "component": {
                "bom-ref": "syft-root",
                "name": "Remap",
                "type": "file",
                "version": "0.1.1",
            },
            "timestamp": "unstable",
            "tools": {
                "components": [
                    {
                        "author": "anchore",
                        "name": "syft",
                        "type": "application",
                        "version": "1.51.0",
                    }
                ]
            },
        },
        "serialNumber": "urn:uuid:unstable",
        "specVersion": "1.7",
        "version": 1,
    }


def swift_fixture() -> SwiftInventory:
    """Return one local Swift target graph."""
    return SwiftInventory(
        name="RemapMac",
        targets=(
            SwiftTarget("Core", "regular", ()),
            SwiftTarget("App", "executable", ("Core",)),
        ),
    )


def app_fixture() -> AppInventory:
    """Return one exact first-party App input graph."""
    return AppInventory(
        inputs=(AppInput("crates/remap-mcp/app/dashboard.ts", "3" * 64),),
        aggregate_sha256="4" * 64,
    )


def evidence_class(component: dict[str, object]) -> str:
    """Extract the one required component evidence class."""
    properties = list_value(component, "properties")
    values = [
        cast("str", property_value["value"])
        for value in properties
        for property_value in [object_cast(value)]
        if property_value.get("name") == "org.agenxy.remap:evidence-class"
    ]
    if len(values) != 1:
        raise AssertionError("fixture component lacks one evidence class")
    return values[0]


def artifact_component(
    document: dict[str, object], digest: ArtifactDigest
) -> dict[str, object]:
    reference = "urn:sha256:" + digest.sha256
    matches = [
        component
        for value in list_value(document, "components")
        for component in [object_cast(value)]
        if component.get("bom-ref") == reference
    ]
    if len(matches) != 1:
        raise AssertionError("fixture lacks exactly one final-artifact component")
    return matches[0]


def replace_artifact_byte_count(component: dict[str, object]) -> None:
    for value in list_value(component, "properties"):
        property_value = object_cast(value)
        if property_value.get("name") == "org.agenxy.remap:artifact-byte-count":
            property_value["value"] = "999"
            return
    raise AssertionError("fixture artifact lacks its byte-count property")


def dependency_row(document: dict[str, object], reference: str) -> dict[str, object]:
    matches = [
        dependency
        for value in list_value(document, "dependencies")
        for dependency in [object_cast(value)]
        if dependency.get("ref") == reference
    ]
    if len(matches) != 1:
        raise AssertionError("fixture lacks exactly one dependency row")
    return matches[0]


def directory_bytes(directory: Path) -> dict[str, bytes]:
    """Read a small evidence directory for byte-for-byte comparison."""
    return {path.name: path.read_bytes() for path in sorted(directory.iterdir())}


def json_object(path: Path) -> dict[str, object]:
    """Read one tested evidence object."""
    return object_cast(cast("object", json.loads(path.read_bytes())))


def object_value(document: dict[str, object], key: str) -> dict[str, object]:
    """Read one required fixture object."""
    return object_cast(document[key])


def list_value(document: dict[str, object], key: str) -> list[object]:
    """Read one required fixture array."""
    value = document[key]
    if not isinstance(value, list):
        raise TypeError(f"{key} must be an array")
    return cast("list[object]", value)


def object_cast(value: object) -> dict[str, object]:
    """Narrow one fixture value to an object."""
    if not isinstance(value, dict):
        raise TypeError("fixture value must be an object")
    return cast("dict[str, object]", value)


if __name__ == "__main__":
    _ = unittest.main()
