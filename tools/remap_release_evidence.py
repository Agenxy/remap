"""Create and verify deterministic, explicitly unsigned Remap release evidence."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, cast

import tomllib

from tools.remap_release_inventory import (
    AppInventory,
    SwiftInventory,
    app_inventory,
    copy_materials,
    generate_syft_sbom,
    run_dependency_policy,
    swift_inventory,
    toolchain_inventory,
)
from tools.remap_release_model import (
    ArtifactDigest,
    ArtifactSpec,
    artifact_reference,
    canonical_bytes,
    canonicalize,
    checksum_lines,
    digest_artifact,
    parse_checksums,
    sha256_file,
    validate_specs,
    verify_sbom_artifacts,
)

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_CHECKSUMS = "artifacts.sha256"
ATTESTATION = "provenance.intoto.json"
EVIDENCE_CHECKSUMS = "evidence.sha256"
MANIFEST = "manifest.json"
SBOM = "sbom.cdx.json"
EVIDENCE_FILES = (ARTIFACT_CHECKSUMS, ATTESTATION, MANIFEST, SBOM)
PRODUCT_REPOSITORY = "https://github.com/agenxy/remap"
PRODUCT_REF_PREFIX = "pkg:generic/remap@"
PREDICATE_TYPE = "https://github.com/agenxy/remap/attestation/release-evidence/v1"
SCHEMA_VERSION = 1


class ExclusiveRename(Protocol):
    """Typed shape of Darwin and Linux exclusive directory rename calls."""

    argtypes: list[object]
    restype: object

    def __call__(
        self,
        old_directory: int,
        old_name: bytes,
        new_directory: int,
        new_name: bytes,
        flags: int,
        /,
    ) -> int: ...


def create(output: Path, specs: tuple[ArtifactSpec, ...]) -> None:
    """Create, self-verify, and atomically publish one evidence directory."""
    validate_specs(specs)
    output = output.expanduser().resolve()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"release evidence output already exists: {output}")
    if not output.parent.is_dir():
        raise FileNotFoundError(
            f"release evidence parent does not exist: {output.parent}"
        )
    version = product_version(ROOT)
    repository = repository_state(ROOT)
    run_dependency_policy(ROOT)
    digests = tuple(sorted((digest_artifact(spec) for spec in specs), key=name_of))
    with tempfile.TemporaryDirectory(
        prefix=f".{output.name}.", dir=output.parent
    ) as directory:
        workspace = Path(directory)
        evidence = workspace / "evidence"
        scan_root = workspace / "scan"
        evidence.mkdir()
        scan_root.mkdir()
        stage_artifacts(scan_root / "artifacts", specs, digests)
        materials = copy_materials(ROOT, scan_root / "materials")
        swift = swift_inventory(ROOT, workspace / "swift-package.json")
        app = app_inventory(ROOT, workspace / "app-metafile.json")
        raw_sbom = generate_syft_sbom(
            ROOT, scan_root, workspace / "raw-sbom.json", version
        )
        sbom = complete_sbom(raw_sbom, swift, app, digests, version)
        material_entries = material_documents(ROOT, materials)
        manifest = manifest_document(
            version, digests, material_entries, repository, swift, app
        )
        attestation = attestation_document(
            version,
            digests,
            material_entries,
            repository,
            toolchain_inventory(ROOT),
        )
        _ = (evidence / ARTIFACT_CHECKSUMS).write_bytes(checksum_lines(digests))
        write_json(evidence / MANIFEST, manifest)
        write_json(evidence / SBOM, sbom)
        write_json(evidence / ATTESTATION, attestation)
        write_evidence_checksums(evidence)
        verify(evidence, specs)
        publish_directory_exclusive(evidence, output)


def publish_directory_exclusive(staged: Path, output: Path) -> None:
    """Atomically publish one directory without replacing raced state."""
    if "/" in staged.name or "/" in output.name:
        raise ValueError("release evidence publication names are invalid")
    source_parent = os.open(
        staged.parent,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    destination_parent: int | None = None
    try:
        destination_parent = os.open(
            output.parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        library = ctypes.CDLL(None, use_errno=True)
        if sys.platform == "darwin":
            rename = cast("ExclusiveRename", cast("object", library.renameatx_np))
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            arguments = (
                source_parent,
                os.fsencode(staged.name),
                destination_parent,
                os.fsencode(output.name),
                0x4,
            )
        elif sys.platform.startswith("linux"):
            rename = cast("ExclusiveRename", cast("object", library.renameat2))
            rename.argtypes = [
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_int,
                ctypes.c_char_p,
                ctypes.c_uint,
            ]
            arguments = (
                source_parent,
                os.fsencode(staged.name),
                destination_parent,
                os.fsencode(output.name),
                0x1,
            )
        else:
            raise OSError(
                "atomic exclusive release-evidence publication is unsupported"
            )
        rename.restype = ctypes.c_int
        _ = ctypes.set_errno(0)
        result = rename(*arguments)
        if result != 0:
            code = ctypes.get_errno()
            if code == errno.EEXIST:
                raise FileExistsError(
                    f"release evidence output already exists: {output}"
                )
            raise OSError(code, os.strerror(code), output)
        os.fsync(source_parent)
        os.fsync(destination_parent)
    finally:
        if destination_parent is not None:
            os.close(destination_parent)
        os.close(source_parent)


def verify(
    evidence: Path,
    specs: tuple[ArtifactSpec, ...],
) -> None:
    """Verify every artifact, evidence file, semantic cross-link, and SBOM parse."""
    validate_specs(specs)
    evidence = evidence.expanduser().resolve()
    verify_evidence_files(evidence)
    manifest = read_canonical_json(evidence / MANIFEST)
    sbom = read_canonical_json(evidence / SBOM)
    attestation = read_canonical_json(evidence / ATTESTATION)
    digests = tuple(sorted((digest_artifact(spec) for spec in specs), key=name_of))
    verify_manifest(manifest, digests)
    verify_artifact_checksums(evidence / ARTIFACT_CHECKSUMS, digests)
    verify_attestation(attestation, digests)
    verify_sbom(sbom, product_version(ROOT), digests)


def complete_sbom(
    document: dict[str, object],
    swift: SwiftInventory,
    app: AppInventory,
    digests: tuple[ArtifactDigest, ...],
    version: str,
) -> dict[str, object]:
    """Normalize Syft output and add its missing first-party language graphs."""
    _ = document.pop("serialNumber", None)
    metadata = object_property(document, "metadata", "CycloneDX SBOM")
    _ = metadata.pop("timestamp", None)
    original_component = object_property(metadata, "component", "SBOM metadata")
    original_reference = required_string(
        original_component, "bom-ref", "SBOM metadata component"
    )
    product_reference = f"{PRODUCT_REF_PREFIX}{version}"
    metadata["component"] = product_component(product_reference, version)
    metadata["properties"] = [
        {
            "name": "org.agenxy.remap:evidence:authentication",
            "value": "unsigned",
        },
        {
            "name": "org.agenxy.remap:rust:dependency-basis",
            "value": "locked source resolution; not binary introspection",
        },
        {
            "name": "org.agenxy.remap:swift:dependency-basis",
            "value": "SwiftPM graph; external packages prohibited",
        },
        {
            "name": "org.agenxy.remap:typescript:dependency-basis",
            "value": "exact esbuild inputs; unrecognized package inputs prohibited",
        },
    ]
    components = object_list(document, "components", "CycloneDX SBOM")
    dependencies = object_list(document, "dependencies", "CycloneDX SBOM")
    remove_unidentified_files(components, dependencies)
    classify_syft_components(components)
    components.extend(artifact_components(digests))
    components.extend(swift_components(swift, version))
    components.append(app_component(app, version))
    require_rust_inventory(components)
    replace_dependency_reference(dependencies, original_reference, product_reference)
    add_dependency(
        dependencies,
        product_reference,
        tuple(artifact_reference(digest) for digest in digests)
        + swift_and_app_refs(version),
    )
    for digest in digests:
        add_dependency(dependencies, artifact_reference(digest), ())
    add_dependency(
        dependencies,
        swift_reference(version),
        tuple(target.reference(version) for target in swift.targets),
    )
    for target in swift.targets:
        add_dependency(
            dependencies,
            target.reference(version),
            tuple(
                swift_target_ref(swift, name, version) for name in target.dependencies
            ),
        )
    add_dependency(dependencies, app_reference(version), ())
    ensure_unique_component_references(components)
    return cast("dict[str, object]", canonicalize(document))


def manifest_document(
    version: str,
    digests: tuple[ArtifactDigest, ...],
    materials: list[dict[str, object]],
    repository: dict[str, object],
    swift: SwiftInventory,
    app: AppInventory,
) -> dict[str, object]:
    """Describe exact bytes, dependency evidence, and deliberately absent claims."""
    return {
        "artifacts": [digest.document() for digest in digests],
        "claims": {
            "artifactDigestsVerified": True,
            "artifactSignaturesAssessed": False,
            "authenticatedAttestation": False,
            "buildInvocationObserved": False,
            "ciIdentityVerified": False,
            "notarizationAssessed": False,
        },
        "dependencyEvidence": {
            "rust": "Cargo.lock cataloged by Syft; binary dependency embedding absent",
            "swift": {
                "externalPackageCount": 0,
                "package": swift.name,
                "targets": [target.name for target in swift.targets],
            },
            "typescriptApp": {
                "aggregateSha256": app.aggregate_sha256,
                "bundledThirdPartyPackageCount": 0,
                "inputs": [
                    {"path": item.path, "sha256": item.sha256} for item in app.inputs
                ],
            },
        },
        "materials": materials,
        "product": {
            "name": "Remap",
            "repository": PRODUCT_REPOSITORY,
            "version": version,
        },
        "releaseReadiness": {
            "ci": {"status": "unverified", "verified": False},
            "distribution": "source-install-only",
            "macOSCodeSignature": {
                "status": "not-assessed",
                "verified": False,
            },
            "macOSLinkedSDKGate": {
                "status": "not-assessed",
                "verified": False,
            },
            "macOSNotarization": {"status": "absent", "verified": False},
            "sourceTree": "clean" if repository["clean"] is True else "dirty",
        },
        "repositoryObservation": repository,
        "schemaVersion": SCHEMA_VERSION,
    }


def attestation_document(
    version: str,
    digests: tuple[ArtifactDigest, ...],
    materials: list[dict[str, object]],
    repository: dict[str, object],
    toolchain: dict[str, object],
) -> dict[str, object]:
    """Build an unsigned in-toto statement that cannot imply SLSA provenance."""
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "predicate": {
            "artifactSignature": {"assessed": False, "verified": False},
            "buildInvocation": {"command": None, "observed": False},
            "builderIdentity": {"id": None, "verified": False},
            "ciIdentity": {"id": None, "verified": False},
            "evidenceGenerator": {
                "name": "Remap release evidence",
                "schemaVersion": SCHEMA_VERSION,
            },
            "materials": materials,
            "notarization": {"assessed": False, "verified": False},
            "repositoryObservation": repository,
            "statementAuthentication": {
                "signaturePresent": False,
                "verified": False,
            },
            "toolchainObservation": toolchain,
        },
        "predicateType": PREDICATE_TYPE,
        "subject": [
            {"digest": {"sha256": digest.sha256}, "name": digest.name}
            for digest in digests
        ],
        "version": version,
    }


def repository_state(root: Path) -> dict[str, object]:
    """Observe Git without claiming that an artifact was built from this state."""
    revision = git(root, ("rev-parse", "HEAD")).decode("ascii").strip()
    if len(revision) != 40 or any(
        value not in "0123456789abcdef" for value in revision
    ):
        raise RuntimeError("Git returned an invalid source revision")
    status = git(
        root,
        ("status", "--porcelain=v1", "--untracked-files=all", "-z"),
    )
    return {
        "clean": not status,
        "revision": revision,
        "statusSha256": sha256_bytes(status),
        "timing": "observed before evidence generation; not proven as build input",
    }


def stage_artifacts(
    destination: Path,
    specs: tuple[ArtifactSpec, ...],
    expected: tuple[ArtifactDigest, ...],
) -> None:
    """Copy final bytes into the isolated scan root and recheck every digest."""
    destination.mkdir()
    expected_by_name = {digest.name: digest for digest in expected}
    for spec in specs:
        target = destination / spec.name
        _ = shutil.copyfile(spec.path, target)
        staged = digest_artifact(ArtifactSpec(spec.name, target))
        if staged != expected_by_name[spec.name]:
            raise RuntimeError(f"artifact {spec.name} changed while it was staged")


def material_documents(root: Path, paths: tuple[Path, ...]) -> list[dict[str, object]]:
    """Bind every source dependency authority without leaking absolute paths."""
    return [
        {
            "path": str(path.relative_to(root)),
            "sha256": sha256_file(path),
        }
        for path in sorted(paths)
    ]


def product_component(reference: str, version: str) -> dict[str, object]:
    """Return the top-level CycloneDX product component."""
    return {
        "bom-ref": reference,
        "name": "Remap",
        "purl": reference,
        "properties": [
            {
                "name": "org.agenxy.remap:evidence-class",
                "value": "artifact-subject-set",
            }
        ],
        "supplier": {"name": "Agenxy"},
        "type": "application",
        "version": version,
    }


def artifact_components(
    digests: tuple[ArtifactDigest, ...],
) -> list[dict[str, object]]:
    """Represent each final artifact as an observed CycloneDX file component."""
    return [
        {
            "bom-ref": artifact_reference(digest),
            "hashes": [{"alg": "SHA-256", "content": digest.sha256}],
            "name": digest.name,
            "properties": [
                {
                    "name": "org.agenxy.remap:evidence-class",
                    "value": "artifact-observed",
                },
                {
                    "name": "org.agenxy.remap:artifact-byte-count",
                    "value": str(digest.byte_count),
                },
            ],
            "type": "file",
        }
        for digest in digests
    ]


def swift_components(swift: SwiftInventory, version: str) -> list[dict[str, object]]:
    """Render the native package and each shipped Swift target."""
    components: list[dict[str, object]] = [
        {
            "bom-ref": swift_reference(version),
            "name": swift.name,
            "properties": [
                {
                    "name": "org.agenxy.remap:evidence-class",
                    "value": "manually-declared-swiftpm",
                },
                {"name": "org.agenxy.remap:language", "value": "Swift"},
                {
                    "name": "org.agenxy.remap:external-package-count",
                    "value": "0",
                },
            ],
            "type": "framework",
            "version": version,
        }
    ]
    for target in swift.targets:
        components.append(
            {
                "bom-ref": target.reference(version),
                "name": target.name,
                "properties": [
                    {
                        "name": "org.agenxy.remap:evidence-class",
                        "value": "manually-declared-swiftpm",
                    },
                    {"name": "org.agenxy.remap:language", "value": "Swift"},
                ],
                "type": "application" if target.kind == "executable" else "library",
                "version": version,
            }
        )
    return components


def app_component(app: AppInventory, version: str) -> dict[str, object]:
    """Render the embedded TypeScript MCP App and its exact aggregate digest."""
    properties = [
        {
            "name": "org.agenxy.remap:evidence-class",
            "value": "manually-declared-esbuild",
        },
        {"name": "org.agenxy.remap:language", "value": "TypeScript"},
        {"name": "org.agenxy.remap:bundled-third-party-count", "value": "0"},
    ]
    properties.extend(
        {
            "name": f"org.agenxy.remap:app-input:{item.path}",
            "value": item.sha256,
        }
        for item in app.inputs
    )
    return {
        "bom-ref": app_reference(version),
        "hashes": [{"alg": "SHA-256", "content": app.aggregate_sha256}],
        "name": "Remap MCP App",
        "properties": properties,
        "type": "application",
        "version": version,
    }


def swift_and_app_refs(version: str) -> tuple[str, ...]:
    """Return product edges missing from Syft's language catalogers."""
    return (swift_reference(version), app_reference(version))


def swift_target_ref(swift: SwiftInventory, name: str, version: str) -> str:
    """Resolve one already-validated Swift target name to its stable reference."""
    for target in swift.targets:
        if target.name == name:
            return target.reference(version)
    raise RuntimeError(f"unknown Swift target dependency: {name}")


def swift_reference(version: str) -> str:
    """Return the stable native package component reference."""
    return f"pkg:generic/remap-swift@{version}"


def app_reference(version: str) -> str:
    """Return the stable embedded App component reference."""
    return f"pkg:generic/remap-mcp-app@{version}"


def replace_dependency_reference(
    dependencies: list[object], original: str, replacement: str
) -> None:
    """Retarget Syft's generated root edges to Remap's stable product reference."""
    for value in dependencies:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX dependency must be an object")
        dependency = cast("dict[str, object]", value)
        if dependency.get("ref") == original:
            dependency["ref"] = replacement
        depends_on = dependency.get("dependsOn")
        if isinstance(depends_on, list):
            dependency["dependsOn"] = [
                replacement if item == original else item
                for item in cast("list[object]", depends_on)
            ]


def add_dependency(
    dependencies: list[object], reference: str, additions: tuple[str, ...]
) -> None:
    """Merge stable dependency edges without duplicate component rows."""
    for value in dependencies:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX dependency must be an object")
        dependency = cast("dict[str, object]", value)
        if dependency.get("ref") != reference:
            continue
        existing = dependency.get("dependsOn", [])
        if not isinstance(existing, list):
            raise TypeError("CycloneDX dependsOn must be a string array")
        existing_values = cast("list[object]", existing)
        if not all(isinstance(item, str) for item in existing_values):
            raise TypeError("CycloneDX dependsOn must be a string array")
        dependency["dependsOn"] = sorted(
            set(cast("list[str]", existing_values)) | set(additions)
        )
        return
    dependencies.append({"dependsOn": sorted(set(additions)), "ref": reference})


def require_rust_inventory(components: list[object]) -> None:
    """Fail rather than emit a multi-language SBOM with no Cargo inventory."""
    for value in components:
        if isinstance(value, dict):
            purl = cast("dict[str, object]", value).get("purl")
            if isinstance(purl, str) and purl.startswith("pkg:cargo/"):
                return
    raise RuntimeError("Syft found no locked Rust packages")


def classify_syft_components(components: list[object]) -> None:
    """Label every discovered package by the bytes that support its inclusion."""
    for value in components:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component must be an object")
        component = cast("dict[str, object]", value)
        raw_properties = component.get("properties", [])
        if not isinstance(raw_properties, list):
            raise TypeError("CycloneDX component properties must be an array")
        properties = cast("list[object]", raw_properties)
        locations = syft_locations(properties)
        observed = any(location.startswith("/artifacts/") for location in locations)
        declared = any(location.startswith("/materials/") for location in locations)
        if observed and declared:
            evidence_class = "artifact-observed-and-lock-declared"
        elif observed:
            evidence_class = "artifact-observed"
        elif declared:
            evidence_class = "lock-declared"
        else:
            evidence_class = "scanner-observed"
        properties.append(
            {
                "name": "org.agenxy.remap:evidence-class",
                "value": evidence_class,
            }
        )
        component["properties"] = properties


def remove_unidentified_files(
    components: list[object], dependencies: list[object]
) -> None:
    """Drop Syft scan-root file identities that leak staging paths."""
    removed: set[str] = set()
    retained: list[object] = []
    for value in components:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component must be an object")
        component = cast("dict[str, object]", value)
        if component.get("type") == "file" and not isinstance(
            component.get("purl"), str
        ):
            removed.add(
                required_string(component, "bom-ref", "CycloneDX file component")
            )
        else:
            retained.append(component)
    components[:] = retained
    retained_dependencies: list[object] = []
    for value in dependencies:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX dependency must be an object")
        dependency = cast("dict[str, object]", value)
        reference = required_string(dependency, "ref", "CycloneDX dependency")
        if reference in removed:
            continue
        depends_on = dependency.get("dependsOn")
        if isinstance(depends_on, list):
            dependency["dependsOn"] = [
                item for item in cast("list[object]", depends_on) if item not in removed
            ]
        retained_dependencies.append(dependency)
    dependencies[:] = retained_dependencies


def syft_locations(properties: list[object]) -> set[str]:
    """Extract portable Syft evidence locations from component properties."""
    locations: set[str] = set()
    for value in properties:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component property must be an object")
        property_value = cast("dict[str, object]", value)
        name = property_value.get("name")
        location = property_value.get("value")
        if (
            isinstance(name, str)
            and name.startswith("syft:location:")
            and isinstance(location, str)
        ):
            locations.add(location)
    return locations


def ensure_unique_component_references(components: list[object]) -> None:
    """Reject ambiguous component identities before evidence publication."""
    references: list[str] = []
    for value in components:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component must be an object")
        reference = required_string(
            cast("dict[str, object]", value), "bom-ref", "CycloneDX component"
        )
        references.append(reference)
    if len(references) != len(set(references)):
        raise RuntimeError("CycloneDX component references are not unique")


def write_evidence_checksums(evidence: Path) -> None:
    """Bind every non-circular evidence sidecar with SHA-256."""
    rows = "".join(
        f"{sha256_file(evidence / name)}  {name}\n" for name in sorted(EVIDENCE_FILES)
    )
    _ = (evidence / EVIDENCE_CHECKSUMS).write_text(rows, encoding="utf-8")


def verify_evidence_files(evidence: Path) -> None:
    """Reject missing, extra, linked, noncanonical, or modified evidence files."""
    expected = {*EVIDENCE_FILES, EVIDENCE_CHECKSUMS}
    if not evidence.is_dir() or evidence.is_symlink():
        raise ValueError("release evidence must be a directory")
    actual = {path.name for path in evidence.iterdir()}
    if actual != expected:
        raise ValueError("release evidence contains missing or unexpected files")
    for name in expected:
        path = evidence / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"release evidence file is unsafe: {name}")
    checksums = parse_checksums((evidence / EVIDENCE_CHECKSUMS).read_bytes())
    if set(checksums) != set(EVIDENCE_FILES):
        raise ValueError("evidence checksum coverage is incomplete")
    for name, expected_digest in checksums.items():
        if sha256_file(evidence / name) != expected_digest:
            raise ValueError(f"release evidence digest mismatch: {name}")


def verify_manifest(
    document: dict[str, object], digests: tuple[ArtifactDigest, ...]
) -> None:
    """Require the manifest to describe the currently supplied artifact bytes."""
    if document.get("schemaVersion") != SCHEMA_VERSION:
        raise ValueError("release manifest schema is unsupported")
    artifacts = document.get("artifacts")
    expected = [digest.document() for digest in digests]
    if artifacts != expected:
        raise ValueError("release manifest does not match the supplied artifacts")
    claims = object_property(document, "claims", "release manifest")
    forbidden = (
        "artifactSignaturesAssessed",
        "authenticatedAttestation",
        "buildInvocationObserved",
        "ciIdentityVerified",
        "notarizationAssessed",
    )
    if any(claims.get(name) is not False for name in forbidden):
        raise ValueError("release manifest makes an unproven trust claim")
    readiness = object_property(document, "releaseReadiness", "release manifest")
    if readiness.get("distribution") != "source-install-only":
        raise ValueError("release manifest overstates distribution readiness")
    ci = object_property(readiness, "ci", "release readiness")
    if ci != {"status": "unverified", "verified": False}:
        raise ValueError("release manifest overstates CI identity or status")
    signature = object_property(readiness, "macOSCodeSignature", "release readiness")
    if signature != {"status": "not-assessed", "verified": False}:
        raise ValueError("release manifest overstates code-signature evidence")
    notarization = object_property(readiness, "macOSNotarization", "release readiness")
    if notarization != {"status": "absent", "verified": False}:
        raise ValueError("release manifest overstates notarization evidence")


def verify_artifact_checksums(path: Path, digests: tuple[ArtifactDigest, ...]) -> None:
    """Require SHA256SUMS to match the manifest and live artifact bytes."""
    expected = {digest.name: digest.sha256 for digest in digests}
    if parse_checksums(path.read_bytes()) != expected:
        raise ValueError("artifact checksums do not match the supplied artifacts")


def verify_attestation(
    document: dict[str, object], digests: tuple[ArtifactDigest, ...]
) -> None:
    """Require exact subjects and explicit absence of authenticated provenance."""
    expected = [
        {"digest": {"sha256": digest.sha256}, "name": digest.name} for digest in digests
    ]
    if document.get("_type") != "https://in-toto.io/Statement/v1":
        raise ValueError("release statement has an invalid in-toto type")
    if (
        document.get("predicateType") != PREDICATE_TYPE
        or document.get("subject") != expected
    ):
        raise ValueError("release statement does not match supplied artifacts")
    predicate = object_property(document, "predicate", "release statement")
    authentication = object_property(
        predicate, "statementAuthentication", "release statement predicate"
    )
    if authentication != {"signaturePresent": False, "verified": False}:
        raise ValueError("release statement makes an authenticated provenance claim")


def verify_sbom(
    document: dict[str, object],
    version: str,
    digests: tuple[ArtifactDigest, ...],
) -> None:
    """Require deterministic CycloneDX language coverage and unsigned metadata."""
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.7":
        raise ValueError("release SBOM must be CycloneDX 1.7")
    if "serialNumber" in document:
        raise ValueError("release SBOM contains a nondeterministic serial number")
    metadata = object_property(document, "metadata", "release SBOM")
    if "timestamp" in metadata:
        raise ValueError("release SBOM contains a nondeterministic timestamp")
    component = object_property(metadata, "component", "release SBOM metadata")
    product_reference = f"{PRODUCT_REF_PREFIX}{version}"
    if component.get("bom-ref") != product_reference:
        raise ValueError("release SBOM product identity is incorrect")
    verify_component_evidence_classes([component])
    components = object_list(document, "components", "release SBOM")
    require_rust_inventory(components)
    references = {
        cast("dict[str, object]", item).get("bom-ref")
        for item in components
        if isinstance(item, dict)
    }
    required = {swift_reference(version), app_reference(version)}
    if not required <= references:
        raise ValueError("release SBOM omitted Swift or TypeScript App coverage")
    verify_component_evidence_classes(components)
    dependency_values = object_list(document, "dependencies", "release SBOM")
    verify_dependency_cross_references(
        dependency_values,
        {value for value in references if isinstance(value, str)} | {product_reference},
    )
    verify_sbom_artifacts(components, dependency_values, product_reference, digests)


def verify_component_evidence_classes(components: list[object]) -> None:
    """Require one explicit evidence class on every SBOM component."""
    for value in components:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX component must be an object")
        properties = cast("dict[str, object]", value).get("properties")
        if not isinstance(properties, list):
            raise TypeError("CycloneDX component omitted its evidence class")
        classes: list[object] = []
        for item in cast("list[object]", properties):
            if isinstance(item, dict):
                property_value = cast("dict[str, object]", item)
                if property_value.get("name") == "org.agenxy.remap:evidence-class":
                    classes.append(property_value.get("value"))
        if len(classes) != 1 or not isinstance(classes[0], str):
            raise ValueError("CycloneDX component evidence class is ambiguous")


def verify_dependency_cross_references(
    dependencies: list[object], component_references: set[str]
) -> None:
    """Require every emitted dependency row and edge to resolve inside the BOM."""
    rows: dict[str, set[str]] = {}
    for value in dependencies:
        if not isinstance(value, dict):
            raise TypeError("CycloneDX dependency must be an object")
        dependency = cast("dict[str, object]", value)
        reference = required_string(dependency, "ref", "CycloneDX dependency")
        raw_dependencies = dependency.get("dependsOn")
        if not isinstance(raw_dependencies, list) or not all(
            isinstance(item, str) for item in cast("list[object]", raw_dependencies)
        ):
            raise TypeError("CycloneDX dependsOn must be a string array")
        if reference in rows:
            raise ValueError("CycloneDX dependency references are duplicated")
        rows[reference] = set(cast("list[str]", raw_dependencies))
    if not set(rows) <= component_references:
        raise ValueError("CycloneDX dependency row references an unknown component")
    if any(
        dependency not in component_references
        for dependencies_for_component in rows.values()
        for dependency in dependencies_for_component
    ):
        raise ValueError("CycloneDX dependency graph references an unknown component")


def read_canonical_json(path: Path) -> dict[str, object]:
    """Decode JSON and prove the stored bytes use the canonical representation."""
    value = cast("object", json.loads(path.read_bytes()))
    if not isinstance(value, dict):
        raise TypeError(f"release evidence must be a JSON object: {path.name}")
    document = cast("dict[str, object]", value)
    if canonical_bytes(document) != path.read_bytes():
        raise ValueError(f"release evidence JSON is not canonical: {path.name}")
    return document


def write_json(path: Path, document: dict[str, object]) -> None:
    """Write one deterministic JSON sidecar."""
    _ = path.write_bytes(canonical_bytes(document))


def product_version(root: Path) -> str:
    """Read the one workspace product version authority."""
    document = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = object_property(document, "workspace", "Cargo.toml")
    package = object_property(workspace, "package", "Cargo workspace")
    return required_string(package, "version", "Cargo workspace package")


def git(root: Path, arguments: tuple[str, ...]) -> bytes:
    """Capture one bounded, read-only Git observation."""
    result = subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=True,
        capture_output=True,
        timeout=30,
    )
    return result.stdout


def object_property(
    document: dict[str, object], key: str, description: str
) -> dict[str, object]:
    """Read one required JSON object property."""
    value = document.get(key)
    if not isinstance(value, dict):
        raise TypeError(f"{description} omitted object {key}")
    return cast("dict[str, object]", value)


def object_list(
    document: dict[str, object], key: str, description: str
) -> list[object]:
    """Read one required JSON array property."""
    value = document.get(key)
    if not isinstance(value, list):
        raise TypeError(f"{description} omitted array {key}")
    return cast("list[object]", value)


def required_string(document: dict[str, object], key: str, description: str) -> str:
    """Read one required nonempty JSON string property."""
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise TypeError(f"{description} omitted string {key}")
    return value


def name_of(digest: ArtifactDigest) -> str:
    """Return an artifact name for stable sorting."""
    return digest.name


def sha256_bytes(data: bytes) -> str:
    """Return a SHA-256 without retaining the input."""
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Arguments:
    """Validated command-line arguments without argparse Any leakage."""

    command: Literal["create", "verify"]
    artifacts: tuple[str, ...]
    evidence: Path


def parse_arguments(arguments: list[str]) -> Arguments:
    """Parse the isolated create and verify command surfaces."""
    parser = argparse.ArgumentParser(
        prog="python -m tools.remap_release_evidence",
        description="Create or verify deterministic, explicitly unsigned release evidence.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("create", "verify"):
        subparser = subparsers.add_parser(command)
        _ = subparser.add_argument("--artifact", action="append", required=True)
        _ = subparser.add_argument("--evidence", type=Path, required=True)
    namespace = parser.parse_args(arguments)
    command_value = cast("object", namespace.command)
    artifact_value = cast("object", namespace.artifact)
    evidence_value = cast("object", namespace.evidence)
    if command_value not in {"create", "verify"}:
        raise ValueError("release evidence command is invalid")
    if not isinstance(artifact_value, list) or not all(
        isinstance(value, str) for value in cast("list[object]", artifact_value)
    ):
        raise TypeError("release evidence artifacts must be strings")
    if not isinstance(evidence_value, Path):
        raise TypeError("release evidence path is invalid")
    return Arguments(
        command=cast("Literal['create', 'verify']", command_value),
        artifacts=tuple(cast("list[str]", artifact_value)),
        evidence=evidence_value,
    )


def main(arguments: list[str] | None = None) -> int:
    """Run the evidence command with one concise, actionable failure surface."""
    options = parse_arguments(sys.argv[1:] if arguments is None else arguments)
    try:
        specs = tuple(ArtifactSpec.parse(value) for value in options.artifacts)
        evidence = options.evidence
        if options.command == "create":
            create(evidence, specs)
            print(f"Release evidence created and verified at {evidence}")
        else:
            verify(evidence, specs)
            print(f"Release evidence verified at {evidence}")
    except (
        FileExistsError,
        FileNotFoundError,
        json.JSONDecodeError,
        OSError,
        RuntimeError,
        TypeError,
        ValueError,
        subprocess.SubprocessError,
    ) as error:
        print(f"Release evidence failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
