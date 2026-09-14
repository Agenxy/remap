"""Typed package and tool inventory for deterministic release evidence."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from tools.remap_freshness import verify_selected_xcode
from tools.remap_release_model import canonical_bytes, sha256_file

SYFT_VERSION = "1.51.1"
TOOL_TIMEOUT_SECONDS = 300


@dataclass(frozen=True)
class SwiftTarget:
    """One first-party non-test Swift package target."""

    name: str
    kind: str
    dependencies: tuple[str, ...]

    def reference(self, version: str) -> str:
        """Return a stable generic Package URL for this private target."""
        return f"pkg:generic/remap-swift-{self.name.lower()}@{version}"


@dataclass(frozen=True)
class SwiftInventory:
    """The dependency-free native Swift package and its shipped targets."""

    name: str
    targets: tuple[SwiftTarget, ...]


@dataclass(frozen=True)
class AppInput:
    """One first-party file proven to enter the embedded MCP App bundle."""

    path: str
    sha256: str


@dataclass(frozen=True)
class AppInventory:
    """The exact first-party inputs to the committed TypeScript App bundle."""

    inputs: tuple[AppInput, ...]
    aggregate_sha256: str


def run_dependency_policy(root: Path) -> None:
    """Fail on every Rust or Bun advisory, policy warning, or stale App bundle."""
    run(
        root,
        ("mise", "exec", "--", "cargo", "deny", "check", "--deny", "warnings"),
    )
    run(
        root,
        ("mise", "exec", "--", "bun", "audit", "--audit-level=low"),
    )


def swift_inventory(root: Path, metadata_path: Path) -> SwiftInventory:
    """Ask SwiftPM for the exact native graph and reject unaudited externals."""
    verify_selected_xcode()
    result = capture(
        root,
        (
            "/usr/bin/xcrun",
            "swift",
            "package",
            "--package-path",
            "platforms/macos",
            "dump-package",
        ),
    )
    _ = metadata_path.write_bytes(result.stdout)
    document = json_object(result.stdout, "Swift package description")
    dependencies = document.get("dependencies")
    if not isinstance(dependencies, list):
        raise TypeError("Swift package description omitted dependencies")
    if dependencies:
        raise RuntimeError(
            "external Swift packages require an approved advisory scanner before release"
        )
    name = required_string(document, "name", "Swift package description")
    raw_targets = document.get("targets")
    if not isinstance(raw_targets, list):
        raise TypeError("Swift package description omitted targets")
    targets = tuple(
        sorted(
            (
                parse_swift_target(target)
                for target in cast("list[object]", raw_targets)
                if target_kind(target) != "test"
            ),
            key=lambda target: target.name,
        )
    )
    if not targets:
        raise RuntimeError("Swift package description contains no shipped targets")
    known = {target.name for target in targets}
    if any(set(target.dependencies) - known for target in targets):
        raise RuntimeError("Swift target graph references an unknown shipped target")
    return SwiftInventory(name=name, targets=targets)


def app_inventory(root: Path, metadata_path: Path) -> AppInventory:
    """Rebuild-check the App and bind every first-party esbuild input."""
    run(
        root,
        (
            "mise",
            "exec",
            "--",
            "bun",
            "tools/build-app.ts",
            "--check",
            "--metadata",
            str(metadata_path),
        ),
    )
    document = json_object(metadata_path.read_bytes(), "esbuild metadata")
    raw_inputs = document.get("inputs")
    if not isinstance(raw_inputs, dict):
        raise TypeError("esbuild metadata omitted inputs")
    input_paths = sorted(cast("dict[str, object]", raw_inputs))
    approved_root = (root / "crates/remap-mcp/app").resolve()
    paths: set[Path] = {
        root / "crates/remap-mcp/app/dashboard.css",
        root / "crates/remap-mcp/app/dashboard.html",
        root / "crates/remap-mcp/app/dashboard.js",
    }
    for relative in input_paths:
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(approved_root):
            raise RuntimeError(
                f"bundled App input {relative} lacks explicit package inventory"
            )
        paths.add(candidate)
    inputs = tuple(
        AppInput(path=str(path.relative_to(root)), sha256=sha256_file(path))
        for path in sorted(paths)
    )
    aggregate = sha256_bytes(
        canonical_bytes([{"path": item.path, "sha256": item.sha256} for item in inputs])
    )
    return AppInventory(inputs=inputs, aggregate_sha256=aggregate)


def generate_syft_sbom(
    root: Path,
    scan_root: Path,
    output: Path,
    version: str,
) -> dict[str, object]:
    """Generate one CycloneDX 1.7 inventory and fail on Syft diagnostics."""
    version_result = capture(
        root,
        ("mise", "exec", "--", "syft", "version", "-o", "json"),
        warnings_fatal=True,
    )
    version_document = json_object(version_result.stdout, "Syft version")
    if version_document.get("version") != SYFT_VERSION:
        raise RuntimeError(f"Syft must be exact version {SYFT_VERSION}")
    _ = capture(
        root,
        (
            "mise",
            "exec",
            "--",
            "syft",
            "scan",
            f"dir:{scan_root}",
            "--source-name",
            "Remap",
            "--source-version",
            version,
            "--output",
            f"cyclonedx-json={output}",
        ),
        warnings_fatal=True,
    )
    document = json_object(output.read_bytes(), "CycloneDX SBOM")
    if document.get("bomFormat") != "CycloneDX" or document.get("specVersion") != "1.7":
        raise RuntimeError("Syft did not produce CycloneDX 1.7 JSON")
    return document


def toolchain_inventory(root: Path) -> dict[str, object]:
    """Record only public tool versions, never host or account identity."""
    tools = {
        "bun": capture(root, ("mise", "exec", "--", "bun", "--version")).text(),
        "cargo": capture(root, ("mise", "exec", "--", "cargo", "--version")).text(),
        "rustc": capture(root, ("mise", "exec", "--", "rustc", "--version")).text(),
        "swift": capture(root, ("/usr/bin/xcrun", "swift", "--version")).text(),
        "syft": SYFT_VERSION,
    }
    if os.uname().sysname == "Darwin":
        tools["xcode"] = capture(root, ("/usr/bin/xcodebuild", "-version")).text()
    return dict(sorted(tools.items()))


def run(root: Path, arguments: tuple[str, ...]) -> None:
    """Run one exact tool boundary with bounded output and no shell."""
    _ = capture(root, arguments)


@dataclass(frozen=True)
class Captured:
    """Bounded standard streams returned by a successful tool invocation."""

    stdout: bytes
    stderr: bytes

    def text(self) -> str:
        """Return trimmed UTF-8 standard output."""
        return self.stdout.decode("utf-8").strip()


def capture(
    root: Path,
    arguments: tuple[str, ...],
    *,
    warnings_fatal: bool = False,
) -> Captured:
    """Capture one command, preserving diagnostics and enforcing time limits."""
    result = subprocess.run(
        arguments,
        cwd=root,
        check=False,
        capture_output=True,
        timeout=TOOL_TIMEOUT_SECONDS,
    )
    if result.returncode != 0:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"tool failed ({arguments[0]}): {message}")
    if warnings_fatal and result.stderr:
        message = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"tool emitted a release warning: {message}")
    return Captured(stdout=result.stdout, stderr=result.stderr)


def parse_swift_target(value: object) -> SwiftTarget:
    """Decode one dependency-free first-party Swift target."""
    if not isinstance(value, dict):
        raise TypeError("Swift target must be an object")
    document = cast("dict[str, object]", value)
    name = required_string(document, "name", "Swift target")
    kind = required_string(document, "type", f"Swift target {name}")
    raw_dependencies = document.get("dependencies")
    if not isinstance(raw_dependencies, list):
        raise TypeError(f"Swift target {name} omitted dependencies")
    dependency_values = cast("list[object]", raw_dependencies)
    dependencies = tuple(
        sorted(parse_swift_dependency(item, name) for item in dependency_values)
    )
    return SwiftTarget(name=name, kind=kind, dependencies=dependencies)


def parse_swift_dependency(value: object, target: str) -> str:
    """Accept only local by-name target edges from SwiftPM."""
    if not isinstance(value, dict):
        raise TypeError(f"Swift target {target} has an invalid dependency")
    by_name = cast("dict[str, object]", value).get("byName")
    if not isinstance(by_name, list) or not by_name or not isinstance(by_name[0], str):
        raise RuntimeError(
            f"Swift target {target} has an external or unsupported dependency"
        )
    return by_name[0]


def target_kind(value: object) -> str:
    """Read a Swift target kind for pre-filtering."""
    if not isinstance(value, dict):
        raise TypeError("Swift target must be an object")
    return required_string(cast("dict[str, object]", value), "type", "Swift target")


def json_object(data: bytes, description: str) -> dict[str, object]:
    """Decode a required top-level JSON object."""
    value = cast("object", json.loads(data))
    if not isinstance(value, dict):
        raise TypeError(f"{description} must be a JSON object")
    return cast("dict[str, object]", value)


def required_string(document: dict[str, object], key: str, description: str) -> str:
    """Read one required nonempty string property."""
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise TypeError(f"{description} omitted {key}")
    return value


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 of one deterministic byte string."""
    return hashlib.sha256(data).hexdigest()


def copy_materials(root: Path, destination: Path) -> tuple[Path, ...]:
    """Copy exact dependency authorities into an isolated Syft scan root."""
    sources = (
        root / "Cargo.lock",
        root / "bun.lock",
        root / "package.json",
        root / "mise.toml",
        root / "platforms/macos/Package.swift",
    )
    destination.mkdir()
    copies: list[Path] = []
    for source in sources:
        target = destination / source.name
        _ = shutil.copyfile(source, target)
        copies.append(source)
    return tuple(copies)
