"""Exact local verification for unpublished Remap Cargo packages."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import cast

import tomllib


def verify_policy_copies(root: Path, product_version: str) -> None:
    """Verify privacy, license, notice, and native version authorities."""
    document = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = document.get("workspace")
    if not isinstance(workspace, dict):
        raise TypeError("Cargo.toml must contain a workspace table")
    sources = workspace_sources(root, cast("dict[str, object]", workspace))
    copies = {
        root / "PRIVACY.md": (root / "crates/remap-mcp/src/privacy.md",),
        root / "LICENSE": tuple(source / "LICENSE" for source in sources.values()),
        root / "NOTICE": tuple(source / "NOTICE" for source in sources.values()),
    }
    for authority, distributed in copies.items():
        verify_exact_copies(root, authority, distributed)
    native_version = (
        root / "platforms/macos/Sources/RemapSystemKit/RemapProduct.swift"
    ).read_text(encoding="utf-8")
    expected = f'public static let version = "{product_version}"'
    if native_version.count(expected) != 1:
        raise RuntimeError(
            "the native product version differs from workspace.package.version"
        )


def verify_exact_copies(
    root: Path,
    authority: Path,
    distributed: tuple[Path, ...],
) -> None:
    """Require every declared distributed policy file to exist byte-for-byte."""
    for copy in distributed:
        if not copy.is_file():
            raise RuntimeError(
                f"{copy.relative_to(root)} is missing the required {authority.name}"
            )
        if copy.read_bytes() != authority.read_bytes():
            raise RuntimeError(
                f"{copy.relative_to(root)} differs from {authority.name}"
            )


def verify(root: Path, version: str, workspace: dict[str, object]) -> None:
    """Compile the exact unpublished crate archives against one another."""
    sources = workspace_sources(root, workspace)
    verify_publishable_dependency_closure(sources)
    cargo = shutil.which("cargo")
    rust_version = workspace_rust_version(workspace)
    if cargo is None:
        raise RuntimeError("the pinned Cargo executable is not available")
    with tempfile.TemporaryDirectory(prefix="remap-package-verify-") as directory:
        verification_root = Path(directory)
        cargo_home = verification_root / "cargo-home"
        cargo_home.mkdir()
        graph = dependency_graph(sources)
        package_environment = os.environ.copy()
        package_environment["CARGO_HOME"] = str(cargo_home)
        package_directory = (
            cargo_target_directory(root, package_environment) / "package"
        )
        for name in sources:
            patches = select_patches(name, graph, sources)
            write_patch_config(cargo_home, patches)
            run(
                root,
                (
                    cargo,
                    f"+{rust_version}",
                    "package",
                    "--locked",
                    "-p",
                    name,
                    "--allow-dirty",
                    "--no-verify",
                ),
                package_environment,
            )
        extracted = verification_root / "sources"
        extracted.mkdir()
        roots = {
            name: extract_package_archive(
                root,
                name,
                version,
                extracted,
                package_directory=package_directory,
            )
            for name in sources
        }
        environment = package_environment.copy()
        environment.update(
            CARGO_TARGET_DIR=str(verification_root / "target"),
            RUSTFLAGS="-Dwarnings",
        )
        for name in sources:
            patches = select_patches(name, graph, roots)
            write_patch_config(cargo_home, patches)
            run(
                root,
                (
                    cargo,
                    f"+{rust_version}",
                    "check",
                    "--locked",
                    "--manifest-path",
                    str(roots[name] / "Cargo.toml"),
                    "--all-targets",
                    "--all-features",
                ),
                environment,
            )


def workspace_rust_version(workspace: dict[str, object]) -> str:
    """Read the exact Rust release shared by every packaged crate."""
    package = workspace.get("package")
    if not isinstance(package, dict):
        raise TypeError("workspace.package must be a table")
    value = cast("dict[str, object]", package).get("rust-version")
    if not isinstance(value, str) or not value:
        raise TypeError("workspace.package.rust-version must be a version string")
    return value


def cargo_target_directory(
    root: Path, environment: dict[str, str] | None = None
) -> Path:
    """Resolve Cargo's target directory using its working-directory semantics."""
    values = os.environ if environment is None else environment
    configured = values.get("CARGO_TARGET_DIR")
    if configured is None:
        return root / "target"
    target = Path(configured).expanduser()
    return target if target.is_absolute() else root / target


def workspace_sources(root: Path, workspace: dict[str, object]) -> dict[str, Path]:
    """Read package names and source paths from authoritative workspace members."""
    members = workspace.get("members")
    if not isinstance(members, list):
        raise TypeError("workspace members must be an array")
    sources: dict[str, Path] = {}
    for member in cast("list[object]", members):
        if not isinstance(member, str):
            raise TypeError("workspace member paths must be strings")
        document = tomllib.loads(
            (root / member / "Cargo.toml").read_text(encoding="utf-8")
        )
        package = document.get("package")
        if not isinstance(package, dict):
            raise TypeError(f"workspace member {member} has no package table")
        name = cast("dict[str, object]", package).get("name")
        if not isinstance(name, str):
            raise TypeError(f"workspace member {member} has no package name")
        sources[name] = root / member
    return dict(sorted(sources.items()))


def dependency_graph(sources: dict[str, Path]) -> dict[str, set[str]]:
    """Build direct internal dependency edges from every package manifest."""
    names = set(sources)
    graph: dict[str, set[str]] = {}
    for name, source in sources.items():
        document = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
        graph[name] = manifest_dependencies(document, names)
    return graph


def verify_publishable_dependency_closure(sources: dict[str, Path]) -> None:
    """Reject a publishable crate whose archive depends on a private crate."""
    unpublished: set[str] = set()
    documents: dict[str, dict[str, object]] = {}
    for name, source in sources.items():
        document = tomllib.loads((source / "Cargo.toml").read_text(encoding="utf-8"))
        documents[name] = document
        package = document.get("package")
        if isinstance(package, dict):
            publish = cast("dict[str, object]", package).get("publish")
            if publish is False or publish == []:
                unpublished.add(name)
    for name, document in documents.items():
        if name in unpublished:
            continue
        private_dependencies = manifest_dependencies(document, unpublished)
        if private_dependencies:
            rendered = ", ".join(sorted(private_dependencies))
            raise RuntimeError(
                f"publishable package {name} depends on private package(s): {rendered}"
            )


def manifest_dependencies(node: object, internal: set[str]) -> set[str]:
    """Collect dependencies from normal, build, dev, and target tables."""
    if not isinstance(node, dict):
        return set()
    dependencies: set[str] = set()
    for key, value in cast("dict[str, object]", node).items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
            if isinstance(value, dict):
                dependencies.update(set(cast("dict[str, object]", value)) & internal)
            continue
        dependencies.update(manifest_dependencies(value, internal))
    return dependencies


def select_patches(
    root: str,
    graph: dict[str, set[str]],
    sources: dict[str, Path],
) -> dict[str, Path]:
    """Select only the transitive internal patches used by one package."""
    selected: set[str] = set()
    pending = list(graph[root])
    while pending:
        name = pending.pop()
        if name in selected:
            continue
        selected.add(name)
        pending.extend(graph[name])
    return {name: sources[name] for name in sorted(selected)}


def extract_package_archive(
    root: Path,
    name: str,
    version: str,
    destination: Path,
    *,
    package_directory: Path | None = None,
) -> Path:
    """Extract one first-party Cargo archive after validating every member path."""
    archive_root = package_directory or cargo_target_directory(root) / "package"
    archive = archive_root / f"{name}-{version}.crate"
    if not archive.is_file():
        raise RuntimeError(f"cargo package did not create {archive}")
    expected_root = f"{name}-{version}"
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        if not members or any(
            member.name != expected_root
            and not member.name.startswith(f"{expected_root}/")
            for member in members
        ):
            raise RuntimeError(f"package {name} contains an invalid archive path")
        if any(not (member.isfile() or member.isdir()) for member in members):
            raise RuntimeError(f"package {name} contains a link or special file")
        bundle.extractall(destination, members=members, filter="data")
    package_root = destination / expected_root
    for policy_file in ("LICENSE", "NOTICE"):
        packaged = package_root / policy_file
        authority = root / policy_file
        if not packaged.is_file():
            raise RuntimeError(f"package {name} omitted {policy_file}")
        if packaged.read_bytes() != authority.read_bytes():
            raise RuntimeError(
                f"package {name} contains a non-authoritative {policy_file}"
            )
    return package_root


def write_patch_config(cargo_home: Path, packages: dict[str, Path]) -> None:
    """Point registry dependencies at the exact local package archives."""
    lines: list[str] = []
    if packages:
        lines.append("[patch.crates-io]")
        lines.extend(
            f"{json.dumps(name)} = {{ path = {json.dumps(str(path))} }}"
            for name, path in sorted(packages.items())
        )
    _ = (cargo_home / "config.toml").write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )


def run(
    root: Path,
    arguments: tuple[str, ...],
    environment: dict[str, str] | None = None,
) -> None:
    """Run one exact package verification boundary."""
    _ = subprocess.run(arguments, cwd=root, env=environment, check=True)
