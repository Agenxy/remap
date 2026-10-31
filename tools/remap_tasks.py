#!/usr/bin/env -S uv run --script
# SPDX-License-Identifier: GPL-3.0-or-later
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Typed development, verification, and CLI installation tasks for Remap."""

from __future__ import annotations

import argparse
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import cast

from tools.remap_app import build as build_native_app
from tools.remap_app import launch as launch_native_app
from tools.remap_freshness import (
    mise_tool_version,
    release_toolchain_required,
    require_release_toolchain,
    verify_selected_xcode,
)
from tools.remap_help import print_task_help
from tools.remap_linux_install import (
    install_or_update as install_or_update_linux,
)
from tools.remap_linux_install import recover as recover_linux
from tools.remap_linux_install import require_linux_bootstrap
from tools.remap_linux_install import uninstall as uninstall_linux
from tools.remap_macos_artifact import expected_macos_sdk, verify_macos_sdk_metadata
from tools.remap_macos_install import (
    install_or_update as install_or_update_macos,
)
from tools.remap_macos_install import (
    recover as recover_macos,
)
from tools.remap_macos_install import (
    require_macos,
    verify_generated_package_contract,
)
from tools.remap_macos_install import uninstall as uninstall_macos
from tools.remap_macos_portable_package import PortablePackage
from tools.remap_macos_portable_package import build as build_portable_macos_package
from tools.remap_macos_release_installer_signing import (
    ensure_release_installer_identity,
)
from tools.remap_macos_signing import ensure_local_codesigning_identity
from tools.remap_macos_verified_package_install import install_verified_package
from tools.remap_package import (
    cargo_target_directory,
    verify_policy_copies,
    workspace_sources,
)
from tools.remap_package import verify as verify_crate_packages
from tools.remap_rehearsal_key import FINGERPRINT_DOCUMENTS, create_rehearsal_key
from tools.remap_rehearsal_publish import (
    RehearsalInputs,
    rehearsal_root_from_environment,
    source_archive,
)
from tools.remap_rehearsal_publish import publish as publish_rehearsal
from tools.remap_rehearsal_publish import (
    release_directory as rehearsal_release_directory,
)
from tools.remap_release_evidence import create as create_release_evidence
from tools.remap_release_evidence import verify as verify_release_evidence
from tools.remap_release_model import ArtifactSpec
from tools.remap_release_signing import (
    REHEARSAL_KEY_VARIABLE,
    REHEARSAL_PACKAGE_VARIABLE,
    REHEARSAL_PIN,
    SWIFT_VERIFIER,
    PackageKind,
    PackageSigning,
    fingerprint,
    preflight,
    selected_signing,
)

ROOT = Path(__file__).resolve().parent.parent
MISE_DOCUMENT = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))
MISE_TOOLS = cast("dict[str, object]", MISE_DOCUMENT["tools"])

RUST_TOOLCHAIN = mise_tool_version(MISE_TOOLS["rust"])
APP_PATHS = (
    "crates/remap-mcp/app",
    "tools",
    "tests/app",
    "playwright.config.ts",
)
PYTHON_PATHS = (
    "tools/__init__.py",
    "tools/remap_tasks.py",
    "tools/remap_docs.py",
    "tools/remap_freshness.py",
    "tools/remap_help.py",
    "tools/remap_lifecycle_approval.py",
    "tools/remap_linux_bootstrap.py",
    "tools/remap_linux_install.py",
    "tools/remap_linux_protocol.py",
    "tools/remap_linux_schema.py",
    "tools/remap_linux_sources.py",
    "tools/remap_macos_bootstrap.py",
    "tools/remap_macos_install.py",
    "tools/remap_macos_artifact.py",
    "tools/remap_macos_installer_package.py",
    "tools/remap_macos_installer_signing.py",
    "tools/remap_macos_signing.py",
    "tools/remap_macos_native_setup.py",
    "tools/remap_macos_package_metadata.py",
    "tools/remap_macos_protocol.py",
    "tools/remap_macos_portable_package.py",
    "tools/remap_macos_release_installer_signing.py",
    "tools/remap_macos_verified_package_install.py",
    "tools/remap_macos_xar.py",
    "tools/remap_native_package.py",
    "tools/remap_native_model.py",
    "tools/remap_app.py",
    "tools/remap_package.py",
    "tools/remap_release_evidence.py",
    "tools/remap_release_artifacts.py",
    "tools/remap_release_inventory.py",
    "tools/remap_release_model.py",
    "tools/remap_release_signing.py",
    "tools/remap_rehearsal_key.py",
    "tools/remap_rehearsal_publish.py",
    "tests/python/test_app.py",
    "tests/python/test_docs.py",
    "tests/python/test_freshness.py",
    "tests/python/test_rehearsal_key.py",
    "tests/python/test_rehearsal_publish.py",
    "tests/python/test_linux_bootstrap.py",
    "tests/python/test_linux_install.py",
    "tests/python/test_linux_sources.py",
    "tests/python/test_macos_bootstrap.py",
    "tests/python/test_macos_install.py",
    "tests/python/test_macos_artifact.py",
    "tests/python/test_macos_installer_package.py",
    "tests/python/test_macos_installer_signing.py",
    "tests/python/test_macos_signing.py",
    "tests/python/test_macos_native_setup.py",
    "tests/python/test_macos_portable_package.py",
    "tests/python/test_macos_release_installer_signing.py",
    "tests/python/test_macos_verified_package_install.py",
    "tests/python/test_native_package.py",
    "tests/python/test_package.py",
    "tests/python/test_release_evidence.py",
    "tests/python/test_release_signing.py",
    "tests/python/test_tasks.py",
)
WORKSPACE_DOCUMENT = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
WORKSPACE = cast("dict[str, object]", WORKSPACE_DOCUMENT["workspace"])
WORKSPACE_PACKAGE = cast("dict[str, object]", WORKSPACE["package"])
PRODUCT_VERSION_VALUE = WORKSPACE_PACKAGE["version"]
if not isinstance(PRODUCT_VERSION_VALUE, str):
    raise TypeError("workspace package version must be a string")
PRODUCT_VERSION = PRODUCT_VERSION_VALUE
NATIVE_INSTALL_UNAVAILABLE = "native product installation is unavailable on this host"
NATIVE_UNINSTALL_UNAVAILABLE = (
    "native product uninstallation is unavailable on this host"
)
CLI_INSTALL_HINT = "run `make install-cli` only for an intentional CLI-only install"
CLI_UNINSTALL_HINT = "run `make uninstall-cli` only for a CLI-only installation"


def run(arguments: Sequence[str], *, environment: dict[str, str] | None = None) -> None:
    """Run one explicit tool boundary and fail on any nonzero exit."""
    _ = subprocess.run(arguments, cwd=ROOT, env=environment, check=True)


def capture(
    arguments: Sequence[str], *, environment: dict[str, str] | None = None
) -> str:
    """Run one explicit read boundary and return standard output."""
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def write_command_output(arguments: Sequence[str], destination: Path) -> None:
    """Capture one generated artifact without interpreting or normalizing it."""
    with destination.open("wb") as output:
        _ = subprocess.run(arguments, cwd=ROOT, stdout=output, check=True)


def inherited_environment(**changes: str) -> dict[str, str]:
    """Return a process environment with explicit task-local changes."""
    environment = os.environ.copy()
    environment.update(changes)
    return environment


def installation_root() -> Path:
    """Resolve the familiar PREFIX/REMAP_INSTALL_ROOT installation contract."""
    configured = os.environ.get("REMAP_INSTALL_ROOT") or os.environ.get("PREFIX")
    root = Path(configured).expanduser() if configured else Path.home() / ".local"
    return root.resolve()


# Whether the reviewed-toolchain pin refuses, rather than reports. `make check` judges
# code and distributes nothing, so it reports; `make release-check` and every packaging
# path set this and enforce the pin, because an artifact someone else installs must be
# able to name the compiler that produced it.
def task_help() -> None:
    """Print the stable Make-facing task catalog."""
    print_task_help()


def task_setup() -> None:
    """Install pinned compilers, analyzers, packages, and browser runtime."""
    # mise refuses to read a configuration file it has not been told to trust, so in a
    # fresh clone every later `mise` call fails until this runs. Running the repository's
    # own setup task is the act of trusting it.
    run(("mise", "trust", "--quiet"))
    run(("mise", "install"))
    run(("mise", "exec", "--", "bun", "install", "--frozen-lockfile"))
    run(
        (
            "mise",
            "exec",
            "--",
            "bunx",
            "playwright",
            "install",
            "chromium",
            "webkit",
        )
    )


def task_setup_install() -> None:
    """Verify the platform-specific prerequisites for native source installation."""
    if sys.platform == "darwin":
        verify_selected_xcode()
    elif sys.platform == "linux":
        require_linux_bootstrap()
    else:
        raise RuntimeError(NATIVE_INSTALL_UNAVAILABLE)


def task_format() -> None:
    """Apply deterministic first-party formatters and rebuild the embedded App."""
    run(("mise", "exec", "--", "cargo", "fmt", "--all"))
    run(("mise", "exec", "--", "swiftformat", "platforms/macos"))
    run(("mise", "exec", "--", "ruff", "format", *PYTHON_PATHS))
    run(
        (
            "mise",
            "exec",
            "--",
            "bunx",
            "biome",
            "check",
            "--write",
            *APP_PATHS,
        )
    )
    run(("mise", "exec", "--", "bun", "run", "app:build"))


def task_test() -> None:
    """Run development tests; the signed native image contract is release-only."""
    run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "test",
            "--locked",
            "--workspace",
            "--all-targets",
        )
    )
    if sys.platform == "darwin":
        verify_selected_xcode()
        run(("xcrun", "swift", "test", "--package-path", "platforms/macos"))
    run(
        (
            "mise",
            "exec",
            "--",
            "uv",
            "run",
            "python",
            "-m",
            "unittest",
            "discover",
            "-s",
            "tests/python",
            "-v",
        )
    )
    run(("mise", "exec", "--", "bun", "run", "app:check"))


def task_quality() -> None:
    """Run structural and repository-specific quality enforcement."""
    run(("mise", "exec", "--", "ruff", "check", *PYTHON_PATHS))
    run(("mise", "exec", "--", "ruff", "format", "--check", *PYTHON_PATHS))
    run(("mise", "exec", "--", "basedpyright", *PYTHON_PATHS))
    if sys.platform == "darwin":
        # Both Swift linters keep a cache under `target/`, and the quality gate runs
        # before anything builds, so in a fresh clone that directory does not exist yet
        # and swiftformat exits 70 rather than creating it.
        (ROOT / "target").mkdir(parents=True, exist_ok=True)
        run(
            (
                "mise",
                "exec",
                "--",
                "swiftformat",
                "--lint",
                "platforms/macos",
                "--cache",
                str(ROOT / "target/swiftformat.cache"),
            )
        )
        run(
            (
                "mise",
                "exec",
                "--",
                "swiftlint",
                "lint",
                "--strict",
                "--cache-path",
                str(ROOT / "target/swiftlint-cache"),
                "--config",
                ".swiftlint.yml",
            )
        )
    run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "run",
            "--locked",
            "--quiet",
            "-p",
            "remap-quality",
            "--",
            "check",
        )
    )


def task_dependencies() -> None:
    """Fail on stale pins, advisories, unapproved sources, or license warnings."""
    run(("mise", "exec", "--", "uv", "run", "python", "-m", "tools.remap_freshness"))
    run(("mise", "exec", "--", "bun", "audit", "--audit-level=low"))
    run(("mise", "exec", "--", "cargo", "deny", "check", "--deny", "warnings"))


def task_docs() -> None:
    """Build and validate API, Markdown, and generated manual pages."""
    run(("mise", "exec", "--", "uv", "run", "python", "-m", "tools.remap_docs"))


def task_build_macos_app() -> Path:
    """Build and verify one project-local native application bundle."""
    require_macos()
    verify_selected_xcode()
    identity = (
        ensure_local_codesigning_identity() if release_toolchain_required() else None
    )
    return build_native_app(
        ROOT, PRODUCT_VERSION, release=False, signing_identity=identity
    )


def task_run_macos_app() -> None:
    """Build and launch one fresh native application instance."""
    bundle = task_build_macos_app()
    launch_native_app(ROOT, bundle, verify_process=False)


def task_verify_macos_app() -> None:
    """Build, launch, and prove the native application remains alive."""
    bundle = task_build_macos_app()
    launch_native_app(ROOT, bundle, verify_process=True)


def task_package_macos() -> None:
    """Build the prebuilt package that signs Remap locally on the target Mac.

    The kind of package is chosen once, here, and never mixed: a development package
    (`REMAP_DEVELOPMENT_PACKAGE=1`) is signed by the development file key named by
    `REMAP_RELEASE_SIGNING_KEY`; a rehearsal package (`REMAP_REHEARSAL_PACKAGE=1`) by the
    rehearsal Secure Enclave key whose blob `REMAP_REHEARSAL_SE_KEY` names; a release
    package by the Secure Enclave key whose blob `REMAP_RELEASE_SE_KEY` names, and by
    nothing else.
    """
    require_macos()
    _ = build_package(selected_signing(os.environ))


def build_package(signing: PackageSigning) -> PortablePackage:
    """Build, sign, and announce one package of `signing`'s kind."""
    require_macos()
    # Refuse a mismatched key or pin before asking the keychain for anything.
    preflight(ROOT, signing)
    kind = signing.kind
    output = package_output(kind)
    package = build_portable_macos_package(
        ROOT,
        product_version=PRODUCT_VERSION,
        output=output,
        signing=signing,
        # A development or rehearsal package carries no Apple installer signature, so it
        # needs no keychain and no person; only a release does.
        installer_identity=(
            ensure_release_installer_identity(ROOT)
            if kind is PackageKind.RELEASE
            else None
        ),
    )
    print(f"Built {package.path} (SHA-256 {package.sha256})")
    print(f"Signed {package.signature_path} " + f"(SHA-256 {package.signature_sha256})")
    note = PACKAGE_NOTES.get(kind)
    if note:
        print(note)
    return package


PACKAGE_NOTES = {
    PackageKind.DEVELOPMENT: (
        "This package is signed by a development key held in a file, not by "
        + "hardware. Its signature establishes that these bytes came from this "
        + "machine and nothing more. Do not distribute it."
    ),
    PackageKind.REHEARSAL: (
        "This is a rehearsal package, not a release. It is signed by the rehearsal "
        + "key, which no release installer accepts, and it carries no Apple Installer "
        + "signature. Publish it only to a rehearsal root, and do not install it as a "
        + "release."
    ),
}


def task_rehearsal_publish() -> None:
    """Build a rehearsal package of HEAD and publish it into a rehearsal root (ADR-0035).

    The root, the URL, the version's place in the root, and a clean working tree are all
    checked before anything builds, because the build is the slow part.
    """
    require_macos()
    root, url = rehearsal_root_from_environment(dict(os.environ))
    destination = rehearsal_release_directory(root, url, PRODUCT_VERSION)
    signing = selected_signing({**os.environ, REHEARSAL_PACKAGE_VARIABLE: "1"})
    if signing.kind is not PackageKind.REHEARSAL:
        raise RuntimeError("a rehearsal root holds only rehearsal packages")
    with tempfile.TemporaryDirectory(prefix="remap-rehearsal-source-") as directory:
        archive = source_archive(ROOT, PRODUCT_VERSION, Path(directory))
        package = build_package(signing)
        release = publish_rehearsal(
            root,
            url,
            RehearsalInputs(
                version=PRODUCT_VERSION,
                package=package.path,
                signature=package.signature_path,
                pin=ROOT / REHEARSAL_PIN,
                source_archive=archive,
            ),
        )
    if release != destination:
        raise RuntimeError(
            f"the rehearsal was published to {release}, not {destination}"
        )
    print(f"Published the {PRODUCT_VERSION} rehearsal to {release}")
    print(
        "Install it with the README's commands, replacing "
        + "https://github.com/Agenxy/remap/releases/download with "
        + f"{url}/releases/Agenxy/remap/download, and verify against "
        + "remap-rehearsal-signing-key.pub."
    )


def task_rehearsal_key() -> None:
    """Create the interim rehearsal Enclave key and write its pin, once only (ADR-0035)."""
    require_macos()
    configured = os.environ.get(REHEARSAL_KEY_VARIABLE)
    if not configured:
        raise RuntimeError(
            f"{REHEARSAL_KEY_VARIABLE} must name where the rehearsal key's blob is kept"
        )
    key_blob = Path(configured).expanduser()
    run(
        (
            "xcrun",
            "swift",
            "build",
            "--configuration",
            "release",
            "--package-path",
            "platforms/macos",
            "--product",
            "remap-release-key",
        )
    )
    tool = Path(
        capture(
            (
                "xcrun",
                "swift",
                "build",
                "--configuration",
                "release",
                "--package-path",
                "platforms/macos",
                "--show-bin-path",
            )
        )
    )
    line = create_rehearsal_key(ROOT, key_blob, tool=tool / "remap-release-key")
    print(f"Wrote {REHEARSAL_PIN}:\n{line}", end="")
    print(
        f"Published its fingerprint, {fingerprint(line)}, in the README and REHEARSAL.md."
    )
    print(
        "Commit them together with: git add "
        + " ".join(str(path) for path in REHEARSAL_KEY_COMMIT)
        + " && git commit -m 'Pin the interim rehearsal signer (ADR-0035)'"
    )


# Everything `make rehearsal-key` writes, which is one commit.
REHEARSAL_KEY_COMMIT = (
    REHEARSAL_PIN,
    SWIFT_VERIFIER,
    *FINGERPRINT_DOCUMENTS,
)


def package_output(kind: PackageKind) -> Path:
    """`dist/Remap-<version>-<arch>[-<kind>].pkg`: a release alone has no suffix."""
    suffix = "" if kind is PackageKind.RELEASE else f"-{kind.value}"
    return ROOT / "dist" / f"Remap-{PRODUCT_VERSION}-{platform.machine()}{suffix}.pkg"


def task_install_package_macos() -> None:
    """Install a detached-signature-verified package from root-owned staging."""
    require_macos()
    configured_package = os.environ.get("REMAP_MACOS_PACKAGE")
    if not configured_package:
        raise RuntimeError("REMAP_MACOS_PACKAGE must name the package to install")
    package = Path(configured_package).expanduser().resolve(strict=True)
    configured_signature = os.environ.get("REMAP_MACOS_PACKAGE_SIGNATURE")
    signature = (
        Path(configured_signature).expanduser().resolve(strict=True)
        if configured_signature
        else package.with_suffix(package.suffix + ".sig").resolve(strict=True)
    )
    install_verified_package(ROOT, package, signature)


def verify_packages() -> None:
    """Compile the exact unpublished crate archives against one another."""
    verify_crate_packages(ROOT, PRODUCT_VERSION, WORKSPACE)


def release_crate_specs() -> tuple[ArtifactSpec, ...]:
    """Return every workspace crate archive under one portable public name."""
    package_directory = cargo_target_directory(ROOT) / "package"
    return tuple(
        ArtifactSpec(
            name=f"{name}-{PRODUCT_VERSION}.crate",
            path=package_directory / f"{name}-{PRODUCT_VERSION}.crate",
        )
        for name in workspace_sources(ROOT, WORKSPACE)
    )


def release_evidence_directory() -> Path:
    """Return the fixed local source-artifact evidence destination."""
    return ROOT / "dist" / f"remap-{PRODUCT_VERSION}-source-evidence"


def task_release_evidence() -> None:
    """Build crate archives and create deterministic unsigned local evidence."""
    evidence = release_evidence_directory()
    if evidence.exists() or evidence.is_symlink():
        raise RuntimeError(
            f"release evidence already exists at {evidence}; verify it or remove it explicitly"
        )
    verify_packages()
    evidence.parent.mkdir(exist_ok=True)
    create_release_evidence(evidence, release_crate_specs())


def task_release_evidence_verify() -> None:
    """Verify existing crate bytes and their deterministic evidence set."""
    verify_release_evidence(release_evidence_directory(), release_crate_specs())


def verify_release_evidence_in_isolation() -> None:
    """Exercise the real evidence generator without publishing persistent output."""
    with tempfile.TemporaryDirectory(
        prefix="remap-release-evidence-check-"
    ) as directory:
        evidence = Path(directory) / "evidence"
        specs = release_crate_specs()
        create_release_evidence(evidence, specs)
        verify_release_evidence(evidence, specs)


def install_cli(root: Path) -> Path:
    """Install and execute the locked release CLI at an explicit root."""
    environment = inherited_environment(
        PATH=f"{root / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"
    )
    run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            f"+{RUST_TOOLCHAIN}",
            "install",
            "--locked",
            "--force",
            "--path",
            "crates/remap",
            "--root",
            str(root),
        ),
        environment=environment,
    )
    binary = root / "bin/remap"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"Cargo did not install an executable at {binary}")
    run((str(binary), "--version"))
    return binary


def task_install_cli() -> None:
    """Install the locked CLI and verify that a fresh lookup selects it."""
    root = installation_root()
    binary = install_cli(root)
    search_path = os.environ.get("PATH", "")
    resolved = shutil.which("remap", path=search_path)
    if resolved is None or Path(resolved).resolve() != binary.resolve():
        winner = resolved or "no command"
        raise RuntimeError(
            f"installed {binary}, but PATH selects {winner}; put {root / 'bin'} first"
        )
    print(f"Installed and verified {binary}")


def task_uninstall_cli() -> None:
    """Remove the Cargo-managed CLI from an explicit installation root."""
    run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "uninstall",
            "--root",
            str(installation_root()),
            "remap",
        )
    )


def task_install_system() -> None:
    """Install and activate the transactional native product."""
    if sys.platform == "darwin":
        install_or_update_macos(ROOT, PRODUCT_VERSION, "install")
    elif sys.platform == "linux":
        install_or_update_linux(ROOT, PRODUCT_VERSION, "install")
    else:
        raise RuntimeError(NATIVE_INSTALL_UNAVAILABLE)


def task_update() -> None:
    """Preview and transactionally update the installed native product."""
    if sys.platform == "darwin":
        install_or_update_macos(ROOT, PRODUCT_VERSION, "update")
    elif sys.platform == "linux":
        install_or_update_linux(ROOT, PRODUCT_VERSION, "update")
    else:
        raise RuntimeError(NATIVE_INSTALL_UNAVAILABLE)


def task_recover() -> None:
    """Preview and explicitly recover interrupted native lifecycle work."""
    if sys.platform == "darwin":
        recover_macos(ROOT)
    elif sys.platform == "linux":
        recover_linux(ROOT)
    else:
        raise RuntimeError(f"{NATIVE_INSTALL_UNAVAILABLE}; recovery did not run")


def task_install() -> None:
    """Install the complete native product when that platform is supported."""
    if sys.platform not in {"darwin", "linux"}:
        message = f"{NATIVE_INSTALL_UNAVAILABLE}; {CLI_INSTALL_HINT}"
        raise RuntimeError(message)
    task_install_system()


def task_uninstall_system() -> None:
    """Restore DNS and remove only the manifest-owned native installation."""
    if sys.platform == "darwin":
        uninstall_macos(ROOT)
    elif sys.platform == "linux":
        uninstall_linux(ROOT)
    else:
        raise RuntimeError(NATIVE_UNINSTALL_UNAVAILABLE)


def task_uninstall() -> None:
    """Uninstall the complete native product when that platform is supported."""
    if sys.platform not in {"darwin", "linux"}:
        message = f"{NATIVE_UNINSTALL_UNAVAILABLE}; {CLI_UNINSTALL_HINT}"
        raise RuntimeError(message)
    task_uninstall_system()


def task_install_check() -> None:
    """Prove install, command discovery, execution, and uninstall in isolation."""
    with tempfile.TemporaryDirectory(prefix="remap-install-") as directory:
        root = Path(directory).resolve()
        binary = install_cli(root)
        environment = inherited_environment(
            PATH=f"{root / 'bin'}{os.pathsep}{os.environ['PATH']}"
        )
        result = subprocess.run(
            ("remap", "--version"),
            cwd=ROOT,
            env=environment,
            check=True,
            capture_output=True,
            text=True,
        )
        if f"remap {PRODUCT_VERSION}" not in result.stdout:
            raise RuntimeError("the isolated shell did not execute the installed Remap")
        run(
            (
                "mise",
                "exec",
                "--",
                "cargo",
                f"+{RUST_TOOLCHAIN}",
                "uninstall",
                "--root",
                str(root),
                "remap",
            ),
            environment=environment,
        )
        if binary.exists():
            raise RuntimeError(
                "the isolated uninstall left the Remap executable behind"
            )


def task_check() -> None:
    """Run the development gate: everything that judges this working copy.

    Not the release gate. This must pass on any Mac or Linux box with the pinned
    tools installed, without network access to a package registry, without the
    reviewed Xcode, and without upgrading anything outside the repository. A gate a
    contributor cannot run is a gate nobody runs.

    Installation checks belong to release-check: neither the isolated CLI install
    nor the certificate-backed native image contract is a development prerequisite.
    Building the development app requires no keychain item or trust approval.
    """
    verify_policy_copies(ROOT, PRODUCT_VERSION)
    task_quality()
    run(("mise", "exec", "--", "cargo", "fmt", "--all", "--check"))
    run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        )
    )
    task_test()
    macos_bundle = task_build_macos_app() if sys.platform == "darwin" else None
    verify_packages()
    task_docs()
    if macos_bundle is not None and release_toolchain_required():
        verify_release_evidence_in_isolation()
        verify_macos_release_metadata(macos_bundle)


def task_release_check() -> None:
    """Run the complete reproducible release gate: the development gate and more.

    What this adds is everything that protects a machine other than this one: pins
    current with their registries, advisories and licences clean, the reviewed
    toolchain enforced rather than reported, release evidence rebuilt in isolation,
    and the linked SDK stamped as expected. It needs the network and a reviewed
    Xcode, and it is the gate a release must pass. This gate also owns the isolated
    CLI install-check and macOS's generated native package contract. The latter
    builds certificate-backed products and may require keychain or trust approval;
    it must never run as a prerequisite for the development gate.
    """
    require_release_toolchain()
    task_dependencies()
    if sys.platform == "darwin":
        # Produce the native binaries before task_check's release metadata checks.
        verify_generated_package_contract(ROOT, PRODUCT_VERSION)
    task_check()
    task_install_check()


def verify_macos_release_metadata(bundle: Path) -> None:
    """Reject public artifacts stamped with the wrong linked SDK."""
    expected_sdk = expected_macos_sdk(ROOT)
    release_directory = Path(
        capture(
            (
                "xcrun",
                "swift",
                "build",
                "--show-bin-path",
                "--configuration",
                "release",
                "--package-path",
                "platforms/macos",
            )
        )
    )
    verify_macos_sdk_metadata(
        (
            bundle / "Contents/MacOS/Remap",
            release_directory / "remap-install",
            release_directory / "remap-resolver",
            release_directory / "remap-system",
        ),
        expected_sdk,
    )


TASKS: dict[str, Callable[[], None]] = {
    "help": task_help,
    "setup": task_setup,
    "format": task_format,
    "check": task_check,
    "release-check": task_release_check,
    "test": task_test,
    "quality": task_quality,
    "dependencies": task_dependencies,
    "docs": task_docs,
    "install": task_install,
    "install-cli": task_install_cli,
    "install-system": task_install_system,
    "install-check": task_install_check,
    "install-package-macos": task_install_package_macos,
    "package-macos": task_package_macos,
    "run-macos": task_run_macos_app,
    "recover": task_recover,
    "release-evidence": task_release_evidence,
    "release-evidence-verify": task_release_evidence_verify,
    "rehearsal-key": task_rehearsal_key,
    "rehearsal-publish": task_rehearsal_publish,
    "setup-install": task_setup_install,
    "update": task_update,
    "verify-macos": task_verify_macos_app,
    "uninstall": task_uninstall,
    "uninstall-cli": task_uninstall_cli,
    "uninstall-system": task_uninstall_system,
}


def main() -> int:
    """Parse one stable task name and execute it."""
    parser = argparse.ArgumentParser(description=__doc__)
    _ = parser.add_argument("task", choices=tuple(TASKS))
    arguments = parser.parse_args()
    task: object = vars(arguments).get("task")
    if not isinstance(task, str):
        parser.error("a task is required")
    try:
        TASKS[task]()
    except KeyboardInterrupt:
        print("task cancelled by the user", file=sys.stderr)
        return 130
    except (OSError, RuntimeError, TypeError, subprocess.CalledProcessError) as error:
        print(f"task failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
