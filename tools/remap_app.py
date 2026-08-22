"""Build and stage the native Remap macOS application bundle."""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from tools.remap_macos_artifact import (
    expected_macos_sdk,
    normalize_macos_sdk_metadata,
)
from tools.remap_macos_signing import (
    LocalCodeSigningIdentity,
    ensure_local_codesigning_identity,
    sign_path,
    verify_local_signature,
)

APP_BUNDLE_ID = "org.agenxy.Remap"
APP_NAME = "Remap"
APP_MINIMUM_MACOS = "15.0"
RESOURCE_BUNDLE_NAME = "RemapMac_RemapApp.bundle"
SYSTEM_APP_BUNDLE = Path("/Applications/Remap.app")


def run(arguments: tuple[str, ...], *, root: Path) -> None:
    """Run one explicit native build boundary."""
    _ = subprocess.run(arguments, cwd=root, check=True)


def capture(arguments: tuple[str, ...], *, root: Path) -> str:
    """Capture one explicit native build result."""
    result = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def build(
    root: Path,
    version: str,
    *,
    release: bool,
    signing_identity: LocalCodeSigningIdentity | None = None,
    sign: bool = True,
) -> Path:
    """Build, bundle, sign, and verify the native macOS application."""
    configuration = "release" if release else "debug"
    identity = signing_identity or (
        ensure_local_codesigning_identity() if sign else None
    )
    run(
        (
            "xcrun",
            "swift",
            "build",
            "--configuration",
            configuration,
            "--package-path",
            "platforms/macos",
            "--product",
            APP_NAME,
        ),
        root=root,
    )
    binary_directory = Path(
        capture(
            (
                "xcrun",
                "swift",
                "build",
                "--show-bin-path",
                "--configuration",
                configuration,
                "--package-path",
                "platforms/macos",
            ),
            root=root,
        )
    )
    binary = binary_directory / APP_NAME
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError(f"Swift did not build the Remap app executable at {binary}")
    destination = root / "dist" / f"{APP_NAME}.app"
    with tempfile.TemporaryDirectory(prefix="remap-app-") as directory:
        staging = Path(directory) / destination.name
        _stage_bundle(root, staging, binary, binary_directory, version)
        normalize_macos_sdk_metadata(
            (staging / f"Contents/MacOS/{APP_NAME}",),
            expected_sdk=expected_macos_sdk(root),
            minimum_macos=APP_MINIMUM_MACOS,
        )
        _replace_generated_bundle(staging, destination)
    if identity is not None:
        _ = sign_path(destination, identity, APP_BUNDLE_ID)
        verify(root, destination, identity)
    else:
        verify_structure(root, destination)
    return destination


def verify(
    root: Path,
    bundle: Path,
    signing_identity: LocalCodeSigningIdentity | None = None,
) -> None:
    """Verify the staged bundle's signature, metadata, and executable."""
    run(
        ("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(bundle)),
        root=root,
    )
    identity = signing_identity or ensure_local_codesigning_identity()
    _ = verify_local_signature(bundle, identity, APP_BUNDLE_ID)
    verify_structure(root, bundle)


def verify_structure(root: Path, bundle: Path) -> None:
    """Verify bundle metadata and executable presence without using a private key."""
    run(("/usr/bin/plutil", "-lint", str(bundle / "Contents/Info.plist")), root=root)
    executable = bundle / f"Contents/MacOS/{APP_NAME}"
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise RuntimeError("the staged Remap app does not contain an executable")


def launch(root: Path, bundle: Path, *, verify_process: bool) -> None:
    """Launch one fresh app instance and optionally prove it remains alive."""
    run(("/usr/bin/open", "-n", str(bundle)), root=root)
    if not verify_process:
        return
    for _attempt in range(50):
        result = subprocess.run(
            ("/usr/bin/pgrep", "-x", APP_NAME),
            cwd=root,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        if result.returncode == 0:
            return
        if result.returncode != 1:
            raise RuntimeError("macOS returned an unexpected process lookup result")
        time.sleep(0.1)
    raise RuntimeError("the Remap app did not remain running after launch")


def _stage_bundle(
    root: Path,
    bundle: Path,
    binary: Path,
    binary_directory: Path,
    version: str,
) -> None:
    contents = bundle / "Contents"
    executable_directory = contents / "MacOS"
    resources = contents / "Resources"
    executable_directory.mkdir(parents=True)
    resources.mkdir()
    _ = shutil.copy2(binary, executable_directory / APP_NAME)
    _write_info_plist(contents / "Info.plist", version)
    _stage_resources(root, binary_directory, resources)


def _write_info_plist(path: Path, version: str) -> None:
    document: dict[str, object] = {
        "CFBundleDevelopmentRegion": "en",
        "CFBundleDisplayName": APP_NAME,
        "CFBundleExecutable": APP_NAME,
        "CFBundleIconFile": "Remap.icns",
        "CFBundleIdentifier": APP_BUNDLE_ID,
        "CFBundleInfoDictionaryVersion": "6.0",
        "CFBundleName": APP_NAME,
        "CFBundlePackageType": "APPL",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": version,
        "LSApplicationCategoryType": "public.app-category.developer-tools",
        "LSMinimumSystemVersion": APP_MINIMUM_MACOS,
        "NSHighResolutionCapable": True,
        "NSPrincipalClass": "NSApplication",
    }
    with path.open("wb") as output:
        plistlib.dump(document, output, sort_keys=True)


def _stage_resources(root: Path, binary_directory: Path, resources: Path) -> None:
    bundle = binary_directory / RESOURCE_BUNDLE_NAME
    if not bundle.is_dir() or bundle.is_symlink():
        raise RuntimeError(
            f"Swift did not produce the expected resource bundle at {bundle}"
        )
    _ = shutil.copytree(bundle, resources / bundle.name)
    for policy_file in ("LICENSE", "NOTICE"):
        _ = shutil.copyfile(root / policy_file, resources / policy_file)
    _build_icon(root, resources / "Remap.icns")


def _build_icon(root: Path, destination: Path) -> None:
    source = root / "platforms/macos/App/Assets/RemapIcon.png"
    if not source.is_file():
        raise RuntimeError("the Remap app icon source is missing")
    iconset = destination.with_suffix(".iconset")
    iconset.mkdir()
    specifications = (
        (16, "icon_16x16.png"),
        (32, "icon_16x16@2x.png"),
        (32, "icon_32x32.png"),
        (64, "icon_32x32@2x.png"),
        (128, "icon_128x128.png"),
        (256, "icon_128x128@2x.png"),
        (256, "icon_256x256.png"),
        (512, "icon_256x256@2x.png"),
        (512, "icon_512x512.png"),
        (1_024, "icon_512x512@2x.png"),
    )
    for size, name in specifications:
        _ = capture(
            (
                "/usr/bin/sips",
                "-z",
                str(size),
                str(size),
                str(source),
                "--out",
                str(iconset / name),
            ),
            root=root,
        )
    run(
        ("/usr/bin/iconutil", "-c", "icns", str(iconset), "-o", str(destination)),
        root=root,
    )
    _ = shutil.rmtree(iconset)


def _replace_generated_bundle(staging: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        if not destination.is_dir() or destination.is_symlink():
            raise RuntimeError(
                f"refusing to replace unsafe generated path {destination}"
            )
        _ = shutil.rmtree(destination)
    _ = shutil.copytree(staging, destination)
