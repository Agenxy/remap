"""Release metadata checks for native macOS executables."""

from __future__ import annotations

import os
import re
import stat
import subprocess
import tempfile
from pathlib import Path

_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?")


def expected_macos_sdk(root: Path) -> str:
    """Return the exact SDK version selected by the repository Xcode pin."""
    lines = (
        (root / "platforms/macos/XCODE_VERSION")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    if len(lines) < 2 or _VERSION.fullmatch(lines[0]) is None:
        raise RuntimeError("the repository macOS SDK pin is malformed")
    return lines[0]


def verify_macos_sdk_metadata(paths: tuple[Path, ...], expected_sdk: str) -> None:
    """Require each release executable to declare the selected macOS SDK."""
    for path in paths:
        result = subprocess.run(
            ("xcrun", "vtool", "-show-build", str(path)),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        require_macos_sdk_stamp(result.stdout, expected_sdk, str(path))


def normalize_macos_sdk_metadata(
    paths: tuple[Path, ...],
    *,
    expected_sdk: str,
    minimum_macos: str,
) -> None:
    """Correct Apple Swift's stale SDK stamp before product code signing.

    The pinned Xcode 27 beta passes the macOS 27 SDK to Swift correctly, but its Swift
    linker currently records the deployment target as both `minos` and `sdk`.
    Apple's vtool is the narrow supported editor for this load command. Every
    rewritten build product is immediately ad-hoc signed so no invalid Mach-O
    artifact remains available to a later packaging step.
    """
    if (
        _VERSION.fullmatch(expected_sdk) is None
        or _VERSION.fullmatch(minimum_macos) is None
    ):
        raise RuntimeError("the requested macOS build versions are malformed")
    for path in paths:
        _normalize_macos_sdk_metadata(
            path,
            expected_sdk=expected_sdk,
            minimum_macos=minimum_macos,
        )


def require_macos_sdk_stamp(output: str, expected_sdk: str, label: str) -> None:
    """Validate one bounded vtool LC_BUILD_VERSION rendering."""
    fields = _build_version_fields(output, label)
    actual_sdk = fields.get("sdk")
    if actual_sdk != expected_sdk:
        raise RuntimeError(
            f"{label} declares SDK {actual_sdk or 'unknown'}; expected {expected_sdk}. "
            + "Public native release is blocked until the selected Apple toolchain "
            + "emits correct LC_BUILD_VERSION metadata."
        )


def _normalize_macos_sdk_metadata(
    path: Path,
    *,
    expected_sdk: str,
    minimum_macos: str,
) -> None:
    information = path.lstat()
    if (
        path.is_symlink()
        or not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or not os.access(path, os.X_OK)
    ):
        raise RuntimeError(f"the macOS build product is unsafe: {path}")
    rendered = _show_build(path)
    fields = _build_version_fields(rendered, str(path))
    if fields.get("minos") != minimum_macos:
        raise RuntimeError(
            f"{path} declares minimum macOS {fields.get('minos') or 'unknown'}; "
            + f"expected {minimum_macos}"
        )
    if fields.get("sdk") == expected_sdk:
        return
    tool, tool_version = _linker_tool(rendered, str(path))
    with tempfile.TemporaryDirectory(
        prefix=".remap-sdk-", dir=path.parent
    ) as directory:
        output = Path(directory) / path.name
        _ = subprocess.run(
            (
                "xcrun",
                "vtool",
                "-set-build-version",
                "macos",
                minimum_macos,
                expected_sdk,
                "-tool",
                tool,
                tool_version,
                "-replace",
                "-output",
                str(output),
                str(path),
            ),
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        os.chmod(output, stat.S_IMODE(information.st_mode))
        os.replace(output, path)
    _ = subprocess.run(
        (
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            str(path),
        ),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    require_macos_sdk_stamp(_show_build(path), expected_sdk, str(path))


def _show_build(path: Path) -> str:
    result = subprocess.run(
        ("xcrun", "vtool", "-show-build", str(path)),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout


def _build_version_fields(output: str, label: str) -> dict[str, str]:
    if len(output.encode("utf-8")) > 65_536:
        raise RuntimeError(f"build metadata exceeded 64 KiB for {label}")
    fields = {
        key: value
        for line in output.splitlines()
        if len(parts := line.split()) == 2
        for key, value in [parts]
        if key in {"platform", "minos", "sdk"}
    }
    if output.count("cmd LC_BUILD_VERSION") != 1 or fields.get("platform") != "MACOS":
        raise RuntimeError(f"{label} does not contain one macOS LC_BUILD_VERSION")
    return fields


def _linker_tool(output: str, label: str) -> tuple[str, str]:
    lines = [line.split() for line in output.splitlines()]
    matches = [
        (parts[1].lower(), lines[index + 1][1])
        for index, parts in enumerate(lines[:-1])
        if len(parts) == 2
        and parts[0] == "tool"
        and parts[1] in {"LD", "LLD"}
        and len(lines[index + 1]) == 2
        and lines[index + 1][0] == "version"
        and _VERSION.fullmatch(lines[index + 1][1]) is not None
    ]
    if len(matches) != 1:
        raise RuntimeError(f"{label} does not declare one supported linker version")
    return matches[0]
