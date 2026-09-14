"""Fail when an exact first-party tool or dependency pin is no longer current."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from http.client import HTTPResponse
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

import tomllib

ROOT = Path(__file__).resolve().parent.parent
MAXIMUM_RESPONSE_BYTES = 1_048_576
REQUEST_TIMEOUT_SECONDS = 10.0


def main() -> int:
    """Verify every exact project pin against its authoritative public registry."""
    try:
        verify_workspace_dependencies()
        verify_javascript_dependencies()
        verify_mise_tools()
        verify_mise_release()
        verify_selected_xcode()
    except (OSError, RuntimeError, TypeError, ValueError, HTTPError, URLError) as error:
        print(f"Dependency freshness failed: {error}", file=sys.stderr)
        return 1
    print("Dependency freshness: every direct pin is current")
    return 0


def verify_workspace_dependencies() -> None:
    """Compare exact Cargo workspace dependencies with crates.io stable maxima."""
    document = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = object_table(document, "workspace")
    dependencies = object_table(workspace, "dependencies")
    for name, specification in sorted(dependencies.items()):
        pinned = cargo_version(specification, name)
        payload = fetch_json(f"https://crates.io/api/v1/crates/{quote(name, safe='')}")
        crate = object_table(payload, "crate")
        latest = string_value(crate, "max_stable_version")
        require_current(f"crate {name}", pinned, latest)


def verify_javascript_dependencies() -> None:
    """Compare exact Bun package pins with the npm latest distribution tag."""
    document = cast(
        "object", json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    )
    if not isinstance(document, dict):
        raise TypeError("package.json root must be an object")
    dependencies = object_table(cast("dict[str, object]", document), "devDependencies")
    for name, specification in sorted(dependencies.items()):
        if not isinstance(specification, str) or not exact_semver(specification):
            raise ValueError(f"npm package {name} is not pinned to an exact version")
        encoded = quote(name, safe="")
        payload = fetch_json(f"https://registry.npmjs.org/{encoded}/latest")
        latest = string_value(payload, "version")
        require_current(f"npm package {name}", specification, latest)


def mise_tool_version(specification: object) -> str:
    """Read a mise tool pin, which is a bare string or a table with options."""
    if isinstance(specification, str):
        return specification
    if isinstance(specification, dict):
        version = cast("dict[str, object]", specification).get("version")
        if isinstance(version, str):
            return version
    raise TypeError("mise tool pins must be a version string or a table with one")


def verify_mise_tools() -> None:
    """Compare exact mise pins with each plugin's current stable release."""
    document = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))
    tools = object_table(document, "tools")
    for name, specification in sorted(tools.items()):
        pinned = mise_tool_version(specification)
        latest = capture(("mise", "latest", name))
        require_current(f"mise tool {name}", pinned, latest)


def verify_mise_release() -> None:
    """Require the bootstrap binary itself to match mise's latest GitHub release."""
    installed = capture(("mise", "--version")).split(maxsplit=1)[0]
    payload = fetch_json("https://api.github.com/repos/jdx/mise/releases/latest")
    latest = string_value(payload, "tag_name").removeprefix("v")
    require_current("mise", installed, latest)


def verify_selected_xcode() -> None:
    """Require macOS builds to use one of the repository's reviewed Xcode builds.

    The pin file names one Xcode version and then every reviewed build of it,
    one per line. More than one build is allowed because Apple withdraws beta
    builds as soon as the next one ships while the hosted CI image lags a
    build behind, so an exact single-build pin could not be satisfied on a
    developer machine and the runner at the same time.
    """
    if sys.platform != "darwin":
        return
    expected = (
        (ROOT / "platforms/macos/XCODE_VERSION")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    if len(expected) < 2 or not all(expected):
        raise ValueError(
            "platforms/macos/XCODE_VERSION must contain a version and at least one build"
        )
    actual = capture(("/usr/bin/xcodebuild", "-version")).splitlines()
    accepted = [
        [f"Xcode {expected[0]}", f"Build version {build}"] for build in expected[1:]
    ]
    if actual not in accepted:
        raise RuntimeError(
            f"selected Xcode is {actual!r}; the reviewed builds are {accepted!r}"
        )


def cargo_version(specification: object, name: str) -> str:
    """Extract one mandatory exact Cargo dependency version."""
    raw: object
    if isinstance(specification, str):
        raw = specification
    elif isinstance(specification, dict):
        raw = cast("dict[str, object]", specification).get("version")
    else:
        raw = None
    if not isinstance(raw, str) or not raw.startswith("="):
        raise ValueError(f"crate {name} is not pinned with an exact =version")
    version = raw.removeprefix("=")
    if not exact_semver(version):
        raise ValueError(f"crate {name} has an invalid exact version")
    return version


def exact_semver(value: str) -> bool:
    """Return whether a pin is an unadorned numeric semantic version."""
    core = value.split("-", maxsplit=1)[0]
    return len(core.split(".")) == 3 and all(
        component.isdecimal() for component in core.split(".")
    )


def fetch_json(url: str) -> dict[str, object]:
    """Read one bounded JSON registry response with an explicit identity."""
    headers = {
        "Accept": "application/json",
        "User-Agent": "Agenxy-Remap-dependency-audit",
    }
    # api.github.com allows sixty anonymous requests an hour per address, and
    # the hosted runners share addresses, so the mise release lookup was
    # refused with 403 on CI. The workflow's token lifts that to the
    # authenticated limit; a developer machine without one keeps the anonymous
    # path.
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    response = cast("HTTPResponse", urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS))
    try:
        data = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    finally:
        response.close()
    if len(data) > MAXIMUM_RESPONSE_BYTES:
        raise RuntimeError(f"registry response exceeds the byte limit: {url}")
    value = cast("object", json.loads(data))
    if not isinstance(value, dict):
        raise TypeError(f"registry response is not an object: {url}")
    return cast("dict[str, object]", value)


def capture(arguments: tuple[str, ...]) -> str:
    """Capture one exact native registry-client boundary without a shell."""
    result = subprocess.run(
        arguments,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def object_table(document: dict[str, object], key: str) -> dict[str, object]:
    """Read a required object property from a decoded document."""
    value = document.get(key)
    if not isinstance(value, dict):
        raise TypeError(f"{key} must be an object")
    return cast("dict[str, object]", value)


def string_value(document: dict[str, object], key: str) -> str:
    """Read one required nonempty string property."""
    value = document.get(key)
    if not isinstance(value, str) or not value:
        raise TypeError(f"registry field {key} must be a nonempty string")
    return value


def require_current(name: str, pinned: str, latest: str) -> None:
    """Reject a stale or unexpectedly ahead version pin."""
    if pinned != latest:
        raise RuntimeError(f"{name} is pinned to {pinned}; current stable is {latest}")


if __name__ == "__main__":
    raise SystemExit(main())
