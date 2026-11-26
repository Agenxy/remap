# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail when an exact first-party tool or dependency pin is no longer current."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tomllib
from http.client import HTTPResponse
from pathlib import Path
from typing import cast
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parent.parent
MAXIMUM_RESPONSE_BYTES = 1_048_576
REQUEST_TIMEOUT_SECONDS = 10.0
ACTION_PIN = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)\s*(?:#.*)?$")
ACTION_REFERENCE = re.compile(r"^([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([0-9a-f]{40})$")


def main() -> int:
    """Verify every exact project pin against its authoritative public registry."""
    try:
        # Every stale pin is reported in one run, so a bump is one edit, not one
        # edit per rerun. A malformed pin or an unreachable registry still stops it.
        stale = [
            *verify_workspace_dependencies(),
            *verify_javascript_dependencies(),
            *verify_mise_tools(),
            *verify_mise_release(),
            *verify_workflow_actions(),
        ]
        # The freshness audit is a release concern in its own right, so it holds the
        # pin whatever mode the process is in.
        verify_selected_xcode(required=True)
    except (OSError, RuntimeError, TypeError, ValueError, HTTPError, URLError) as error:
        print(f"Dependency freshness failed: {error}", file=sys.stderr)
        return 1
    if stale:
        print(f"Dependency freshness failed: {len(stale)} stale pins", file=sys.stderr)
        for message in stale:
            print(f"  {message}", file=sys.stderr)
        return 1
    print("Dependency freshness: every direct pin is current")
    return 0


def verify_workspace_dependencies() -> list[str]:
    """Compare exact Cargo workspace dependencies with crates.io stable maxima."""
    document = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    workspace = object_table(document, "workspace")
    dependencies = object_table(workspace, "dependencies")
    stale: list[str] = []
    for name, specification in sorted(dependencies.items()):
        pinned = cargo_version(specification, name)
        payload = fetch_json(f"https://crates.io/api/v1/crates/{quote(name, safe='')}")
        crate = object_table(payload, "crate")
        latest = string_value(crate, "max_stable_version")
        stale += stale_pin(f"crate {name}", pinned, latest)
    return stale


def verify_javascript_dependencies() -> list[str]:
    """Compare exact Bun package pins with the npm latest distribution tag."""
    document = cast(
        "object", json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    )
    if not isinstance(document, dict):
        raise TypeError("package.json root must be an object")
    dependencies = object_table(cast("dict[str, object]", document), "devDependencies")
    stale: list[str] = []
    for name, specification in sorted(dependencies.items()):
        if not isinstance(specification, str) or not exact_semver(specification):
            raise ValueError(f"npm package {name} is not pinned to an exact version")
        encoded = quote(name, safe="")
        payload = fetch_json(f"https://registry.npmjs.org/{encoded}/latest")
        latest = string_value(payload, "version")
        stale += stale_pin(f"npm package {name}", specification, latest)
    return stale


def mise_tool_version(specification: object) -> str:
    """Read a mise tool pin, which is a bare string or a table with options."""
    if isinstance(specification, str):
        return specification
    if isinstance(specification, dict):
        version = cast("dict[str, object]", specification).get("version")
        if isinstance(version, str):
            return version
    raise TypeError("mise tool pins must be a version string or a table with one")


def verify_mise_tools() -> list[str]:
    """Compare exact mise pins with each plugin's current stable release."""
    document = tomllib.loads((ROOT / "mise.toml").read_text(encoding="utf-8"))
    tools = object_table(document, "tools")
    stale: list[str] = []
    for name, specification in sorted(tools.items()):
        pinned = mise_tool_version(specification)
        latest = capture(("mise", "latest", name))
        stale += stale_pin(f"mise tool {name}", pinned, latest)
    return stale


def verify_mise_release() -> list[str]:
    """Require the bootstrap binary itself to match mise's latest GitHub release."""
    installed = capture(("mise", "--version")).split(maxsplit=1)[0]
    payload = fetch_json("https://api.github.com/repos/jdx/mise/releases/latest")
    latest = string_value(payload, "tag_name").removeprefix("v")
    return stale_pin("mise", installed, latest)


def workflow_action_pins(text: str, source: str) -> list[tuple[str, str]]:
    """Read every `uses:` pin, refusing any that is not an immutable commit."""
    pins: list[tuple[str, str]] = []
    for line in text.splitlines():
        match = ACTION_PIN.match(line)
        if match is None:
            continue
        reference = ACTION_REFERENCE.match(match.group(1))
        if reference is None:
            raise ValueError(
                f"{source} uses {match.group(1)}, which is not pinned to a commit"
            )
        pins.append((reference.group(1), reference.group(2)))
    return pins


def verify_workflow_actions() -> list[str]:
    """Require each pinned workflow action to be its latest release's commit."""
    pins: set[tuple[str, str]] = set()
    for workflow in sorted((ROOT / ".github/workflows").glob("*.yml")):
        source = str(workflow.relative_to(ROOT))
        pins.update(workflow_action_pins(workflow.read_text(encoding="utf-8"), source))
    stale: list[str] = []
    for repository, pinned in sorted(pins):
        release = fetch_json(
            f"https://api.github.com/repos/{repository}/releases/latest"
        )
        tag = string_value(release, "tag_name")
        commit = fetch_json(
            f"https://api.github.com/repos/{repository}/commits/{quote(tag, safe='')}"
        )
        latest = string_value(commit, "sha")
        stale += stale_pin(f"action {repository} ({tag})", pinned, latest)
    return stale


_release_toolchain_required = False


def require_release_toolchain() -> None:
    """Make the reviewed-toolchain pin refuse for the rest of this process.

    Release and packaging paths call this. Everything else reports a mismatch and
    continues, so that a machine whose Xcode has moved can still build, test and
    install locally. What the pin buys is the ability to say which compiler produced
    an artifact, which matters to whoever installs it, not to the person writing it.
    """
    global _release_toolchain_required
    _release_toolchain_required = True


def release_toolchain_required() -> bool:
    """Whether the reviewed-toolchain pin refuses rather than reports."""
    return _release_toolchain_required


def verify_selected_xcode(*, required: bool | None = None) -> None:
    """Require macOS builds to use one of the repository's reviewed Xcode builds.

    `required=False` reports the mismatch and continues. A local build is judged by
    the same tests either way; what an unreviewed toolchain costs is the ability to
    say which compiler produced an artifact, which matters only for something
    someone else installs. Refusing a developer's build for it blocks work and
    protects nobody, so the release paths pass `required=True` and keep the pin.

    The pin file names one Xcode version and then every reviewed build of it,
    one per line. More than one build is allowed because Apple withdraws beta
    builds as soon as the next one ships while the hosted CI image lags a
    build behind, so an exact single-build pin could not be satisfied on a
    developer machine and the runner at the same time.
    """
    if sys.platform != "darwin":
        return
    if required is None:
        required = _release_toolchain_required
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
        message = f"selected Xcode is {actual!r}; the reviewed builds are {accepted!r}"
        if required:
            raise RuntimeError(message)
        advice = "This build is for local use and must not be distributed;"
        print(
            f"warning: {message}. {advice} `make release-check` enforces the pin.",
            file=sys.stderr,
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


def stale_pin(name: str, pinned: str, latest: str) -> list[str]:
    """Name a stale or unexpectedly ahead version pin, or nothing when it is current."""
    if pinned != latest:
        return [f"{name} is pinned to {pinned}; current stable is {latest}"]
    return []


if __name__ == "__main__":
    raise SystemExit(main())
