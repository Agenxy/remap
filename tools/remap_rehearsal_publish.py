# SPDX-License-Identifier: GPL-3.0-or-later
"""Publish a rehearsal of a Remap release into a root with the production layout (ADR-0035).

The root is static files a rehearsal host serves: the GitHub release-asset tree, a shim of
the two GitHub API answers that name those assets, and a Homebrew tap. A published version
is never rewritten, because a rehearsal that changed under an installer would prove nothing.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

OWNER = "Agenxy"
REPOSITORY = "remap"
FORMULA_TEMPLATE = (
    Path(__file__).resolve().parent / "templates" / "homebrew-remap.rb.in"
)


@dataclass(frozen=True)
class RehearsalInputs:
    """The exact files one rehearsal publishes, all produced by the release pipeline."""

    version: str
    package: Path
    signature: Path
    pin: Path
    source_archive: Path


def release_directory(root: Path, base_url: str, version: str) -> Path:
    """The release-asset directory `version` would be published to, which must be new.

    `make rehearsal-publish` asks this before it builds anything, so a root, a URL, or an
    already published version that would be refused is refused first.
    """
    if not root.is_absolute() or not root.is_dir():
        raise ValueError(
            f"the rehearsal root {root} must be an existing absolute directory"
        )
    if not base_url.startswith(("https://", "http://")) or base_url.endswith("/"):
        raise ValueError(
            "the rehearsal URL must be an http(s) origin and path with no trailing /"
        )
    release = root / "releases" / OWNER / REPOSITORY / "download" / f"v{version}"
    if release.exists():
        raise FileExistsError(
            f"{release} is already published; a rehearsal is never rewritten"
        )
    return release


def source_archive(repository: Path, version: str, destination: Path) -> Path:
    """`git archive` of HEAD, laid out as GitHub's tag archive is, into `destination`.

    The package is built from the working tree and the archive from HEAD, so they are the
    same source only when the tree has nothing HEAD does not; anything else is refused.
    """
    changes = subprocess.run(
        ("git", "-C", str(repository), "status", "--porcelain"),
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    if changes:
        raise RuntimeError(
            "the working tree has changes HEAD does not, so a package built from it "
            + "would not match HEAD's source archive; commit or remove them first"
        )
    archive = destination / f"remap-{version}.tar.gz"
    _ = subprocess.run(
        (
            "git",
            "-C",
            str(repository),
            "archive",
            "--format=tar.gz",
            f"--prefix={REPOSITORY}-{version}/",
            f"--output={archive}",
            "HEAD",
        ),
        check=True,
        timeout=300,
    )
    return archive


def publish(root: Path, base_url: str, inputs: RehearsalInputs) -> Path:
    """Write one version into `root` and return its release-asset directory."""
    release = release_directory(root, base_url, inputs.version)
    tag = f"v{inputs.version}"
    archive = root / "releases" / OWNER / REPOSITORY / "archive" / "refs" / "tags"
    release.mkdir(parents=True)
    assets = [inputs.package, inputs.signature, inputs.pin]
    for asset in assets:
        _ = shutil.copyfile(asset, release / asset.name)
    sums = "".join(
        f"{_sha256(release / asset.name)}  {asset.name}\n" for asset in sorted(assets)
    )
    _ = (release / "SHA256SUMS").write_text(sums, encoding="utf-8")
    archive.mkdir(parents=True, exist_ok=True)
    source = archive / f"{tag}.tar.gz"
    _ = shutil.copyfile(inputs.source_archive, source)
    _write_api_shim(root, base_url, tag, release)
    _write_formula(root, base_url, inputs.version, source)
    return release


def _write_api_shim(root: Path, base_url: str, tag: str, release: Path) -> None:
    """Answer `releases/latest` and `releases/tags/<tag>` in GitHub's shape."""
    download = f"{base_url}/releases/{OWNER}/{REPOSITORY}/download/{tag}"
    assets = [
        {
            "browser_download_url": f"{download}/{path.name}",
            "name": path.name,
            "size": path.stat().st_size,
        }
        for path in sorted(release.iterdir())
    ]
    document = {
        "assets": assets,
        "draft": False,
        "name": f"Remap {tag.removeprefix('v')} (rehearsal)",
        "prerelease": True,
        "tag_name": tag,
    }
    text = json.dumps(document, indent=2, sort_keys=True) + "\n"
    api = root / "api" / "repos" / OWNER / REPOSITORY / "releases"
    (api / "tags").mkdir(parents=True, exist_ok=True)
    _ = (api / "tags" / tag).write_text(text, encoding="utf-8")
    _ = (api / "latest").write_text(text, encoding="utf-8")


def _write_formula(root: Path, base_url: str, version: str, source: Path) -> None:
    """Render the tap formula against the source archive this root serves."""
    url = (
        f"{base_url}/releases/{OWNER}/{REPOSITORY}/archive/refs/tags/v{version}.tar.gz"
    )
    formula = (
        FORMULA_TEMPLATE.read_text(encoding="utf-8")
        .replace("{{source_url}}", url)
        .replace("{{source_sha256}}", _sha256(source))
        .replace("{{version}}", version)
    )
    if "{{" in formula:
        raise ValueError(
            "the Homebrew formula template has a placeholder this publisher does not fill"
        )
    directory = root / "homebrew" / "Formula"
    directory.mkdir(parents=True, exist_ok=True)
    _ = (directory / "remap.rb").write_text(formula, encoding="utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def rehearsal_root_from_environment(
    environment: dict[str, str] | None = None,
) -> tuple[Path, str]:
    """Read the two settings `make rehearsal-publish` requires, refusing either missing."""
    values = os.environ if environment is None else environment
    root = values.get("REMAP_REHEARSAL_ROOT", "")
    url = values.get("REMAP_REHEARSAL_URL", "")
    if not root or not url:
        raise ValueError(
            "set REMAP_REHEARSAL_ROOT to the rehearsal root directory and "
            + "REMAP_REHEARSAL_URL to the URL that serves it"
        )
    return Path(root), url
