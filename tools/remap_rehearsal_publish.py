# SPDX-License-Identifier: GPL-3.0-or-later
"""Publish a rehearsal of a Remap release into a root with the production layout (ADR-0035).

The root is static files a rehearsal host serves: the GitHub release-asset tree, a shim of
the two GitHub API answers that name those assets, and a Homebrew tap. A published version
is never rewritten, because a rehearsal that changed under an installer would prove nothing.

The root is served only over HTTPS, or over plain HTTP to a loopback address, which is how a
Supgang `forward` or `connect` delivers it after authenticating the peer. Nothing served
from the root is a trust anchor: an installing Mac checks the published fingerprint and the
repository's committed pin, never the copy beside the package. Every write into the root
refuses a symbolic link on its way and replaces a file whole rather than writing through it.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

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
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        raise ValueError(
            f"the rehearsal root {root} must be an existing absolute directory"
        )
    require_rehearsal_url(base_url)
    release = root / "releases" / OWNER / REPOSITORY / "download" / f"v{version}"
    if release.exists() or release.is_symlink():
        raise FileExistsError(
            f"{release} is already published; a rehearsal is never rewritten"
        )
    return release


def require_rehearsal_url(base_url: str) -> None:
    """`https://`, or `http://` only to a loopback address; never a trailing `/`.

    Plain HTTP across a network lets anyone on the path change what is served. Loopback is
    where a Supgang `forward` or `connect` delivers the deck root, over a path Supgang has
    already authenticated (K7 ADR 0167 §6). A loopback name such as `localhost` is refused,
    because only an address says where the bytes come from.
    """
    parts = urlsplit(base_url)
    if parts.scheme not in {"https", "http"}:
        raise ValueError(
            "the rehearsal URL must be https://, or http:// to a loopback address"
        )
    if base_url.endswith("/") or parts.query or parts.fragment or not parts.hostname:
        raise ValueError(
            "the rehearsal URL must be an origin and path with no trailing /, query, "
            + "or fragment"
        )
    if parts.username is not None or parts.password is not None:
        raise ValueError("the rehearsal URL must not carry credentials")
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and _is_loopback_address(parts.hostname):
        return
    raise ValueError(
        "the rehearsal URL must be https://, or http:// to a loopback address "
        + "(127.0.0.0/8 or [::1]) such as a Supgang forward"
    )


def _is_loopback_address(host: str) -> bool:
    """Exactly 127.0.0.0/8 or ::1; an IPv4-mapped IPv6 form is not accepted."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv4Address):
        return address in ipaddress.IPv4Network("127.0.0.0/8")
    return address == ipaddress.IPv6Address("::1")


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
    # Every place this writes is checked before anything is written, so a link planted
    # anywhere in the root refuses the whole publication rather than half of it.
    for relative in DIRECTORIES:
        _ = _directory(root, relative)
    for relative in REPLACED:
        _require_replaceable(root / relative)
    release.mkdir()
    assets = [inputs.package, inputs.signature, inputs.pin]
    for asset in assets:
        _write_new(release / asset.name, asset.read_bytes())
    sums = "".join(
        f"{_sha256(release / asset.name)}  {asset.name}\n" for asset in sorted(assets)
    )
    _write_new(release / "SHA256SUMS", sums.encode())
    archive = _directory(
        root, Path("releases") / OWNER / REPOSITORY / "archive" / "refs" / "tags"
    )
    source = archive / f"{tag}.tar.gz"
    _write_new(source, inputs.source_archive.read_bytes())
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
    api = _directory(root, Path("api/repos") / OWNER / REPOSITORY / "releases")
    tags = _directory(root, api.relative_to(root) / "tags")
    _write_new(tags / tag, text.encode())
    _replace(api / "latest", text.encode())


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
    directory = _directory(root, Path("homebrew/Formula"))
    _replace(directory / "remap.rb", formula.encode())


DIRECTORIES = (
    Path("releases") / OWNER / REPOSITORY / "download",
    Path("releases") / OWNER / REPOSITORY / "archive" / "refs" / "tags",
    Path("api/repos") / OWNER / REPOSITORY / "releases" / "tags",
    Path("homebrew/Formula"),
)
REPLACED = (
    Path("api/repos") / OWNER / REPOSITORY / "releases" / "latest",
    Path("homebrew/Formula/remap.rb"),
)


def _require_replaceable(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not stat.S_ISREG(path.lstat().st_mode)):
        raise RuntimeError(
            f"{path} is not a regular file; the root is never written through a link"
        )


def _directory(root: Path, relative: Path) -> Path:
    """`root / relative` as real directories, creating any missing, following no link."""
    path = root
    for part in relative.parts:
        path = path / part
        if path.is_symlink():
            raise RuntimeError(
                f"{path} is a symbolic link; the root is never written through one"
            )
        if not path.exists():
            path.mkdir(mode=0o755)
        elif not path.is_dir():
            raise RuntimeError(f"{path} is not a directory")
    return path


_NEW_FILE = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC


def _write_new(path: Path, data: bytes) -> None:
    """Create one file that must not exist yet, not even as a link."""
    with os.fdopen(os.open(path, _NEW_FILE, 0o644), "wb") as output:
        _ = output.write(data)


def _replace(path: Path, data: bytes) -> None:
    """Replace one file whole, so a link planted at its path is never followed."""
    _require_replaceable(path)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        _write_new(temporary, data)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


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
