# SPDX-License-Identifier: GPL-3.0-or-later
"""The rehearsal root has the production layout and is never rewritten (ADR-0035)."""

from __future__ import annotations

import hashlib
import json
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import cast

from tools.remap_rehearsal_publish import (
    RehearsalInputs,
    publish,
    rehearsal_root_from_environment,
    release_directory,
    source_archive,
)

URL = "https://rehearsal.example/remap"
PACKAGE = "Remap-0.2.0-arm64-rehearsal.pkg"


def _fixture(base: Path) -> tuple[Path, RehearsalInputs]:
    """A scratch root and the four inputs one rehearsal publishes."""
    root = base / "root"
    root.mkdir()
    inputs = base / "inputs"
    inputs.mkdir()
    files = {
        PACKAGE: b"package",
        f"{PACKAGE}.sig": b"signature",
        "remap-rehearsal-signing-key.pub": b"ssh-ed25519 AAAA remap-release-rehearsal-only\n",
        "source.tar.gz": b"source",
    }
    for name, data in files.items():
        _ = (inputs / name).write_bytes(data)
    return root, RehearsalInputs(
        version="0.2.0",
        package=inputs / PACKAGE,
        signature=inputs / f"{PACKAGE}.sig",
        pin=inputs / "remap-rehearsal-signing-key.pub",
        source_archive=inputs / "source.tar.gz",
    )


class RehearsalPublishTests(unittest.TestCase):
    """Publish one version into a scratch root and read back what an installer sees."""

    def scratch(self) -> tuple[Path, RehearsalInputs]:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        return _fixture(Path(directory.name))

    def test_assets_follow_the_github_release_layout_with_checksums(self) -> None:
        root, inputs = self.scratch()
        release = publish(root, URL, inputs)
        self.assertEqual(release, root / "releases/Agenxy/remap/download/v0.2.0")
        names = sorted(path.name for path in release.iterdir())
        expected = [
            PACKAGE,
            f"{PACKAGE}.sig",
            "SHA256SUMS",
            "remap-rehearsal-signing-key.pub",
        ]
        self.assertEqual(names, expected)
        sums = (release / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        self.assertIn(f"{hashlib.sha256(b'package').hexdigest()}  {PACKAGE}", sums)
        self.assertEqual(len(sums), 3)

    def test_the_api_shim_names_every_asset_at_the_rehearsal_url(self) -> None:
        root, inputs = self.scratch()
        _ = publish(root, URL, inputs)
        api = root / "api/repos/Agenxy/remap/releases"
        latest_text = (api / "latest").read_text(encoding="utf-8")
        self.assertEqual((api / "tags/v0.2.0").read_text(encoding="utf-8"), latest_text)
        latest = cast("dict[str, object]", json.loads(latest_text))
        self.assertEqual(latest["tag_name"], "v0.2.0")
        self.assertIs(latest["prerelease"], True)
        assets = cast("list[dict[str, object]]", latest["assets"])
        download = f"{URL}/releases/Agenxy/remap/download/v0.2.0"
        self.assertEqual(assets[0]["browser_download_url"], f"{download}/{PACKAGE}")
        self.assertEqual(assets[0]["size"], len(b"package"))

    def test_the_formula_builds_the_served_source_and_says_what_it_installs(
        self,
    ) -> None:
        root, inputs = self.scratch()
        _ = publish(root, URL, inputs)
        formula = (root / "homebrew/Formula/remap.rb").read_text(encoding="utf-8")
        source = f"{URL}/releases/Agenxy/remap/archive/refs/tags/v0.2.0.tar.gz"
        self.assertIn(f'url "{source}"', formula)
        self.assertIn(f'sha256 "{hashlib.sha256(b"source").hexdigest()}"', formula)
        self.assertIn('license "GPL-3.0-or-later"', formula)
        self.assertIn("remap 0.2.0", formula)
        self.assertIn("installs the remap command only", formula)
        self.assertNotIn("{{", formula)

    def test_a_published_version_is_never_rewritten(self) -> None:
        root, inputs = self.scratch()
        _ = publish(root, URL, inputs)
        with self.assertRaisesRegex(FileExistsError, "never rewritten"):
            _ = publish(root, URL, inputs)

    def test_settings_are_required_and_checked(self) -> None:
        root, inputs = self.scratch()
        with self.assertRaisesRegex(ValueError, "REMAP_REHEARSAL_ROOT"):
            _ = rehearsal_root_from_environment({})
        with self.assertRaisesRegex(ValueError, "existing absolute directory"):
            _ = publish(Path("relative"), URL, inputs)
        with self.assertRaisesRegex(ValueError, "no trailing"):
            _ = publish(root, URL + "/", inputs)
        with self.assertRaisesRegex(ValueError, "http"):
            _ = publish(root, "file:///tmp", inputs)

    def test_the_destination_is_checked_before_anything_is_built(self) -> None:
        root, inputs = self.scratch()
        self.assertEqual(
            release_directory(root, URL, "0.2.0"),
            root / "releases/Agenxy/remap/download/v0.2.0",
        )
        _ = publish(root, URL, inputs)
        with self.assertRaisesRegex(FileExistsError, "never rewritten"):
            _ = release_directory(root, URL, "0.2.0")
        with self.assertRaisesRegex(ValueError, "existing absolute directory"):
            _ = release_directory(root / "missing", URL, "0.2.1")


class SourceArchiveTests(unittest.TestCase):
    """The source archive is HEAD, laid out as GitHub's tag archive, from a clean tree."""

    def repository(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        repository = Path(directory.name) / "remap"
        repository.mkdir()

        def git(*arguments: str) -> None:
            _ = subprocess.run(
                ("git", "-C", str(repository), *arguments),
                check=True,
                capture_output=True,
                timeout=60,
            )

        git("init", "-q")
        _ = (repository / "README.md").write_text("Remap\n", encoding="utf-8")
        git("add", "README.md")
        git(
            "-c",
            "user.name=Remap Tests",
            "-c",
            "user.email=tests@remap.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "fixture",
        )
        return repository

    def test_head_is_archived_under_the_tag_archive_prefix(self) -> None:
        repository = self.repository()
        destination = repository.parent / "out"
        destination.mkdir()
        archive = source_archive(repository, "0.2.0", destination)
        self.assertEqual(archive.name, "remap-0.2.0.tar.gz")
        with tarfile.open(archive) as members:
            self.assertIn("remap-0.2.0/README.md", members.getnames())

    def test_a_tree_with_changes_head_lacks_is_refused(self) -> None:
        repository = self.repository()
        _ = (repository / "README.md").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(RuntimeError, "commit or remove them"):
            _ = source_archive(repository, "0.2.0", repository.parent)


if __name__ == "__main__":
    _ = unittest.main()
