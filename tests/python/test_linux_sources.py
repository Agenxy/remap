"""Cross-language and drift proofs for Linux generation source manifests."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import AbstractContextManager
from pathlib import Path
from typing import cast
from unittest import mock

from tools import remap_linux_install
from tools.remap_linux_install import MANPAGE_NAMES
from tools.remap_linux_sources import (
    EXPECTED_SOURCE_COUNT,
    pin_source_manifest,
    source_manifest_digest,
)


class LinuxSourceManifestTests(unittest.TestCase):
    """Keep Python's reviewed bytes identical to native Rust authority bytes."""

    def test_native_build_uses_the_explicit_cargo_target_directory(self) -> None:
        root = Path("/workspace/remap")
        staging = Path("/tmp/staging")
        with (
            mock.patch.dict(
                "os.environ", {"CARGO_TARGET_DIR": "/var/tmp/remap-target"}
            ),
            mock.patch("tools.remap_linux_install._run"),
            mock.patch(
                "tools.remap_linux_install._copy_source",
                return_value=staging / "remap-linux-system",
            ) as copy_source,
        ):
            _ = remap_linux_install.build_native_helper(root, staging)

        copy_source.assert_called_once_with(
            Path("/var/tmp/remap-target/release/remap-linux-system"),
            staging / "remap-linux-system",
        )

    def test_relative_cargo_target_directory_is_root_relative(self) -> None:
        root = Path("/workspace/remap")
        staging = Path("/tmp/staging")
        with (
            mock.patch.dict("os.environ", {"CARGO_TARGET_DIR": "build/native"}),
            mock.patch("tools.remap_linux_install._run"),
            mock.patch(
                "tools.remap_linux_install._copy_source",
                return_value=staging / "remap-linux-system",
            ) as copy_source,
        ):
            _ = remap_linux_install.build_native_helper(root, staging)

        copy_source.assert_called_once_with(
            root / "build/native/release/remap-linux-system",
            staging / "remap-linux-system",
        )

    def test_language_neutral_sha256_fixture_matches_native_rust(self) -> None:
        fixture = load_manifest_fixture()
        values = fixture.get("sources")
        self.assertIsInstance(values, list)
        decoded: list[tuple[str, int, bytes]] = []
        for value in cast("list[object]", values):
            self.assertIsInstance(value, dict)
            source = cast("dict[str, object]", value)
            self.assertEqual(set(source), {"path", "mode", "contentHex"})
            path = source.get("path")
            mode = source.get("mode")
            content_hex = source.get("contentHex")
            if (
                not isinstance(path, str)
                or not isinstance(mode, int)
                or isinstance(mode, bool)
                or not isinstance(content_hex, str)
            ):
                raise TypeError("the shared source fixture contains an invalid entry")
            decoded.append((path, mode, bytes.fromhex(content_hex)))
        self.assertEqual(source_manifest_digest(decoded), fixture.get("sha256"))

    def test_all_source_classes_remain_pinned_across_the_lifecycle(self) -> None:
        for case in ("cli", "daemon", "helper", "asset"):
            with (
                self.subTest(case=case),
                tempfile.TemporaryDirectory(
                    prefix="remap-source-manifest-"
                ) as directory,
            ):
                root = Path(directory).resolve()
                cli, daemon, helper, assets = source_tree(root)
                with (
                    _without_xattrs(),
                    pin_source_manifest(
                        cli=cli,
                        daemon=daemon,
                        helper=helper,
                        assets=assets,
                        manpage_names=MANPAGE_NAMES,
                        owner_uid=os.getuid(),
                    ) as manifest,
                ):
                    self.assertEqual(len(manifest.sources), EXPECTED_SOURCE_COUNT)
                    self.assertRegex(manifest.sha256, r"[0-9a-f]{64}\Z")
                    manifest.verify()
                    selected = {
                        "cli": cli,
                        "daemon": daemon,
                        "helper": helper,
                        "asset": assets / "LICENSE",
                    }[case]
                    selected_mode = 0o400 if case == "asset" else 0o500
                    if case == "asset":
                        _ = selected.rename(assets / "LICENSE.reviewed")
                        _ = selected.write_bytes(b"replacement asset")
                    else:
                        selected.chmod(0o700)
                        _ = selected.write_bytes(f"substituted {case}".encode())
                    selected.chmod(selected_mode)
                    with self.assertRaisesRegex(RuntimeError, "source (path )?changed"):
                        manifest.verify()

    def test_final_source_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-source-symlink-") as directory:
            root = Path(directory).resolve()
            cli, daemon, helper, assets = source_tree(root)
            target = root / "alternate"
            _ = target.write_bytes(b"alternate")
            cli.unlink()
            cli.symlink_to(target)
            with (
                _without_xattrs(),
                self.assertRaises(OSError),
                pin_source_manifest(
                    cli=cli,
                    daemon=daemon,
                    helper=helper,
                    assets=assets,
                    manpage_names=MANPAGE_NAMES,
                    owner_uid=os.getuid(),
                ),
            ):
                self.fail("a symbolic-link source must never be pinned")

    def test_source_ancestor_symlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-source-ancestor-") as directory:
            root = Path(directory).resolve()
            real = root / "real"
            real.mkdir()
            cli, daemon, helper, assets = source_tree(real)
            alias = root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            with (
                _without_xattrs(),
                self.assertRaises(OSError),
                pin_source_manifest(
                    cli=alias / cli.name,
                    daemon=daemon,
                    helper=helper,
                    assets=assets,
                    manpage_names=MANPAGE_NAMES,
                    owner_uid=os.getuid(),
                ),
            ):
                self.fail("an ancestor symbolic link must never be followed")


def source_tree(root: Path) -> tuple[Path, Path, Path, Path]:
    cli = source_file(root / "remap", b"remap", 0o500)
    daemon = source_file(root / "remapd", b"remapd", 0o500)
    helper = source_file(root / "remap-linux-system", b"helper", 0o500)
    assets = root / "assets"
    assets.mkdir(mode=0o700)
    _ = source_file(assets / "LICENSE", b"license", 0o400)
    _ = source_file(assets / "NOTICE", b"notice", 0o400)
    manpages = assets / "manpages"
    manpages.mkdir(mode=0o700)
    for name in MANPAGE_NAMES:
        _ = source_file(manpages / name, name.encode(), 0o400)
    for shell in ("bash", "fish", "zsh"):
        _ = source_file(assets / f"remap.{shell}", shell.encode(), 0o400)
    return cli, daemon, helper, assets


def source_file(path: Path, content: bytes, mode: int) -> Path:
    _ = path.write_bytes(content)
    path.chmod(mode)
    return path


def _without_xattrs() -> AbstractContextManager[object]:
    return mock.patch.object(os, "listxattr", return_value=(), create=True)


def load_manifest_fixture() -> dict[str, object]:
    path = (
        Path(__file__).resolve().parents[2]
        / "crates/remap-linux-system/tests/fixtures/linux-source-manifest-v1.json"
    )
    value = cast("object", json.loads(path.read_bytes()))
    if not isinstance(value, dict):
        raise TypeError("the shared Linux manifest fixture is not an object")
    fixture = cast("dict[str, object]", value)
    if (
        set(fixture) != {"schema", "sources", "sha256"}
        or fixture.get("schema") != "remap.linux-source-manifest-fixture/v1"
    ):
        raise RuntimeError("the shared Linux manifest fixture has an invalid schema")
    return fixture


if __name__ == "__main__":
    _ = unittest.main()
