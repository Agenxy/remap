"""Release-package policy regressions."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.remap_package import (
    cargo_target_directory,
    verify_exact_copies,
    verify_publishable_dependency_closure,
)


class PackagePolicyTests(unittest.TestCase):
    """Keep public crate dependency closure publishable."""

    def test_cargo_target_directory_matches_cargo_environment_semantics(self) -> None:
        root = Path("/workspace")
        self.assertEqual(cargo_target_directory(root, {}), root / "target")
        self.assertEqual(
            cargo_target_directory(root, {"CARGO_TARGET_DIR": "build/cargo"}),
            root / "build/cargo",
        )
        self.assertEqual(
            cargo_target_directory(root, {"CARGO_TARGET_DIR": "/var/tmp/remap-cargo"}),
            Path("/var/tmp/remap-cargo"),
        )

    def test_workspace_publishable_dependency_closure_is_complete(self) -> None:
        root = Path(__file__).resolve().parents[2]
        sources = {
            manifest.parent.name: manifest.parent
            for manifest in (root / "crates").glob("*/Cargo.toml")
        }

        verify_publishable_dependency_closure(sources)

    def test_private_runtime_dependency_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-package-policy-") as directory:
            root = Path(directory)
            public = root / "public"
            private = root / "private"
            public.mkdir()
            private.mkdir()
            _ = (public / "Cargo.toml").write_text(
                """[package]
name = "public"
version = "1.0.0"

[dependencies]
private = { path = "../private", version = "=1.0.0" }
""",
                encoding="utf-8",
            )
            _ = (private / "Cargo.toml").write_text(
                """[package]
name = "private"
version = "1.0.0"
publish = false
""",
                encoding="utf-8",
            )

            with self.assertRaisesRegex(RuntimeError, "public.*private"):
                verify_publishable_dependency_closure(
                    {"public": public, "private": private}
                )

    def test_missing_declared_policy_copy_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-policy-copy-") as directory:
            root = Path(directory)
            authority = root / "LICENSE"
            _ = authority.write_text("license\n", encoding="utf-8")

            with self.assertRaisesRegex(RuntimeError, "missing.*LICENSE"):
                verify_exact_copies(
                    root,
                    authority,
                    (root / "crate/LICENSE",),
                )
