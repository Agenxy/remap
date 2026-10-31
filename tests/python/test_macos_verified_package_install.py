# SPDX-License-Identifier: GPL-3.0-or-later
"""Root-owned staging contract for verified macOS packages."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import remap_macos_verified_package_install as verified_install
from tools.remap_release_signing import fingerprint

RELEASE_PIN = "ecdsa-sha2-nistp256 release-key remap-release-v2\n"
DEVELOPMENT_PIN = "ssh-ed25519 development-key remap-release-development-only\n"
# Fixture pins need a well-formed key only where a fingerprint is taken.
REHEARSAL_PIN = (
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBI5Kvkb"
    + "CKt1ALyXYnhyFFPtYP5RuHixZ12wcy3xLWHYoleWuWCLc6nP23SVRTsLOGvLzWPBVbYHfiMwqexbHuMA= "
    + "remap-release-rehearsal-only\n"
)
REHEARSAL_PACKAGE = "Remap-0.2.0-arm64-rehearsal.pkg"


def _pinned_root(
    directory: str, *, release: str = RELEASE_PIN, rehearsal: str | None = None
) -> Path:
    root = Path(directory)
    pins = root / "docs/release"
    pins.mkdir(parents=True)
    _ = (pins / "remap-release-signing-key.pub").write_text(release, encoding="utf-8")
    _ = (pins / "remap-development-signing-key.pub").write_text(
        DEVELOPMENT_PIN, encoding="utf-8"
    )
    if rehearsal is not None:
        _ = (pins / "remap-rehearsal-signing-key.pub").write_text(
            rehearsal, encoding="utf-8"
        )
    return root


class MacOSVerifiedPackageInstallTests(unittest.TestCase):
    def _install(
        self, root: Path, name: str, environment: dict[str, str]
    ) -> tuple[list[str], list[Path], list[tuple[str, ...]]]:
        """Install with every effect recorded; returns pins, installer checks, commands."""
        package = root / name
        signature = root / f"{name}.sig"
        _ = package.write_bytes(b"package")
        _ = signature.write_bytes(b"signature")
        pins: list[str] = []
        installer_checks: list[Path] = []
        commands: list[tuple[str, ...]] = []

        def verify(
            _path: Path,
            _signature: Path,
            *,
            public_key: str,
            expected_package_owner_uid: int | None = None,
        ) -> None:
            del expected_package_owner_uid
            pins.append(public_key)

        def run(arguments: tuple[str, ...], *, check: bool = True) -> None:
            del check
            commands.append(arguments)

        def check_installer(path: Path, _certificate: Path) -> None:
            installer_checks.append(path)

        with (
            mock.patch.dict(os.environ, environment, clear=True),
            mock.patch.object(verified_install, "_run", side_effect=run),
            mock.patch.object(verified_install, "verify_staging"),
            mock.patch.object(
                verified_install,
                "verify_package_signature",
                side_effect=check_installer,
            ),
            mock.patch.object(
                verified_install,
                "verify_detached_package_signature",
                side_effect=verify,
            ),
        ):
            verified_install.install_verified_package(root, package, signature)
        return pins, installer_checks, commands

    def test_a_release_package_verifies_against_the_release_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory)
            pins, installer_checks, _ = self._install(root, "Remap.pkg", {})
        self.assertEqual(pins, [RELEASE_PIN, RELEASE_PIN])
        self.assertEqual(len(installer_checks), 2)

    def test_a_development_package_verifies_only_on_request(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory)
            pins, installer_checks, _ = self._install(
                root,
                "Remap-0.2.0-arm64-development.pkg",
                {"REMAP_DEVELOPMENT_PACKAGE": "1"},
            )
            self.assertEqual(pins, [DEVELOPMENT_PIN, DEVELOPMENT_PIN])
            self.assertEqual(installer_checks, [])
            with self.assertRaisesRegex(RuntimeError, "REMAP_DEVELOPMENT_PACKAGE=1"):
                _ = self._install(root, "Remap-0.2.0-arm64-development.pkg", {})

    def test_a_rehearsal_package_verifies_only_as_a_rehearsal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory, rehearsal=REHEARSAL_PIN)
            printed = io.StringIO()
            with contextlib.redirect_stdout(printed):
                pins, installer_checks, commands = self._install(
                    root, REHEARSAL_PACKAGE, {"REMAP_REHEARSAL_PACKAGE": "1"}
                )
            self.assertEqual(pins, [REHEARSAL_PIN, REHEARSAL_PIN])
            self.assertEqual(installer_checks, [])
            self.assertTrue(any("/usr/sbin/installer" in c for c in commands))
            self.assertIn(
                "Installing a rehearsal package, not a release", printed.getvalue()
            )
            # Never as a release, whatever the release pin says.
            with self.assertRaisesRegex(RuntimeError, "never installed as a release"):
                _ = self._install(root, REHEARSAL_PACKAGE, {})
            for refused, environment, message in (
                ("Remap.pkg", {"REMAP_REHEARSAL_PACKAGE": "1"}, "is not one"),
                (
                    REHEARSAL_PACKAGE,
                    {"REMAP_REHEARSAL_PACKAGE": "1", "REMAP_DEVELOPMENT_PACKAGE": "1"},
                    "two kinds of package at once",
                ),
            ):
                with (
                    self.subTest(package=refused, environment=environment),
                    self.assertRaisesRegex(RuntimeError, message),
                ):
                    _ = self._install(root, refused, environment)

    def test_a_rehearsal_needs_its_committed_and_marked_pin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory)
            with self.assertRaisesRegex(RuntimeError, "has not been committed"):
                _ = self._install(
                    root, REHEARSAL_PACKAGE, {"REMAP_REHEARSAL_PACKAGE": "1"}
                )
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory, rehearsal=RELEASE_PIN)
            with self.assertRaisesRegex(RuntimeError, "remap-release-rehearsal-only"):
                _ = self._install(
                    root, REHEARSAL_PACKAGE, {"REMAP_REHEARSAL_PACKAGE": "1"}
                )

    def test_a_revoked_rehearsal_pin_installs_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory, rehearsal=REHEARSAL_PIN)
            _ = (
                root / "docs/release/remap-rehearsal-revoked-fingerprints.txt"
            ).write_text(
                f"# revoked\n{fingerprint(REHEARSAL_PIN)} 2026-11-01 rotated\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RuntimeError, "is revoked"):
                _ = self._install(
                    root, REHEARSAL_PACKAGE, {"REMAP_REHEARSAL_PACKAGE": "1"}
                )

    def test_a_rehearsal_marked_release_pin_verifies_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory, release=REHEARSAL_PIN)
            with self.assertRaisesRegex(RuntimeError, "still the rehearsal key"):
                _ = self._install(root, "Remap.pkg", {})

    def test_a_development_marked_release_pin_verifies_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory, release=DEVELOPMENT_PIN)
            with self.assertRaisesRegex(RuntimeError, "still the development key"):
                _ = self._install(root, "Remap.pkg", {})

    def test_package_is_reverified_after_root_owned_copy_before_installer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = _pinned_root(directory)
            package = root / "Remap.pkg"
            signature = root / "Remap.pkg.sig"
            _ = package.write_bytes(b"package")
            _ = signature.write_bytes(b"signature")
            calls: list[tuple[str, ...]] = []
            verifications: list[tuple[Path, int | None]] = []
            package_signatures: list[Path] = []

            def run(arguments: tuple[str, ...], *, check: bool = True) -> None:
                del check
                calls.append(arguments)

            def record_verification(
                path: Path,
                _signature: Path,
                *,
                public_key: str,
                expected_package_owner_uid: int | None = None,
            ) -> None:
                del public_key
                verifications.append((path, expected_package_owner_uid))

            def record_package_signature(path: Path, _certificate: Path) -> None:
                package_signatures.append(path)

            with (
                mock.patch.dict(os.environ, {}, clear=True),
                mock.patch.object(verified_install, "_run", side_effect=run),
                mock.patch.object(verified_install, "verify_staging"),
                mock.patch.object(
                    verified_install,
                    "verify_package_signature",
                    side_effect=record_package_signature,
                ),
                mock.patch.object(
                    verified_install,
                    "verify_detached_package_signature",
                    side_effect=record_verification,
                ),
            ):
                verified_install.install_verified_package(root, package, signature)

        self.assertEqual(verifications[0], (package, None))
        self.assertEqual(verifications[1][1], 0)
        self.assertEqual(package_signatures[0], package)
        self.assertEqual(package_signatures[1].name, "Remap.pkg")
        copy_index = next(
            index for index, call in enumerate(calls) if "/usr/bin/install" in call
        )
        install_index = next(
            index for index, call in enumerate(calls) if "/usr/sbin/installer" in call
        )
        self.assertLess(copy_index, install_index)

    def test_staging_rejects_user_owned_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            staging = parent / f"{verified_install.STAGING_PREFIX}{'a' * 36}"
            staging.mkdir(mode=0o755)
            package = staging / "Remap.pkg"
            _ = package.write_bytes(b"package")
            os.chmod(package, 0o444)
            with (
                mock.patch.object(verified_install, "STAGING_PARENT", parent),
                self.assertRaisesRegex(RuntimeError, "root-owned"),
            ):
                verified_install.verify_staging(staging, package)

    def test_staging_contract_requires_read_only_unique_regular_package(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            staging = parent / f"{verified_install.STAGING_PREFIX}{'a' * 36}"
            staging.mkdir(mode=0o755)
            package = staging / "Remap.pkg"
            _ = package.write_bytes(b"package")
            os.chmod(package, 0o644)
            root_directory = mock.Mock(
                st_mode=staging.stat().st_mode,
                st_uid=0,
                st_gid=0,
                st_nlink=staging.stat().st_nlink,
            )
            root_package = mock.Mock(
                st_mode=package.stat().st_mode,
                st_uid=0,
                st_gid=0,
                st_nlink=1,
                st_size=package.stat().st_size,
            )
            with (
                mock.patch.object(verified_install, "STAGING_PARENT", parent),
                mock.patch.object(
                    Path, "lstat", side_effect=(root_directory, root_package)
                ),
                self.assertRaisesRegex(RuntimeError, "root-owned"),
            ):
                verified_install.verify_staging(staging, package)


if __name__ == "__main__":
    _ = unittest.main()
