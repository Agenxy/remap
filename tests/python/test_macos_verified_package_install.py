"""Root-owned staging contract for verified macOS packages."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import remap_macos_verified_package_install as verified_install


class MacOSVerifiedPackageInstallTests(unittest.TestCase):
    def test_package_is_reverified_after_root_owned_copy_before_installer(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "Remap.pkg"
            signature = root / "Remap.pkg.sig"
            public_key = root / "docs/release/remap-release-signing-key.pub"
            public_key.parent.mkdir(parents=True)
            _ = package.write_bytes(b"package")
            _ = signature.write_bytes(b"signature")
            _ = public_key.write_text("ssh-ed25519 public-key\n", encoding="utf-8")
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
