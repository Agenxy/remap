"""Contracts for the dedicated complete-package Installer signer."""

from __future__ import annotations

import hashlib
import ssl
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tools import remap_macos_release_installer_signing as release_signing


class MacOSReleaseInstallerSigningTests(unittest.TestCase):
    def test_identity_resolution_requests_only_valid_identities(self) -> None:
        keychain = Path("/Users/example/Library/Keychains/login.keychain-db")
        root = Path(__file__).resolve().parents[2]
        certificate = root / release_signing.PINNED_CERTIFICATE
        certificate_der = bytes(
            ssl.PEM_cert_to_DER_cert(certificate.read_text(encoding="ascii"))
        )
        sha1 = hashlib.sha1(certificate_der).hexdigest().upper()
        sha256 = hashlib.sha256(certificate_der).hexdigest().upper()
        output = f'  1) {sha1} "Remap Release Installer"\n'
        with (
            mock.patch.object(
                release_signing,
                "_capture",
                return_value=output,
            ) as capture,
            mock.patch.object(
                release_signing,
                "_certificate_hashes",
                return_value=[(sha1, sha256)],
            ),
            mock.patch.object(release_signing, "_ensure_builder_trust"),
            mock.patch.object(
                release_signing,
                "login_keychain",
                return_value=keychain,
            ),
        ):
            identity = release_signing.ensure_release_installer_identity(root)

        self.assertEqual(
            capture.call_args.args[0],
            (
                "/usr/bin/security",
                "find-identity",
                "-v",
                "-p",
                "basic",
                str(keychain),
            ),
        )
        self.assertEqual(
            identity,
            release_signing.ReleaseInstallerSigningIdentity(
                name=release_signing.IDENTITY_NAME,
                sha1=sha1,
                sha256=sha256,
                keychain=keychain,
            ),
        )

    def test_release_identity_is_distinct_and_installer_only(self) -> None:
        configuration = release_signing.openssl_configuration()
        self.assertIn("CN = Remap Release Installer", configuration)
        self.assertIn("OU = Remap Release Signing", configuration)
        self.assertIn("1.2.840.113635.100.4.13", configuration)
        self.assertNotIn("codeSigning", configuration)
        self.assertNotIn("Remap Local Codesign", configuration)

    def test_complete_package_signing_pins_fingerprint_without_timestamp(self) -> None:
        identity = release_signing.ReleaseInstallerSigningIdentity(
            name=release_signing.IDENTITY_NAME,
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        output = (
            "Status: signed by a certificate that is not trusted\n"
            "1. Remap Release Installer\n"
            "SHA256 Fingerprint:\n"
            f"    {' '.join('BB' for _ in range(32))}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.pkg"

            def create(arguments: tuple[str, ...]) -> None:
                self.assertIn("--timestamp=none", arguments)
                _ = signed.write_bytes(b"signed package")

            with (
                mock.patch.object(release_signing, "_run", side_effect=create),
                mock.patch.object(release_signing, "_capture", return_value=output),
            ):
                release_signing.sign_package(
                    Path(directory) / "unsigned.pkg",
                    signed,
                    identity,
                )

    def test_complete_package_signing_rejects_wrong_certificate(self) -> None:
        identity = release_signing.ReleaseInstallerSigningIdentity(
            name=release_signing.IDENTITY_NAME,
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.pkg"

            def create(arguments: tuple[str, ...]) -> None:
                del arguments
                _ = signed.write_bytes(b"signed package")

            with (
                mock.patch.object(release_signing, "_run", side_effect=create),
                mock.patch.object(
                    release_signing,
                    "_capture",
                    return_value="Status: signed\n1. Other\nSHA256 Fingerprint: AA",
                ),
                self.assertRaisesRegex(RuntimeError, "wrong Installer certificate"),
            ):
                release_signing.sign_package(
                    Path(directory) / "unsigned.pkg",
                    signed,
                    identity,
                )

    def test_staged_package_verification_uses_the_pinned_certificate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificate = (
                Path(__file__).resolve().parents[2]
                / "docs/release/remap-release-installer.pem"
            )
            expected = release_signing.certificate_sha256(certificate)
            output = (
                "Status: signed by a certificate that is not trusted\n"
                "1. Remap Release Installer\n"
                "SHA256 Fingerprint:\n"
                f"    {' '.join(expected[index : index + 2] for index in range(0, 64, 2))}\n"
            )
            with mock.patch.object(
                release_signing,
                "_capture",
                return_value=output,
            ):
                release_signing.verify_package_signature(
                    root / "Remap.pkg", certificate
                )


if __name__ == "__main__":
    _ = unittest.main()
