"""Contracts for Remap's durable local Installer signing identity."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast
from unittest import mock

from tools import remap_macos_installer_signing
from tools.remap_macos_installer_signing import LocalInstallerSigningIdentity


class MacOSInstallerSigningTests(unittest.TestCase):
    def test_policy_is_installer_only_and_durable(self) -> None:
        configuration = remap_macos_installer_signing.openssl_configuration()

        self.assertIn("CN = Remap Local Installer", configuration)
        self.assertIn(remap_macos_installer_signing.INSTALLER_EKU, configuration)
        self.assertNotIn("codeSigning", configuration)
        self.assertIn("CA:TRUE,pathlen:0", configuration)

    def test_creation_limits_private_key_use_to_productsign(self) -> None:
        calls: list[tuple[tuple[str, ...], bytes]] = []
        certificate = _pem("CERTIFICATE", b"certificate")
        private_key = _pem("PRIVATE KEY", b"private")

        def run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
            calls.append((arguments, input_bytes))
            return certificate + private_key if "req" in arguments else b""

        with (
            mock.patch(
                "tools.remap_macos_installer_signing._run_binary",
                side_effect=run_binary,
            ),
            mock.patch(
                "tools.remap_macos_installer_signing._make_archive",
                return_value=b"archive",
            ) as make_archive,
        ):
            remap_macos_installer_signing.create_identity(
                Path("/tmp/login.keychain-db")
            )

        imported, archive = next(call for call in calls if "import" in call[0])
        trusted = next(call for call in calls if "add-trusted-cert" in call[0])
        make_archive.assert_called_once_with(certificate, private_key)
        self.assertIn("-x", imported)
        self.assertEqual(imported[imported.index("-T") + 1], "/usr/bin/productsign")
        self.assertEqual(imported[imported.index("import") + 1], "/dev/stdin")
        self.assertEqual(archive, b"archive")
        self.assertIn("basic", trusted[0])
        self.assertNotIn("codeSign", trusted[0])
        self.assertEqual(trusted[1], certificate)

    def test_archive_uses_only_anonymous_pipe_inputs(self) -> None:
        completed = subprocess.CompletedProcess((), 0, b"archive", b"")
        with (
            mock.patch(
                "tools.remap_macos_installer_signing.os.pipe",
                side_effect=((20, 21), (22, 23)),
            ),
            mock.patch("tools.remap_macos_installer_signing.os.write") as write,
            mock.patch("tools.remap_macos_installer_signing.os.close") as close,
            mock.patch(
                "tools.remap_macos_installer_signing.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            make_archive = cast(
                "Callable[[bytes, bytes], bytes]",
                vars(remap_macos_installer_signing)["_make_archive"],
            )
            archive = make_archive(b"certificate", b"key")

        self.assertEqual(archive, b"archive")
        write.assert_has_calls((mock.call(21, b"certificate"), mock.call(23, b"key")))
        self.assertEqual(
            [call.args[0] for call in close.call_args_list], [21, 23, 20, 22]
        )
        arguments = cast(tuple[str, ...], run.call_args.args[0])
        self.assertIn("/dev/fd/20", arguments)
        self.assertIn("/dev/fd/22", arguments)
        self.assertIn("/dev/stdout", arguments)
        self.assertEqual(run.call_args.kwargs["pass_fds"], (20, 22))

    def test_sign_package_requires_exact_trusted_certificate(self) -> None:
        identity = LocalInstallerSigningIdentity(
            name="Remap Local Installer",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        output = (
            "Status: signed by a certificate trusted on this system\n"
            "1. Remap Local Installer\n"
            "SHA256 Fingerprint:\n"
            f"    {' '.join(identity.sha256[index : index + 2] for index in range(0, 64, 2))}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.pkg"

            def create_output(arguments: tuple[str, ...]) -> None:
                del arguments
                _ = signed.write_bytes(b"package")

            with (
                mock.patch(
                    "tools.remap_macos_installer_signing._run",
                    side_effect=create_output,
                ),
                mock.patch(
                    "tools.remap_macos_installer_signing._capture",
                    return_value=output,
                ),
            ):
                remap_macos_installer_signing.sign_package(
                    Path(directory) / "unsigned.pkg",
                    signed,
                    identity,
                )
            self.assertTrue(signed.is_file())

    def test_sign_package_rejects_current_user_only_trust(self) -> None:
        identity = LocalInstallerSigningIdentity(
            name="Remap Local Installer",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        output = (
            "Status: signed by a certificate trusted for current user\n"
            "1. Remap Local Installer\n"
            "SHA256 Fingerprint:\n"
            f"    {' '.join(identity.sha256[index : index + 2] for index in range(0, 64, 2))}\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.pkg"

            def create_output(arguments: tuple[str, ...]) -> None:
                del arguments
                _ = signed.write_bytes(b"package")

            with (
                mock.patch(
                    "tools.remap_macos_installer_signing._run",
                    side_effect=create_output,
                ),
                mock.patch(
                    "tools.remap_macos_installer_signing._capture",
                    return_value=output,
                ),
                self.assertRaisesRegex(RuntimeError, "system-wide"),
            ):
                remap_macos_installer_signing.sign_package(
                    Path(directory) / "unsigned.pkg",
                    signed,
                    identity,
                )
            self.assertFalse(signed.exists())

    def test_administrator_trust_uses_exact_system_policy(self) -> None:
        certificate = _pem("CERTIFICATE", b"certificate")
        identity = LocalInstallerSigningIdentity(
            name="Remap Local Installer",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        with (
            mock.patch(
                "tools.remap_macos_installer_signing._administrator_trust_is_exact",
                side_effect=[False, True],
            ),
            mock.patch(
                "tools.remap_macos_installer_signing._certificate_hashes",
                return_value=[],
            ),
            mock.patch(
                "tools.remap_macos_installer_signing._capture",
                return_value=certificate.decode("ascii"),
            ),
            mock.patch(
                "tools.remap_macos_installer_signing._require_certificate_identity"
            ) as require_identity,
            mock.patch(
                "tools.remap_macos_installer_signing._run_authorized"
            ) as authorized,
        ):
            remap_macos_installer_signing.ensure_administrator_trust(identity)

        arguments = cast(tuple[str, ...], authorized.call_args.args[0])
        self.assertEqual(arguments[:3], ("/usr/bin/security", "add-trusted-cert", "-d"))
        self.assertEqual(arguments[arguments.index("-p") + 1], "basic")
        self.assertEqual(
            arguments[arguments.index("-k") + 1],
            "/Library/Keychains/System.keychain",
        )
        self.assertEqual(arguments[-1], "/dev/stdin")
        require_identity.assert_called_once_with(certificate, identity)
        self.assertEqual(authorized.call_args.args[1], certificate)

    def test_sign_package_removes_its_exact_output_after_verification_failure(
        self,
    ) -> None:
        identity = LocalInstallerSigningIdentity(
            name="Remap Local Installer",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        with tempfile.TemporaryDirectory() as directory:
            signed = Path(directory) / "signed.pkg"

            def create_output(arguments: tuple[str, ...]) -> None:
                del arguments
                _ = signed.write_bytes(b"package")

            with (
                mock.patch(
                    "tools.remap_macos_installer_signing._run",
                    side_effect=create_output,
                ),
                mock.patch(
                    "tools.remap_macos_installer_signing._capture",
                    return_value="Status: rejected",
                ),
                self.assertRaisesRegex(RuntimeError, "wrong certificate"),
            ):
                remap_macos_installer_signing.sign_package(
                    Path(directory) / "unsigned.pkg",
                    signed,
                    identity,
                )
            self.assertFalse(signed.exists())


def _pem(label: str, body: bytes) -> bytes:
    encoded = label.encode()
    return (
        b"-----BEGIN "
        + encoded
        + b"-----\n"
        + body
        + b"\n-----END "
        + encoded
        + b"-----\n"
    )


if __name__ == "__main__":
    _ = unittest.main()
