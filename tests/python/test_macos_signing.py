# SPDX-License-Identifier: GPL-3.0-or-later
"""Contract tests for Remap's durable user-owned macOS signing identity."""

from __future__ import annotations

import base64
import hashlib
import os
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import cast, override
from unittest import mock

from tools import remap_macos_signing
from tools.remap_macos_signing import LocalCodeSigningIdentity


class AmbiguousIdentityTests(unittest.TestCase):
    """An ambiguous identity name is a configuration this tool must not create."""

    FIRST: str = "A" * 40
    SECOND: str = "B" * 40

    @staticmethod
    def _listing(*fingerprints: str) -> str:
        lines = [
            f'  {index + 1}) {fingerprint} "{remap_macos_signing.IDENTITY_NAME}"'
            for index, fingerprint in enumerate(fingerprints)
        ]
        lines.append(f"     {len(fingerprints)} valid identities found")
        return "\n".join(lines) + "\n"

    def _with_listing(self, listing: str) -> AbstractContextManager[object]:
        return mock.patch.object(
            remap_macos_signing,
            "_run_result",
            return_value=subprocess.CompletedProcess(
                args=(), returncode=0, stdout=listing, stderr=""
            ),
        )

    def test_one_identity_is_accepted(self) -> None:
        with self._with_listing(self._listing(self.FIRST)):
            remap_macos_signing.require_one_visible_identity()

    def test_no_identity_is_accepted_here(self) -> None:
        """Absence is handled by the caller, which creates one."""
        with self._with_listing("     0 valid identities found\n"):
            remap_macos_signing.require_one_visible_identity()

    def test_two_identities_of_the_same_name_are_refused(self) -> None:
        with (
            self._with_listing(self._listing(self.FIRST, self.SECOND)),
            self.assertRaises(RuntimeError) as raised,
        ):
            remap_macos_signing.require_one_visible_identity()
        message = str(raised.exception)
        self.assertIn(self.FIRST, message)
        self.assertIn(self.SECOND, message)
        self.assertIn("delete-certificate", message)

    def test_other_products_identities_are_not_counted(self) -> None:
        """Only this product's name is this product's business."""
        listing = (
            f'  1) {self.FIRST} "{remap_macos_signing.IDENTITY_NAME}"\n'
            f'  2) {self.SECOND} "Some Other Product"\n'
            "     2 valid identities found\n"
        )
        with self._with_listing(listing):
            remap_macos_signing.require_one_visible_identity()

    def test_ensure_refuses_before_creating_a_second_identity(self) -> None:
        """The refusal has to come first, or this tool is what made the mess."""
        with (
            mock.patch.object(
                remap_macos_signing,
                "require_one_visible_identity",
                side_effect=RuntimeError("ambiguous"),
            ),
            mock.patch.object(remap_macos_signing, "create_identity") as create,
            mock.patch.object(remap_macos_signing, "login_keychain") as keychain,
            self.assertRaisesRegex(RuntimeError, "ambiguous"),
        ):
            _ = remap_macos_signing.ensure_local_codesigning_identity()
        create.assert_not_called()
        keychain.assert_not_called()


class MacOSSigningTests(unittest.TestCase):
    """Keep local identity selection exact and fail closed on ambiguity."""

    @override
    def setUp(self) -> None:
        # These tests describe the interactive machine. CI sets the headless
        # variable for the gate as a whole, and it must not leak in here.
        variable = remap_macos_signing.HEADLESS_TRUST_VARIABLE
        saved = os.environ.pop(variable, None)

        def restore() -> None:
            if saved is not None:
                os.environ[variable] = saved

        self.addCleanup(restore)

    def test_headless_trust_uses_the_system_keychain_and_admits_apple_tools(
        self,
    ) -> None:
        calls: list[tuple[tuple[str, ...], bytes]] = []
        certificate = _pem("CERTIFICATE", b"certificate")
        private_key = _pem("PRIVATE KEY", b"private")

        def run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
            calls.append((arguments, input_bytes))
            return certificate + private_key if "req" in arguments else b""

        with tempfile.TemporaryDirectory() as home:
            _ = (Path(home) / "remap-headless.keychain-password").write_text(
                "secret-for-this-run\n", encoding="utf-8"
            )
            with (
                mock.patch.dict(
                    os.environ,
                    {
                        remap_macos_signing.HEADLESS_TRUST_VARIABLE: "1",
                        "RUNNER_TEMP": home,
                    },
                ),
                mock.patch(
                    "tools.remap_macos_signing._run_binary", side_effect=run_binary
                ),
                mock.patch(
                    "tools.remap_macos_signing._make_archive", return_value=b"archive"
                ),
            ):
                remap_macos_signing.create_identity(
                    Path(home) / "remap-headless.keychain-db"
                )

        trusted = next(call for call in calls if "add-trusted-cert" in call[0])
        partition = next(call for call in calls if "set-key-partition-list" in call[0])
        self.assertEqual(trusted[0][:2], ("/usr/bin/sudo", "-n"))
        self.assertIn("-d", trusted[0])
        self.assertIn(str(remap_macos_signing.SYSTEM_KEYCHAIN), trusted[0])
        self.assertEqual(trusted[1], certificate)
        self.assertEqual(
            partition[0][partition[0].index("-k") + 1], "secret-for-this-run"
        )
        self.assertIn("apple-tool:,apple:,codesign:", partition[0])

    def test_openssl_policy_is_a_durable_codesigning_root(self) -> None:
        configuration = remap_macos_signing.openssl_configuration()

        self.assertIn("CN = Remap Build Signing", configuration)
        # macOS names the developer in Login Items after the organisation.
        self.assertIn("\nO = Remap\n", configuration)
        self.assertIn("rsa:3072", _creation_arguments())
        self.assertIn("extendedKeyUsage = critical,codeSigning", configuration)
        self.assertIn("basicConstraints = critical,CA:TRUE,pathlen:0", configuration)

    def test_existing_identity_requires_exact_certificate_fingerprints(self) -> None:
        keychain = Path("/Users/example/Library/Keychains/login.keychain-db")
        outputs = (
            subprocess.CompletedProcess(
                args=(),
                returncode=0,
                stdout=(
                    "  1) 0123456789ABCDEF0123456789ABCDEF01234567 "
                    + '"Remap Build Signing"\n     1 valid identities found\n'
                ),
                stderr="",
            ),
            subprocess.CompletedProcess(
                args=(),
                returncode=0,
                stdout=(
                    "SHA-256 hash: "
                    + "A" * 64
                    + "\n"
                    + "SHA-1 hash: 0123456789ABCDEF0123456789ABCDEF01234567\n"
                ),
                stderr="",
            ),
        )
        with mock.patch(
            "tools.remap_macos_signing.subprocess.run", side_effect=outputs
        ):
            identity = remap_macos_signing.resolve_identity(keychain)

        self.assertEqual(
            identity,
            LocalCodeSigningIdentity(
                name="Remap Build Signing",
                sha1="0123456789ABCDEF0123456789ABCDEF01234567",
                sha256="A" * 64,
                keychain=keychain,
            ),
        )

    def test_duplicate_named_identity_is_rejected(self) -> None:
        output = """  1) 0123456789ABCDEF0123456789ABCDEF01234567 "Remap Build Signing"
  2) 89ABCDEF0123456789ABCDEF0123456789ABCDEF "Remap Build Signing"
     2 valid identities found
"""
        with (
            mock.patch(
                "tools.remap_macos_signing.subprocess.run",
                return_value=subprocess.CompletedProcess((), 0, output, ""),
            ),
            self.assertRaisesRegex(RuntimeError, "multiple usable identities"),
        ):
            _ = remap_macos_signing.resolve_identity(Path("/tmp/keychain"))

    def test_creation_imports_a_nonextractable_key_and_limits_trust(self) -> None:
        calls: list[tuple[tuple[str, ...], bytes]] = []
        certificate = _pem("CERTIFICATE", b"certificate")
        private_key = _pem("PRIVATE KEY", b"private")

        imported_files: list[tuple[Path, bytes, int, int]] = []

        def run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
            calls.append((arguments, input_bytes))
            if "import" in arguments:
                source = Path(arguments[arguments.index("import") + 1])
                imported_files.append(
                    (
                        source,
                        source.read_bytes(),
                        source.stat().st_mode & 0o777,
                        source.parent.stat().st_mode & 0o777,
                    )
                )
            return certificate + private_key if "req" in arguments else b""

        with (
            mock.patch("tools.remap_macos_signing._run_binary", side_effect=run_binary),
            mock.patch(
                "tools.remap_macos_signing._make_archive", return_value=b"archive"
            ) as make_archive,
        ):
            remap_macos_signing.create_identity(Path("/tmp/login.keychain-db"))

        imported, _ = next(call for call in calls if "import" in call[0])
        trusted = next(call for call in calls if "add-trusted-cert" in call[0])
        password = cast(str, make_archive.call_args.args[2])
        make_archive.assert_called_once_with(certificate, private_key, password)
        self.assertGreaterEqual(len(password), 32)
        self.assertEqual(imported[imported.index("-P") + 1], password)
        self.assertIn("-x", imported)
        self.assertEqual(imported[imported.index("-T") + 1], "/usr/bin/codesign")
        # macOS names the key's access dialog after the imported file, so the
        # file carries the identity's name, never "stdin".
        [(source, archive, mode, directory_mode)] = imported_files
        self.assertEqual(source.name, "Remap Build Signing.p12")
        # An explicit `-f pkcs12` makes macOS label the key "Imported Private Key".
        self.assertNotIn("-f", imported)
        self.assertEqual(archive, b"archive")
        self.assertEqual((mode, directory_mode), (0o600, 0o700))
        self.assertFalse(source.exists(), "the archive outlives its import")
        self.assertIn("codeSign", trusted[0])
        self.assertNotIn("-d", trusted[0])
        self.assertEqual(trusted[1], certificate)

    def test_archive_uses_only_anonymous_pipe_inputs(self) -> None:
        completed = subprocess.CompletedProcess((), 0, b"archive", b"")
        with (
            mock.patch(
                "tools.remap_macos_signing.os.pipe",
                side_effect=((10, 11), (12, 13)),
            ),
            mock.patch("tools.remap_macos_signing.os.write") as write,
            mock.patch("tools.remap_macos_signing.os.close") as close,
            mock.patch(
                "tools.remap_macos_signing.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            make_archive = cast(
                "Callable[[bytes, bytes, str], bytes]",
                vars(remap_macos_signing)["_make_archive"],
            )
            archive = make_archive(b"certificate", b"key", "run-password")

        self.assertEqual(archive, b"archive")
        write.assert_has_calls((mock.call(11, b"certificate"), mock.call(13, b"key")))
        self.assertEqual(
            [call.args[0] for call in close.call_args_list], [11, 13, 10, 12]
        )
        arguments = cast(tuple[str, ...], run.call_args.args[0])
        self.assertIn("/dev/fd/10", arguments)
        self.assertIn("/dev/fd/12", arguments)
        self.assertIn("/dev/stdout", arguments)
        self.assertIn("pass:run-password", arguments)
        self.assertEqual(run.call_args.kwargs["pass_fds"], (10, 12))

    def test_artifact_batch_uses_one_codesign_process(self) -> None:
        identity = LocalCodeSigningIdentity(
            name="Remap Build Signing",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        paths = (Path("/tmp/cli"), Path("/tmp/daemon"), Path("/tmp/Remap.app"))
        with mock.patch("tools.remap_macos_signing._run") as run:
            remap_macos_signing.sign_paths(
                paths,
                identity,
                identifier_prefix="org.agenxy.Remap.",
            )

        run.assert_called_once()
        arguments = cast(tuple[str, ...], run.call_args.args[0])
        self.assertEqual(arguments.count("/usr/bin/codesign"), 1)
        self.assertEqual(arguments[arguments.index("--options") + 1], "runtime")
        self.assertEqual(
            arguments[arguments.index("--prefix") + 1], "org.agenxy.Remap."
        )
        for path in paths:
            self.assertIn(str(path), arguments)

    def test_signature_verification_rejects_a_non_hardened_artifact(self) -> None:
        identity = LocalCodeSigningIdentity(
            name="Remap Build Signing",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        details = "\n".join(
            (
                "Identifier=org.agenxy.Remap.cli",
                "Authority=Remap Build Signing",
                "CDHash=" + "a" * 40,
                "CodeDirectory v=20400 size=100 flags=0x0(none)",
            )
        )
        with (
            mock.patch("tools.remap_macos_signing._run"),
            mock.patch("tools.remap_macos_signing._capture", return_value=details),
            self.assertRaisesRegex(RuntimeError, "hardened runtime"),
        ):
            _ = remap_macos_signing.verify_local_signature(
                Path("/tmp/remap"), identity, "org.agenxy.Remap.cli"
            )


class PendingTrustTests(unittest.TestCase):
    """A creation stopped at its trust dialog resumes; nothing else does."""

    keychain: Path = Path("/tmp/login.keychain-db")
    der: bytes = b"exact certificate bytes"

    @override
    def setUp(self) -> None:
        variable = remap_macos_signing.HEADLESS_TRUST_VARIABLE
        saved = os.environ.pop(variable, None)

        def restore() -> None:
            if saved is not None:
                os.environ[variable] = saved

        self.addCleanup(restore)

    def _hashes(self) -> list[tuple[str, str]]:
        return [
            (
                hashlib.sha1(self.der).hexdigest().upper(),
                hashlib.sha256(self.der).hexdigest().upper(),
            )
        ]

    def _record(
        self, reason: str, exported: bytes
    ) -> tuple[bool, list[tuple[tuple[str, ...], bytes]]]:
        sha1 = self._hashes()[0][0]
        listing = (
            "Policy: Code Signing\n  Matching identities\n"
            + f'  1) {sha1} "Remap Build Signing" ({reason})\n'
            + "     1 identities found\n"
        )
        certificate = _pem("CERTIFICATE", base64.b64encode(exported))
        calls: list[tuple[tuple[str, ...], bytes]] = []

        def capture(arguments: tuple[str, ...]) -> str:
            return listing if "find-identity" in arguments else certificate.decode()

        def run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
            calls.append((arguments, input_bytes))
            return b""

        with (
            mock.patch("tools.remap_macos_signing._capture", side_effect=capture),
            mock.patch(
                "tools.remap_macos_signing._certificate_hashes",
                return_value=self._hashes(),
            ),
            mock.patch("tools.remap_macos_signing._run_binary", side_effect=run_binary),
        ):
            recorded = remap_macos_signing.record_pending_trust(self.keychain)
        return recorded, calls

    def test_an_untrusted_exact_identity_is_trusted_once(self) -> None:
        recorded, calls = self._record("CSSMERR_TP_NOT_TRUSTED", self.der)

        self.assertTrue(recorded)
        self.assertEqual(len(calls), 1)
        arguments, certificate = calls[0]
        self.assertEqual(arguments[:2], ("/usr/bin/security", "add-trusted-cert"))
        self.assertIn("codeSign", arguments)
        self.assertEqual(certificate, _pem("CERTIFICATE", base64.b64encode(self.der)))

    def test_an_identity_refused_for_another_reason_is_left_alone(self) -> None:
        recorded, calls = self._record("CSSMERR_TP_CERT_EXPIRED", self.der)

        self.assertFalse(recorded)
        self.assertEqual(calls, [])

    def test_a_certificate_that_changes_on_export_is_refused(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "not the one in the keychain"):
            _ = self._record("CSSMERR_TP_NOT_TRUSTED", b"a different certificate")

    def test_ensure_resumes_instead_of_creating_a_second_identity(self) -> None:
        identity = LocalCodeSigningIdentity(
            name="Remap Build Signing",
            sha1=self._hashes()[0][0],
            sha256=self._hashes()[0][1],
            keychain=self.keychain,
        )
        with (
            mock.patch("tools.remap_macos_signing.require_one_visible_identity"),
            mock.patch(
                "tools.remap_macos_signing.login_keychain", return_value=self.keychain
            ),
            mock.patch(
                "tools.remap_macos_signing.resolve_identity",
                side_effect=[None, identity],
            ),
            mock.patch(
                "tools.remap_macos_signing._certificate_hashes",
                return_value=self._hashes(),
            ),
            mock.patch(
                "tools.remap_macos_signing.record_pending_trust", return_value=True
            ),
            mock.patch("tools.remap_macos_signing.create_identity") as create,
        ):
            resumed = remap_macos_signing.ensure_local_codesigning_identity()

        self.assertEqual(resumed, identity)
        create.assert_not_called()


def _creation_arguments() -> str:
    calls: list[tuple[str, ...]] = []
    material = _pem("CERTIFICATE", b"certificate") + _pem("PRIVATE KEY", b"private")

    def run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
        del input_bytes
        calls.append(arguments)
        return material if "req" in arguments else b""

    with (
        mock.patch("tools.remap_macos_signing._run_binary", side_effect=run_binary),
        mock.patch("tools.remap_macos_signing._make_archive", return_value=b"archive"),
    ):
        remap_macos_signing.create_identity(Path("/tmp/login.keychain-db"))
    return " ".join(calls[0])


def _pem(label: str, body: bytes) -> bytes:
    return (
        b"-----BEGIN "
        + label.encode()
        + b"-----\n"
        + body
        + b"\n-----END "
        + label.encode()
        + b"-----\n"
    )


class TrustDialogTests(unittest.TestCase):
    def test_an_unanswered_trust_dialog_says_how_to_resume(self) -> None:
        def run_binary(arguments: tuple[str, ...], _input: bytes) -> bytes:
            raise subprocess.TimeoutExpired(arguments, 120)

        with self.assertRaises(RuntimeError) as raised:
            remap_macos_signing.record_trust(
                Path("/tmp/login.keychain-db"),
                b"certificate",
                policy="codeSign",
                name="Remap Build Signing",
                run=run_binary,
            )
        message = str(raised.exception)
        self.assertIn('"Remap Build Signing"', message)
        self.assertIn("Run the same command again", message)
        self.assertIsNone(raised.exception.__cause__)


if __name__ == "__main__":
    _ = unittest.main()
