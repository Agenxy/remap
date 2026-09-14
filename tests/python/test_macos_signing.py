"""Contract tests for Remap's durable user-owned macOS signing identity."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import cast, override
from unittest import mock

from tools import remap_macos_signing
from tools.remap_macos_signing import LocalCodeSigningIdentity


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

        self.assertIn("CN = Remap Local Codesign", configuration)
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
                    + '"Remap Local Codesign"\n     1 valid identities found\n'
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
                name="Remap Local Codesign",
                sha1="0123456789ABCDEF0123456789ABCDEF01234567",
                sha256="A" * 64,
                keychain=keychain,
            ),
        )

    def test_duplicate_named_identity_is_rejected(self) -> None:
        output = """  1) 0123456789ABCDEF0123456789ABCDEF01234567 "Remap Local Codesign"
  2) 89ABCDEF0123456789ABCDEF0123456789ABCDEF "Remap Local Codesign"
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

        def run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
            calls.append((arguments, input_bytes))
            return certificate + private_key if "req" in arguments else b""

        with (
            mock.patch("tools.remap_macos_signing._run_binary", side_effect=run_binary),
            mock.patch(
                "tools.remap_macos_signing._make_archive", return_value=b"archive"
            ) as make_archive,
        ):
            remap_macos_signing.create_identity(Path("/tmp/login.keychain-db"))

        imported, archive = next(call for call in calls if "import" in call[0])
        trusted = next(call for call in calls if "add-trusted-cert" in call[0])
        make_archive.assert_called_once_with(certificate, private_key)
        self.assertIn("-x", imported)
        self.assertEqual(imported[imported.index("-T") + 1], "/usr/bin/codesign")
        self.assertEqual(imported[imported.index("import") + 1], "/dev/stdin")
        self.assertEqual(archive, b"archive")
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
                "Callable[[bytes, bytes], bytes]",
                vars(remap_macos_signing)["_make_archive"],
            )
            archive = make_archive(b"certificate", b"key")

        self.assertEqual(archive, b"archive")
        write.assert_has_calls((mock.call(11, b"certificate"), mock.call(13, b"key")))
        self.assertEqual(
            [call.args[0] for call in close.call_args_list], [11, 13, 10, 12]
        )
        arguments = cast(tuple[str, ...], run.call_args.args[0])
        self.assertIn("/dev/fd/10", arguments)
        self.assertIn("/dev/fd/12", arguments)
        self.assertIn("/dev/stdout", arguments)
        self.assertEqual(run.call_args.kwargs["pass_fds"], (10, 12))

    def test_artifact_batch_uses_one_codesign_process(self) -> None:
        identity = LocalCodeSigningIdentity(
            name="Remap Local Codesign",
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
            name="Remap Local Codesign",
            sha1="A" * 40,
            sha256="B" * 64,
            keychain=Path("/Users/example/Library/Keychains/login.keychain-db"),
        )
        details = "\n".join(
            (
                "Identifier=org.agenxy.Remap.cli",
                "Authority=Remap Local Codesign",
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


if __name__ == "__main__":
    _ = unittest.main()
