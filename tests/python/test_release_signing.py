"""The two kinds of package, their two pins, and the signer each one may use."""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import cast, final, override
from unittest.mock import patch

from tools import remap_release_signing as signing
from tools.remap_macos_portable_package import (
    PACKAGE_NAMESPACE,
    verify_detached_package_signature,
)
from tools.remap_release_signing import (
    DEVELOPMENT_PIN,
    RELEASE_PIN,
    DevelopmentSigning,
    EnclaveSigner,
    FileKeySigner,
    PackageKind,
    ReleaseSigning,
    canonical_public_key,
    open_signer,
    preflight,
    selected_signing,
    swift_build_arguments,
    verify_embedded_pin,
)

REPOSITORY = Path(__file__).resolve().parents[2]
SWIFT_VERIFIER = (
    REPOSITORY
    / "platforms/macos/Sources/RemapPortableInstaller/PortableReleaseManifest.swift"
)
SWIFT_PINS = re.compile(
    r'#if REMAP_DEVELOPMENT_PACKAGE\n\s*static let releasePublicKey = """\n'
    + r'(?P<development>.*?)\n\s*"""\n\s*#else\n'
    + r'\s*static let releasePublicKey = """\n(?P<release>.*?)\n\s*"""\n\s*#endif\n',
    re.DOTALL,
)


def _swift_literal(body: str) -> str:
    """The value of a Swift multi-line literal whose lines end in continuations."""
    lines = [line.strip() for line in body.splitlines()]
    if not all(line.endswith("\\") for line in lines[:-1]):
        raise AssertionError("every line but the last must end in a continuation")
    return "".join(line.removesuffix("\\") for line in lines)


def _keygen(*arguments: str) -> str:
    return subprocess.run(
        ("/usr/bin/ssh-keygen", *arguments),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout


@final
class ReleaseSigningTests(unittest.TestCase):
    directory = Path()

    @override
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="remap-release-signing-test-"))
        os.chmod(self.directory, 0o700)
        (self.directory / "docs/release").mkdir(parents=True)

    @override
    def tearDown(self) -> None:
        shutil.rmtree(self.directory)

    def _key(self, name: str, kind: str, comment: str) -> Path:
        key = self.directory / name
        _ = _keygen("-q", "-t", kind, "-N", "", "-C", comment, "-f", str(key))
        return key

    def _pins(self, *, release: str, development: str) -> None:
        _ = (self.directory / RELEASE_PIN).write_text(release, encoding="utf-8")
        _ = (self.directory / DEVELOPMENT_PIN).write_text(development, encoding="utf-8")

    def _real_pins(self) -> tuple[Path, Path]:
        """A real P-256 release pin and a marked Ed25519 development pin and key."""
        release = self._key("release", "ecdsa", "remap-release-v2")
        development = self._key(
            "development", "ed25519", "remap-release-development-only"
        )
        self._pins(
            release=release.with_suffix(".pub").read_text(encoding="utf-8"),
            development=development.with_suffix(".pub").read_text(encoding="utf-8"),
        )
        return release, development

    def _blob(self, data: bytes) -> Path:
        blob = self.directory / "release.key"
        _ = blob.write_bytes(data)
        os.chmod(blob, 0o600)
        return blob

    def test_a_release_build_refuses_an_openssh_file_key(self) -> None:
        release, _ = self._real_pins()
        with self.assertRaisesRegex(RuntimeError, "file key can never sign a release"):
            preflight(self.directory, ReleaseSigning(release))
        with self.assertRaisesRegex(RuntimeError, "file key can never sign a release"):
            _ = selected_signing({"REMAP_RELEASE_SIGNING_KEY": str(release)})

    def test_a_release_build_refuses_a_development_marked_pin(self) -> None:
        _, development = self._real_pins()
        self._pins(
            release=development.with_suffix(".pub").read_text(encoding="utf-8"),
            development=development.with_suffix(".pub").read_text(encoding="utf-8"),
        )
        with self.assertRaisesRegex(RuntimeError, "remap-release-development-only"):
            preflight(self.directory, ReleaseSigning(self._blob(b"\x30enclave blob")))

    def test_the_repository_release_pin_cannot_sign_a_release_yet(self) -> None:
        """Until the owner pins the Secure Enclave key, no release can be built."""
        blob = self._blob(b"\x30enclave blob")
        with self.assertRaisesRegex(RuntimeError, "remap-release-development-only"):
            preflight(REPOSITORY, ReleaseSigning(blob))

    def test_a_release_pin_must_be_p256_and_distinct_from_development(self) -> None:
        _, development = self._real_pins()
        unmarked = self._key("unmarked", "ed25519", "remap-release")
        self._pins(
            release=unmarked.with_suffix(".pub").read_text(encoding="utf-8"),
            development=development.with_suffix(".pub").read_text(encoding="utf-8"),
        )
        with self.assertRaisesRegex(RuntimeError, "ecdsa-sha2-nistp256"):
            preflight(self.directory, ReleaseSigning(self._blob(b"\x30enclave blob")))

    def test_a_key_blob_must_be_one_small_owner_only_file(self) -> None:
        _ = self._real_pins()
        blob = self._blob(b"\x30enclave blob")
        preflight(self.directory, ReleaseSigning(blob))
        os.chmod(blob, 0o644)
        with self.assertRaisesRegex(RuntimeError, "owner-only"):
            preflight(self.directory, ReleaseSigning(blob))
        os.chmod(blob, 0o600)
        link = self.directory / "link.key"
        link.symlink_to(blob)
        with self.assertRaisesRegex(RuntimeError, "owner-only"):
            preflight(self.directory, ReleaseSigning(link))

    def test_a_blob_for_another_key_is_refused_before_anything_is_signed(self) -> None:
        release, _ = self._real_pins()
        stranger = self._key("stranger", "ecdsa", "remap-release-v2")
        blob = self._blob(b"\x30enclave blob")
        tool = Path("/private/build/remap-release-key")
        answer = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=stranger.with_suffix(".pub").read_text(encoding="utf-8"),
            stderr="",
        )
        with (
            patch.object(subprocess, "run", return_value=answer) as runner,
            self.assertRaisesRegex(RuntimeError, "not the pinned release key"),
        ):
            _ = open_signer(self.directory, ReleaseSigning(blob), release_key_tool=tool)
        runner.assert_called_once()
        self.assertEqual(
            runner.call_args.args[0],
            (str(tool), "public-key", "--key", str(blob)),
        )

        answer.stdout = release.with_suffix(".pub").read_text(encoding="utf-8")
        with patch.object(subprocess, "run", return_value=answer) as runner:
            signer = open_signer(
                self.directory, ReleaseSigning(blob), release_key_tool=tool
            )
        self.assertEqual(signer, EnclaveSigner(tool, blob))
        runner.assert_called_once()

    def test_the_enclave_signer_streams_the_message_to_its_tool(self) -> None:
        tool = Path("/private/build/remap-release-key")
        blob = Path("/private/release/release.key")
        message = io.BytesIO(b"exact package bytes")
        answer = subprocess.CompletedProcess(
            args=(), returncode=0, stdout=b"-----BEGIN SSH SIGNATURE-----\n", stderr=b""
        )
        with patch.object(subprocess, "run", return_value=answer) as runner:
            signature = EnclaveSigner(tool, blob).sign(
                message, namespace="remap-release"
            )
        self.assertEqual(signature, answer.stdout)
        self.assertEqual(
            runner.call_args.args[0],
            (str(tool), "sign", "--key", str(blob), "-n", "remap-release"),
        )
        stdin = cast("object", runner.call_args.kwargs["stdin"])
        self.assertIs(stdin, message)

    def test_the_development_path_is_unchanged(self) -> None:
        _, development = self._real_pins()
        selected = selected_signing(
            {
                "REMAP_DEVELOPMENT_PACKAGE": "1",
                "REMAP_RELEASE_SIGNING_KEY": str(development),
            }
        )
        self.assertEqual(selected, DevelopmentSigning(development))
        preflight(self.directory, selected)
        signer = open_signer(
            self.directory, selected, release_key_tool=Path("/nonexistent")
        )
        self.assertEqual(signer, FileKeySigner(development))
        self.assertEqual(
            swift_build_arguments(PackageKind.DEVELOPMENT),
            ("-Xswiftc", "-DREMAP_DEVELOPMENT_PACKAGE"),
        )
        self.assertEqual(swift_build_arguments(PackageKind.RELEASE), ())

        package = self.directory / "Remap.pkg"
        _ = package.write_bytes(b"exact package bytes")
        os.chmod(package, 0o400)
        with package.open("rb") as message:
            data = signer.sign(message, namespace=PACKAGE_NAMESPACE)
        signature = self.directory / "Remap.pkg.sig"
        _ = signature.write_bytes(data)
        os.chmod(signature, 0o400)
        verify_detached_package_signature(
            package,
            signature,
            public_key=signing.pinned_public_key(
                self.directory, PackageKind.DEVELOPMENT
            ),
        )

    def test_a_development_key_must_match_the_development_pin(self) -> None:
        release, _ = self._real_pins()
        other = self._key("other", "ed25519", "remap-release-development-only")
        os.chmod(other, 0o600)
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            preflight(self.directory, DevelopmentSigning(other))
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            preflight(self.directory, DevelopmentSigning(release))

    def test_the_two_kinds_are_never_mixed(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "never signs a development package"):
            _ = selected_signing(
                {
                    "REMAP_DEVELOPMENT_PACKAGE": "1",
                    "REMAP_RELEASE_SIGNING_KEY": "/private/development",
                    "REMAP_RELEASE_SE_KEY": "/private/release.key",
                }
            )
        with self.assertRaisesRegex(RuntimeError, "dedicated release key"):
            _ = selected_signing({})
        self.assertEqual(
            selected_signing({"REMAP_RELEASE_SE_KEY": "/private/release.key"}),
            ReleaseSigning(Path("/private/release.key")),
        )

    def test_an_installer_must_embed_exactly_its_own_pin(self) -> None:
        release, development = self._real_pins()
        release_key = canonical_public_key(
            release.with_suffix(".pub").read_text(encoding="utf-8")
        ).split()[1]
        development_key = canonical_public_key(
            development.with_suffix(".pub").read_text(encoding="utf-8")
        ).split()[1]
        installer = self.directory / "remap-portable-installer"
        _ = installer.write_bytes(b"\xcf\xfa\xed\xfe" + development_key.encode())
        verify_embedded_pin(installer, self.directory, PackageKind.DEVELOPMENT)
        with self.assertRaisesRegex(RuntimeError, "release pin"):
            verify_embedded_pin(installer, self.directory, PackageKind.RELEASE)
        _ = installer.write_bytes(
            b"\xcf\xfa\xed\xfe" + development_key.encode() + release_key.encode()
        )
        with self.assertRaisesRegex(RuntimeError, "development pin"):
            verify_embedded_pin(installer, self.directory, PackageKind.DEVELOPMENT)

    def test_public_keys_are_canonical_and_self_describing(self) -> None:
        release, development = self._real_pins()
        for key in (release, development):
            line = key.with_suffix(".pub").read_text(encoding="utf-8")
            self.assertEqual(canonical_public_key(line), " ".join(line.split()[:2]))
        ecdsa_blob = release.with_suffix(".pub").read_text(encoding="utf-8").split()[1]
        for unsafe in (
            "",
            "ssh-rsa AAAA",
            "ssh-ed25519",
            "ssh-ed25519 a b c",
            f"ssh-ed25519 {ecdsa_blob}",
            "ecdsa-sha2-nistp256 not*base64",
        ):
            with self.subTest(value=unsafe), self.assertRaises(RuntimeError):
                _ = canonical_public_key(unsafe)


@final
class PinConsistencyTests(unittest.TestCase):
    """Each committed pin, its compiled-in copy, and the published fingerprints agree."""

    def test_each_doc_pin_is_byte_identical_to_its_swift_constant(self) -> None:
        source = SWIFT_VERIFIER.read_text(encoding="utf-8")
        match = SWIFT_PINS.search(source)
        self.assertIsNotNone(match, "the Swift verifier must select one pin by kind")
        assert match is not None
        self.assertEqual(source.count("static let releasePublicKey"), 2)
        for kind, pin in (("development", DEVELOPMENT_PIN), ("release", RELEASE_PIN)):
            with self.subTest(kind=kind):
                document = (REPOSITORY / pin).read_text(encoding="utf-8")
                self.assertEqual(document.count("\n"), 1)
                self.assertEqual(_swift_literal(match.group(kind)) + "\n", document)

    def test_the_development_pin_says_what_it_is(self) -> None:
        pin = (REPOSITORY / DEVELOPMENT_PIN).read_text(encoding="utf-8")
        self.assertIn("remap-release-development-only", pin)

    def test_published_fingerprints_follow_the_release_pin(self) -> None:
        listing = _keygen("-l", "-E", "sha256", "-f", str(REPOSITORY / RELEASE_PIN))
        fingerprint = listing.split()[1]
        tutorial = (REPOSITORY / "docs/tutorials/first-map-macos.md").read_text(
            encoding="utf-8"
        )
        self.assertIn(listing.strip(), tutorial)
        for document in ("README.md", "docs/release/EVIDENCE.md"):
            with self.subTest(document=document):
                text = (REPOSITORY / document).read_text(encoding="utf-8")
                self.assertTrue(
                    fingerprint in text, f"{document} must quote {fingerprint}"
                )


if __name__ == "__main__":
    _ = unittest.main()
