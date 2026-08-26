"""Contract tests for the target-Mac-self-signed native package."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zlib
from collections.abc import Callable
from pathlib import Path
from typing import cast, final, override
from unittest.mock import ANY, call, patch

import tools.remap_macos_portable_package as portable_package
from tools.remap_macos_package_metadata import (
    NORMALIZED_PACKAGE_MTIME,
    normalize_package_extended_attributes,
    normalize_package_timestamps,
    verify_payload_member_names,
)
from tools.remap_macos_portable_package import (
    PACKAGE_NAMESPACE,
    XAR_HEADER,
    XAR_MAGIC,
    canonical_release_json,
    canonical_release_public_key,
    canonicalize_xar_metadata,
    release_entries,
    release_manifest,
    validate_version,
    verify_detached_package_signature,
    verify_no_local_build_paths,
)
from tools.remap_release_artifacts import publish_release_artifacts


@final
class PortablePackageTests(unittest.TestCase):
    directory = Path()

    @override
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="remap-portable-test-"))
        os.chmod(self.directory, 0o700)

    @override
    def tearDown(self) -> None:
        shutil.rmtree(self.directory)

    def test_release_manifest_is_canonical_and_complete(self) -> None:
        payload = self.directory / "payload"
        binary = payload / "product/bin/remap"
        binary.parent.mkdir(parents=True)
        os.chmod(payload, 0o700)
        os.chmod(payload / "product", 0o700)
        os.chmod(payload / "product/bin", 0o700)
        _ = binary.write_bytes(b"remap")
        os.chmod(binary, 0o500)

        entries = release_entries(payload)
        document = release_manifest("0.2.0", "arm64", entries)
        encoded = canonical_release_json(document)

        self.assertEqual(
            encoded,
            json.dumps(
                document,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode(),
        )
        self.assertEqual(document["productIdentifier"], "org.agenxy.Remap")
        self.assertEqual(document["minimumMacOSVersion"], "15.0")
        self.assertEqual(
            [entry["path"] for entry in entries],
            ["product", "product/bin", "product/bin/remap"],
        )

    def test_signing_streams_bytes_without_external_signature_creation(self) -> None:
        payload = self.directory / "release-manifest.json"
        _ = payload.write_bytes(b'{"schemaVersion":1}')
        signature_bytes = b"-----BEGIN SSH SIGNATURE-----\nfixture\n"
        sign_file = cast("Callable[..., None]", vars(portable_package)["_sign_file"])
        completed = subprocess.CompletedProcess(
            args=(),
            returncode=0,
            stdout=signature_bytes,
            stderr=b"Signing data on standard input\n",
        )

        with patch.object(subprocess, "run", return_value=completed) as runner:
            sign_file(payload, Path("/private/release.pub"), namespace="release")

        runner.assert_called_once_with(
            (
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                "/private/release.pub",
                "-n",
                "release",
            ),
            cwd=self.directory,
            check=True,
            stdin=ANY,
            capture_output=True,
            timeout=120,
        )
        self.assertEqual(payload.with_suffix(".json.sig").read_bytes(), signature_bytes)
        self.assertEqual(
            stat.S_IMODE(payload.with_suffix(".json.sig").stat().st_mode),
            0o400,
        )

    def test_release_entries_reject_links_and_noncanonical_modes(self) -> None:
        payload = self.directory / "payload"
        payload.mkdir(mode=0o700)
        unsafe = payload / "unsafe"
        _ = unsafe.write_bytes(b"unsafe")
        os.chmod(unsafe, 0o600)
        with self.assertRaisesRegex(RuntimeError, "unsafe metadata"):
            _ = release_entries(payload)

        unsafe.unlink()
        unsafe.symlink_to("missing")
        with self.assertRaisesRegex(RuntimeError, "symlink"):
            _ = release_entries(payload)

    def test_package_timestamps_are_stable_and_reject_links(self) -> None:
        payload = self.directory / "payload"
        child = payload / "child"
        payload.mkdir(mode=0o700)
        _ = child.write_bytes(b"remap")
        os.utime(payload, (1_700_000_000, 1_700_000_000))
        os.utime(child, (1_800_000_000, 1_800_000_000))

        normalize_package_timestamps(payload)

        self.assertEqual(payload.stat().st_mtime_ns, NORMALIZED_PACKAGE_MTIME * 10**9)
        self.assertEqual(child.stat().st_mtime_ns, NORMALIZED_PACKAGE_MTIME * 10**9)
        child.unlink()
        child.symlink_to("missing")
        with self.assertRaisesRegex(RuntimeError, "timestamp input is unsafe"):
            normalize_package_timestamps(payload)

    def test_package_extended_attributes_are_removed(self) -> None:
        payload = self.directory / "payload"
        child = payload / "child"
        payload.mkdir(mode=0o700)
        _ = child.write_bytes(b"remap")
        for path, value in ((payload, "directory"), (child, "file")):
            _ = subprocess.run(
                (
                    "/usr/bin/xattr",
                    "-w",
                    "com.agenxy.remap-test",
                    value,
                    str(path),
                ),
                check=True,
                timeout=30,
            )

        normalize_package_extended_attributes(payload)

        for path in (payload, child):
            result = subprocess.run(
                ("/usr/bin/xattr", str(path)),
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.stdout, "")

    def test_payload_members_are_canonical_and_not_appledouble(self) -> None:
        verify_payload_member_names(
            """.
./Library
./Library/Application Support
./Library/Application Support/Agenxy/Remap/remap
"""
        )
        for listing in (
            ".\n./Library/._Application Support\n",
            ".\n./Library/Application Support/._remap\n",
            ".\n./Library/../private/file\n",
            ".\n./Library//file\n",
            ".\nLibrary/file\n",
            ".\n./Library/file\x00suffix\n",
        ):
            with (
                self.subTest(listing=listing),
                self.assertRaisesRegex(RuntimeError, "unsafe member"),
            ):
                verify_payload_member_names(listing)

    def test_strip_removes_existing_signature_before_mutating_binary(self) -> None:
        binary = self.directory / "signed-binary"
        _ = binary.write_bytes(b"Mach-O fixture")
        strip_mach_o = cast(
            "Callable[..., None]", vars(portable_package)["_strip_mach_o"]
        )

        with patch.object(portable_package, "_run") as runner:
            strip_mach_o(binary, root=self.directory)

        self.assertEqual(
            runner.call_args_list,
            [
                call(
                    ("/usr/bin/codesign", "--remove-signature", str(binary)),
                    root=self.directory,
                ),
                call(
                    ("/usr/bin/xcrun", "strip", "-S", str(binary)),
                    root=self.directory,
                ),
            ],
        )

    def test_xar_metadata_is_canonical_across_build_instances(self) -> None:
        first = self.directory / "first.pkg"
        second = self.directory / "second.pkg"
        self._write_test_xar(first, timestamp="2026-08-21T10:00:00", inode=41)
        self._write_test_xar(second, timestamp="2026-08-21T11:00:00", inode=92)

        canonicalize_xar_metadata(first)
        canonicalize_xar_metadata(second)

        self.assertEqual(first.read_bytes(), second.read_bytes())

    @staticmethod
    def _write_test_xar(path: Path, *, timestamp: str, inode: int) -> None:
        document = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<xar><toc><checksum style="sha1"><size>20</size>'
            "<offset>0</offset></checksum>"
            f"<creation-time>{timestamp}</creation-time>"
            '<file id="1"><name>Payload</name><type>file</type>'
            f"<inode>{inode}</inode><deviceno>16777232</deviceno>"
            "<mode>0644</mode><uid>501</uid><user>builder</user>"
            "<gid>20</gid><group>staff</group>"
            f"<atime>{timestamp}Z</atime><mtime>{timestamp}Z</mtime>"
            f"<ctime>{timestamp}Z</ctime><FinderCreateTime>"
            f"<time>{timestamp}</time><nanoseconds>0</nanoseconds>"
            "</FinderCreateTime><data><size>7</size><offset>20</offset>"
            "<length>7</length></data></file></toc></xar>"
        ).encode()
        compressed = zlib.compress(document)
        header = XAR_HEADER.pack(
            XAR_MAGIC,
            XAR_HEADER.size,
            1,
            len(compressed),
            len(document),
            1,
        )
        _ = path.write_bytes(
            header + compressed + hashlib.sha1(compressed).digest() + b"payload"
        )
        os.chmod(path, 0o400)

    def test_package_version_is_canonical(self) -> None:
        for value in ("0.2", "v0.2.0", "00.2.0", "0.2.0-beta"):
            with (
                self.subTest(value=value),
                self.assertRaisesRegex(RuntimeError, "canonical SemVer"),
            ):
                validate_version(value)

    def test_release_public_key_matches_the_native_verifier(self) -> None:
        root = Path(__file__).resolve().parents[2]
        public_key = (
            (root / "docs/release/remap-release-signing-key.pub")
            .read_text(encoding="utf-8")
            .strip()
        )
        native = (
            root
            / "platforms/macos/Sources/RemapPortableInstaller/PortableReleaseManifest.swift"
        ).read_text(encoding="utf-8")
        self.assertIn(public_key, native)

    def test_release_public_key_is_one_canonical_ed25519_identity(self) -> None:
        key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest remap-release"
        self.assertEqual(
            canonical_release_public_key(key),
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest",
        )
        for unsafe in ("", "ssh-rsa value", "ssh-ed25519", "ssh-ed25519 a b c"):
            with (
                self.subTest(value=unsafe),
                self.assertRaisesRegex(RuntimeError, "canonical Ed25519"),
            ):
                _ = canonical_release_public_key(unsafe)

    def test_detached_package_signature_binds_exact_bytes_and_namespace(self) -> None:
        key = self.directory / "release-key"
        _ = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(key),
            ),
            check=True,
            timeout=30,
        )
        package = self.directory / "Remap.pkg"
        _ = package.write_bytes(b"exact package bytes")
        os.chmod(package, 0o400)
        self._sign(package, key, PACKAGE_NAMESPACE)
        signature = package.with_suffix(".pkg.sig")
        os.chmod(signature, 0o400)
        public_key = key.with_suffix(".pub").read_text(encoding="utf-8")

        verify_detached_package_signature(
            package,
            signature,
            public_key=public_key,
        )
        previous_directory = Path.cwd()
        try:
            os.chdir(self.directory)
            verify_detached_package_signature(
                Path("Remap.pkg"),
                Path("Remap.pkg.sig"),
                public_key=public_key,
            )
        finally:
            os.chdir(previous_directory)
        os.chmod(package, 0o600)
        _ = package.write_bytes(b"changed package bytes")
        os.chmod(package, 0o400)
        with self.assertRaisesRegex(RuntimeError, "signature is invalid"):
            verify_detached_package_signature(
                package,
                signature,
                public_key=public_key,
            )

    def test_detached_package_signature_rejects_other_namespaces(self) -> None:
        key = self.directory / "release-key"
        _ = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-q",
                "-t",
                "ed25519",
                "-N",
                "",
                "-f",
                str(key),
            ),
            check=True,
            timeout=30,
        )
        package = self.directory / "Remap.pkg"
        _ = package.write_bytes(b"exact package bytes")
        os.chmod(package, 0o400)
        self._sign(package, key, "not-remap-package")
        signature = package.with_suffix(".pkg.sig")
        os.chmod(signature, 0o400)

        with self.assertRaisesRegex(RuntimeError, "signature is invalid"):
            verify_detached_package_signature(
                package,
                signature,
                public_key=key.with_suffix(".pub").read_text(encoding="utf-8"),
            )

    def test_release_pair_collision_removes_only_the_new_package(self) -> None:
        package = self.directory / "source.pkg"
        signature = self.directory / "source.pkg.sig"
        output = self.directory / "published.pkg"
        output_signature = self.directory / "published.pkg.sig"
        _ = package.write_bytes(b"package")
        _ = signature.write_bytes(b"signature")
        _ = output_signature.write_bytes(b"foreign signature")
        for path in (package, signature, output_signature):
            os.chmod(path, 0o400)

        with self.assertRaises(FileExistsError):
            publish_release_artifacts(
                package=package,
                signature=signature,
                output=output,
                output_signature=output_signature,
            )

        self.assertFalse(output.exists())
        self.assertEqual(output_signature.read_bytes(), b"foreign signature")

    def test_release_executable_rejects_local_build_paths(self) -> None:
        executable = self.directory / "remap"
        _ = executable.write_bytes(b"Mach-O\x00/Users/builder/project/remap")
        with self.assertRaisesRegex(RuntimeError, "local build path"):
            verify_no_local_build_paths(executable)

        _ = executable.write_bytes(b"Mach-O\x00/usr/src/remap")
        verify_no_local_build_paths(executable)

    def _sign(self, path: Path, key: Path, namespace: str) -> None:
        _ = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(key),
                "-n",
                namespace,
                str(path),
            ),
            cwd=self.directory,
            check=True,
            timeout=30,
        )
