"""Adversarial tests for the unprivileged native package image."""

from __future__ import annotations

import json
import os
import plistlib
import sys
import tempfile
import unittest
from ctypes import (
    CDLL,
    c_char_p,
    c_int,
    c_size_t,
    c_ssize_t,
    c_uint32,
    c_void_p,
    create_string_buffer,
    get_errno,
)
from pathlib import Path
from typing import cast
from unittest import mock

from tools import remap_native_package
from tools.remap_native_package import (
    CURRENT_ROOT,
    DAEMON_LABEL,
    GENERATIONS_ROOT,
    INSTALL_CONFIGURATION,
    RESOLVER_LABEL,
    SYSTEM_SOCKET,
    NativeProductFiles,
    assemble,
    daemon_launchd_document,
    has_extended_acl,
    resolver_launchd_document,
)


class NativePackageTests(unittest.TestCase):
    """Verify determinism, ownership metadata, and hostile input rejection."""

    def test_manifest_is_deterministic_complete_and_immutable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-native-package-") as directory:
            base = Path(directory)
            files = _fixture_files(base / "inputs")
            first_root = _private_directory(base / "first")
            second_root = _private_directory(base / "second")
            first = _assemble(first_root, files)
            second = _assemble(second_root, files)

            self.assertEqual(first.generation_id, second.generation_id)
            self.assertEqual(len(first.generation_id.rsplit("-", maxsplit=1)[1]), 64)
            self.assertEqual(first.manifest_digest, second.manifest_digest)
            self.assertEqual(first.manifest.read_bytes(), second.manifest.read_bytes())
            descriptor = os.open(first.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertFalse(has_extended_acl(descriptor, first.root))
            finally:
                os.close(descriptor)
            document = cast(
                "dict[str, object]", json.loads(first.manifest.read_bytes())
            )
            entries = cast("list[dict[str, object]]", document["entries"])
            paths = {_path(entry) for entry in entries}
            self.assertIn("bin/remap", paths)
            self.assertIn(INSTALL_CONFIGURATION, paths)
            self.assertIn("libexec/remap-install", paths)
            self.assertIn("libexec/remap-resolver", paths)
            self.assertIn("app/Remap.app/Contents/MacOS/Remap", paths)
            self.assertIn("share/man/man1/remap-doctor.1", paths)
            self.assertIn("share/licenses/remap/LICENSE", paths)
            self.assertIn("share/licenses/remap/NOTICE", paths)
            self.assertTrue(
                all(cast("int", entry["mode"]) & 0o222 == 0 for entry in entries)
            )
            directories = [entry for entry in entries if entry["kind"] == "directory"]
            self.assertTrue(
                all(
                    "byteCount" not in entry and "sha256" not in entry
                    for entry in directories
                )
            )
            self.assertNotIn("previousGenerationID", document)
            publications = cast("list[dict[str, object]]", document["publications"])
            public_directories = {
                _path(publication): publication
                for publication in publications
                if publication["kind"] == "directory"
            }
            self.assertEqual(
                set(public_directories),
                {
                    "usr/local",
                    "usr/local/bin",
                    "usr/local/share",
                    "usr/local/share/bash-completion",
                    "usr/local/share/bash-completion/completions",
                    "usr/local/share/fish",
                    "usr/local/share/fish/vendor_completions.d",
                    "usr/local/share/licenses",
                    "usr/local/share/licenses/remap",
                    "usr/local/share/man",
                    "usr/local/share/man/man1",
                    "usr/local/share/zsh",
                    "usr/local/share/zsh/site-functions",
                },
            )
            self.assertTrue(
                all(
                    publication["mode"] == 0o755
                    and publication["ownerUID"] == 0
                    and publication["groupGID"] == 0
                    and "target" not in publication
                    and "source" not in publication
                    and "sha256" not in publication
                    and "byteCount" not in publication
                    for publication in public_directories.values()
                )
            )
            links = [
                publication
                for publication in publications
                if publication["kind"] == "symbolicLink"
            ]
            targets = {cast("str", publication["target"]) for publication in links}
            self.assertIn(str(CURRENT_ROOT / "bin/remap"), targets)
            launchd = [
                publication
                for publication in publications
                if _path(publication).startswith("Library/LaunchDaemons/")
            ]
            self.assertEqual(len(launchd), 2)
            self.assertTrue(
                all(publication["kind"] == "regularFile" for publication in launchd)
            )
            self.assertTrue(
                all(
                    first.generation_id in cast("str", publication["source"])
                    for publication in launchd
                )
            )
            configuration = cast(
                "dict[str, object]",
                json.loads((first.payload / INSTALL_CONFIGURATION).read_bytes()),
            )
            self.assertEqual(configuration["ownerUID"], 501)
            self.assertEqual(configuration["schemaVersion"], 2)
            self.assertEqual(configuration["signingCertificateSHA256"], "0" * 64)
            self.assertEqual(
                configuration["controlSocket"],
                "/Users/lael/Library/Application Support/org.Agenxy.Remap/control.sock",
            )
            self.assertEqual(
                stat_mode(first.manifest) & 0o777,
                0o400,
            )
            self.assertEqual(stat_mode(first.root) & 0o777, 0o700)
            self.assertTrue(
                all(
                    stat_mode(path) & 0o777 == 0o500
                    for path in first.root.rglob("*")
                    if path.is_dir()
                )
            )

    def test_package_rejects_source_symbolic_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-native-package-") as directory:
            base = Path(directory)
            files = _fixture_files(base / "inputs")
            linked = files.app / "Contents/Resources/linked"
            linked.symlink_to("ordinary.txt")
            root = _private_directory(base / "package")
            with self.assertRaisesRegex(RuntimeError, "link or special file"):
                _ = _assemble(root, files)

    def test_package_removes_unexpected_extended_attributes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-native-package-") as directory:
            base = Path(directory)
            files = _fixture_files(base / "inputs")
            root = _private_directory(base / "package")
            attribute = (
                "com.agenxy.remap.test"
                if sys.platform == "darwin"
                else "user.remap-test"
            )
            try:
                set_test_xattr(root, attribute, b"untrusted")
            except OSError as error:
                self.skipTest(f"extended attributes are unavailable: {error}")

            package = _assemble(root, files)

            descriptor = os.open(package.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                remaining = set(list_test_xattrs(descriptor)) - {"com.apple.provenance"}
            finally:
                os.close(descriptor)
            self.assertEqual(remaining, set())

    def test_generation_identity_binds_configuration_and_publications(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-native-package-") as directory:
            base = Path(directory)
            files = _fixture_files(base / "inputs")
            first = _assemble(_private_directory(base / "first"), files)
            changed = assemble(
                _private_directory(base / "changed"),
                files,
                product_version="0.1.0",
                account_name="lael",
                owner_uid=501,
                group_name="staff",
                data_directory=Path(
                    "/Users/lael/Library/Application Support/org.Agenxy.Remap"
                ),
                upstreams=["198.51.100.53:53"],
                previous_generation_id=None,
            )

            self.assertEqual(first.generation_id, changed.generation_id)
            with mock.patch.object(
                remap_native_package,
                "CURRENT_ROOT",
                Path("/Library/Application Support/Agenxy/Remap/alternate"),
            ):
                republished = _assemble(_private_directory(base / "republished"), files)
            self.assertNotEqual(first.generation_id, republished.generation_id)
            daemon = plist_document(first.payload / f"launchd/{DAEMON_LABEL}.plist")
            resolver = plist_document(first.payload / f"launchd/{RESOLVER_LABEL}.plist")
            generation_root = GENERATIONS_ROOT / first.generation_id
            self.assertEqual(
                cast("list[str]", daemon["ProgramArguments"])[0],
                str(generation_root / "libexec/remapd"),
            )
            self.assertEqual(
                cast("list[str]", resolver["ProgramArguments"])[0],
                str(generation_root / "libexec/remap-resolver"),
            )

    def test_launchd_documents_keep_root_and_user_boundaries_separate(self) -> None:
        daemon = daemon_launchd_document(
            generation_id="0.1.0-a1b2c3d4",
            account_name="lael",
            group_name="staff",
            data_directory=Path(
                "/Users/lael/Library/Application Support/org.Agenxy.Remap"
            ),
            upstreams=["192.0.2.53:53"],
        )
        resolver = resolver_launchd_document(
            generation_id="0.1.0-a1b2c3d4",
            owner_uid=501,
            data_directory=Path(
                "/Users/lael/Library/Application Support/org.Agenxy.Remap"
            ),
        )
        self.assertEqual(daemon["Label"], DAEMON_LABEL)
        self.assertEqual(daemon["UserName"], "lael")
        self.assertNotIn("UserName", resolver)
        self.assertEqual(resolver["Label"], RESOLVER_LABEL)
        self.assertEqual(
            cast("list[str]", daemon["ProgramArguments"])[0],
            str(GENERATIONS_ROOT / "0.1.0-a1b2c3d4/libexec/remapd"),
        )
        self.assertEqual(
            cast("list[str]", resolver["ProgramArguments"])[0],
            str(GENERATIONS_ROOT / "0.1.0-a1b2c3d4/libexec/remap-resolver"),
        )
        daemon_arguments = cast("list[str]", daemon["ProgramArguments"])
        resolver_arguments = cast("list[str]", resolver["ProgramArguments"])
        self.assertEqual(
            daemon_arguments[daemon_arguments.index("--system-socket") + 1],
            str(SYSTEM_SOCKET),
        )
        self.assertEqual(
            resolver_arguments[resolver_arguments.index("--system-socket") + 1],
            str(SYSTEM_SOCKET),
        )
        self.assertEqual(
            cast("dict[str, object]", daemon["Sockets"])["remap-system"],
            {
                "SockPathMode": 0o600,
                "SockPathName": str(SYSTEM_SOCKET),
                "SockType": "stream",
            },
        )
        self.assertIn("--owner-uid", cast("list[str]", resolver["ProgramArguments"]))
        self.assertEqual(
            cast("dict[str, object]", daemon["HardResourceLimits"])["Core"],
            0,
        )

    def test_launchd_document_rejects_noncanonical_or_unsafe_upstreams(self) -> None:
        for upstream in (
            "192.0.2.53",
            "2001:db8::53",
            "[2001:0db8::53]:53",
            "127.0.0.1:53",
            "[::1]:53",
            "224.0.0.1:53",
        ):
            with self.subTest(upstream=upstream), self.assertRaises(ValueError):
                _ = daemon_launchd_document(
                    generation_id="0.1.0-a1b2c3d4",
                    account_name="lael",
                    group_name="staff",
                    data_directory=Path(
                        "/Users/lael/Library/Application Support/org.Agenxy.Remap"
                    ),
                    upstreams=[upstream],
                )

    def test_launchd_document_starts_dormant_for_native_supervisor_publication(
        self,
    ) -> None:
        document = daemon_launchd_document(
            generation_id="0.1.0-a1b2c3d4",
            account_name="lael",
            group_name="staff",
            data_directory=Path(
                "/Users/lael/Library/Application Support/org.Agenxy.Remap"
            ),
            upstreams=["192.0.2.53:53", "[2001:db8::53]:53"],
        )

        arguments = cast("list[str]", document["ProgramArguments"])
        self.assertNotIn("--dns-upstream", arguments)
        self.assertEqual(arguments[-1], "--launchd-sockets")


def _assemble(root: Path, files: NativeProductFiles):
    return assemble(
        root,
        files,
        product_version="0.1.0",
        account_name="lael",
        owner_uid=501,
        group_name="staff",
        data_directory=Path("/Users/lael/Library/Application Support/org.Agenxy.Remap"),
        upstreams=["192.0.2.53:53"],
        previous_generation_id=None,
    )


def _fixture_files(root: Path) -> NativeProductFiles:
    _ = root.mkdir(mode=0o700)
    cli = _file(root / "remap", executable=True)
    daemon = _file(root / "remapd", executable=True)
    installer = _file(root / "remap-install", executable=True)
    resolver = _file(root / "remap-resolver", executable=True)
    system_tool = _file(root / "remap-system", executable=True)
    app = root / "Remap.app"
    _ = _file(app / "Contents/MacOS/Remap", executable=True)
    _ = _file(app / "Contents/Resources/ordinary.txt", executable=False)
    manpages = root / "manpages"
    for name in (
        "remap.1",
        "remap-apply.1",
        "remap-completions.1",
        "remap-daemon.1",
        "remap-disable.1",
        "remap-doctor.1",
        "remap-enable.1",
        "remap-get.1",
        "remap-list.1",
        "remap-manpage.1",
        "remap-manpages.1",
        "remap-mcp.1",
        "remap-preview.1",
        "remap-remove.1",
        "remap-resolve.1",
        "remap-set.1",
        "remap-status.1",
        "remap-system-recover.1",
        "remap-system-status.1",
        "remap-system-uninstall.1",
        "remap-system.1",
        "remap-validate.1",
    ):
        _ = _file(manpages / name, executable=False)
    completions = {
        shell: _file(root / f"remap.{shell}", executable=False)
        for shell in ("bash", "fish", "zsh")
    }
    return NativeProductFiles(
        app=app,
        cli=cli,
        daemon=daemon,
        installer=installer,
        resolver=resolver,
        system_tool=system_tool,
        manpages=manpages,
        completions=completions,
        license=_file(root / "LICENSE", executable=False),
        notice=_file(root / "NOTICE", executable=False),
        signing_certificate_sha256="0" * 64,
    )


def _file(path: Path, *, executable: bool) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    _ = path.write_text(f"fixture:{path.name}\n", encoding="utf-8")
    os.chmod(path, 0o500 if executable else 0o400)
    return path


def _private_directory(path: Path) -> Path:
    _ = path.mkdir(mode=0o700)
    return path


def _path(entry: dict[str, object]) -> str:
    return cast("str", entry["path"])


def stat_mode(path: Path) -> int:
    return path.stat().st_mode


def plist_document(path: Path) -> dict[str, object]:
    return cast("dict[str, object]", plistlib.loads(path.read_bytes()))


def set_test_xattr(path: Path, name: str, value: bytes) -> None:
    if sys.platform != "darwin":
        os.setxattr(path, name, value, follow_symlinks=False)
        return
    library = CDLL(None, use_errno=True)
    library.setxattr.argtypes = [
        c_char_p,
        c_char_p,
        c_void_p,
        c_size_t,
        c_uint32,
        c_int,
    ]
    library.setxattr.restype = c_int
    if (
        library.setxattr(
            os.fsencode(path),
            name.encode("utf-8"),
            value,
            len(value),
            0,
            0,
        )
        != 0
    ):
        raise OSError(get_errno(), f"could not set test xattr on {path}")


def list_test_xattrs(descriptor: int) -> list[str]:
    if sys.platform != "darwin":
        return os.listxattr(descriptor)
    library = CDLL(None, use_errno=True)
    library.flistxattr.argtypes = [c_int, c_void_p, c_size_t, c_int]
    library.flistxattr.restype = c_ssize_t
    size = cast("int", library.flistxattr(descriptor, None, 0, 0))
    if size < 0:
        raise OSError(get_errno(), "could not list test xattrs")
    if size == 0:
        return []
    buffer = create_string_buffer(size)
    received = cast("int", library.flistxattr(descriptor, buffer, size, 0))
    if received < 0:
        raise OSError(get_errno(), "could not read test xattrs")
    return [name.decode("utf-8") for name in buffer.raw[:received].split(b"\0") if name]


if __name__ == "__main__":
    _ = unittest.main()
