"""Adversarial proofs for the Linux root-helper bootstrap boundary."""

from __future__ import annotations

import errno
import fcntl
import os
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import AbstractContextManager, nullcontext
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tools import remap_linux_bootstrap as bootstrap
from tools.remap_linux_bootstrap import FileIdentity, TrustedHelper


class LinuxBootstrapSecurityTests(unittest.TestCase):
    """Reject every same-UID substitution before privileged helper execution."""

    def test_reviewed_source_rejects_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-source-hardlink-") as directory:
            source = Path(directory) / "helper"
            alias = Path(directory) / "alias"
            _ = source.write_bytes(b"reviewed helper")
            source.chmod(0o500)
            os.link(source, alias)
            with _without_xattrs():
                descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    with self.assertRaisesRegex(RuntimeError, "unsafe ownership"):
                        _ = bootstrap.review_helper_source(
                            source, descriptor, os.getuid()
                        )
                finally:
                    os.close(descriptor)

    def test_reviewed_source_rejects_every_xattr_including_acl(self) -> None:
        source = Path("/private/reviewed-helper")
        for name in ("user.untrusted", "system.posix_acl_access"):
            with (
                self.subTest(name=name),
                mock.patch(
                    "tools.remap_linux_bootstrap.file_identity",
                    return_value=replace(
                        file_identity(owner_uid=os.getuid(), mode=0o500),
                        xattrs=((name, b"value"),),
                    ),
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.require_path_matches_descriptor"
                ),
                self.assertRaisesRegex(RuntimeError, "unsafe ownership"),
            ):
                _ = bootstrap.review_helper_source(source, 7, os.getuid())

    def test_runtime_and_random_directory_reject_write_or_acl_metadata(self) -> None:
        unsafe: tuple[tuple[int, frozenset[str]], ...] = (
            (0o777, frozenset[str]()),
            (0o755, bootstrap.ACL_XATTRS),
        )
        for mode, xattrs in unsafe:
            information = SimpleNamespace(
                st_mode=stat.S_IFDIR | mode,
                st_uid=0,
                st_gid=0,
                st_dev=1,
                st_ino=2,
                st_nlink=1,
                st_ctime_ns=3,
            )
            with (
                self.subTest(mode=mode, xattrs=xattrs),
                mock.patch("tools.remap_linux_bootstrap.os.open", return_value=7),
                mock.patch(
                    "tools.remap_linux_bootstrap.os.fstat", return_value=information
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.os.listxattr",
                    return_value=xattrs,
                    create=True,
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.require_path_matches_descriptor"
                ),
                mock.patch("tools.remap_linux_bootstrap.os.close"),
                self.assertRaisesRegex(RuntimeError, "unsafe metadata"),
            ):
                bootstrap.verify_trusted_directory(
                    Path("/run/remap-bootstrap-test"), expected_mode=None
                )

    @unittest.skipUnless(sys.platform == "linux", "Linux O_PATH is required")
    def test_execute_only_directory_supports_metadata_verification_open(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-opath-") as root:
            directory = Path(root) / "execute-only"
            directory.mkdir(mode=0o111)
            with self.assertRaises(PermissionError):
                descriptor = os.open(
                    directory,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                )
                os.close(descriptor)
            descriptor = bootstrap.open_metadata_directory(directory)
            try:
                self.assertTrue(stat.S_ISDIR(os.fstat(descriptor).st_mode))
            finally:
                os.close(descriptor)

    def test_helper_identity_drift_is_rejected_before_execution(self) -> None:
        original = file_identity()
        helper = TrustedHelper(Path("/run/remap-safe/helper"), original)
        drifts = (
            replace(original, inode=original.inode + 1),
            replace(original, digest="f" * 64),
            replace(original, xattrs=(("security.selinux", b"changed"),)),
        )
        for drift in drifts:
            with (
                self.subTest(drift=drift),
                mock.patch("tools.remap_linux_bootstrap.verify_root_owned_ancestry"),
                mock.patch("tools.remap_linux_bootstrap.os.open", return_value=7),
                mock.patch("tools.remap_linux_bootstrap.fcntl.flock"),
                mock.patch(
                    "tools.remap_linux_bootstrap.require_path_matches_descriptor"
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.file_identity", return_value=drift
                ),
                mock.patch("tools.remap_linux_bootstrap.os.close"),
                self.assertRaisesRegex(RuntimeError, "changed before execution"),
                bootstrap.open_verified_helper(helper),
            ):
                self.fail("a drifted helper must never be yielded")

    def test_helper_path_drift_is_rejected_before_execution(self) -> None:
        helper = TrustedHelper(Path("/run/remap-safe/helper"), file_identity())
        with (
            mock.patch("tools.remap_linux_bootstrap.verify_root_owned_ancestry"),
            mock.patch("tools.remap_linux_bootstrap.os.open", return_value=7),
            mock.patch("tools.remap_linux_bootstrap.fcntl.flock"),
            mock.patch(
                "tools.remap_linux_bootstrap.require_path_matches_descriptor",
                side_effect=RuntimeError("path changed"),
            ),
            mock.patch("tools.remap_linux_bootstrap.os.close"),
            self.assertRaisesRegex(RuntimeError, "path changed"),
            bootstrap.open_verified_helper(helper),
        ):
            self.fail("a replaced path must never be yielded")

    def test_installed_helper_rejects_unsafe_root_ancestry(self) -> None:
        with (
            mock.patch(
                "tools.remap_linux_bootstrap.verify_root_owned_ancestry",
                side_effect=RuntimeError("unsafe installed ancestry"),
            ),
            mock.patch("tools.remap_linux_bootstrap.os.open") as open_file,
            self.assertRaisesRegex(RuntimeError, "unsafe installed ancestry"),
        ):
            _ = bootstrap.capture_trusted_helper(
                Path("/usr/libexec/remap/generations/id/remap-linux-system"),
                expected_digest=None,
                expected_mode=0o755,
            )
        open_file.assert_not_called()

    def test_initial_root_helper_rejects_every_unsafe_metadata_class(self) -> None:
        baseline = file_identity()
        unsafe = (
            replace(baseline, links=2),
            replace(baseline, owner_uid=501),
            replace(baseline, owner_gid=20),
            replace(baseline, mode=0o755),
            replace(baseline, xattrs=(("user.untrusted", b"value"),)),
            replace(
                baseline,
                xattrs=(("system.posix_acl_access", b"value"),),
            ),
        )
        for identity in unsafe:
            with (
                self.subTest(identity=identity),
                mock.patch("tools.remap_linux_bootstrap.verify_root_owned_ancestry"),
                mock.patch("tools.remap_linux_bootstrap.os.open", return_value=7),
                mock.patch(
                    "tools.remap_linux_bootstrap.file_identity",
                    return_value=identity,
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.require_path_matches_descriptor"
                ),
                mock.patch("tools.remap_linux_bootstrap.os.close"),
                self.assertRaisesRegex(RuntimeError, "unsafe identity"),
            ):
                _ = bootstrap.capture_trusted_helper(
                    Path("/run/remap-bootstrap/helper"),
                    expected_digest=baseline.digest,
                    expected_mode=0o555,
                )

    def test_staged_destination_path_substitution_is_rejected(self) -> None:
        with (
            mock.patch("tools.remap_linux_bootstrap.verify_root_owned_ancestry"),
            mock.patch("tools.remap_linux_bootstrap.os.open", return_value=7),
            mock.patch("tools.remap_linux_bootstrap.file_identity"),
            mock.patch(
                "tools.remap_linux_bootstrap.require_path_matches_descriptor",
                side_effect=RuntimeError("staged path changed"),
            ),
            mock.patch("tools.remap_linux_bootstrap.os.close"),
            self.assertRaisesRegex(RuntimeError, "staged path changed"),
        ):
            _ = bootstrap.capture_trusted_helper(
                Path("/run/remap-bootstrap/helper"),
                expected_digest=None,
                expected_mode=0o555,
            )

    def test_post_execution_path_substitution_is_rejected(self) -> None:
        helper = TrustedHelper(Path("/run/remap-bootstrap/helper"), file_identity())
        with (
            mock.patch("tools.remap_linux_bootstrap.os.open", return_value=7),
            mock.patch(
                "tools.remap_linux_bootstrap.require_path_matches_descriptor",
                side_effect=RuntimeError("post-execution path changed"),
            ),
            mock.patch("tools.remap_linux_bootstrap.os.close"),
            self.assertRaisesRegex(RuntimeError, "post-execution path changed"),
        ):
            bootstrap.verify_pinned_helper(helper)

    def test_unsafe_runtime_root_blocks_before_any_sudo_call(self) -> None:
        with (
            mock.patch(
                "tools.remap_linux_bootstrap.verify_trusted_directory",
                side_effect=RuntimeError("unsafe /run"),
            ),
            mock.patch("tools.remap_linux_bootstrap._run") as run,
            self.assertRaisesRegex(RuntimeError, "unsafe /run"),
            bootstrap.bootstrap_helper(Path("."), Path("/tmp/source"), os.getuid()),
        ):
            self.fail("unsafe runtime ancestry must block bootstrap")
        run.assert_not_called()

    def test_malformed_bootstrap_namespace_blocks_normal_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-bootstrap-namespace-") as root:
            runtime = Path(root)
            (runtime / "remap-bootstrap-not-a-canonical-id").mkdir()
            with (
                mock.patch.object(bootstrap, "RUNTIME_ROOT", runtime),
                self.assertRaisesRegex(RuntimeError, "administrator inspection"),
            ):
                bootstrap.inspect_bootstrap_residue()

    def test_source_rename_is_detected_and_exact_staging_is_removed(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-bootstrap-rename-") as directory:
            runtime = Path(directory)
            source = runtime / "source"
            old_source = runtime / "source.old"
            _ = source.write_bytes(b"reviewed helper")
            source.chmod(0o500)
            commands: list[tuple[str, ...]] = []

            def run(arguments: tuple[str, ...], _root: Path) -> None:
                commands.append(arguments)
                if arguments[3] == str(bootstrap.MKDIR):
                    Path(arguments[-1]).mkdir(mode=0o711)
                elif (
                    arguments[3] == str(bootstrap.INSTALL)
                    and "--directory" not in arguments
                ):
                    _ = source.rename(old_source)
                    _ = source.write_bytes(b"replacement helper")
                    source.chmod(0o500)
                    _ = Path(arguments[-1]).write_bytes(b"replacement helper")
                    Path(arguments[-1]).chmod(0o555)
                elif arguments[3] == str(bootstrap.UNLINK):
                    Path(arguments[-1]).unlink()
                elif arguments[3] == str(bootstrap.RMDIR):
                    Path(arguments[-1]).rmdir()

            staged = TrustedHelper(
                runtime
                / (bootstrap.BOOTSTRAP_DIRECTORY_PREFIX + "a" * 32)
                / bootstrap.BOOTSTRAP_HELPER_NAME,
                replace(file_identity(), digest="e" * 64),
            )
            with (
                _without_xattrs(),
                mock.patch.object(bootstrap, "RUNTIME_ROOT", runtime),
                mock.patch(
                    "tools.remap_linux_bootstrap.secrets.token_hex",
                    return_value="a" * 32,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_trusted_directory"),
                mock.patch(
                    "tools.remap_linux_bootstrap._verify_trusted_directory_descriptor"
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.sealed_helper_source",
                    return_value=nullcontext(
                        bootstrap.SealedHelperSource(source, descriptor=-1)
                    ),
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_sealed_helper_source"),
                mock.patch("tools.remap_linux_bootstrap.inspect_bootstrap_residue"),
                mock.patch(
                    "tools.remap_linux_bootstrap.capture_trusted_helper",
                    return_value=staged,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_pinned_helper"),
                mock.patch("tools.remap_linux_bootstrap._run", side_effect=run),
                self.assertRaisesRegex(RuntimeError, "path changed"),
                bootstrap.bootstrap_helper(runtime, source, os.getuid()),
            ):
                self.fail("renamed source must never yield a root helper")

        tools = tuple(command[3] for command in commands)
        self.assertIn(str(bootstrap.UNLINK), tools)
        self.assertIn(str(bootstrap.RMDIR), tools)

    def test_cleanup_refuses_a_replaced_staged_destination(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="remap-bootstrap-cleanup-"
        ) as directory:
            runtime = Path(directory)
            source = runtime / "source"
            _ = source.write_bytes(b"reviewed helper")
            source.chmod(0o500)
            staged = TrustedHelper(
                runtime
                / (bootstrap.BOOTSTRAP_DIRECTORY_PREFIX + "b" * 32)
                / bootstrap.BOOTSTRAP_HELPER_NAME,
                file_identity(),
            )
            commands: list[tuple[str, ...]] = []

            def run(arguments: tuple[str, ...], _root: Path) -> None:
                commands.append(arguments)
                if arguments[3] == str(bootstrap.MKDIR):
                    Path(arguments[-1]).mkdir(mode=0o711)
                elif arguments[3] == str(bootstrap.INSTALL):
                    _ = Path(arguments[-1]).write_bytes(b"reviewed helper")
                    Path(arguments[-1]).chmod(0o555)

            with (
                mock.patch.object(bootstrap, "RUNTIME_ROOT", runtime),
                mock.patch(
                    "tools.remap_linux_bootstrap.secrets.token_hex",
                    return_value="b" * 32,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_trusted_directory"),
                mock.patch(
                    "tools.remap_linux_bootstrap._verify_trusted_directory_descriptor"
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.sealed_helper_source",
                    return_value=nullcontext(
                        bootstrap.SealedHelperSource(source, descriptor=-1)
                    ),
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_sealed_helper_source"),
                mock.patch("tools.remap_linux_bootstrap.inspect_bootstrap_residue"),
                mock.patch(
                    "tools.remap_linux_bootstrap.review_helper_source",
                    return_value=staged.identity,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_reviewed_helper_source"),
                mock.patch(
                    "tools.remap_linux_bootstrap.capture_trusted_helper",
                    return_value=staged,
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.verify_pinned_helper",
                    side_effect=RuntimeError("changed during cleanup"),
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap._run",
                    side_effect=run,
                ),
                self.assertRaisesRegex(RuntimeError, "changed during cleanup"),
                bootstrap.bootstrap_helper(runtime, source, os.getuid()),
            ):
                pass

        tools = tuple(command[3] for command in commands)
        self.assertNotIn(str(bootstrap.UNLINK), tools)
        self.assertNotIn(str(bootstrap.RMDIR), tools)

    def test_random_directory_collision_never_mutates_or_cleans_foreign_state(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="remap-bootstrap-collision-"
        ) as directory:
            runtime = Path(directory)
            source = runtime / "source"
            _ = source.write_bytes(b"reviewed helper")
            source.chmod(0o500)
            commands: list[tuple[str, ...]] = []

            def collide(arguments: tuple[str, ...], _root: Path) -> None:
                commands.append(arguments)
                raise subprocess.CalledProcessError(1, arguments)

            with (
                _without_xattrs(),
                mock.patch.object(bootstrap, "RUNTIME_ROOT", runtime),
                mock.patch(
                    "tools.remap_linux_bootstrap.secrets.token_hex",
                    return_value="c" * 32,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_trusted_directory"),
                mock.patch(
                    "tools.remap_linux_bootstrap._verify_trusted_directory_descriptor"
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.sealed_helper_source",
                    return_value=nullcontext(
                        bootstrap.SealedHelperSource(source, descriptor=-1)
                    ),
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_sealed_helper_source"),
                mock.patch("tools.remap_linux_bootstrap.inspect_bootstrap_residue"),
                mock.patch("tools.remap_linux_bootstrap._run", side_effect=collide),
                self.assertRaises(subprocess.CalledProcessError),
                bootstrap.bootstrap_helper(runtime, source, os.getuid()),
            ):
                self.fail("an exclusive directory collision must not yield")

        self.assertEqual(len(commands), 1)
        self.assertEqual(commands[0][3], str(bootstrap.MKDIR))
        self.assertNotIn(str(bootstrap.INSTALL), commands[0])
        self.assertNotIn(str(bootstrap.UNLINK), commands[0])
        self.assertNotIn(str(bootstrap.RMDIR), commands[0])

    def test_runtime_and_staged_paths_are_leased_across_every_mutation(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-bootstrap-lease-") as directory:
            runtime = Path(directory)
            source = runtime / "source"
            _ = source.write_bytes(b"reviewed helper")
            source.chmod(0o500)
            staged_path = (
                runtime
                / (bootstrap.BOOTSTRAP_DIRECTORY_PREFIX + "d" * 32)
                / bootstrap.BOOTSTRAP_HELPER_NAME
            )
            identity = file_identity()
            staged = TrustedHelper(staged_path, identity)
            paths: dict[int, Path] = {}
            leased: list[tuple[Path, int]] = []
            active: set[int] = set()
            events: list[str] = []
            original_open = os.open
            original_close = os.close

            def open_recorded(path: os.PathLike[str] | str, flags: int) -> int:
                descriptor = original_open(path, flags)
                paths[descriptor] = Path(path)
                active.add(descriptor)
                return descriptor

            def close_recorded(descriptor: int) -> None:
                active.remove(descriptor)
                original_close(descriptor)

            def flock_recorded(descriptor: int, operation: int) -> None:
                self.assertEqual(operation, fcntl.LOCK_SH | fcntl.LOCK_NB)
                leased.append((paths[descriptor], descriptor))
                events.append(f"lease:{paths[descriptor]}")

            def has_active_lease(path: Path) -> bool:
                return any(
                    leased_path == path and descriptor in active
                    for leased_path, descriptor in leased
                )

            def run(arguments: tuple[str, ...], _root: Path) -> None:
                tool = arguments[3]
                events.append(f"run:{tool}")
                if tool == str(bootstrap.MKDIR):
                    self.assertTrue(has_active_lease(runtime))
                    Path(arguments[-1]).mkdir(mode=0o711)
                elif tool == str(bootstrap.INSTALL):
                    self.assertTrue(has_active_lease(runtime))
                    self.assertFalse(has_active_lease(staged_path))
                    _ = Path(arguments[-1]).write_bytes(b"reviewed helper")
                    Path(arguments[-1]).chmod(0o555)
                elif tool == str(bootstrap.UNLINK):
                    self.assertTrue(has_active_lease(runtime))
                    self.assertTrue(has_active_lease(staged_path))
                    Path(arguments[-1]).unlink()
                elif tool == str(bootstrap.RMDIR):
                    self.assertTrue(has_active_lease(runtime))
                    self.assertTrue(has_active_lease(staged_path))
                    Path(arguments[-1]).rmdir()

            with (
                mock.patch.object(bootstrap, "RUNTIME_ROOT", runtime),
                mock.patch(
                    "tools.remap_linux_bootstrap.secrets.token_hex",
                    return_value="d" * 32,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_trusted_directory"),
                mock.patch(
                    "tools.remap_linux_bootstrap._verify_trusted_directory_descriptor"
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.sealed_helper_source",
                    return_value=nullcontext(
                        bootstrap.SealedHelperSource(source, descriptor=-1)
                    ),
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_sealed_helper_source"),
                mock.patch("tools.remap_linux_bootstrap.inspect_bootstrap_residue"),
                mock.patch(
                    "tools.remap_linux_bootstrap.review_helper_source",
                    return_value=identity,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_reviewed_helper_source"),
                mock.patch(
                    "tools.remap_linux_bootstrap.capture_trusted_helper",
                    return_value=staged,
                ),
                mock.patch("tools.remap_linux_bootstrap.verify_pinned_helper"),
                mock.patch(
                    "tools.remap_linux_bootstrap.os.open", side_effect=open_recorded
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.os.close", side_effect=close_recorded
                ),
                mock.patch(
                    "tools.remap_linux_bootstrap.fcntl.flock",
                    side_effect=flock_recorded,
                ),
                mock.patch("tools.remap_linux_bootstrap._run", side_effect=run),
                bootstrap.bootstrap_helper(runtime, source, os.getuid()) as helper,
            ):
                self.assertEqual(helper, staged)
                events.append("yield")
                self.assertFalse(has_active_lease(runtime))
                self.assertTrue(has_active_lease(staged_path))

        self.assertLess(
            events.index(f"lease:{runtime}"), events.index(f"run:{bootstrap.MKDIR}")
        )
        self.assertLess(
            events.index(f"run:{bootstrap.INSTALL}"),
            events.index(f"lease:{staged_path}"),
        )
        self.assertLess(events.index(f"lease:{staged_path}"), events.index("yield"))
        self.assertEqual(events.count(f"lease:{runtime}"), 2)
        self.assertLess(
            len(events) - 1 - events[::-1].index(f"lease:{runtime}"),
            events.index(f"run:{bootstrap.UNLINK}"),
        )
        self.assertFalse(active)

    @unittest.skipUnless(
        sys.platform == "linux" and callable(getattr(os, "memfd_create", None)),
        "Linux memfd sealing is required",
    )
    def test_sealed_memfd_blocks_mutation_and_path_swap_disclosure(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-memfd-race-") as directory:
            root = Path(directory).resolve()
            source = root / "source"
            original = root / "source.original"
            sensitive = root / "sensitive"
            destination = root / "destination"
            approved = b"approved helper bytes\n" * 8_192
            foreign = b"FOREIGN-SENSITIVE-BYTES\n" * 8_192
            _ = source.write_bytes(approved)
            source.chmod(0o500)
            _ = sensitive.write_bytes(foreign)
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            stop = threading.Event()
            start = threading.Event()
            observed: list[bytes] = []
            thread_errors: list[BaseException] = []

            def swap_source() -> None:
                try:
                    _ = start.wait(timeout=5)
                    _ = source.rename(original)
                    source.symlink_to(sensitive)
                except OSError as error:
                    thread_errors.append(error)

            def watch_destination() -> None:
                try:
                    _ = start.wait(timeout=5)
                    while not stop.is_set():
                        try:
                            observed.append(destination.read_bytes())
                        except FileNotFoundError:
                            pass
                        _ = stop.wait(0.0005)
                except OSError as error:
                    thread_errors.append(error)

            attacker = threading.Thread(target=swap_source)
            watcher = threading.Thread(target=watch_destination)
            attacker.start()
            watcher.start()
            try:
                with bootstrap.sealed_helper_source(
                    source,
                    descriptor,
                    bootstrap.review_helper_source(source, descriptor, os.getuid()),
                ) as sealed:
                    with self.assertRaises(OSError) as mutation:
                        _ = os.pwrite(sealed.descriptor, b"x", 0)
                    self.assertEqual(mutation.exception.errno, errno.EPERM)
                    start.set()
                    attacker.join(timeout=5)
                    self.assertFalse(attacker.is_alive())
                    self.assertTrue(source.is_symlink())
                    _ = subprocess.run(
                        (
                            str(bootstrap.INSTALL),
                            "--mode=0555",
                            "--",
                            str(sealed.path),
                            str(destination),
                        ),
                        check=True,
                    )
                    observed.append(destination.read_bytes())
            finally:
                stop.set()
                start.set()
                watcher.join(timeout=5)
                attacker.join(timeout=5)
                os.close(descriptor)

        self.assertFalse(watcher.is_alive())
        self.assertFalse(thread_errors)
        self.assertTrue(observed)
        self.assertEqual(observed[-1], approved)
        self.assertTrue(
            all(b"FOREIGN-SENSITIVE-BYTES" not in item for item in observed)
        )


def file_identity(*, owner_uid: int = 0, mode: int = 0o555) -> FileIdentity:
    return FileIdentity(
        device=1,
        inode=2,
        mode=mode,
        owner_uid=owner_uid,
        owner_gid=0,
        links=1,
        size=1024,
        modified_ns=3,
        changed_ns=4,
        digest="b" * 64,
        xattrs=(),
    )


def _without_xattrs() -> AbstractContextManager[object]:
    return mock.patch.object(os, "listxattr", return_value=(), create=True)


if __name__ == "__main__":
    _ = unittest.main()
