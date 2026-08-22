"""Adversarial contracts for macOS source-helper bootstrap and recovery."""

from __future__ import annotations

import fcntl
import hashlib
import io
import os
import subprocess
import tempfile
import time
import unittest
from collections.abc import Generator, Sequence
from contextlib import contextmanager, redirect_stdout
from pathlib import Path
from typing import cast
from unittest import mock

from tools import remap_macos_bootstrap
from tools.remap_macos_protocol import (
    bootstrap_recovery_has_effects,
    render_bootstrap_recovery_preview,
)


class MacOSBootstrapTests(unittest.TestCase):
    """Prove exact-byte publication, cleanup, and recovery parsing."""

    def test_residue_is_disclosed_without_implicit_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            helper = Path(directory) / (
                remap_macos_bootstrap.BOOTSTRAP_PREFIX + "0" * 32
            )
            _ = helper.write_bytes(b"corrupt bootstrap")
            os.chmod(helper, 0o555)
            output = io.StringIO()
            descriptor = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW)
            try:

                @contextmanager
                def reviewed_descriptor(_path: Path) -> Generator[int]:
                    yield descriptor

                with (
                    mock.patch.object(
                        remap_macos_bootstrap,
                        "PRIVILEGED_HELPER_DIRECTORY",
                        Path(directory),
                    ),
                    mock.patch.object(
                        remap_macos_bootstrap,
                        "validated_bootstrap_descriptor",
                        side_effect=reviewed_descriptor,
                    ),
                    mock.patch.object(
                        remap_macos_bootstrap,
                        "verified_code_identity",
                        side_effect=RuntimeError("invalid signature"),
                    ),
                    redirect_stdout(output),
                ):
                    remap_macos_bootstrap.inspect_bootstrap_residue()
            finally:
                os.close(descriptor)

        self.assertIn(str(helper), output.getvalue())
        self.assertIn("invalid code identity", output.getvalue())
        self.assertIn(
            hashlib.sha256(b"corrupt bootstrap").hexdigest(), output.getvalue()
        )
        self.assertIn("retained for explicit recovery", output.getvalue())

    def test_publish_ready_stage_residue_is_disclosed_for_native_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = root / (remap_macos_bootstrap.BOOTSTRAP_STAGE_PREFIX + "1" * 32)
            stage.mkdir(mode=0o711)
            actual = stage.lstat()
            values = list(actual)
            values[4] = 0
            values[5] = 0
            root_owned = os.stat_result(values)
            output = io.StringIO()
            with (
                mock.patch.object(
                    remap_macos_bootstrap, "PRIVILEGED_HELPER_DIRECTORY", root
                ),
                mock.patch.object(Path, "lstat", return_value=root_owned),
                redirect_stdout(output),
            ):
                remap_macos_bootstrap.inspect_bootstrap_residue()

        self.assertIn("root:wheel 0711", output.getvalue())
        self.assertIn("not executed", output.getvalue())

    def test_publication_holds_shared_vnode_lease_until_exact_unlink(self) -> None:
        with self.bootstrap_fixture() as fixture:
            with self.bootstrap_context(fixture) as helper:
                descriptor = os.open(helper, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                finally:
                    os.close(descriptor)
            self.assertFalse(helper.exists())

    def test_source_swap_never_sends_foreign_path_bytes_to_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.source(root, b"reviewed helper bytes")
            moved = root / "reviewed"
            foreign = root / "foreign"
            foreign_bytes = b"root-only foreign bytes"
            _ = foreign.write_bytes(foreign_bytes)
            privileged_arguments: list[tuple[str, ...]] = []
            observed: list[bytes] = []

            def run(arguments: tuple[str, ...], *, root: Path) -> None:
                del root
                privileged_arguments.append(arguments)
                self.emulate_privileged(arguments)

            def swap_then_copy(
                arguments: tuple[str, ...],
                descriptor: int,
                byte_count: int,
                *,
                root: Path,
            ) -> None:
                del root
                _ = source.rename(moved)
                source.symlink_to(foreign)
                data = os.pread(descriptor, byte_count, 0)
                observed.append(data)
                _ = Path(arguments[-1]).write_bytes(data)

            with (
                self.bootstrap_patches(root, run=run, copy=swap_then_copy),
                self.assertRaisesRegex(RuntimeError, "source changed"),
                remap_macos_bootstrap.bootstrap_helper(root, source, "a" * 40),
            ):
                self.fail("a swapped source must never publish")

            self.assertEqual(observed, [b"reviewed helper bytes"])
            self.assertNotIn(foreign_bytes, observed)
            flattened = "\0".join(
                part for call in privileged_arguments for part in call
            )
            self.assertNotIn(str(source), flattened)
            self.assertNotIn(str(foreign), flattened)
            self.assertFalse(
                any(path.name.startswith("org.agenxy.Remap") for path in root.iterdir())
            )

    def test_no_clobber_collision_never_marks_or_removes_foreign_destination(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.source(root, b"reviewed")
            collision: list[Path] = []

            def run(arguments: tuple[str, ...], *, root: Path) -> None:
                del root
                if arguments[2] == "/bin/mv":
                    destination = Path(arguments[-1])
                    _ = destination.write_bytes(b"foreign")
                    os.chmod(destination, 0o555)
                    collision.append(destination)
                    return
                self.emulate_privileged(arguments)

            with (
                self.bootstrap_patches(root, run=run),
                self.assertRaisesRegex(RuntimeError, "did not consume its stage"),
                remap_macos_bootstrap.bootstrap_helper(root, source, "a" * 40),
            ):
                self.fail("a no-clobber collision must fail before publication")

            destination = self.assert_single(collision)
            self.assertEqual(destination.read_bytes(), b"foreign")
            self.assertFalse(
                any(
                    path.name.startswith(remap_macos_bootstrap.BOOTSTRAP_STAGE_PREFIX)
                    for path in root.iterdir()
                )
            )

    def test_descriptor_transfer_never_reads_attacker_extended_eof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.source(root, b"reviewed")
            destination = root / "privileged-sink"
            os.chmod(source, 0o700)
            racer = os.open(source, os.O_WRONLY | os.O_NOFOLLOW)
            os.chmod(source, 0o500)
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.ftruncate(racer, remap_macos_bootstrap.MAX_BOOTSTRAP_BYTES + 1)
                with self.assertRaisesRegex(RuntimeError, "grew during transfer"):
                    remap_macos_bootstrap.run_with_input_descriptor(
                        ("/usr/bin/tee", str(destination)),
                        descriptor,
                        len(b"reviewed"),
                        root=root,
                    )
            finally:
                os.close(descriptor)
                os.close(racer)

            transferred = destination.read_bytes() if destination.exists() else b""
            self.assertEqual(transferred, b"reviewed"[: len(transferred)])
            self.assertLessEqual(len(transferred), len(b"reviewed"))

    def test_forked_stderr_holder_is_group_killed_at_the_overall_deadline(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            contents = b"x" * 65_536
            source = self.source(root, contents)
            descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            parent_id_path = root / "parent.pid"
            child_id_path = root / "child.pid"
            script = (
                'echo "$$" > "$1"; '
                '/bin/sh -c \'echo "$$" > "$1"; exec /bin/sleep 60\' '
                'remap-child "$2" & /bin/cat >/dev/null; exit 0'
            )
            started = time.monotonic()

            try:
                with (
                    mock.patch.object(
                        remap_macos_bootstrap, "HELPER_TIMEOUT_SECONDS", 0.2
                    ),
                    self.assertRaises(subprocess.TimeoutExpired),
                ):
                    remap_macos_bootstrap.run_with_input_descriptor(
                        (
                            "/bin/sh",
                            "-c",
                            script,
                            "remap-parent",
                            str(parent_id_path),
                            str(child_id_path),
                        ),
                        descriptor,
                        len(contents),
                        root=root,
                    )
            finally:
                os.close(descriptor)

            elapsed = time.monotonic() - started
            parent_id = int(parent_id_path.read_text(encoding="utf-8"))
            child_id = int(child_id_path.read_text(encoding="utf-8"))
            self.assertLess(elapsed, 1.5)
            self.require_process_gone(parent_id)
            self.require_process_gone(child_id)

    def test_oversized_private_stage_stops_before_hash_or_code_review(self) -> None:
        expected = remap_macos_bootstrap.MAX_BOOTSTRAP_BYTES
        oversized = expected + 1
        calls: list[tuple[str, ...]] = []

        def capture(
            arguments: Sequence[str],
            *,
            root: Path,
            include_standard_error: bool = False,
        ) -> str:
            del root, include_standard_error
            calls.append(tuple(arguments))
            return f"{oversized}:0:0:1:400:Regular File"

        with (
            mock.patch.object(
                remap_macos_bootstrap,
                "capture",
                side_effect=capture,
            ),
            mock.patch.object(
                remap_macos_bootstrap, "verified_code_identity"
            ) as code_identity,
            self.assertRaisesRegex(RuntimeError, "unsafe size or metadata"),
        ):
            remap_macos_bootstrap.verify_private_staged_helper(
                Path("."),
                Path("/Library/PrivilegedHelperTools/private/candidate"),
                "a" * 64,
                expected,
                "b" * 40,
            )

        self.assertEqual(len(calls), 1)
        arguments = calls[0]
        self.assertIn("/usr/bin/stat", arguments)
        self.assertNotIn("/usr/bin/shasum", arguments)
        code_identity.assert_not_called()

    def test_post_publish_verification_failure_unlinks_exact_published_inode(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = self.source(root, b"reviewed")
            code_checks = iter(
                (
                    (remap_macos_bootstrap.BOOTSTRAP_IDENTIFIER, "a" * 40),
                    (remap_macos_bootstrap.BOOTSTRAP_IDENTIFIER, "a" * 40),
                    RuntimeError("post-publish code failure"),
                )
            )

            def identity(*_args: object, **_kwargs: object) -> tuple[str, str]:
                value = next(code_checks)
                if isinstance(value, Exception):
                    raise value
                return value

            with (
                self.bootstrap_patches(root),
                mock.patch.object(
                    remap_macos_bootstrap,
                    "verified_code_identity",
                    side_effect=identity,
                ),
                self.assertRaisesRegex(RuntimeError, "post-publish code failure"),
                remap_macos_bootstrap.bootstrap_helper(root, source, "a" * 40),
            ):
                self.fail("post-publish verification failure must not yield")

            self.assertFalse(
                any(
                    path.name.startswith(remap_macos_bootstrap.BOOTSTRAP_PREFIX)
                    for path in root.iterdir()
                )
            )

    def test_cleanup_refuses_to_unlink_replacement_path(self) -> None:
        with self.bootstrap_fixture() as fixture:
            root, _source = fixture
            moved = root / "published-vnode"
            with (
                self.assertRaisesRegex(RuntimeError, "changed identity"),
                self.bootstrap_context(fixture) as helper,
            ):
                _ = helper.rename(moved)
                _ = helper.write_bytes(b"replacement")
                os.chmod(helper, 0o555)
            self.assertEqual(helper.read_bytes(), b"replacement")
            self.assertEqual(moved.read_bytes(), b"helper")

    def test_recovery_preview_binds_verified_and_invalid_direct_candidates(
        self,
    ) -> None:
        document = bootstrap_recovery_result("7" * 64, inactive=True)

        self.assertTrue(bootstrap_recovery_has_effects(document))
        rendered = render_bootstrap_recovery_preview(document)
        self.assertIn("verified CDHash " + "6" * 40, rendered)
        self.assertIn("SHA-256 " + "5" * 64, rendered)

        data = cast("dict[str, object]", document["data"])
        candidate = cast("list[dict[str, object]]", data["candidates"])[0]
        candidate["codeValidity"] = "invalid"
        candidate["codeIdentifier"] = None
        candidate["cdHash"] = None
        rendered = render_bootstrap_recovery_preview(document)
        self.assertIn("invalid code identity", rendered)

    def test_recovery_rejects_effect_or_metadata_drift(self) -> None:
        document = bootstrap_recovery_result("7" * 64, inactive=True)
        data = cast("dict[str, object]", document["data"])
        data["effects"] = []
        with self.assertRaisesRegex(RuntimeError, "bootstrap effects"):
            _ = bootstrap_recovery_has_effects(document)

        document = bootstrap_recovery_result("7" * 64, inactive=False)
        data = cast("dict[str, object]", document["data"])
        candidates = cast("list[dict[str, object]]", data["candidates"])
        candidates[0]["ownerUID"] = False
        with self.assertRaisesRegex(RuntimeError, "unsafe bootstrap metadata"):
            _ = render_bootstrap_recovery_preview(document)

    def test_publish_ready_stage_preview_binds_mode_and_partial_bytes(self) -> None:
        document = bootstrap_recovery_result("7" * 64, inactive=False)
        data = cast("dict[str, object]", document["data"])
        cast("list[dict[str, object]]", data["candidates"]).clear()
        stage_path = (
            "/Library/PrivilegedHelperTools/org.agenxy.Remap.install-stage." + "b" * 32
        )
        data["stagingCandidates"] = [stage_candidate(stage_path, mode=0o711)]
        data["effects"] = [f"remove private orphan bootstrap stage {stage_path}"]

        rendered = render_bootstrap_recovery_preview(document)

        self.assertIn("root:wheel 0711", rendered)
        self.assertIn("mode 0555 SHA-256 " + "8" * 64, rendered)
        self.assertTrue(bootstrap_recovery_has_effects(document))

    @staticmethod
    def source(root: Path, contents: bytes) -> Path:
        source = root / "source"
        _ = source.write_bytes(contents)
        os.chmod(source, 0o500)
        return source

    @staticmethod
    def emulate_privileged(arguments: tuple[str, ...]) -> None:
        tool = arguments[2]
        if tool == "/bin/mkdir":
            Path(arguments[-1]).mkdir(mode=0o700)
        elif tool == "/usr/bin/install":
            _ = Path(arguments[-1]).write_bytes(b"")
            os.chmod(arguments[-1], 0o600)
        elif tool == "/bin/chmod" and arguments[3] != "-N":
            os.chmod(arguments[-1], int(arguments[3], 8))
        elif tool == "/bin/mv":
            _ = Path(arguments[-2]).rename(arguments[-1])
        elif tool == "/bin/unlink":
            Path(arguments[-1]).unlink()
        elif tool == "/bin/rmdir":
            Path(arguments[-1]).rmdir()

    @staticmethod
    def copy_descriptor(
        arguments: tuple[str, ...],
        descriptor: int,
        byte_count: int,
        *,
        root: Path,
    ) -> None:
        del root
        _ = Path(arguments[-1]).write_bytes(os.pread(descriptor, byte_count, 0))

    @staticmethod
    def assert_single(values: list[Path]) -> Path:
        if len(values) != 1:
            raise AssertionError(f"expected one value, got {values}")
        return values[0]

    def require_process_gone(self, process_id: int) -> None:
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                os.kill(process_id, 0)
            except ProcessLookupError:
                return
            time.sleep(0.01)
        self.fail(f"process {process_id} survived bootstrap group cleanup")

    @contextmanager
    def bootstrap_fixture(self):
        temporary = tempfile.TemporaryDirectory()
        try:
            root = Path(temporary.name)
            yield root, self.source(root, b"helper")
        finally:
            temporary.cleanup()

    @contextmanager
    def bootstrap_context(self, fixture: tuple[Path, Path]):
        root, source = fixture
        with (
            self.bootstrap_patches(root),
            remap_macos_bootstrap.bootstrap_helper(root, source, "a" * 40) as helper,
        ):
            yield helper

    @contextmanager
    def bootstrap_patches(
        self,
        root: Path,
        *,
        run: object | None = None,
        copy: object | None = None,
    ):
        def default_run(arguments: tuple[str, ...], *, root: Path) -> None:
            del root
            self.emulate_privileged(arguments)

        run_effect = run or default_run
        copy_effect = copy or self.copy_descriptor
        with (
            mock.patch.object(
                remap_macos_bootstrap, "PRIVILEGED_HELPER_DIRECTORY", root
            ),
            mock.patch.object(remap_macos_bootstrap, "verify_bootstrap_directory"),
            mock.patch.object(remap_macos_bootstrap, "inspect_bootstrap_residue"),
            mock.patch.object(
                remap_macos_bootstrap,
                "verified_code_identity",
                return_value=(remap_macos_bootstrap.BOOTSTRAP_IDENTIFIER, "a" * 40),
            ),
            mock.patch.object(
                remap_macos_bootstrap, "list_extended_attributes", return_value=[]
            ),
            mock.patch.object(
                remap_macos_bootstrap, "has_extended_acl", return_value=False
            ),
            mock.patch.object(remap_macos_bootstrap, "verify_private_staged_helper"),
            mock.patch.object(remap_macos_bootstrap, "require_exact_open_file"),
            mock.patch.object(remap_macos_bootstrap, "run", side_effect=run_effect),
            mock.patch.object(
                remap_macos_bootstrap, "run_cleanup", side_effect=run_effect
            ),
            mock.patch.object(
                remap_macos_bootstrap,
                "run_with_input_descriptor",
                side_effect=copy_effect,
            ),
            mock.patch("builtins.print"),
        ):
            yield


def bootstrap_recovery_result(token: str, *, inactive: bool) -> dict[str, object]:
    path = "/Library/PrivilegedHelperTools/org.agenxy.Remap.install." + "a" * 32
    activity = "inactive" if inactive else "active"
    effect = f"remove inactive orphan bootstrap helper {path}"
    return success(
        "preview-bootstrap-recovery",
        {
            "approvalToken": token,
            "candidates": [
                {
                    "activity": activity,
                    "byteCount": 1_048_576,
                    "cdHash": "6" * 40,
                    "codeIdentifier": "org.agenxy.Remap.install-bootstrap",
                    "codeValidity": "verified",
                    "extendedAttributeNames": [],
                    "fileIdentity": {"deviceID": 1, "fileID": 2},
                    "flags": 0,
                    "groupGID": 0,
                    "linkCount": 1,
                    "mode": 0o555,
                    "ownerUID": 0,
                    "path": path,
                    "sha256": "5" * 64,
                }
            ],
            "effects": [effect] if inactive else [],
            "schemaVersion": 3,
            "stagingCandidates": [],
        },
    )


def stage_candidate(path: str, *, mode: int) -> dict[str, object]:
    return {
        "extendedAttributeNames": [],
        "fileIdentity": {"deviceID": 3, "fileID": 4},
        "flags": 0,
        "groupGID": 0,
        "linkCount": 2,
        "mode": mode,
        "ownerUID": 0,
        "path": path,
        "stagedFile": {
            "byteCount": 17,
            "extendedAttributeNames": [],
            "fileIdentity": {"deviceID": 3, "fileID": 5},
            "flags": 0,
            "groupGID": 0,
            "linkCount": 1,
            "mode": 0o555,
            "ownerUID": 0,
            "path": f"{path}/candidate",
            "sha256": "8" * 64,
        },
    }


def success(command: str, data: dict[str, object]) -> dict[str, object]:
    return {"command": command, "data": data, "ok": True, "schemaVersion": 1}


if __name__ == "__main__":
    _ = unittest.main()
