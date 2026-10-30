# SPDX-License-Identifier: GPL-3.0-or-later
"""The one-time step that creates the rehearsal signer, driven without an Enclave."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import final, override
from unittest.mock import patch

from tools.remap_rehearsal_key import create_rehearsal_key
from tools.remap_release_signing import REHEARSAL_PIN

TOOL = Path("/private/build/remap-release-key")


def _keygen_public(directory: Path, kind: str, comment: str) -> str:
    """A fixture public line from a key generated now; no key is ever committed."""
    key = directory / f"fixture-{kind}-{len(comment)}"
    _ = subprocess.run(
        (
            "/usr/bin/ssh-keygen",
            "-q",
            "-t",
            kind,
            "-N",
            "",
            "-C",
            comment,
            "-f",
            str(key),
        ),
        check=True,
        capture_output=True,
        timeout=30,
    )
    return key.with_suffix(".pub").read_text(encoding="utf-8")


@final
class RehearsalKeyCreationTests(unittest.TestCase):
    directory = Path()

    @override
    def setUp(self) -> None:
        self.directory = Path(tempfile.mkdtemp(prefix="remap-rehearsal-key-test-"))
        os.chmod(self.directory, 0o700)
        (self.directory / "docs/release").mkdir(parents=True)

    @override
    def tearDown(self) -> None:
        shutil.rmtree(self.directory)

    def _created(self, stdout: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=(), returncode=0, stdout=stdout)

    def test_the_helper_is_asked_for_a_rehearsal_key_and_its_line_is_pinned(
        self,
    ) -> None:
        line = _keygen_public(self.directory, "ecdsa", "remap-release-rehearsal-only")
        blob = self.directory / "remap-rehearsal.enclave-key"
        with patch.object(subprocess, "run", return_value=self._created(line)) as run:
            pinned = create_rehearsal_key(self.directory, blob, tool=TOOL)
        self.assertEqual(
            run.call_args.args[0],
            (str(TOOL), "create", "--kind", "rehearsal", "--key", str(blob)),
        )
        self.assertEqual(pinned, line)
        pin = (self.directory / REHEARSAL_PIN).read_text(encoding="utf-8")
        self.assertEqual(pin, line)

    def test_nothing_is_asked_of_the_enclave_when_a_refusal_applies(self) -> None:
        refusals = (
            (Path("relative/remap-rehearsal.key"), "absolute path"),
            (self.directory / "remap-release.key", "contains `rehearsal`"),
        )
        for blob, message in refusals:
            with (
                self.subTest(blob=blob),
                patch.object(subprocess, "run") as run,
                self.assertRaisesRegex(RuntimeError, message),
            ):
                _ = create_rehearsal_key(self.directory, blob, tool=TOOL)
            run.assert_not_called()
        existing = self.directory / "remap-rehearsal.key"
        _ = existing.write_bytes(b"earlier")
        with (
            patch.object(subprocess, "run") as run,
            self.assertRaisesRegex(RuntimeError, "never overwritten"),
        ):
            _ = create_rehearsal_key(self.directory, existing, tool=TOOL)
        run.assert_not_called()
        _ = (self.directory / REHEARSAL_PIN).write_text("pinned\n", encoding="utf-8")
        with (
            patch.object(subprocess, "run") as run,
            self.assertRaisesRegex(RuntimeError, "already committed"),
        ):
            _ = create_rehearsal_key(
                self.directory, self.directory / "new-rehearsal.key", tool=TOOL
            )
        run.assert_not_called()

    def test_only_one_marked_p256_line_becomes_the_pin(self) -> None:
        blob = self.directory / "remap-rehearsal.key"
        unmarked = _keygen_public(self.directory, "ecdsa", "remap-release-v2")
        ed25519 = _keygen_public(
            self.directory, "ed25519", "remap-release-rehearsal-only"
        )
        for stdout in (unmarked, ed25519, "", unmarked + unmarked):
            with (
                self.subTest(stdout=stdout),
                patch.object(subprocess, "run", return_value=self._created(stdout)),
                self.assertRaises(RuntimeError),
            ):
                _ = create_rehearsal_key(self.directory, blob, tool=TOOL)
            self.assertFalse((self.directory / REHEARSAL_PIN).exists())
        failed = subprocess.CompletedProcess(args=(), returncode=2, stdout="")
        with (
            patch.object(subprocess, "run", return_value=failed),
            self.assertRaisesRegex(RuntimeError, "did not create"),
        ):
            _ = create_rehearsal_key(self.directory, blob, tool=TOOL)


if __name__ == "__main__":
    _ = unittest.main()
