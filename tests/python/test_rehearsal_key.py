# SPDX-License-Identifier: GPL-3.0-or-later
"""The one-time step that creates and pins the rehearsal signer, driven without an Enclave."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import final, override
from unittest.mock import patch

from tools.remap_rehearsal_key import (
    FINGERPRINT_DOCUMENTS,
    FINGERPRINT_PENDING,
    FINGERPRINT_PUBLISHED,
    create_rehearsal_key,
    published_fingerprint_line,
)
from tools.remap_release_signing import (
    REHEARSAL_PIN,
    REHEARSAL_SWIFT_PENDING,
    SWIFT_VERIFIER,
    fingerprint,
    rehearsal_swift_branch,
    swift_pin_literal,
)

REPOSITORY = Path(__file__).resolve().parents[2]
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
        for relative in (SWIFT_VERIFIER, *FINGERPRINT_DOCUMENTS):
            destination = self.directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            _ = shutil.copyfile(REPOSITORY / relative, destination)

    @override
    def tearDown(self) -> None:
        shutil.rmtree(self.directory)

    def _created(self, stdout: str) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(args=(), returncode=0, stdout=stdout)

    def _text(self, relative: Path) -> str:
        return (self.directory / relative).read_text(encoding="utf-8")

    def test_one_run_writes_the_pin_literal_and_fingerprint_for_one_commit(
        self,
    ) -> None:
        line = _keygen_public(self.directory, "ecdsa", "remap-release-rehearsal-only")
        blob = self.directory / "remap-rehearsal.enclave-key"
        before = {
            path: self._text(path) for path in (SWIFT_VERIFIER, *FINGERPRINT_DOCUMENTS)
        }
        with patch.object(subprocess, "run", return_value=self._created(line)) as run:
            pinned = create_rehearsal_key(self.directory, blob, tool=TOOL)
        self.assertEqual(
            run.call_args.args[0],
            (str(TOOL), "create", "--kind", "rehearsal", "--key", str(blob)),
        )
        self.assertEqual(pinned, line)
        self.assertEqual(self._text(REHEARSAL_PIN), line)
        source = self._text(SWIFT_VERIFIER)
        self.assertEqual(rehearsal_swift_branch(source), swift_pin_literal(line))
        self.assertNotIn(REHEARSAL_SWIFT_PENDING, source)
        published = FINGERPRINT_PUBLISHED.format(fingerprint=fingerprint(line))
        for document in FINGERPRINT_DOCUMENTS:
            with self.subTest(document=document):
                text = self._text(document)
                self.assertEqual(published_fingerprint_line(text), published)
                self.assertNotIn(FINGERPRINT_PENDING, text)
                # Nothing else in the document changes.
                self.assertEqual(
                    text.replace(published, FINGERPRINT_PENDING), before[document]
                )

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

    def test_no_document_is_written_through_a_symbolic_link(self) -> None:
        outside = self.directory / "outside.md"
        readme = self.directory / "README.md"
        _ = outside.write_text(readme.read_text(encoding="utf-8"), encoding="utf-8")
        readme.unlink()
        readme.symlink_to(outside)
        before = outside.read_text(encoding="utf-8")
        with (
            patch.object(subprocess, "run") as run,
            self.assertRaisesRegex(RuntimeError, "symbolic link"),
        ):
            _ = create_rehearsal_key(
                self.directory, self.directory / "remap-rehearsal.key", tool=TOOL
            )
        run.assert_not_called()
        self.assertEqual(outside.read_text(encoding="utf-8"), before)
        self.assertFalse((self.directory / REHEARSAL_PIN).exists())

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


@final
class PublishedFingerprintTests(unittest.TestCase):
    """The README and REHEARSAL.md publish exactly the committed pin's fingerprint."""

    def test_the_documents_publish_the_committed_pin_or_say_none_is(self) -> None:
        pin = REPOSITORY / REHEARSAL_PIN
        expected = (
            FINGERPRINT_PUBLISHED.format(
                fingerprint=fingerprint(pin.read_text(encoding="utf-8"))
            )
            if pin.exists()
            else FINGERPRINT_PENDING
        )
        for document in FINGERPRINT_DOCUMENTS:
            with self.subTest(document=document):
                text = (REPOSITORY / document).read_text(encoding="utf-8")
                self.assertEqual(published_fingerprint_line(text), expected)

    def test_the_documented_sequence_checks_the_anchor_not_the_served_pin(self) -> None:
        text = (REPOSITORY / "docs/release/REHEARSAL.md").read_text(encoding="utf-8")
        sequence = text[text.index("## Installing a rehearsal on the clean Mac") :]
        for step in (
            "shasum -a 256 -c SHA256SUMS",
            '"$GITHUB/remap-rehearsal-signing-key.pub"',
            '"$GITHUB/remap-rehearsal-revoked-fingerprints.txt"',
            '= "$FINGERPRINT"',
            'grep -qxF "$FINGERPRINT"',
            "cmp committed-rehearsal-key.pub remap-rehearsal-signing-key.pub",
            '"$(cat committed-rehearsal-key.pub)" > remap-allowed-signers',
            'sudo installer -pkg "$install_dir/Remap.pkg" -target /',
        ):
            with self.subTest(step=step):
                self.assertIn(step, sequence)
        self.assertTrue(
            sequence.index("shasum")
            < sequence.index("cmp ")
            < sequence.index("installer -pkg")
        )
        # The served pin is never the allow-list.
        self.assertIsNone(re.search(r"cat remap-rehearsal-signing-key\.pub", sequence))
        self.assertIn("https://raw.githubusercontent.com/Agenxy/remap/", sequence)


if __name__ == "__main__":
    _ = unittest.main()
