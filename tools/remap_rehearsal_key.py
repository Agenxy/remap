# SPDX-License-Identifier: GPL-3.0-or-later
"""Create the interim rehearsal signer and pin it, once the owner approves (ADR-0035).

This is the one step that makes a key. Nothing in the development gate runs it. It asks this
Mac's Secure Enclave, through `remap-release-key create --kind rehearsal`, for a P-256 key
that signs without anyone present, keeps only the Enclave's device-bound blob, and writes
everything the pin commit needs:

- `docs/release/remap-rehearsal-signing-key.pub`, the pin;
- the rehearsal branch of the Swift verifier, as a literal like every other pin's;
- the pin's SHA-256 fingerprint in the README and `docs/release/REHEARSAL.md`, which is the
  trust anchor an installing Mac reads over HTTPS from GitHub.

No file is written through a symbolic link, and each existing file is replaced whole.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import uuid
from pathlib import Path

from tools.remap_release_signing import (
    REHEARSAL_KEY_VARIABLE,
    REHEARSAL_PIN,
    RELEASE_KEY_TYPE,
    SWIFT_VERIFIER,
    canonical_public_key,
    fingerprint,
    rehearsal_pin_line,
    rehearsal_swift_branch,
    with_rehearsal_literal,
)

FINGERPRINT_DOCUMENTS = (Path("README.md"), Path("docs/release/REHEARSAL.md"))
FINGERPRINT_PENDING = (
    "The rehearsal pin's fingerprint is not published yet, so no rehearsal can run."
)
FINGERPRINT_PUBLISHED = "The rehearsal pin's SHA-256 fingerprint is `{fingerprint}`."
FINGERPRINT_LINE = re.compile(
    r"^The rehearsal pin's (?:fingerprint is not published yet, so no rehearsal can "
    + r"run\.|SHA-256 fingerprint is `SHA256:[A-Za-z0-9+/]{43}`\.)$",
    re.MULTILINE,
)


def published_fingerprint_line(document: str) -> str:
    """The one line of a document that publishes, or says it cannot yet publish, the pin."""
    lines = [match.group(0) for match in FINGERPRINT_LINE.finditer(document)]
    if len(lines) != 1:
        raise RuntimeError(
            "a fingerprint document must carry exactly one rehearsal fingerprint line"
        )
    return lines[0]


def with_fingerprint(document: str, public_key: str) -> str:
    """The document with its fingerprint line naming this pin."""
    _ = published_fingerprint_line(document)
    line = FINGERPRINT_PUBLISHED.format(fingerprint=fingerprint(public_key))
    return FINGERPRINT_LINE.sub(lambda _match: line, document, count=1)


def create_rehearsal_key(root: Path, key_blob: Path, *, tool: Path) -> str:
    """Create the key at `key_blob`, pin it under `root`, and return the pin line.

    Every refusal happens before the Enclave is asked for anything, and the pin is written
    only from a line that is exactly one marked P-256 public key.
    """
    pin = root / REHEARSAL_PIN
    if pin.exists() or pin.is_symlink():
        raise RuntimeError(
            f"{REHEARSAL_PIN} is already committed. A rotation revokes it first: "
            + "docs/release/REHEARSAL.md lists the steps."
        )
    if not key_blob.is_absolute() or "rehearsal" not in key_blob.name.lower():
        raise RuntimeError(
            f"{REHEARSAL_KEY_VARIABLE} must be an absolute path whose file name contains "
            + "`rehearsal`, so it can never be taken for the release key's blob"
        )
    if key_blob.exists() or key_blob.is_symlink():
        raise RuntimeError(
            f"{key_blob} already exists; a rehearsal key is never overwritten"
        )
    documents = {
        path: _read_regular(root, path)
        for path in (SWIFT_VERIFIER, *FINGERPRINT_DOCUMENTS)
    }
    _ = rehearsal_swift_branch(documents[SWIFT_VERIFIER])
    for path in FINGERPRINT_DOCUMENTS:
        _ = published_fingerprint_line(documents[path])
    line = _created_public_line(key_blob, tool)
    updated = {
        SWIFT_VERIFIER: with_rehearsal_literal(documents[SWIFT_VERIFIER], line),
        **{
            path: with_fingerprint(documents[path], line)
            for path in FINGERPRINT_DOCUMENTS
        },
    }
    _create_exclusively(pin, line)
    for path, text in updated.items():
        _replace_regular(root, path, text)
    return line


def _created_public_line(key_blob: Path, tool: Path) -> str:
    # The helper's notice, which names the kind and its exposure, goes to the terminal.
    result = subprocess.run(
        (str(tool), "create", "--kind", "rehearsal", "--key", str(key_blob)),
        check=False,
        stdout=subprocess.PIPE,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError("remap-release-key did not create the rehearsal key")
    line = rehearsal_pin_line(result.stdout)
    if canonical_public_key(line).split()[0] != RELEASE_KEY_TYPE:
        raise RuntimeError(
            f"the interim rehearsal key must be a {RELEASE_KEY_TYPE} Enclave key"
        )
    return line


def _checked_path(root: Path, relative: Path) -> Path:
    """`root / relative`, refusing it if any part of the way is a symbolic link."""
    path = root / relative
    if path.resolve(strict=False) != root.resolve() / relative:
        raise RuntimeError(f"{relative} is reached through a symbolic link")
    return path


def _read_regular(root: Path, relative: Path) -> str:
    path = _checked_path(root, relative)
    if not stat.S_ISREG(path.lstat().st_mode):
        raise RuntimeError(f"{relative} is not a regular file")
    return path.read_text(encoding="utf-8")


def _create_exclusively(path: Path, text: str) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    with os.fdopen(os.open(path, flags, 0o644), "w", encoding="utf-8") as output:
        _ = output.write(text)


def _replace_regular(root: Path, relative: Path, text: str) -> None:
    """Replace one regular file whole, so a link planted at its path is never followed."""
    path = _checked_path(root, relative)
    information = path.lstat()
    if not stat.S_ISREG(information.st_mode):
        raise RuntimeError(f"{relative} is not a regular file")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    mode = stat.S_IMODE(information.st_mode)
    try:
        with os.fdopen(
            os.open(temporary, flags, mode), "w", encoding="utf-8"
        ) as output:
            _ = output.write(text)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
