# SPDX-License-Identifier: GPL-3.0-or-later
"""Create the interim rehearsal signer and write its pin, once the owner approves (ADR-0035).

This is the one step that makes a key. Nothing in the development gate runs it. It asks this
Mac's Secure Enclave, through `remap-release-key create --kind rehearsal`, for a P-256 key
that signs without anyone present, keeps only the Enclave's device-bound blob, and writes the
public line to `docs/release/remap-rehearsal-signing-key.pub` for the owner to commit.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from tools.remap_release_signing import (
    REHEARSAL_KEY_VARIABLE,
    REHEARSAL_PIN,
    RELEASE_KEY_TYPE,
    canonical_public_key,
    rehearsal_pin_swift,
)


def create_rehearsal_key(root: Path, key_blob: Path, *, tool: Path) -> str:
    """Create the key at `key_blob`, write its pin under `root`, and return the pin line.

    Every refusal happens before the Enclave is asked for anything, and the pin is written
    only from a line that is exactly one marked P-256 public key.
    """
    pin = root / REHEARSAL_PIN
    if pin.exists() or pin.is_symlink():
        raise RuntimeError(
            f"{REHEARSAL_PIN} is already committed. A rotation is a new key and a new pin "
            + "commit: `git rm` the old pin in that commit, then run this again."
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
    line = result.stdout
    _ = rehearsal_pin_swift(line)
    if canonical_public_key(line).split()[0] != RELEASE_KEY_TYPE:
        raise RuntimeError(
            f"the interim rehearsal key must be a {RELEASE_KEY_TYPE} Enclave key"
        )
    with pin.open("x", encoding="utf-8") as output:
        _ = output.write(line)
    return line
