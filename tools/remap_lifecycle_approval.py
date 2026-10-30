# SPDX-License-Identifier: GPL-3.0-or-later
"""Explicit, bounded approval input for native lifecycle operations."""

from __future__ import annotations

import re
import sys
from typing import TextIO

APPROVAL_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
APPROVAL_PREFIX_LENGTH = 12
MAX_APPROVAL_LINE_CHARACTERS = 96
SUDO = "/usr/bin/sudo"
# What an administrator password approves, for each operation that asks for one.
ADMINISTRATOR_PURPOSES = {
    "install": "install its DNS service",
    "update": "update its DNS service",
    "recover": "repair its DNS service",
    "uninstall": "remove its DNS service",
    "install-package": "install the Remap package you verified",
}


def administrator_prompt(operation: str) -> str:
    """The question sudo asks, saying who is asking and what the password approves.

    sudo's own prompt is a bare "Password:", which names neither. `%p` is sudo's
    escape for the account whose password it wants.
    """
    return (
        f"Remap needs administrator approval to {ADMINISTRATOR_PURPOSES[operation]}."
        + " Password for %p: "
    )


def administrator_command(operation: str, *command: str) -> tuple[str, ...]:
    """Run `command` through sudo with that prompt, or validate sudo without one."""
    return (SUDO, "-p", administrator_prompt(operation), *(command or ("-v",)))


def confirm_approval(
    token: str,
    operation: str,
    *,
    input_stream: TextIO | None = None,
    output_stream: TextIO | None = None,
) -> str:
    """Require an exact interactive prefix or full noninteractive token."""
    if not APPROVAL_TOKEN_PATTERN.fullmatch(token):
        raise RuntimeError("the native installer returned an invalid approval token")
    source = input_stream or sys.stdin
    destination = output_stream or sys.stdout
    if source.isatty():
        expected = f"approve {token[:APPROVAL_PREFIX_LENGTH]}"
        prompt = f"Type '{expected}' to approve this exact {operation} preview: "
    else:
        expected = token
        prompt = (
            "Non-interactive approval requires the full 64-character token "
            "on standard input: "
        )
    print(prompt, end="", file=destination, flush=True)
    response = source.readline(MAX_APPROVAL_LINE_CHARACTERS + 1)
    if (
        len(response) > MAX_APPROVAL_LINE_CHARACTERS
        or response.rstrip("\r\n") != expected
    ):
        action = f"Re-run 'make {operation}' to review a fresh preview."
        raise RuntimeError(
            "Approval was not confirmed. No Remap product state changed. " + action
        )
    print("Approval confirmed. Applying only the reviewed state.", file=destination)
    return token
