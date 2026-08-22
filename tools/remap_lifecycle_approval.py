"""Explicit, bounded approval input for native lifecycle operations."""

from __future__ import annotations

import re
import sys
from typing import TextIO

APPROVAL_TOKEN_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
APPROVAL_PREFIX_LENGTH = 12
MAX_APPROVAL_LINE_CHARACTERS = 96


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
