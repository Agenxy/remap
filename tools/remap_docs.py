"""Build and validate Remap's API, Markdown, and generated manual pages."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from typing import cast
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_EXCLUDED_COMPONENTS = frozenset(
    {
        ".build",
        ".git",
        "DerivedData",
        "node_modules",
        "playwright-report",
        "target",
        "test-results",
    }
)
MARKDOWN_LINK: re.Pattern[str] = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")


def check_markdown_links(root: Path) -> list[str]:
    """Return deterministic diagnostics for missing local Markdown targets."""
    diagnostics: list[str] = []
    for document in markdown_documents(root):
        source = document.read_text(encoding="utf-8")
        for line_number, line in enumerate(source.splitlines(), start=1):
            for raw_target in cast("list[str]", MARKDOWN_LINK.findall(line)):
                target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
                split = urlsplit(target)
                if split.scheme or target.startswith("#"):
                    continue
                relative = unquote(split.path)
                if not relative:
                    continue
                candidate = (
                    root / relative.removeprefix("/")
                    if relative.startswith("/")
                    else document.parent / relative
                ).resolve()
                try:
                    _ = candidate.relative_to(root.resolve())
                except ValueError:
                    diagnostics.append(
                        f"{document.relative_to(root)}:{line_number}: link leaves the repository: {target}"
                    )
                    continue
                if not candidate.exists():
                    diagnostics.append(
                        f"{document.relative_to(root)}:{line_number}: missing link target: {target}"
                    )
    return diagnostics


def markdown_documents(root: Path) -> list[Path]:
    """Return first-party Markdown documents in stable order."""
    return sorted(
        document
        for document in root.rglob("*.md")
        if document.is_file()
        and not MARKDOWN_EXCLUDED_COMPONENTS.intersection(
            document.relative_to(root).parts
        )
    )


def run(arguments: Sequence[str], *, environment: dict[str, str] | None = None) -> None:
    """Run one explicit documentation-tool boundary."""
    _ = subprocess.run(arguments, cwd=ROOT, env=environment, check=True)


def check() -> None:
    """Build API docs and validate every local documentation carrier."""
    diagnostics = check_markdown_links(ROOT)
    if diagnostics:
        raise RuntimeError("\n".join(diagnostics))
    environment = os.environ.copy()
    environment["RUSTDOCFLAGS"] = "-D warnings"
    run(
        ("cargo", "doc", "--locked", "--workspace", "--no-deps"),
        environment=environment,
    )
    run(("cargo", "build", "--locked", "--quiet", "-p", "remap"))
    with tempfile.TemporaryDirectory(prefix="remap-manpages-") as directory:
        destination = Path(directory)
        run((str(ROOT / "target/debug/remap"), "manpages", str(destination)))
        manpages = sorted(destination.glob("*.1"))
        if len(manpages) != 22:
            raise RuntimeError(f"generated {len(manpages)} manpages; expected 22")
        run(("/usr/bin/mandoc", "-Tlint", "-Werror", *(str(path) for path in manpages)))


def main() -> int:
    """Run the stable documentation gate."""
    try:
        check()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"documentation check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
