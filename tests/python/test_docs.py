"""Tests for local documentation-link validation."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tools.remap_docs import check_markdown_links


class DocumentationTests(unittest.TestCase):
    """Verify link checking without network access or rendered heuristics."""

    def test_accepts_relative_files_anchors_and_external_links(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-docs-") as directory:
            root = Path(directory)
            _ = (root / "docs").mkdir()
            _ = (root / "docs/guide.md").write_text("# Guide\n", encoding="utf-8")
            _ = (root / "README.md").write_text(
                "[guide](docs/guide.md#guide) [section](#local) [web](https://example.com)\n",
                encoding="utf-8",
            )
            self.assertEqual(check_markdown_links(root), [])

    def test_reports_missing_and_escaping_targets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-docs-") as directory:
            root = Path(directory)
            _ = (root / "README.md").write_text(
                "[missing](docs/missing.md)\n[escape](../outside.md)\n",
                encoding="utf-8",
            )
            diagnostics = check_markdown_links(root)
            self.assertEqual(len(diagnostics), 2)
            self.assertIn("missing link target", diagnostics[0])
            self.assertIn("link leaves the repository", diagnostics[1])

    def test_scans_platform_docs_and_ignores_generated_trees(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-docs-") as directory:
            root = Path(directory)
            _ = (root / "platforms/linux").mkdir(parents=True)
            _ = (root / "platforms/linux/README.md").write_text(
                "[missing](../../docs/missing.md)\n",
                encoding="utf-8",
            )
            _ = (root / "node_modules/package").mkdir(parents=True)
            _ = (root / "node_modules/package/README.md").write_text(
                "[generated](missing.md)\n",
                encoding="utf-8",
            )

            diagnostics = check_markdown_links(root)

            self.assertEqual(len(diagnostics), 1)
            self.assertIn("platforms/linux/README.md", diagnostics[0])


if __name__ == "__main__":
    _ = unittest.main()
