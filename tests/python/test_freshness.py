"""Pure tests for dependency-freshness contract parsing."""

from __future__ import annotations

import unittest

from tools.remap_freshness import cargo_version, exact_semver, require_current


class FreshnessTests(unittest.TestCase):
    """Reject loose, malformed, and stale dependency specifications."""

    def test_cargo_versions_must_be_exact(self) -> None:
        self.assertEqual(cargo_version("=1.2.3", "example"), "1.2.3")
        self.assertEqual(
            cargo_version({"version": "=1.2.3", "features": ["typed"]}, "example"),
            "1.2.3",
        )
        for specification in ("1.2.3", "^1.2.3", {"version": "~1.2.3"}):
            with self.assertRaisesRegex(ValueError, "not pinned"):
                _ = cargo_version(specification, "example")

    def test_semver_and_current_version_checks_are_strict(self) -> None:
        self.assertTrue(exact_semver("1.2.3"))
        self.assertTrue(exact_semver("1.2.3-rc.1"))
        self.assertFalse(exact_semver("v1.2.3"))
        self.assertFalse(exact_semver("1.2"))
        require_current("example", "1.2.3", "1.2.3")
        with self.assertRaisesRegex(RuntimeError, "current stable is 1.2.4"):
            require_current("example", "1.2.3", "1.2.4")


if __name__ == "__main__":
    _ = unittest.main()
