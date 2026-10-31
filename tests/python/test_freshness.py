# SPDX-License-Identifier: GPL-3.0-or-later
"""Pure tests for dependency-freshness contract parsing."""

from __future__ import annotations

import unittest

from tools.remap_freshness import (
    cargo_version,
    exact_semver,
    stale_pin,
    workflow_action_pins,
)


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
        self.assertEqual(stale_pin("example", "1.2.3", "1.2.3"), [])
        self.assertEqual(
            stale_pin("example", "1.2.3", "1.2.4"),
            ["example is pinned to 1.2.3; current stable is 1.2.4"],
        )
        self.assertEqual(
            stale_pin("example", "1.2.4", "1.2.3"),
            ["example is pinned to 1.2.4; current stable is 1.2.3"],
        )

    def test_workflow_actions_must_be_pinned_to_commits(self) -> None:
        sha = "3d3c42e5aac5ba805825da76410c181273ba90b1"
        workflow = (
            "steps:\n"
            f"      - uses: actions/checkout@{sha} # v7\n"
            f"        uses: jdx/mise-action@{sha}\n"
            "      - run: make check\n"
        )
        self.assertEqual(
            workflow_action_pins(workflow, "ci.yml"),
            [("actions/checkout", sha), ("jdx/mise-action", sha)],
        )
        for reference in ("actions/checkout@v7", f"actions/checkout@{sha[:12]}"):
            with self.assertRaisesRegex(ValueError, "not pinned to a commit"):
                _ = workflow_action_pins(f"      - uses: {reference}\n", "ci.yml")


if __name__ == "__main__":
    _ = unittest.main()
