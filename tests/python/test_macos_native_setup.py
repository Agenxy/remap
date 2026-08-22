"""Contracts for the native Apple Installer setup builder."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.remap_macos_native_setup import (
    installed_generation_id,
    resolver_upstreams_from_tool,
)


class MacOSNativeSetupTests(unittest.TestCase):
    def test_installed_generation_is_bound_to_one_exact_root_owned_link(self) -> None:
        generation = "0.1.1-" + "a" * 64
        generations = Path(
            "/Library/Application Support/Agenxy/Remap/Install/Generations"
        )
        current = Path("/Library/Application Support/Agenxy/Remap/Install/current")
        information = os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, 0, 0, 0, 0, 0, 0))
        with (
            patch.object(Path, "lstat", return_value=information),
            patch("os.readlink", return_value=str(generations / generation)),
            patch("tools.remap_macos_native_setup.GENERATIONS_ROOT", generations),
        ):
            self.assertEqual(installed_generation_id(current), generation)

    def test_installed_generation_rejects_a_non_root_owned_pointer(self) -> None:
        information = os.stat_result(
            (stat.S_IFLNK | 0o777, 1, 1, 1, 501, 20, 0, 0, 0, 0)
        )
        with (
            patch.object(Path, "lstat", return_value=information),
            self.assertRaisesRegex(RuntimeError, "unsafe metadata"),
        ):
            _ = installed_generation_id(Path("/tmp/current"))

    def test_absent_installed_generation_is_a_clean_install(self) -> None:
        self.assertIsNone(installed_generation_id(Path("/tmp/remap-absent-current")))

    def test_resolver_plan_accepts_one_bounded_native_plan(self) -> None:
        document = {
            "command": "plan",
            "data": {"services": [], "upstreams": ["192.0.2.53", "2001:db8::53"]},
            "ok": True,
        }
        result = _completed(json.dumps(document).encode())
        with patch("subprocess.run", return_value=result):
            self.assertEqual(
                resolver_upstreams_from_tool(Path("/tmp/remap-system"), Path("/tmp")),
                ["192.0.2.53:53", "[2001:db8::53]:53"],
            )

    def test_resolver_plan_rejects_more_than_four_upstreams(self) -> None:
        document = {
            "command": "plan",
            "data": {
                "services": [],
                "upstreams": [f"192.0.2.{index}" for index in range(5)],
            },
            "ok": True,
        }
        result = _completed(json.dumps(document).encode())
        with (
            patch("subprocess.run", return_value=result),
            self.assertRaisesRegex(RuntimeError, "unsafe upstream"),
        ):
            _ = resolver_upstreams_from_tool(Path("/tmp/remap-system"), Path("/tmp"))

    def test_resolver_plan_rejects_an_ambiguous_envelope(self) -> None:
        result = _completed(
            b'{"command":"plan","data":{"upstreams":["1.1.1.1"]},"ok":true,"extra":1}'
        )
        with (
            patch("subprocess.run", return_value=result),
            self.assertRaisesRegex(RuntimeError, "envelope"),
        ):
            _ = resolver_upstreams_from_tool(Path("/tmp/remap-system"), Path("/tmp"))

    def test_resolver_plan_rejects_values_that_are_not_safe_ip_addresses(self) -> None:
        for upstream in ("localhost", "127.0.0.1", "::1", "224.0.0.1", "ff02::1"):
            document = {
                "command": "plan",
                "data": {"services": [], "upstreams": [upstream]},
                "ok": True,
            }
            with (
                self.subTest(upstream=upstream),
                patch(
                    "subprocess.run",
                    return_value=_completed(json.dumps(document).encode()),
                ),
                self.assertRaisesRegex(RuntimeError, "unsafe upstream"),
            ):
                _ = resolver_upstreams_from_tool(
                    Path("/tmp/remap-system"), Path("/tmp")
                )

    def test_resolver_plan_rejects_duplicate_canonical_upstreams(self) -> None:
        document = {
            "command": "plan",
            "data": {"services": [], "upstreams": ["2001:db8::1", "2001:0db8::1"]},
            "ok": True,
        }
        with (
            patch(
                "subprocess.run", return_value=_completed(json.dumps(document).encode())
            ),
            self.assertRaisesRegex(RuntimeError, "duplicate upstreams"),
        ):
            _ = resolver_upstreams_from_tool(Path("/tmp/remap-system"), Path("/tmp"))


def _completed(stdout: bytes) -> subprocess.CompletedProcess[bytes]:
    return subprocess.CompletedProcess(
        args=("remap-system",),
        returncode=0,
        stdout=stdout,
        stderr=b"",
    )


if __name__ == "__main__":
    _ = unittest.main()
