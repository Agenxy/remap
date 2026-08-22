"""Release metadata tests for native macOS executables."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.remap_macos_artifact import (
    normalize_macos_sdk_metadata,
    require_macos_sdk_stamp,
)


def _metadata(sdk: str, *, minimum: str = "15.0") -> str:
    return f"""binary:
Load command 1
      cmd LC_BUILD_VERSION
 platform MACOS
    minos {minimum}
      sdk {sdk}
   ntools 1
     tool LD
  version 27037.0
"""


class MacOSArtifactTests(unittest.TestCase):
    """Keep linked-SDK metadata inside the public release gate."""

    def test_exact_macos_sdk_stamp_is_required(self) -> None:
        valid = """binary:
Load command 1
      cmd LC_BUILD_VERSION
 platform MACOS
    minos 15.0
      sdk 27.0
"""
        require_macos_sdk_stamp(valid, "27.0", "binary")
        with self.assertRaisesRegex(RuntimeError, "declares SDK 15.0"):
            require_macos_sdk_stamp(
                valid.replace("sdk 27.0", "sdk 15.0"), "27.0", "binary"
            )

    def test_missing_duplicate_and_oversized_metadata_are_rejected(self) -> None:
        missing = "platform MACOS\nminos 15.0\nsdk 27.0\n"
        duplicate = (
            "cmd LC_BUILD_VERSION\ncmd LC_BUILD_VERSION\nplatform MACOS\nsdk 27.0\n"
        )
        with self.assertRaisesRegex(RuntimeError, "one macOS"):
            require_macos_sdk_stamp(missing, "27.0", "binary")
        with self.assertRaisesRegex(RuntimeError, "one macOS"):
            require_macos_sdk_stamp(duplicate, "27.0", "binary")
        with self.assertRaisesRegex(RuntimeError, "64 KiB"):
            require_macos_sdk_stamp("x" * 65_537, "27.0", "binary")

    def test_normalizer_uses_vtool_then_restores_a_valid_signature(self) -> None:
        original = _metadata("15.0")
        corrected = _metadata("27.0")
        calls: list[tuple[str, ...]] = []
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "helper"
            _ = binary.write_bytes(b"original")
            os.chmod(binary, 0o555)

            def run(
                arguments: tuple[str, ...], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                calls.append(arguments)
                if "-show-build" in arguments:
                    output = (
                        corrected if binary.read_bytes() == b"patched" else original
                    )
                    return subprocess.CompletedProcess(arguments, 0, output, "")
                if "-set-build-version" in arguments:
                    output = Path(arguments[arguments.index("-output") + 1])
                    _ = output.write_bytes(b"patched")
                return subprocess.CompletedProcess(arguments, 0, "", "")

            with patch("tools.remap_macos_artifact.subprocess.run", side_effect=run):
                normalize_macos_sdk_metadata(
                    (binary,), expected_sdk="27.0", minimum_macos="15.0"
                )

            self.assertEqual(binary.read_bytes(), b"patched")
            self.assertTrue(any("-set-build-version" in call for call in calls))
            self.assertTrue(any(call[0] == "/usr/bin/codesign" for call in calls))

    def test_normalizer_rejects_the_wrong_minimum_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "helper"
            _ = binary.write_bytes(b"original")
            os.chmod(binary, 0o555)
            result = subprocess.CompletedProcess(
                ("xcrun", "vtool"), 0, _metadata("15.0", minimum="14.0"), ""
            )
            with (
                patch("tools.remap_macos_artifact.subprocess.run", return_value=result),
                self.assertRaisesRegex(RuntimeError, "minimum macOS 14.0"),
            ):
                normalize_macos_sdk_metadata(
                    (binary,), expected_sdk="27.0", minimum_macos="15.0"
                )
            self.assertEqual(binary.read_bytes(), b"original")


if __name__ == "__main__":
    _ = unittest.main()
