# SPDX-License-Identifier: GPL-3.0-or-later
"""Every macOS executable names itself the way its installers sign it (ADR-0034)."""

from __future__ import annotations

import plistlib
import re
import tempfile
import unittest
from pathlib import Path
from typing import cast

from tools.remap_app import COPYRIGHT
from tools.remap_macos_portable_package import PRODUCT_IDENTIFIERS
from tools.remap_package import verify_native_plist_versions
from tools.remap_tasks import PRODUCT_VERSION

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "platforms/macos/Package.swift"
SWIFT_PRODUCT = re.compile(
    r'\.executable\(name: "([a-z-]+)", targets: \["([A-Za-z]+)"\]\)'
)
EXECUTABLE_TARGET = re.compile(
    r'^        \.executableTarget\(\n            name: "([A-Za-z]+)",\n(.*?)^        \)',
    re.MULTILINE | re.DOTALL,
)
EMBEDDED_PLIST = re.compile(r'embeddedInfoPlist\("([A-Za-z]+)"\)')
RUST_PRODUCTS = {"remap": "crates/remap/build.rs", "remapd": "crates/remapd/build.rs"}
RUST_CONSTANT = re.compile(
    r'^const (IDENTIFIER|NAME|COPYRIGHT): &str = "([^"]+)";$', re.MULTILINE
)


def _swift_helpers() -> dict[str, str]:
    """Each helper product and its target.

    Helper products are named in lowercase, so `Remap`, the app, which carries a
    bundle of its own, does not match.
    """
    return dict(SWIFT_PRODUCT.findall(PACKAGE.read_text(encoding="utf-8")))


def _embedded_plists() -> dict[str, list[str]]:
    """Each executable target and the plists its own block embeds."""
    blocks = EXECUTABLE_TARGET.finditer(PACKAGE.read_text(encoding="utf-8"))
    return {
        block.group(1): [
            plist.group(1) for plist in EMBEDDED_PLIST.finditer(block.group(2))
        ]
        for block in blocks
    }


def _swift_plist(target: str) -> dict[str, object]:
    path = ROOT / "platforms/macos/Sources" / target / "Info.plist"
    return cast("dict[str, object]", plistlib.loads(path.read_bytes()))


def _rust_constants(build_script: str) -> dict[str, str]:
    source = (ROOT / build_script).read_text(encoding="utf-8")
    return dict(RUST_CONSTANT.findall(source))


class MacOSProductIdentityTests(unittest.TestCase):
    def test_every_swift_helper_embeds_a_plist_naming_its_signing_identifier(
        self,
    ) -> None:
        embedded = _embedded_plists()
        helpers = _swift_helpers()
        self.assertEqual(
            set(helpers) | set(RUST_PRODUCTS),
            set(PRODUCT_IDENTIFIERS),
        )
        for product, target in helpers.items():
            with self.subTest(product=product):
                document = _swift_plist(target)
                self.assertEqual(
                    document["CFBundleIdentifier"], PRODUCT_IDENTIFIERS[product]
                )
                name = document["CFBundleName"]
                self.assertIsInstance(name, str)
                self.assertTrue(str(name).startswith("Remap "))
                self.assertEqual(document["CFBundleDisplayName"], name)
                # Its own target block embeds its own plist, and no other.
                self.assertEqual(embedded[target], [target])

    def test_no_executable_target_embeds_another_targets_plist(self) -> None:
        embedded = _embedded_plists()
        self.assertEqual(embedded.pop("RemapApp"), [])
        self.assertEqual(
            embedded, {target: [target] for target in _swift_helpers().values()}
        )

    def test_every_rust_executable_embeds_its_signing_identifier(self) -> None:
        for product, build_script in RUST_PRODUCTS.items():
            with self.subTest(product=product):
                constants = _rust_constants(build_script)
                self.assertEqual(constants["IDENTIFIER"], PRODUCT_IDENTIFIERS[product])
                self.assertTrue(constants["NAME"].startswith("Remap "))

    def test_every_product_has_a_distinct_name(self) -> None:
        names = [
            _swift_plist(target)["CFBundleName"] for target in _swift_helpers().values()
        ]
        names.extend(_rust_constants(path)["NAME"] for path in RUST_PRODUCTS.values())
        self.assertEqual(len(names), len(set(names)))

    def test_every_executable_states_the_same_copyright_as_the_app(self) -> None:
        for target in _swift_helpers().values():
            with self.subTest(target=target):
                self.assertEqual(
                    _swift_plist(target)["NSHumanReadableCopyright"], COPYRIGHT
                )
        for build_script in RUST_PRODUCTS.values():
            with self.subTest(build_script=build_script):
                self.assertEqual(_rust_constants(build_script)["COPYRIGHT"], COPYRIGHT)

    def test_every_swift_plist_declares_the_product_version(self) -> None:
        verify_native_plist_versions(ROOT, PRODUCT_VERSION)

    def test_a_plist_left_at_an_older_version_fails_the_gate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-plist-version-") as directory:
            root = Path(directory)
            plist = root / "platforms/macos/Sources/RemapExample/Info.plist"
            plist.parent.mkdir(parents=True)
            document = {
                "CFBundleShortVersionString": "0.1.0",
                "CFBundleVersion": "0.1.0",
            }
            _ = plist.write_bytes(plistlib.dumps(document))

            with self.assertRaisesRegex(RuntimeError, "RemapExample/Info.plist"):
                verify_native_plist_versions(root, "0.2.0")


if __name__ == "__main__":
    _ = unittest.main()
