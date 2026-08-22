"""Exact contracts for Remap's no-shell Apple Installer bootstrap."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import cast

from tools import remap_macos_installer_package
from tools.remap_native_package import NativePackage


class MacOSInstallerPackageTests(unittest.TestCase):
    def test_configuration_binds_app_bootstrap_and_service_to_one_signer(self) -> None:
        document = remap_macos_installer_package.service_configuration_document(
            owner_uid=501,
            app_cdhash="a" * 40,
            bootstrap_cdhash="b" * 40,
            service_cdhash="c" * 40,
            source_package=_source_package(),
            signing_certificate_sha256="D" * 64,
        )
        app = cast(dict[str, object], document["app"])
        bootstrap = cast(dict[str, object], document["bootstrap"])
        helper = cast(dict[str, object], document["helper"])

        self.assertEqual(document["ownerUID"], 501)
        self.assertEqual(app["identifier"], "org.agenxy.Remap")
        self.assertEqual(
            bootstrap["identifier"],
            "org.agenxy.Remap.installer-bootstrap",
        )
        self.assertEqual(
            helper["identifier"],
            "org.agenxy.Remap.installer-service",
        )
        self.assertEqual(app["certificateSHA256"], "d" * 64)
        self.assertEqual(document["sourceManifestDigest"], "d" * 64)
        self.assertEqual(
            document["sourcePackageRoot"],
            "/Library/Application Support/Agenxy/Remap/Installer/Sources/" + "d" * 64,
        )
        encoded = json.dumps(document, separators=(",", ":"), sort_keys=True)
        self.assertNotIn(": ", encoded)
        self.assertNotIn(", ", encoded)

    def test_launchd_service_is_on_demand_and_has_no_shell(self) -> None:
        document = remap_macos_installer_package.launchd_document()

        self.assertEqual(
            document["ProgramArguments"],
            ["/Library/PrivilegedHelperTools/org.agenxy.Remap.installer-service"],
        )
        self.assertEqual(
            document["MachServices"],
            {"org.agenxy.Remap.installer-service": True},
        )
        self.assertNotIn("RunAtLoad", document)
        self.assertNotIn("KeepAlive", document)
        self.assertNotIn("/bin/sh", repr(document))

    def test_source_package_is_copied_before_its_directories_are_sealed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            source = workspace / "source"
            source.mkdir(mode=0o700)
            payload = source / "payload"
            payload.mkdir(mode=0o700)
            product = payload / "app"
            product.mkdir(mode=0o700)
            binary = product / "Remap"
            _ = binary.write_bytes(b"signed fixture")
            os.chmod(binary, 0o500)
            os.chmod(product, 0o500)
            os.chmod(payload, 0o500)
            manifest = source / "manifest.json"
            _ = manifest.write_bytes(b"{}")
            os.chmod(manifest, 0o400)
            package = NativePackage(
                root=source,
                payload=payload,
                manifest=manifest,
                manifest_digest=hashlib.sha256(b"{}").hexdigest(),
                generation_id="fixture",
            )
            destination = workspace / "destination"

            remap_macos_installer_package.stage_source_package(package, destination)

            self.assertEqual(
                (destination / "payload/app/Remap").read_bytes(), b"signed fixture"
            )
            self.assertEqual(destination.stat().st_mode & 0o777, 0o700)
            self.assertEqual((destination / "payload").stat().st_mode & 0o777, 0o500)
            self.assertEqual(
                (destination / "payload/app").stat().st_mode & 0o777, 0o500
            )

    def test_lifecycle_parent_modes_match_the_native_install_topology(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            payload = Path(directory) / "payload"
            payload.mkdir(mode=0o700)
            configuration = payload.joinpath(
                *remap_macos_installer_package.SERVICE_CONFIGURATION.parts[1:]
            )

            remap_macos_installer_package.prepare_lifecycle_parent_chain(
                payload,
                configuration.parent,
                private_leaf=True,
            )

            application_support = payload / "Library/Application Support"
            self.assertEqual(
                (application_support / "Agenxy").stat().st_mode & 0o777,
                remap_macos_installer_package.AGENXY_DIRECTORY_MODE,
            )
            self.assertEqual(
                (application_support / "Agenxy/Remap").stat().st_mode & 0o777,
                remap_macos_installer_package.REMAP_DIRECTORY_MODE,
            )
            self.assertEqual(
                (application_support / "Agenxy/Remap/Installer").stat().st_mode & 0o777,
                remap_macos_installer_package.INSTALLER_DIRECTORY_MODE,
            )


def _source_package() -> NativePackage:
    root = Path("/tmp/remap-source")
    return NativePackage(
        root=root,
        payload=root / "payload",
        manifest=root / "manifest.json",
        manifest_digest="d" * 64,
        generation_id="0.1.1-fixture",
    )


if __name__ == "__main__":
    _ = unittest.main()
