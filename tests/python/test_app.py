#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Application signing contracts, with real ad-hoc verification on macOS."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from typing import cast
from unittest import mock

from tools import remap_app, remap_tasks
from tools.remap_macos_signing import LocalCodeSigningIdentity

IDENTITY = LocalCodeSigningIdentity(
    name="Remap Local Codesign",
    sha1="A" * 40,
    sha256="B" * 64,
    keychain=Path("/unused/login.keychain-db"),
)
AD_HOC_DETAILS = (
    "Identifier=org.agenxy.Remap\n"
    "Signature=adhoc\n"
    "CodeDirectory v=20500 size=100 flags=0x10002(adhoc,runtime)\n"
)
DURABLE_DETAILS = (
    "Identifier=org.agenxy.Remap\n"
    + "Authority=Remap Local Codesign\n"
    + "CodeDirectory v=20500 size=100 flags=0x10000(runtime)\n"
    + "CDHash="
    + "a" * 40
    + "\n"
)


@contextmanager
def app_inputs(*, native: bool = False) -> Generator[Path]:
    """Stage real bundle inputs, substituting only compilation and icon tooling."""
    with tempfile.TemporaryDirectory(prefix="remap-app-test-") as directory:
        root = Path(directory)
        binaries = root / "swift-bin"
        binaries.mkdir()
        executable = binaries / remap_app.APP_NAME
        if native:
            _ = shutil.copyfile("/bin/echo", executable)
        else:
            _ = executable.write_bytes(b"synthetic executable")
        executable.chmod(0o755)
        (binaries / remap_app.RESOURCE_BUNDLE_NAME).mkdir()
        for name in ("LICENSE", "NOTICE"):
            _ = (root / name).write_text(name, encoding="utf-8")
        with (
            mock.patch("tools.remap_app.expected_macos_sdk", return_value="26.0"),
            mock.patch("tools.remap_app.normalize_macos_sdk_metadata"),
            mock.patch("tools.remap_app._build_icon"),
        ):
            yield root


def tool_result(
    root: Path, arguments: tuple[str, ...], details: str
) -> subprocess.CompletedProcess[str]:
    """Model tool output while refusing any keychain, trust, or privilege command."""
    if arguments[0] == "xcrun":
        return subprocess.CompletedProcess(arguments, 0, str(root / "swift-bin"), "")
    if arguments[0] == "/usr/bin/plutil":
        return subprocess.CompletedProcess(arguments, 0, "", "")
    if arguments[0] != "/usr/bin/codesign":
        raise AssertionError(f"unexpected build command: {arguments[0]}")
    output = details if "-d" in arguments else ""
    if "-r-" in arguments:
        output = f'designated => certificate root = H"{IDENTITY.sha1.lower()}"'
    return subprocess.CompletedProcess(arguments, 0, "", output)


class AppSigningTests(unittest.TestCase):
    """Distinguish development integrity from durable release signer identity."""

    def test_development_task_does_not_request_a_durable_identity(self) -> None:
        with (
            mock.patch("tools.remap_freshness._release_toolchain_required", False),
            mock.patch("tools.remap_tasks.require_macos"),
            mock.patch("tools.remap_tasks.verify_selected_xcode"),
            mock.patch("tools.remap_tasks.ensure_local_codesigning_identity") as ensure,
            mock.patch("tools.remap_tasks.build_native_app") as build,
        ):
            _ = remap_tasks.task_build_macos_app()
        ensure.assert_not_called()
        build.assert_called_once_with(
            remap_tasks.ROOT,
            remap_tasks.PRODUCT_VERSION,
            release=False,
            signing_identity=None,
        )

    def test_release_gate_still_supplies_a_durable_identity_to_the_app_task(
        self,
    ) -> None:
        with (
            mock.patch("tools.remap_freshness._release_toolchain_required", False),
            mock.patch("tools.remap_tasks.require_macos"),
            mock.patch("tools.remap_tasks.verify_selected_xcode"),
            mock.patch("tools.remap_tasks.task_dependencies"),
            mock.patch("tools.remap_tasks.verify_generated_package_contract"),
            mock.patch("tools.remap_tasks.task_install_check"),
            mock.patch(
                "tools.remap_tasks.task_check",
                side_effect=remap_tasks.task_build_macos_app,
            ),
            mock.patch(
                "tools.remap_tasks.ensure_local_codesigning_identity",
                return_value=IDENTITY,
            ) as ensure,
            mock.patch("tools.remap_tasks.build_native_app") as build,
        ):
            remap_tasks.task_release_check()
        ensure.assert_called_once_with()
        build.assert_called_once_with(
            remap_tasks.ROOT,
            remap_tasks.PRODUCT_VERSION,
            release=False,
            signing_identity=IDENTITY,
        )

    def test_development_build_creates_no_identity_or_trust_setting(self) -> None:
        for headless in ("0", "1"):
            with self.subTest(headless=headless), app_inputs() as root:

                def run(
                    arguments: tuple[str, ...], **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    return tool_result(root, arguments, AD_HOC_DETAILS)

                with (
                    mock.patch.dict(os.environ, {"REMAP_HEADLESS_TRUST": headless}),
                    mock.patch(
                        "tools.remap_app.subprocess.run", side_effect=run
                    ) as calls,
                    mock.patch(
                        "tools.remap_app.ensure_local_codesigning_identity",
                        side_effect=AssertionError("development requested a keychain"),
                    ) as ensure,
                    mock.patch("tools.remap_macos_signing.create_identity") as create,
                    mock.patch("tools.remap_macos_signing.trust_arguments") as trust,
                ):
                    bundle = remap_app.build(root, "0.2.0", release=False)

                ensure.assert_not_called()
                create.assert_not_called()
                trust.assert_not_called()
                commands = [
                    cast("tuple[str, ...]", call.args[0])
                    for call in calls.call_args_list
                ]
                self.assertIn(
                    (
                        "/usr/bin/codesign",
                        "--force",
                        "--sign",
                        "-",
                        "--timestamp=none",
                        "--options",
                        "runtime",
                        "--identifier",
                        "org.agenxy.Remap",
                        str(bundle),
                    ),
                    commands,
                )
                self.assertIn(
                    (
                        "/usr/bin/codesign",
                        "--verify",
                        "--strict",
                        "--verbose=2",
                        str(bundle),
                    ),
                    commands,
                )

    def test_release_build_requires_and_verifies_the_durable_identity(self) -> None:
        with app_inputs() as root:

            def run(
                arguments: tuple[str, ...], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                return tool_result(root, arguments, DURABLE_DETAILS)

            with (
                mock.patch("tools.remap_app.subprocess.run", side_effect=run) as calls,
                mock.patch(
                    "tools.remap_app.ensure_local_codesigning_identity",
                    return_value=IDENTITY,
                ) as ensure,
            ):
                bundle = remap_app.build(root, "0.2.0", release=True)

            ensure.assert_called_once_with()
            commands = [
                cast("tuple[str, ...]", call.args[0]) for call in calls.call_args_list
            ]
            signing = next(command for command in commands if "--sign" in command)
            self.assertEqual(signing[signing.index("--sign") + 1], IDENTITY.sha1)
            self.assertIn(str(IDENTITY.keychain), signing)
            requirement = (
                '-R=identifier "org.agenxy.Remap" and certificate root = H"'
                + IDENTITY.sha1.lower()
                + '"'
            )
            self.assertIn(
                ("/usr/bin/codesign", "--verify", "--strict", requirement, str(bundle)),
                commands,
            )

    def test_release_identity_failure_never_falls_back_to_ad_hoc(self) -> None:
        with (
            mock.patch(
                "tools.remap_app.ensure_local_codesigning_identity",
                side_effect=RuntimeError("identity unavailable"),
            ),
            mock.patch("tools.remap_app.run") as run,
            self.assertRaisesRegex(RuntimeError, "identity unavailable"),
        ):
            _ = remap_app.build(Path("/unused"), "0.2.0", release=True)
        run.assert_not_called()

    def test_explicit_identity_retains_existing_signing_behavior(self) -> None:
        for release in (False, True):
            for sign in (False, True):
                with self.subTest(release=release, sign=sign), app_inputs() as root:
                    with (
                        mock.patch("tools.remap_app.run"),
                        mock.patch(
                            "tools.remap_app.capture",
                            return_value=str(root / "swift-bin"),
                        ),
                        mock.patch(
                            "tools.remap_app.ensure_local_codesigning_identity"
                        ) as ensure,
                        mock.patch("tools.remap_app.sign_path") as signing,
                        mock.patch("tools.remap_app.verify_local_signature") as verify,
                    ):
                        bundle = remap_app.build(
                            root,
                            "0.2.0",
                            release=release,
                            signing_identity=IDENTITY,
                            sign=sign,
                        )
                    ensure.assert_not_called()
                    signing.assert_called_once_with(
                        bundle, IDENTITY, remap_app.APP_BUNDLE_ID
                    )
                    verify.assert_called_once_with(
                        bundle, IDENTITY, remap_app.APP_BUNDLE_ID
                    )

    def test_unsigned_release_staging_does_not_create_an_identity(self) -> None:
        with app_inputs() as root:
            with (
                mock.patch("tools.remap_app.run") as run,
                mock.patch(
                    "tools.remap_app.capture", return_value=str(root / "swift-bin")
                ),
                mock.patch(
                    "tools.remap_app.ensure_local_codesigning_identity"
                ) as ensure,
                mock.patch("tools.remap_app.verify") as verify,
            ):
                _ = remap_app.build(root, "0.2.0", release=True, sign=False)
            ensure.assert_not_called()
            verify.assert_not_called()
            self.assertFalse(
                any("/usr/bin/codesign" in call.args[0] for call in run.call_args_list)
            )

    def test_development_verifier_rejects_wrong_identifier_runtime_or_signature(
        self,
    ) -> None:
        invalid = (
            (AD_HOC_DETAILS.replace("org.agenxy.Remap", "wrong"), "identifier"),
            (AD_HOC_DETAILS.replace("0x10002(adhoc,runtime)", "0x2(adhoc)"), "runtime"),
            (DURABLE_DETAILS, "ad-hoc"),
            ("", "identifier"),
        )
        for details, reason in invalid:
            with (
                self.subTest(reason=reason),
                mock.patch("tools.remap_app.run"),
                mock.patch("tools.remap_app.capture", return_value=details),
                self.assertRaisesRegex(RuntimeError, reason),
            ):
                remap_app.verify(Path("/unused"), Path("/unused/Remap.app"))

    def test_development_verifier_propagates_strict_verification_failure(self) -> None:
        with (
            mock.patch(
                "tools.remap_app.run",
                side_effect=subprocess.CalledProcessError(1, "codesign"),
            ),
            mock.patch("tools.remap_app.capture") as capture,
            self.assertRaises(subprocess.CalledProcessError),
        ):
            remap_app.verify(Path("/unused"), Path("/unused/Remap.app"))
        capture.assert_not_called()

    def test_release_verification_rejects_an_ad_hoc_bundle(self) -> None:
        with app_inputs() as root:

            def run(
                arguments: tuple[str, ...], **_kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                return tool_result(root, arguments, AD_HOC_DETAILS)

            with (
                mock.patch("tools.remap_app.subprocess.run", side_effect=run),
                self.assertRaisesRegex(
                    RuntimeError, "does not use Remap Local Codesign"
                ),
            ):
                remap_app.verify(root, root / "Remap.app", IDENTITY)

    # Real codesign and Mach-O execution require macOS; no keychain is needed.
    @unittest.skipUnless(sys.platform == "darwin", "requires macOS codesign and Mach-O")
    def test_native_development_bundle_verifies_without_keychain_or_trust(self) -> None:
        native_run = subprocess.run
        with app_inputs(native=True) as root:

            def run(
                arguments: tuple[str, ...], **kwargs: object
            ) -> subprocess.CompletedProcess[str]:
                if arguments[0] == "xcrun":
                    return tool_result(root, arguments, "")
                if arguments[0] not in {"/usr/bin/codesign", "/usr/bin/plutil"}:
                    raise AssertionError(
                        "native development build accessed another tool"
                    )
                return native_run(
                    arguments,
                    cwd=root,
                    check=True,
                    capture_output=bool(kwargs.get("capture_output")),
                    text=True,
                )

            with (
                mock.patch("tools.remap_app.subprocess.run", side_effect=run),
                mock.patch(
                    "tools.remap_app.ensure_local_codesigning_identity",
                    side_effect=AssertionError("native build requested a keychain"),
                ) as ensure,
                mock.patch("tools.remap_macos_signing.create_identity") as create,
                mock.patch("tools.remap_macos_signing.trust_arguments") as trust,
            ):
                bundle = remap_app.build(root, "0.2.0", release=False)
            ensure.assert_not_called()
            create.assert_not_called()
            trust.assert_not_called()
            _ = native_run(
                ("/usr/bin/codesign", "--verify", "--strict", str(bundle)), check=True
            )
            details = native_run(
                ("/usr/bin/codesign", "-d", "--verbose=4", str(bundle)),
                check=True,
                capture_output=True,
                text=True,
            ).stderr
            self.assertIn("Identifier=org.agenxy.Remap\n", details)
            self.assertIn("Signature=adhoc\n", details)
            self.assertRegex(details, r"flags=0x[0-9a-f]+\([^)]*\bruntime\b")
            result = native_run(
                (str(bundle / "Contents/MacOS/Remap"), "ad-hoc runs"),
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(result.stdout.strip(), "ad-hoc runs")


if __name__ == "__main__":
    _ = unittest.main()
