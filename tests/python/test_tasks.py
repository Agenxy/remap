#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.14"
# dependencies = []
# ///
"""Task-front-door behavior that must remain honest across platforms."""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Generator, Sequence
from pathlib import Path
from unittest.mock import patch

from tools import remap_tasks
from tools.remap_macos_install import verify_generated_package_contract
from tools.remap_macos_portable_package import PortablePackage
from tools.remap_macos_release_installer_signing import (
    ReleaseInstallerSigningIdentity,
)
from tools.remap_macos_signing import LocalCodeSigningIdentity
from tools.remap_release_model import ArtifactSpec
from tools.remap_tasks import (
    task_build_macos_app,
    task_help,
    task_install,
    task_package_macos,
    task_recover,
    task_release_evidence,
    task_release_evidence_verify,
    task_setup_install,
    task_uninstall,
    task_update,
    verify_release_evidence_in_isolation,
)


@contextlib.contextmanager
def gate_tool_boundaries() -> Generator[None]:
    """Keep task dispatch real while replacing external builds and read boundaries."""
    with contextlib.ExitStack() as stack:
        for name in (
            "run",
            "task_quality",
            "verify_policy_copies",
            "verify_packages",
            "task_docs",
            "task_dependencies",
            "verify_selected_xcode",
        ):
            _ = stack.enter_context(patch(f"tools.remap_tasks.{name}"))
        _ = stack.enter_context(
            patch("tools.remap_macos_install.verify_selected_xcode")
        )
        _ = stack.enter_context(patch("tools.remap_macos_install.native_user"))
        _ = stack.enter_context(
            patch("tools.remap_freshness._release_toolchain_required", False)
        )
        _ = stack.enter_context(
            patch(
                "subprocess.run",
                side_effect=AssertionError("unexpected external command"),
            )
        )
        yield


@contextlib.contextmanager
def record_commands() -> Generator[list[tuple[str, ...]]]:
    """Capture the commands a task would run, without running any of them."""
    commands: list[tuple[str, ...]] = []

    def record(command: Sequence[str], **_: object) -> None:
        commands.append(tuple(command))

    with patch("tools.remap_tasks.run", side_effect=record):
        yield commands


class FreshCloneQualityTests(unittest.TestCase):
    """The quality gate must run in a clone where nothing has been built yet."""

    @unittest.skipUnless(
        sys.platform == "darwin",
        "the Swift linters and their caches are macOS only",
    )
    def test_quality_creates_the_cache_directory_it_passes_to_the_swift_linters(
        self,
    ) -> None:
        """A fresh clone has no `target/`, and swiftformat refuses to create it."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            with (
                patch("tools.remap_tasks.ROOT", root),
                record_commands() as commands,
            ):
                remap_tasks.task_quality()
            self.assertTrue(
                (root / "target").is_dir(),
                "the quality gate must create the cache directory it names",
            )
            cache_arguments = [
                argument
                for command in commands
                for argument in command
                if "swiftformat.cache" in argument or "swiftlint-cache" in argument
            ]
            self.assertTrue(cache_arguments, "expected the Swift linters to be invoked")
            for argument in cache_arguments:
                self.assertTrue(
                    Path(argument).parent.is_dir(),
                    f"cache directory for {argument} must exist before the linter runs",
                )

    def test_setup_trusts_the_repository_configuration_before_using_mise(self) -> None:
        """Every later `mise` call fails in a fresh clone until the config is trusted."""
        with record_commands() as commands:
            remap_tasks.task_setup()
        self.assertTrue(commands, "expected setup to run commands")
        trusting = [
            index for index, command in enumerate(commands) if "trust" in command
        ]
        self.assertTrue(trusting, "setup must trust the repository mise config")
        trust = trusting[0]
        other = [
            index
            for index, command in enumerate(commands)
            if command and command[0] == "mise" and "trust" not in command
        ]
        self.assertTrue(other, "expected setup to use mise after trusting it")
        self.assertLess(
            trust,
            min(other),
            "trusting the config must precede every other mise call",
        )


class GateSigningBoundaryTests(unittest.TestCase):
    """Exercise the gate call graph without requiring keychain or native authority."""

    def test_development_gate_never_acquires_an_identity_or_checks_installation(
        self,
    ) -> None:
        for platform in ("darwin", "linux"):
            with (
                self.subTest(platform=platform),
                gate_tool_boundaries(),
                contextlib.ExitStack() as stack,
            ):
                _ = stack.enter_context(
                    patch("tools.remap_tasks.sys.platform", platform)
                )
                signers = [
                    stack.enter_context(
                        patch(
                            f"tools.{module}.ensure_local_codesigning_identity",
                            side_effect=AssertionError(
                                "locked keychain must not be reached"
                            ),
                        )
                    )
                    for module in (
                        "remap_tasks",
                        "remap_app",
                        "remap_macos_install",
                        "remap_macos_signing",
                    )
                ]
                install = stack.enter_context(
                    patch(
                        "tools.remap_tasks.task_install_check",
                        side_effect=AssertionError("development gate must not install"),
                    )
                )
                native_contract = stack.enter_context(
                    patch(
                        "tools.remap_tasks.verify_generated_package_contract",
                        wraps=verify_generated_package_contract,
                    )
                )
                build = stack.enter_context(
                    patch(
                        "tools.remap_tasks.build_native_app",
                        return_value=Path("/unused/Remap.app"),
                    )
                )
                remap_tasks.task_check()
                for signer in signers:
                    signer.assert_not_called()
                install.assert_not_called()
                native_contract.assert_not_called()
                if platform == "darwin":
                    build.assert_called_once_with(
                        remap_tasks.ROOT,
                        remap_tasks.PRODUCT_VERSION,
                        release=False,
                        signing_identity=None,
                    )
                else:
                    build.assert_not_called()

    def test_release_gate_reaches_native_identity_and_propagates_unavailability(
        self,
    ) -> None:
        with (
            gate_tool_boundaries(),
            patch("tools.remap_tasks.sys.platform", "darwin"),
            patch(
                "tools.remap_macos_install.ensure_local_codesigning_identity",
                side_effect=RuntimeError("locked keychain"),
            ) as ensure,
            patch("tools.remap_tasks.build_native_app") as build,
            self.assertRaisesRegex(RuntimeError, "locked keychain"),
        ):
            remap_tasks.task_release_check()
        ensure.assert_called_once_with()
        build.assert_not_called()

    def test_release_gate_retains_install_check_and_signed_native_contract(
        self,
    ) -> None:
        identity = LocalCodeSigningIdentity(
            "Remap Local Codesign", "A" * 40, "B" * 64, Path("/unused/keychain")
        )
        with (
            gate_tool_boundaries(),
            patch("tools.remap_tasks.sys.platform", "darwin"),
            patch(
                "tools.remap_tasks.verify_generated_package_contract"
            ) as native_contract,
            patch("tools.remap_tasks.task_install_check") as install,
            patch(
                "tools.remap_tasks.ensure_local_codesigning_identity",
                return_value=identity,
            ) as ensure,
            patch(
                "tools.remap_tasks.build_native_app",
                return_value=Path("/unused/Remap.app"),
            ) as build,
            patch("tools.remap_tasks.verify_release_evidence_in_isolation") as evidence,
            patch("tools.remap_tasks.verify_macos_release_metadata") as metadata,
        ):
            remap_tasks.task_release_check()
        native_contract.assert_called_once_with(
            remap_tasks.ROOT, remap_tasks.PRODUCT_VERSION
        )
        install.assert_called_once_with()
        ensure.assert_called_once_with()
        build.assert_called_once_with(
            remap_tasks.ROOT,
            remap_tasks.PRODUCT_VERSION,
            release=False,
            signing_identity=identity,
        )
        evidence.assert_called_once_with()
        metadata.assert_called_once_with(Path("/unused/Remap.app"))
        self.assertIs(
            remap_tasks.TASKS["install-check"], remap_tasks.task_install_check
        )


class NativeProductTaskTests(unittest.TestCase):
    """Prevent native-product targets from degrading into a CLI-only install."""

    def test_install_fails_honestly_when_native_product_is_unavailable(self) -> None:
        """An unsupported host must not silently install only one binary."""
        with (
            patch("tools.remap_tasks.sys.platform", "win32"),
            self.assertRaisesRegex(RuntimeError, "make install-cli"),
        ):
            task_install()

    def test_uninstall_fails_honestly_when_native_product_is_unavailable(self) -> None:
        """An unsupported uninstall must not silently target only one binary."""
        with (
            patch("tools.remap_tasks.sys.platform", "win32"),
            self.assertRaisesRegex(RuntimeError, "make uninstall-cli"),
        ):
            task_uninstall()

    def test_recovery_fails_honestly_when_native_product_is_unavailable(self) -> None:
        with (
            patch("tools.remap_tasks.sys.platform", "win32"),
            self.assertRaisesRegex(RuntimeError, "recovery did not run"),
        ):
            task_recover()

    def test_linux_lifecycle_targets_dispatch_to_the_native_orchestrator(self) -> None:
        with (
            patch("tools.remap_tasks.sys.platform", "linux"),
            patch("tools.remap_tasks.install_or_update_linux") as install,
            patch("tools.remap_tasks.recover_linux") as recover,
            patch("tools.remap_tasks.uninstall_linux") as uninstall,
        ):
            task_install()
            task_update()
            task_recover()
            task_uninstall()

        install.assert_any_call(Path(__file__).resolve().parents[2], "0.2.0", "install")
        install.assert_any_call(Path(__file__).resolve().parents[2], "0.2.0", "update")
        root = Path(__file__).resolve().parents[2]
        recover.assert_called_once_with(root)
        uninstall.assert_called_once_with(root)

    def test_setup_install_selects_only_the_current_platform_preflight(self) -> None:
        with (
            patch("tools.remap_tasks.sys.platform", "linux"),
            patch("tools.remap_tasks.require_linux_bootstrap") as linux,
            patch("tools.remap_tasks.verify_selected_xcode") as xcode,
        ):
            task_setup_install()

        linux.assert_called_once_with()
        xcode.assert_not_called()

    def test_app_build_verifies_the_selected_xcode_before_compiling(self) -> None:
        with (
            patch("tools.remap_tasks.require_macos"),
            patch(
                "tools.remap_tasks.verify_selected_xcode",
                side_effect=RuntimeError("wrong Xcode"),
            ),
            patch("tools.remap_tasks.build_native_app") as build,
            self.assertRaisesRegex(RuntimeError, "wrong Xcode"),
        ):
            _ = task_build_macos_app()
        build.assert_not_called()

    def test_macos_package_never_selects_a_personal_ssh_key(self) -> None:
        with (
            patch.dict("tools.remap_tasks.os.environ", {}, clear=True),
            patch("tools.remap_tasks.require_macos"),
            patch("tools.remap_tasks.build_portable_macos_package") as build,
            self.assertRaisesRegex(RuntimeError, "dedicated release key"),
        ):
            task_package_macos()
        build.assert_not_called()

    def test_macos_package_uses_only_the_explicit_release_key(self) -> None:
        release_key = "/private/release/remap-release.pub"
        expected_identity = ReleaseInstallerSigningIdentity(
            name="Remap Release Installer",
            sha1="b" * 40,
            sha256="c" * 64,
            keychain=Path("/private/release/login.keychain-db"),
        )
        with (
            patch.dict(
                "tools.remap_tasks.os.environ",
                {"REMAP_RELEASE_SIGNING_KEY": release_key},
                clear=True,
            ),
            patch("tools.remap_tasks.require_macos"),
            patch(
                "tools.remap_tasks.ensure_release_installer_identity"
            ) as installer_identity,
            patch("tools.remap_tasks.build_portable_macos_package") as build,
        ):
            installer_identity.return_value = expected_identity
            build.return_value = PortablePackage(
                path=Path("/private/release/Remap.pkg"),
                sha256="a" * 64,
                signature_path=Path("/private/release/Remap.pkg.sig"),
                signature_sha256="c" * 64,
                release_manifest_sha256="b" * 64,
                architecture="arm64",
                product_version="0.2.0",
            )
            task_package_macos()

        self.assertEqual(build.call_args.kwargs["signing_key"], Path(release_key))
        self.assertEqual(
            build.call_args.kwargs["installer_identity"],
            expected_identity,
        )

    def test_release_evidence_uses_every_verified_workspace_crate(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-task-") as directory:
            root = Path(directory)
            sources = {"alpha": root / "crates/alpha", "beta": root / "crates/beta"}
            with (
                patch("tools.remap_tasks.ROOT", root),
                patch("tools.remap_tasks.PRODUCT_VERSION", "1.2.3"),
                patch(
                    "tools.remap_tasks.cargo_target_directory",
                    return_value=root / "target",
                ) as target_directory,
                patch("tools.remap_tasks.verify_packages") as packages,
                patch("tools.remap_tasks.workspace_sources", return_value=sources),
                patch("tools.remap_tasks.create_release_evidence") as create,
                patch("tools.remap_tasks.verify_release_evidence") as verify,
            ):
                task_release_evidence()
                task_release_evidence_verify()

        packages.assert_called_once_with()
        target_directory.assert_called_with(root)
        evidence = root / "dist/remap-1.2.3-source-evidence"
        expected = (
            ArtifactSpec(
                "alpha-1.2.3.crate", root / "target/package/alpha-1.2.3.crate"
            ),
            ArtifactSpec("beta-1.2.3.crate", root / "target/package/beta-1.2.3.crate"),
        )
        create.assert_called_once_with(evidence, expected)
        verify.assert_called_once_with(evidence, expected)

    def test_existing_release_evidence_prevents_package_replacement(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-release-task-") as directory:
            root = Path(directory)
            evidence = root / "dist/remap-1.2.3-source-evidence"
            evidence.mkdir(parents=True)
            archive = root / "target/package/alpha-1.2.3.crate"
            archive.parent.mkdir(parents=True)
            _ = archive.write_bytes(b"original archive")
            with (
                patch("tools.remap_tasks.ROOT", root),
                patch("tools.remap_tasks.PRODUCT_VERSION", "1.2.3"),
                patch("tools.remap_tasks.verify_packages") as packages,
                self.assertRaisesRegex(RuntimeError, "release evidence already exists"),
            ):
                task_release_evidence()

            packages.assert_not_called()
            self.assertEqual(archive.read_bytes(), b"original archive")

    def test_release_evidence_gate_creates_and_verifies_one_isolated_set(self) -> None:
        specs = (ArtifactSpec("remap.crate", Path("remap.crate")),)
        outputs: list[Path] = []

        def capture(output: Path, _specs: tuple[ArtifactSpec, ...]) -> None:
            outputs.append(output)

        with (
            patch("tools.remap_tasks.release_crate_specs", return_value=specs),
            patch("tools.remap_tasks.create_release_evidence", side_effect=capture),
            patch("tools.remap_tasks.verify_release_evidence") as verify,
        ):
            verify_release_evidence_in_isolation()

        self.assertEqual(len(outputs), 1)
        output = outputs[0]
        self.assertEqual(output.name, "evidence")
        verify.assert_called_once_with(output, specs)

    def test_dependency_free_make_help_matches_the_typed_task_catalog(self) -> None:
        make_help = subprocess.run(
            # --no-print-directory: this test runs inside `make check`, and a
            # nested GNU make announces the directory it enters unless told
            # not to; that line is make's, not the help text's.
            ("make", "--no-print-directory", "help"),
            cwd=Path(__file__).resolve().parents[2],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        typed_help = io.StringIO()
        with contextlib.redirect_stdout(typed_help):
            task_help()

        self.assertEqual(make_help, typed_help.getvalue())

    def test_make_does_not_interpolate_lifecycle_values_into_shell_text(self) -> None:
        result = subprocess.run(
            ("make", "-n", "install", "REMAP_LINUX_LINK=2'; REMAP_INJECTED"),
            cwd=Path(__file__).resolve().parents[2],
            check=True,
            capture_output=True,
            text=True,
        )

        self.assertNotIn("REMAP_INJECTED", result.stdout)
        self.assertIn("python -m tools.remap_tasks install", result.stdout)
        self.assertNotIn("mise exec", result.stdout)
        self.assertIn("MISE_AUTO_INSTALL=0", result.stdout)
        self.assertIn("mise which uv", result.stdout)


if __name__ == "__main__":
    _ = unittest.main()
