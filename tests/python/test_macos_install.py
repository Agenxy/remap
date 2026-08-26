"""Pure contract tests for the native macOS lifecycle orchestrator."""

from __future__ import annotations

import io
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from typing import override
from unittest import mock

from tools import remap_macos_install
from tools.remap_lifecycle_approval import confirm_approval
from tools.remap_macos_install import (
    helper_json,
    require_public_command_slot,
    require_readable_exact,
    verify_uninstalled,
)
from tools.remap_macos_protocol import (
    InstallerStatus,
    approval_token,
    installer_status,
    is_exact_update,
    recovery_has_effects,
    render_preview,
    render_recovery_preview,
    resolver_upstreams,
)
from tools.remap_native_package import NativePackage, NativeProductFiles


class MacOSInstallOrchestratorTests(unittest.TestCase):
    """Reject malformed helper output before it can steer privileged work."""

    def test_status_validates_active_generation_and_recovery_counts(self) -> None:
        document = success(
            "status",
            {
                "activeGenerationID": "0.1.1-0123456789abcdef0123",
                "dns": {"active": True, "effectiveRemapServiceCount": 1},
                "generations": [{"generationID": "0.1.1-0123456789abcdef0123"}],
                "services": [{"loaded": True}, {"loaded": False}],
                "transactions": [
                    {"recoveryRequired": True},
                    {"recoveryRequired": False},
                ],
            },
        )

        status = installer_status(document)

        self.assertEqual(status.active_generation_id, "0.1.1-0123456789abcdef0123")
        self.assertEqual(status.pending_recovery_count, 1)
        self.assertEqual(status.loaded_service_count, 1)
        self.assertTrue(status.dns_active)
        self.assertEqual(status.effective_remap_service_count, 1)

    def test_status_rejects_generation_path_injection(self) -> None:
        document = success(
            "status",
            {
                "activeGenerationID": "../../foreign",
                "dns": {"active": False, "effectiveRemapServiceCount": 0},
                "generations": [],
                "services": [],
                "transactions": [],
            },
        )

        with self.assertRaisesRegex(RuntimeError, "generation identity"):
            _ = installer_status(document)

    def test_status_requires_effective_remap_resolver_observation(self) -> None:
        document = success(
            "status",
            {
                "activeGenerationID": None,
                "dns": {"active": False},
                "generations": [],
                "services": [],
                "transactions": [],
            },
        )

        with self.assertRaisesRegex(TypeError, "invalid DNS status"):
            _ = installer_status(document)

    def test_resolver_plan_accepts_canonical_unicast_endpoints(self) -> None:
        document = success(
            "resolver-plan",
            {"upstreams": ["192.0.2.53:53", "[2001:db8::53]:53"]},
        )

        self.assertEqual(
            resolver_upstreams(document),
            ["192.0.2.53:53", "[2001:db8::53]:53"],
        )

    def test_resolver_plan_rejects_loopback_duplicates_and_five_entries(self) -> None:
        invalid = (
            ["127.0.0.1:53"],
            ["192.0.2.1:53", "192.0.2.1:53"],
            [f"192.0.2.{index}:53" for index in range(1, 6)],
        )
        for upstreams in invalid:
            with (
                self.subTest(upstreams=upstreams),
                self.assertRaises(RuntimeError),
            ):
                _ = resolver_upstreams(
                    success("resolver-plan", {"upstreams": upstreams})
                )

    def test_preview_renders_exact_effects_and_escapes_terminal_controls(self) -> None:
        document = success(
            "preview",
            {
                "approvalToken": "a" * 64,
                "effects": ["publish immutable generation", "activate\u001bDNS"],
                "generationID": "0.1.1-0123456789abcdef0123",
                "operation": "install",
                "pendingRecoveryTransactions": ["install-prior"],
                "publicationChangeDetails": [
                    {
                        "action": "create",
                        "nextGenerationID": "0.1.1-0123456789abcdef0123",
                        "path": "usr/local/bin/remap",
                    },
                    {
                        "action": "replace",
                        "nextGenerationID": "0.1.1-0123456789abcdef0123",
                        "path": "usr/local/share/man/man1/remap.1",
                        "previousGenerationID": "0.1.0-abcdef0123456789abcd",
                    },
                ],
                "publicationChanges": 2,
                "schemaVersion": 2,
            },
        )

        rendered = render_preview(document)

        self.assertIn(
            "Preview: install generation 0.1.1-0123456789abcdef0123", rendered
        )
        self.assertIn("Publication changes: 2", rendered)
        self.assertIn(
            "create /usr/local/bin/remap -> 0.1.1-0123456789abcdef0123",
            rendered,
        )
        previous = "0.1.0-abcdef0123456789abcd"
        current = "0.1.1-0123456789abcdef0123"
        expected_change = (
            f"replace /usr/local/share/man/man1/remap.1: {previous} -> {current}"
        )
        self.assertIn(expected_change, rendered)
        self.assertIn("Pending recovery transactions: 1", rendered)
        self.assertIn("activate\\u{001b}DNS", rendered)
        self.assertIn(f"Approval token: {'a' * 64}", rendered)
        self.assertNotIn("\u001b", rendered)

    def test_preview_rejects_unordered_escaping_or_inconsistent_changes(self) -> None:
        generation = "0.1.1-0123456789abcdef0123"
        invalid_changes = (
            [
                {
                    "action": "create",
                    "nextGenerationID": generation,
                    "path": "usr/local/share",
                },
                {
                    "action": "create",
                    "nextGenerationID": generation,
                    "path": "usr/local/bin",
                },
            ],
            [
                {
                    "action": "create",
                    "nextGenerationID": generation,
                    "path": "../escape",
                }
            ],
            [
                {
                    "action": "remove",
                    "nextGenerationID": generation,
                    "path": "usr/local/bin/remap",
                }
            ],
        )
        for changes in invalid_changes:
            document = success(
                "preview",
                {
                    "approvalToken": "a" * 64,
                    "effects": ["bounded effect"],
                    "generationID": generation,
                    "operation": "install",
                    "pendingRecoveryTransactions": [],
                    "publicationChangeDetails": changes,
                    "publicationChanges": len(changes),
                    "schemaVersion": 2,
                },
            )
            with self.subTest(changes=changes), self.assertRaises(RuntimeError):
                _ = render_preview(document)

    def test_recovery_preview_is_exact_bounded_and_tokenized(self) -> None:
        document = success(
            "preview-recovery",
            {
                "approvalToken": "b" * 64,
                "detachedGenerationNames": [".retired-generation"],
                "effects": ["restore resolver state\u001b"],
                "orphanedStagingTransactionIDs": ["orphan-1"],
                "requestedTransactionID": None,
                "schemaVersion": 1,
                "selectedTransactionIDs": ["install-1"],
                "transactions": [
                    {
                        "generationID": "0.1.1-0123456789abcdef0123",
                        "journalHeadDigest": "c" * 64,
                        "operation": "install",
                        "phase": "dnsActive",
                        "previousGenerationID": None,
                        "recordCount": 4,
                        "recoveryRequired": True,
                        "transactionID": "install-1",
                    }
                ],
            },
        )

        rendered = render_recovery_preview(document)

        self.assertIn("install-1", rendered)
        self.assertIn(".retired-generation", rendered)
        self.assertIn("restore resolver state\\u{001b}", rendered)
        self.assertNotIn("\u001b", rendered)
        self.assertTrue(recovery_has_effects(document))
        self.assertEqual(approval_token(document, "preview-recovery"), "b" * 64)

    def test_interactive_approval_requires_the_exact_reviewed_prefix(self) -> None:
        token = "a" * 64
        output = io.StringIO()
        approved = confirm_approval(
            token,
            "install",
            input_stream=TerminalInput(f"approve {token[:12]}\n"),
            output_stream=output,
        )

        self.assertEqual(approved, token)
        self.assertIn("exact install preview", output.getvalue())
        self.assertIn("Approval confirmed", output.getvalue())

    def test_interactive_approval_defaults_to_no_on_mismatch_or_eof(self) -> None:
        token = "b" * 64
        for response in ("", f"approve {token[:11]}\n", "yes\n", "x" * 97):
            with (
                self.subTest(response=response),
                self.assertRaisesRegex(RuntimeError, "No Remap product state changed"),
            ):
                _ = confirm_approval(
                    token,
                    "update",
                    input_stream=TerminalInput(response),
                    output_stream=io.StringIO(),
                )

    def test_noninteractive_approval_requires_the_full_token(self) -> None:
        token = "c" * 64
        self.assertEqual(
            confirm_approval(
                token,
                "recover",
                input_stream=io.StringIO(f"{token}\n"),
                output_stream=io.StringIO(),
            ),
            token,
        )
        with self.assertRaisesRegex(RuntimeError, "No Remap product state changed"):
            _ = confirm_approval(
                token,
                "recover",
                input_stream=io.StringIO(f"{token[:12]}\n"),
                output_stream=io.StringIO(),
            )

    def test_recovery_preview_rejects_unselected_or_malformed_transactions(
        self,
    ) -> None:
        document = success(
            "preview-recovery",
            {
                "approvalToken": "d" * 64,
                "detachedGenerationNames": [],
                "effects": ["recover transaction missing"],
                "orphanedStagingTransactionIDs": [],
                "requestedTransactionID": None,
                "schemaVersion": 1,
                "selectedTransactionIDs": ["missing"],
                "transactions": [],
            },
        )

        with self.assertRaisesRegex(RuntimeError, "recovery transactions"):
            _ = render_recovery_preview(document)

    def test_helper_timeout_reports_unknown_outcome_and_recovery(self) -> None:
        timeout = subprocess.TimeoutExpired("remap-install", 120)
        with (
            mock.patch("tools.remap_macos_install.subprocess.run", side_effect=timeout),
            self.assertRaisesRegex(
                RuntimeError, "outcome is unknown and journal recovery is required"
            ),
        ):
            _ = helper_json(Path("."), Path("/owned/remap-install"), ("status",))

    def test_administrator_timeout_is_bounded_and_reports_no_effect(self) -> None:
        timeout = subprocess.TimeoutExpired(("/usr/bin/sudo", "-v"), 120)
        with (
            mock.patch("tools.remap_macos_install._run", side_effect=timeout),
            self.assertRaisesRegex(
                RuntimeError,
                "authenticate locally.*No privileged Remap state changed",
            ),
        ):
            remap_macos_install.authorize_administrator(Path("."))

    def test_administrator_authorization_uses_the_native_sudo_prompt(self) -> None:
        with mock.patch("tools.remap_macos_install._run") as run:
            remap_macos_install.authorize_administrator(Path("."))

        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [("/usr/bin/sudo", "-v")],
        )

    def test_exact_update_is_a_verified_no_op(self) -> None:
        package = NativePackage(
            root=Path("package"),
            payload=Path("package/payload"),
            manifest=Path("package/manifest.json"),
            manifest_digest="0" * 64,
            generation_id="0.1.1-exact",
        )
        status = InstallerStatus(
            active_generation_id="0.1.1-exact",
            generation_count=1,
            pending_recovery_count=0,
            loaded_service_count=2,
            service_count=2,
            dns_active=True,
            effective_remap_service_count=1,
        )

        self.assertTrue(is_exact_update("update", status, package.generation_id))
        self.assertFalse(is_exact_update("install", status, package.generation_id))

    def test_install_passes_the_approved_token_without_implicit_recovery(self) -> None:
        generation = "0.1.1-0123456789abcdef0123"
        token = "e" * 64
        package = NativePackage(
            root=Path("package"),
            payload=Path("package/payload"),
            manifest=Path("package/manifest.json"),
            manifest_digest="f" * 64,
            generation_id=generation,
        )
        preview = success(
            "preview",
            {
                "approvalToken": token,
                "effects": ["publish the reviewed generation"],
                "generationID": generation,
                "operation": "install",
                "pendingRecoveryTransactions": [],
                "publicationChangeDetails": [],
                "publicationChanges": 0,
                "schemaVersion": 2,
            },
        )
        calls: list[tuple[str, ...]] = []

        def helper_result(
            _root: Path, _helper: Path, arguments: tuple[str, ...]
        ) -> dict[str, object]:
            calls.append(arguments)
            if arguments == ("status",):
                active = generation if len(calls) > 4 else None
                return status_result(active)
            if arguments == ("resolver-plan",):
                return success("resolver-plan", {"upstreams": ["192.0.2.53:53"]})
            if arguments[0:2] == ("preview", "install"):
                return preview
            if arguments[0] == "install":
                return success("install", {})
            raise AssertionError(f"unexpected helper arguments: {arguments}")

        files = NativeProductFiles(
            app=Path("Remap.app"),
            cli=Path("remap"),
            daemon=Path("remapd"),
            installer=Path("candidate"),
            resolver=Path("remap-resolver"),
            system_tool=Path("remap-system"),
            manpages=Path("manpages"),
            completions={},
            license=Path("LICENSE"),
            notice=Path("NOTICE"),
            signing_certificate_sha256="0" * 64,
        )
        build = remap_macos_install.NativeBuild(files=files, installer_cdhash="1" * 40)
        account = mock.Mock(pw_uid=501, pw_gid=20, pw_name="person")
        with (
            mock.patch("tools.remap_macos_install.require_macos"),
            mock.patch("tools.remap_macos_install.require_public_command_slot"),
            mock.patch("tools.remap_macos_install.native_user", return_value=account),
            mock.patch(
                "tools.remap_macos_install.build_native_products", return_value=build
            ),
            mock.patch(
                "tools.remap_macos_install.authorize_administrator"
            ) as administrator,
            mock.patch(
                "tools.remap_macos_install.bootstrap_helper",
                return_value=nullcontext(Path("bootstrap")),
            ),
            mock.patch(
                "tools.remap_macos_install._selected_helper",
                return_value=Path("helper"),
            ),
            mock.patch(
                "tools.remap_macos_install.helper_json", side_effect=helper_result
            ),
            mock.patch("tools.remap_macos_install._group_name", return_value="staff"),
            mock.patch(
                "tools.remap_macos_install._private_data_path",
                return_value=Path("data"),
            ),
            mock.patch("tools.remap_macos_install._ensure_private_data_directory"),
            mock.patch("tools.remap_macos_install.assemble", return_value=package),
            mock.patch(
                "tools.remap_macos_install._package_arguments",
                return_value=("--package-root", "/reviewed"),
            ),
            mock.patch("tools.remap_macos_install.verify_installed_product"),
            mock.patch("builtins.print"),
        ):
            remap_macos_install.install_or_update(Path("."), "0.1.1", "install")

        self.assertFalse(any(arguments[0] == "recover" for arguments in calls))
        mutation = next(arguments for arguments in calls if arguments[0] == "install")
        token_index = mutation.index("--approval-token")
        self.assertEqual(mutation[token_index + 1], token)
        administrator.assert_called_once_with(Path("."))

    def test_rejected_privileged_mutation_does_not_report_success(self) -> None:
        generation = "0.1.1-0123456789abcdef0123"
        package = NativePackage(
            root=Path("package"),
            payload=Path("package/payload"),
            manifest=Path("package/manifest.json"),
            manifest_digest="f" * 64,
            generation_id=generation,
        )
        preview = success(
            "preview",
            {
                "approvalToken": "e" * 64,
                "effects": ["publish the reviewed generation"],
                "generationID": generation,
                "operation": "install",
                "pendingRecoveryTransactions": [],
                "publicationChangeDetails": [],
                "publicationChanges": 0,
                "schemaVersion": 2,
            },
        )

        def helper_result(
            _root: Path, _helper: Path, arguments: tuple[str, ...]
        ) -> dict[str, object]:
            if arguments == ("status",):
                return status_result(None)
            if arguments == ("resolver-plan",):
                return success("resolver-plan", {"upstreams": ["192.0.2.53:53"]})
            if arguments[0:2] == ("preview", "install"):
                return preview
            if arguments[0] == "install":
                raise RuntimeError("approval rejected")
            raise AssertionError(f"unexpected helper arguments: {arguments}")

        files = mock.Mock(installer=Path("candidate"))
        build = remap_macos_install.NativeBuild(files=files, installer_cdhash="1" * 40)
        account = mock.Mock(pw_uid=501, pw_gid=20, pw_name="person")
        with (
            mock.patch("tools.remap_macos_install.require_macos"),
            mock.patch("tools.remap_macos_install.require_public_command_slot"),
            mock.patch("tools.remap_macos_install.native_user", return_value=account),
            mock.patch(
                "tools.remap_macos_install.build_native_products", return_value=build
            ),
            mock.patch(
                "tools.remap_macos_install.authorize_administrator",
            ),
            mock.patch(
                "tools.remap_macos_install.bootstrap_helper",
                return_value=nullcontext(Path("bootstrap")),
            ),
            mock.patch(
                "tools.remap_macos_install._selected_helper",
                return_value=Path("helper"),
            ),
            mock.patch(
                "tools.remap_macos_install.helper_json", side_effect=helper_result
            ),
            mock.patch("tools.remap_macos_install._group_name", return_value="staff"),
            mock.patch(
                "tools.remap_macos_install._private_data_path",
                return_value=Path("data"),
            ),
            mock.patch("tools.remap_macos_install.assemble", return_value=package),
            mock.patch(
                "tools.remap_macos_install._package_arguments",
                return_value=("--package-root", "/reviewed"),
            ),
            mock.patch(
                "tools.remap_macos_install._ensure_private_data_directory"
            ) as ensure,
            mock.patch("builtins.print"),
            self.assertRaisesRegex(RuntimeError, "approval rejected"),
        ):
            remap_macos_install.install_or_update(Path("."), "0.1.1", "install")

        ensure.assert_called_once()

    def test_recovery_has_its_own_preview_token_and_verifies_convergence(self) -> None:
        token = "9" * 64
        calls: list[tuple[str, ...]] = []
        previews = iter(
            (recovery_result(token, dirty=True), recovery_result(token, dirty=False))
        )
        bootstrap_previews = iter(
            (
                bootstrap_recovery_result(token, inactive=True),
                bootstrap_recovery_result(token, inactive=False),
            )
        )
        statuses = iter(
            (
                status_result("0.1.1-0123456789abcdef0123", recovery_required=True),
                status_result("0.1.1-0123456789abcdef0123"),
            )
        )

        def helper_result(
            _root: Path, _helper: Path, arguments: tuple[str, ...]
        ) -> dict[str, object]:
            calls.append(arguments)
            if arguments == ("status",):
                return next(statuses)
            if arguments == ("preview", "recover", "--all"):
                return next(previews)
            if arguments == ("preview", "recover-bootstrap-helpers"):
                return next(bootstrap_previews)
            if arguments[0] == "recover":
                return success("recover", {})
            if arguments[0] == "recover-bootstrap-helpers":
                return success("recover-bootstrap-helpers", {})
            raise AssertionError(f"unexpected helper arguments: {arguments}")

        with (
            mock.patch("tools.remap_macos_install.require_macos"),
            mock.patch(
                "tools.remap_macos_install.build_installer",
                return_value=(Path("candidate"), "1" * 40),
            ),
            mock.patch("tools.remap_macos_install.authorize_administrator"),
            mock.patch(
                "tools.remap_macos_install.bootstrap_helper",
                return_value=nullcontext(Path("bootstrap")),
            ),
            mock.patch(
                "tools.remap_macos_install._selected_helper",
                return_value=Path("helper"),
            ),
            mock.patch(
                "tools.remap_macos_install.helper_json", side_effect=helper_result
            ),
            mock.patch("builtins.print"),
        ):
            remap_macos_install.recover(Path("."))

        mutation = next(arguments for arguments in calls if arguments[0] == "recover")
        self.assertEqual(
            mutation,
            ("recover", "--all", "--approval-token", token),
        )
        bootstrap_mutation = next(
            arguments
            for arguments in calls
            if arguments[0] == "recover-bootstrap-helpers"
        )
        self.assertEqual(
            bootstrap_mutation,
            ("recover-bootstrap-helpers", "--approval-token", token),
        )

    def test_bootstrap_residue_recovery_runs_when_lifecycle_is_clean(self) -> None:
        token = "5" * 64
        calls: list[tuple[str, ...]] = []
        bootstrap_previews = iter(
            (
                bootstrap_recovery_result(token, inactive=True),
                bootstrap_recovery_result(token, inactive=False),
            )
        )

        def helper_result(
            _root: Path, _helper: Path, arguments: tuple[str, ...]
        ) -> dict[str, object]:
            calls.append(arguments)
            if arguments == ("status",):
                return status_result(None)
            if arguments == ("preview", "recover", "--all"):
                return recovery_result("4" * 64, dirty=False)
            if arguments == ("preview", "recover-bootstrap-helpers"):
                return next(bootstrap_previews)
            if arguments[0] == "recover-bootstrap-helpers":
                return success("recover-bootstrap-helpers", {})
            raise AssertionError(f"unexpected helper arguments: {arguments}")

        with (
            mock.patch("tools.remap_macos_install.require_macos"),
            mock.patch(
                "tools.remap_macos_install.build_installer",
                return_value=(Path("candidate"), "1" * 40),
            ),
            mock.patch(
                "tools.remap_macos_install.authorize_administrator"
            ) as administrator,
            mock.patch(
                "tools.remap_macos_install.bootstrap_helper",
                return_value=nullcontext(Path("bootstrap")),
            ),
            mock.patch(
                "tools.remap_macos_install._selected_helper",
                return_value=Path("helper"),
            ),
            mock.patch(
                "tools.remap_macos_install.helper_json", side_effect=helper_result
            ),
            mock.patch("builtins.print"),
        ):
            remap_macos_install.recover(Path("."))

        self.assertNotIn(("recover", "--all"), calls)
        administrator.assert_called_once_with(Path("."))
        self.assertIn(("recover-bootstrap-helpers", "--approval-token", token), calls)

    def test_product_recovery_cannot_invalidate_bootstrap_residue_recovery(
        self,
    ) -> None:
        token = "7" * 64
        installed_helper = Path("installed-helper")
        bootstrap = Path("bootstrap")
        installed_exists = True
        recovery_previews = iter(
            (recovery_result(token, dirty=True), recovery_result(token, dirty=False))
        )
        bootstrap_previews = iter(
            (
                bootstrap_recovery_result(token, inactive=True),
                bootstrap_recovery_result(token, inactive=False),
            )
        )

        def helper_result(
            _root: Path, helper: Path, arguments: tuple[str, ...]
        ) -> dict[str, object]:
            nonlocal installed_exists
            if helper == installed_helper and not installed_exists:
                raise RuntimeError("the installed recovery helper was purged")
            if arguments == ("status",):
                generation = "0.1.1-0123456789abcdef0123" if installed_exists else None
                return status_result(generation, recovery_required=installed_exists)
            if arguments == ("preview", "recover", "--all"):
                return next(recovery_previews)
            if arguments[0] == "recover":
                installed_exists = False
                return success("recover", {})
            if arguments == ("preview", "recover-bootstrap-helpers"):
                return next(bootstrap_previews)
            if arguments[0] == "recover-bootstrap-helpers":
                return success("recover-bootstrap-helpers", {})
            raise AssertionError(f"unexpected helper arguments: {arguments}")

        with (
            mock.patch("tools.remap_macos_install.require_macos"),
            mock.patch(
                "tools.remap_macos_install.build_installer",
                return_value=(Path("candidate"), "1" * 40),
            ),
            mock.patch("tools.remap_macos_install.authorize_administrator"),
            mock.patch(
                "tools.remap_macos_install.bootstrap_helper",
                return_value=nullcontext(bootstrap),
            ),
            mock.patch(
                "tools.remap_macos_install._selected_helper",
                return_value=installed_helper,
            ),
            mock.patch(
                "tools.remap_macos_install.helper_json", side_effect=helper_result
            ),
            mock.patch("builtins.print"),
        ):
            remap_macos_install.recover(Path("."))

        self.assertFalse(installed_exists)

    def test_uninstall_uses_native_restoration_proof_without_public_dns(self) -> None:
        generation = "0.1.1-0123456789abcdef0123"
        token = "6" * 64
        calls: list[tuple[str, ...]] = []
        statuses = iter((status_result(generation), status_result(None)))
        preview = success(
            "preview",
            {
                "approvalToken": token,
                "effects": ["restore the exact native resolver state"],
                "generationID": generation,
                "operation": "uninstall",
                "pendingRecoveryTransactions": [],
                "publicationChangeDetails": [],
                "publicationChanges": 0,
                "schemaVersion": 2,
            },
        )

        def helper_result(
            _root: Path, _helper: Path, arguments: tuple[str, ...]
        ) -> dict[str, object]:
            calls.append(arguments)
            if arguments == ("status",):
                return next(statuses)
            if arguments[0:2] == ("preview", "uninstall"):
                return preview
            if arguments[0] == "uninstall":
                return success("uninstall", {})
            raise AssertionError(f"unexpected helper arguments: {arguments}")

        with (
            mock.patch("tools.remap_macos_install.require_macos"),
            mock.patch(
                "tools.remap_macos_install.build_installer",
                return_value=(Path("candidate"), "1" * 40),
            ),
            mock.patch("tools.remap_macos_install.authorize_administrator"),
            mock.patch(
                "tools.remap_macos_install.bootstrap_helper",
                return_value=nullcontext(Path("bootstrap")),
            ),
            mock.patch(
                "tools.remap_macos_install._selected_helper",
                return_value=Path("helper"),
            ),
            mock.patch(
                "tools.remap_macos_install.helper_json", side_effect=helper_result
            ),
            mock.patch("tools.remap_macos_install.verify_uninstalled") as verified,
            mock.patch("socket.getaddrinfo") as public_dns,
            mock.patch("builtins.print"),
        ):
            remap_macos_install.uninstall(Path("."))

        verified.assert_called_once()
        public_dns.assert_not_called()
        mutation = next(arguments for arguments in calls if arguments[0] == "uninstall")
        self.assertIn(token, mutation)

    def test_shadowing_cli_is_rejected_before_native_mutation(self) -> None:
        with (
            mock.patch(
                "tools.remap_macos_install.shutil.which",
                return_value="/Users/person/.local/bin/remap\u001b",
            ),
            self.assertRaisesRegex(RuntimeError, "make uninstall-cli") as captured,
        ):
            require_public_command_slot()

        self.assertNotIn("\u001b", str(captured.exception))
        self.assertIn("\\u{001b}", str(captured.exception))

    def test_installed_asset_requires_exact_readable_bytes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="remap-installed-asset-") as directory:
            root = Path(directory)
            expected = root / "expected"
            installed = root / "installed"
            _ = expected.write_bytes(b"expected\n")
            _ = installed.write_bytes(b"expected\n")

            require_readable_exact(expected, installed)
            _ = installed.write_bytes(b"different\n")
            with self.assertRaisesRegex(RuntimeError, "differs from its build"):
                require_readable_exact(expected, installed)

    def test_uninstall_verification_rejects_every_owned_residue(self) -> None:
        status = InstallerStatus(
            active_generation_id=None,
            generation_count=0,
            pending_recovery_count=0,
            loaded_service_count=0,
            service_count=0,
            dns_active=False,
            effective_remap_service_count=0,
        )
        stale_resolver = InstallerStatus(
            active_generation_id=None,
            generation_count=0,
            pending_recovery_count=0,
            loaded_service_count=0,
            service_count=0,
            dns_active=False,
            effective_remap_service_count=1,
        )
        with self.assertRaisesRegex(RuntimeError, "active or recoverable system state"):
            verify_uninstalled(stale_resolver)
        with tempfile.TemporaryDirectory(prefix="remap-uninstall-proof-") as directory:
            root = Path(directory)
            public_directory = root / "share"
            public_directory.mkdir()
            with (
                mock.patch.object(
                    remap_macos_install, "SYSTEM_CLI", root / "bin/remap"
                ),
                mock.patch.object(
                    remap_macos_install, "SYSTEM_APP", root / "Remap.app"
                ),
                mock.patch.object(
                    remap_macos_install, "SYSTEM_MAN_DIRECTORY", root / "man"
                ),
                mock.patch.object(
                    remap_macos_install,
                    "SYSTEM_POLICY_DIRECTORY",
                    root / "licenses",
                ),
                mock.patch.object(
                    remap_macos_install,
                    "SYSTEM_COMPLETIONS",
                    {"bash": root / "completion"},
                ),
                mock.patch.object(
                    remap_macos_install,
                    "SYSTEM_PUBLIC_DIRECTORIES",
                    (public_directory,),
                ),
                mock.patch.object(
                    remap_macos_install, "INSTALL_ROOT", root / "private-install"
                ),
                mock.patch.object(remap_macos_install, "MANPAGE_NAMES", ("remap.1",)),
                mock.patch.object(
                    remap_macos_install,
                    "DAEMON_LABEL",
                    "org.agenxy.Remap.test-daemon",
                ),
                mock.patch.object(
                    remap_macos_install,
                    "RESOLVER_LABEL",
                    "org.agenxy.Remap.test-resolver",
                ),
            ):
                verify_uninstalled(status)
                candidate = root / "bin/remap"
                candidate.parent.mkdir()
                candidate.touch()
                with self.assertRaisesRegex(RuntimeError, "manifest-owned path"):
                    verify_uninstalled(status)
                candidate.unlink()
                marker = public_directory / ".remap-owned-directory"
                marker.touch()
                with self.assertRaisesRegex(RuntimeError, "directory ownership"):
                    verify_uninstalled(status)
                marker.unlink()
                (root / "private-install").mkdir()
                with self.assertRaisesRegex(RuntimeError, "installer topology"):
                    verify_uninstalled(status)


def success(command: str, data: dict[str, object]) -> dict[str, object]:
    return {
        "schemaVersion": 1,
        "ok": True,
        "command": command,
        "data": data,
    }


def status_result(
    active_generation: str | None, *, recovery_required: bool = False
) -> dict[str, object]:
    return success(
        "status",
        {
            "activeGenerationID": active_generation,
            "dns": {
                "active": active_generation is not None,
                "effectiveRemapServiceCount": 1 if active_generation is not None else 0,
            },
            "generations": [] if active_generation is None else [{}],
            "services": [] if active_generation is None else [{"loaded": True}] * 2,
            "transactions": ([{"recoveryRequired": True}] if recovery_required else []),
        },
    )


def recovery_result(token: str, *, dirty: bool) -> dict[str, object]:
    transaction = {
        "generationID": "0.1.1-0123456789abcdef0123",
        "journalHeadDigest": "8" * 64,
        "operation": "install",
        "phase": "dnsActive",
        "previousGenerationID": None,
        "recordCount": 4,
        "recoveryRequired": True,
        "transactionID": "install-1",
    }
    return success(
        "preview-recovery",
        {
            "approvalToken": token,
            "detachedGenerationNames": [],
            "effects": ["recover and collect transaction install-1"] if dirty else [],
            "orphanedStagingTransactionIDs": [],
            "requestedTransactionID": None,
            "schemaVersion": 1,
            "selectedTransactionIDs": ["install-1"] if dirty else [],
            "transactions": [transaction] if dirty else [],
        },
    )


def bootstrap_recovery_result(token: str, *, inactive: bool) -> dict[str, object]:
    path = "/Library/PrivilegedHelperTools/org.agenxy.Remap.install." + "a" * 32
    activity = "inactive" if inactive else "active"
    effect = f"remove inactive orphan bootstrap helper {path}"
    return success(
        "preview-bootstrap-recovery",
        {
            "approvalToken": token,
            "candidates": [
                {
                    "activity": activity,
                    "byteCount": 1_048_576,
                    "cdHash": "6" * 40,
                    "codeIdentifier": "org.agenxy.Remap.install-bootstrap",
                    "codeValidity": "verified",
                    "extendedAttributeNames": [],
                    "fileIdentity": {"deviceID": 1, "fileID": 2},
                    "flags": 0,
                    "groupGID": 0,
                    "linkCount": 1,
                    "mode": 0o555,
                    "ownerUID": 0,
                    "path": path,
                    "sha256": "5" * 64,
                }
            ],
            "effects": [effect] if inactive else [],
            "schemaVersion": 3,
            "stagingCandidates": [],
        },
    )


class TerminalInput(io.StringIO):
    """In-memory approval input that models a real interactive terminal."""

    @override
    def isatty(self) -> bool:
        return True


if __name__ == "__main__":
    _ = unittest.main()
