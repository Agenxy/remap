"""Linux source-lifecycle protocol and orchestration contracts."""

from __future__ import annotations

import copy
import io
import json
import subprocess
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from typing import cast
from unittest import mock

from tools import remap_linux_install
from tools.remap_lifecycle_approval import confirm_approval
from tools.remap_linux_bootstrap import FileIdentity, TrustedHelper
from tools.remap_linux_install import (
    LinuxBuild,
    NativeAccount,
    configured_link,
)
from tools.remap_linux_protocol import (
    LinkCandidate,
    LinuxStatus,
    approval_token,
    helper_error,
    installed_publication_paths,
    lifecycle_status,
    preview_has_effects,
    preview_identity,
    recovery_has_effects,
    removed_publication_paths,
    render_preview,
    render_recovery_preview,
    render_status,
    source_manifest_sha256,
)
from tools.remap_linux_sources import PinnedSourceManifest

GENERATION = "01234567-89ab-4cde-8fab-0123456789ab"
PREVIOUS = "fedcba98-7654-4321-8fed-ba9876543210"
TOKEN = "a" * 64
SOURCE_DIGEST = "c" * 64


class LinuxLifecycleProtocolTests(unittest.TestCase):
    """Reject incomplete, unsafe, or inconsistent native helper documents."""

    def test_status_preserves_typed_link_backend_and_recovery_facts(self) -> None:
        status = lifecycle_status(status_document())

        self.assertEqual(status.active_generation_id, GENERATION)
        self.assertEqual(status.previous_generation_id, PREVIOUS)
        self.assertEqual(status.link_index, 2)
        self.assertEqual(status.owner_uid, 501)
        self.assertEqual(status.backend, "network_manager")
        self.assertEqual(status.interface_name, "enp0s1")
        self.assertEqual(
            status.link_candidates,
            (LinkCandidate(2, "enp0s1", "network_manager", "supported_primary"),),
        )
        rendered = render_status(status)
        self.assertIn("ubuntu 24.04", rendered)
        self.assertIn("systemd_resolved", rendered)
        self.assertIn("2 (enp0s1, network_manager, supported_primary)", rendered)
        self.assertIn("Verified interrupted lifecycle state: none", rendered)

    def test_helper_error_rejects_unknown_v1_fields(self) -> None:
        document: dict[str, object] = {
            "command": "status",
            "error": {
                "category": "permission_denied",
                "hint": "request authorization",
                "message": "root is required",
            },
            "ok": False,
            "schemaVersion": 1,
        }
        encoded = json.dumps(document).encode()
        self.assertIn("permission_denied", helper_error(encoded, 1))
        document["unknown"] = True
        self.assertIn(
            "no valid diagnostic", helper_error(json.dumps(document).encode(), 1)
        )

    def test_inspect_renders_required_typed_state_residue(self) -> None:
        document = status_document(active=False)
        document["command"] = "inspect"
        data = payload(document)
        data["installationState"] = "recovery_required"
        data["recoveryRequired"] = True
        data["stateResidue"] = copy.deepcopy(state_payload(state_recovery_document()))

        status = lifecycle_status(document, "inspect")
        rendered = render_status(status)

        self.assertTrue(status.recovery_required)
        self.assertIn("/var/lib/remap-system/.installation.new", rendered)
        self.assertIn(f"SHA-256 {bytes(range(32)).hex()}", rendered)

        data["unknown"] = True
        with self.assertRaisesRegex(RuntimeError, "incompatible inspect status"):
            _ = lifecycle_status(document, "inspect")

    def test_preview_renders_every_publication_and_escapes_controls(self) -> None:
        document = preview_document()

        rendered = render_preview(document)

        self.assertIn("Linux install preview", rendered)
        self.assertIn(f"Generation: {GENERATION}", rendered)
        self.assertIn("Link: 2 (enp0s1)", rendered)
        self.assertIn("create /usr/bin/remap", rendered)
        self.assertIn("activate\\u{001b}resolver", rendered)
        self.assertIn(f"Reviewed source manifest SHA-256: {SOURCE_DIGEST}", rendered)
        self.assertIn(TOKEN, rendered)
        self.assertNotIn("\u001b", rendered)
        self.assertTrue(preview_has_effects(document))
        self.assertEqual(approval_token(document, "preview"), TOKEN)
        self.assertEqual(source_manifest_sha256(document), SOURCE_DIGEST)
        self.assertEqual(installed_publication_paths(document), ("/usr/bin/remap",))
        self.assertEqual(removed_publication_paths(document), ())

    def test_preview_rejects_path_escape_and_state_mismatch(self) -> None:
        for path in ("/usr/../tmp/remap", "/usr//bin/remap", "/usr/bin/remap/"):
            invalid = preview_document()
            data = payload(invalid)
            data["publications"] = [
                {
                    "action": "create",
                    "nextGenerationID": GENERATION,
                    "path": path,
                    "previousGenerationID": None,
                }
            ]

            with (
                self.subTest(path=path),
                self.assertRaisesRegex(RuntimeError, "unsafe publication"),
            ):
                _ = render_preview(invalid)

        mismatch = preview_document()
        payload(mismatch)["hasEffects"] = False
        with self.assertRaisesRegex(RuntimeError, "invalid lifecycle preview"):
            _ = render_preview(mismatch)

    def test_preview_rejects_unknown_envelope_data_and_nested_fields(self) -> None:
        malformed: list[dict[str, object]] = []
        envelope = preview_document()
        envelope["unknown"] = True
        malformed.append(envelope)
        data = preview_document()
        payload(data)["unknown"] = True
        malformed.append(data)
        publication = preview_document()
        raw_publications = payload(publication).get("publications")
        self.assertIsInstance(raw_publications, list)
        publication_values = cast("list[object]", raw_publications)
        self.assertIsInstance(publication_values[0], dict)
        publication_fields = cast("dict[str, object]", publication_values[0])
        publication_fields["unknown"] = True
        malformed.append(publication)

        for document in malformed:
            with (
                self.subTest(document=document),
                self.assertRaisesRegex(RuntimeError, "incompatible"),
            ):
                _ = render_preview(document)

        self.assertEqual(preview_identity(preview_document()), (GENERATION, 2))

    def test_uninstall_and_empty_recovery_use_nullable_generation(self) -> None:
        uninstall = preview_document(operation="uninstall")
        uninstall_data = payload(uninstall)
        uninstall_data["generationID"] = None
        uninstall_data["publications"] = [
            {
                "action": "remove",
                "nextGenerationID": None,
                "path": "/usr/bin/remap",
                "previousGenerationID": GENERATION,
            }
        ]
        self.assertIn("Generation: none", render_preview(uninstall))
        self.assertIsNone(source_manifest_sha256(uninstall))
        self.assertEqual(removed_publication_paths(uninstall), ("/usr/bin/remap",))

        recovery = success(
            "preview-recovery",
            {
                "approvalToken": TOKEN,
                "bootstrapResidues": [],
                "effects": [],
                "generationID": None,
                "hasEffects": False,
                "installationPhase": None,
                "schemaVersion": 1,
                "stateResidue": None,
            },
        )
        self.assertIn("Installation phase: none", render_recovery_preview(recovery))
        self.assertFalse(recovery_has_effects(recovery))

    def test_recovery_renders_complete_typed_bootstrap_identity(self) -> None:
        residue = bootstrap_residue("a")
        document = recovery_document([residue])

        rendered = render_recovery_preview(document)

        self.assertIn("Verified bootstrap crash residues: 1", rendered)
        self.assertIn(f"/run/remap-bootstrap-{'a' * 32}", rendered)
        self.assertIn("mode 0711, owner 0:0", rendered)
        self.assertIn("mode 0555, owner 0:0, links 1, bytes 4096", rendered)
        self.assertIn(f"Helper SHA-256: {'d' * 64}", rendered)
        self.assertIn(f"SHA-256 {bytes(range(32)).hex()}", rendered)
        self.assertTrue(recovery_has_effects(document))

        empty = bootstrap_residue("b")
        empty["helper"] = None
        empty_rendered = render_recovery_preview(recovery_document([empty]))
        self.assertIn("Helper: none (verified empty crash directory)", empty_rendered)

    def test_recovery_rejects_unknown_duplicate_unordered_or_mismatched_residue(
        self,
    ) -> None:
        first = bootstrap_residue("a")
        second = bootstrap_residue("b")
        malformed: list[dict[str, object]] = []

        unknown = copy.deepcopy(first)
        directory_payload(unknown)["unknown"] = True
        malformed.append(recovery_document([unknown]))

        mismatched = copy.deepcopy(first)
        helper_payload(mismatched)["path"] = "/run/remap-bootstrap-" + "f" * 32
        malformed.append(recovery_document([mismatched]))

        unsafe_mode = copy.deepcopy(first)
        directory_payload(unsafe_mode)["mode"] = 0o777
        malformed.append(recovery_document([unsafe_mode]))

        bad_digest = copy.deepcopy(first)
        xattr_payload(directory_payload(bad_digest))["digest"] = [0] * 31
        malformed.append(recovery_document([bad_digest]))

        mismatched_effect = recovery_document([copy.deepcopy(first)])
        payload(mismatched_effect)["effects"] = ["remove some different bootstrap path"]
        malformed.append(mismatched_effect)

        malformed.append(recovery_document([first, first]))
        malformed.append(recovery_document([second, first]))

        for document in malformed:
            with (
                self.subTest(document=document),
                self.assertRaises((RuntimeError, TypeError)),
            ):
                _ = render_recovery_preview(document)

    def test_recovery_renders_and_strictly_validates_lifecycle_state_residue(
        self,
    ) -> None:
        document = state_recovery_document()
        rendered = render_recovery_preview(document)

        self.assertIn("Verified interrupted lifecycle state:", rendered)
        self.assertIn("Directory: /var/lib/remap-system", rendered)
        self.assertIn("Remove directory: no", rendered)
        self.assertIn(".installation.new, bytes 19", rendered)
        self.assertIn(f"SHA-256 {bytes(range(32)).hex()}", rendered)

        malformed: list[dict[str, object]] = []
        unknown = state_recovery_document()
        state_payload(unknown)["unknown"] = True
        malformed.append(unknown)

        unsafe_path = state_recovery_document()
        state_entry_payload(unsafe_path)["path"] = "/var/lib/remap-system/../owned"
        malformed.append(unsafe_path)

        empty = state_recovery_document()
        state = state_payload(empty)
        state["entries"] = []
        state["removeDirectory"] = False
        malformed.append(empty)

        for invalid in malformed:
            with (
                self.subTest(document=invalid),
                self.assertRaises((RuntimeError, TypeError)),
            ):
                _ = render_recovery_preview(invalid)

    def test_link_selection_error_lists_only_native_candidates(self) -> None:
        status = LinuxStatus(
            active_generation_id=None,
            previous_generation_id=None,
            link_index=None,
            owner_uid=None,
            recovery_required=False,
            installation_state="absent",
            backend=None,
            interface_name=None,
            link_candidates=(
                LinkCandidate(7, "wlan0", "network_manager", "supported_primary"),
                LinkCandidate(8, "eth0", "systemd_networkd", "supported_primary"),
            ),
            hint="Select one listed interface index.",
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        with (
            mock.patch.dict("tools.remap_linux_install.os.environ", {}, clear=True),
            self.assertRaisesRegex(
                RuntimeError, r"7 \(wlan0, network_manager, supported_primary\)"
            ),
        ):
            _ = configured_link(status)

    def test_only_one_proven_primary_link_is_selected_automatically(self) -> None:
        status = lifecycle_status(status_document(active=False))
        with mock.patch.dict("tools.remap_linux_install.os.environ", {}, clear=True):
            self.assertEqual(configured_link(status), 2)


class LinuxLifecycleOrchestratorTests(unittest.TestCase):
    """Keep approval and recovery authority inside the native helper."""

    def test_noninteractive_approval_requires_the_complete_native_token(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "No Remap product state changed"):
            _ = confirm_approval(
                TOKEN,
                "install",
                input_stream=io.StringIO(f"approve {TOKEN[:12]}\n"),
                output_stream=io.StringIO(),
            )
        approved = confirm_approval(
            TOKEN,
            "install",
            input_stream=io.StringIO(f"{TOKEN}\n"),
            output_stream=io.StringIO(),
        )
        self.assertEqual(approved, TOKEN)

    def test_shadowing_cli_blocks_before_native_build_or_authorization(self) -> None:
        with (
            mock.patch(
                "tools.remap_linux_install.shutil.which",
                return_value="/home/person/.local/bin/remap",
            ),
            self.assertRaisesRegex(RuntimeError, "make uninstall-cli"),
        ):
            remap_linux_install.require_public_command_slot()

    def test_user_writable_helper_path_is_never_executed_with_sudo(self) -> None:
        with (
            mock.patch("tools.remap_linux_install.subprocess.run") as run,
            self.assertRaisesRegex(TypeError, "pinned trusted helper"),
        ):
            _ = remap_linux_install.helper_json(
                Path("."), Path("/tmp/user-controlled-helper"), ("status",)
            )

        run.assert_not_called()

    def test_pinned_root_helper_is_the_only_sudo_execution_target(self) -> None:
        helper = TrustedHelper(
            path=Path("/run/remap-bootstrap-safe/remap-linux-system"),
            identity=file_identity(),
        )
        completed = subprocess.CompletedProcess[bytes](args=(), returncode=0)
        with (
            mock.patch(
                "tools.remap_linux_install.open_verified_helper",
                return_value=nullcontext(7),
            ),
            mock.patch("tools.remap_linux_install.verify_pinned_helper"),
            mock.patch(
                "tools.remap_linux_install.subprocess.run", return_value=completed
            ) as run,
            mock.patch(
                "tools.remap_linux_install.decode_document",
                return_value=status_document(active=False),
            ),
        ):
            _ = remap_linux_install.helper_json(Path("."), helper, ("status",))

        call = run.call_args
        self.assertIsNotNone(call)
        command = cast("tuple[str, ...]", call.args[0])
        self.assertEqual(command[0:4], ("/usr/bin/sudo", "-n", "--", str(helper.path)))
        self.assertNotIn("/tmp", command)

    def test_helper_drift_after_sudo_is_rejected_before_output_is_trusted(self) -> None:
        helper = TrustedHelper(
            path=Path("/run/remap-bootstrap-safe/remap-linux-system"),
            identity=file_identity(),
        )
        completed = subprocess.CompletedProcess[bytes](args=(), returncode=0)
        with (
            mock.patch(
                "tools.remap_linux_install.open_verified_helper",
                return_value=nullcontext(7),
            ),
            mock.patch(
                "tools.remap_linux_install.verify_pinned_helper",
                side_effect=RuntimeError("helper changed during execution"),
            ),
            mock.patch(
                "tools.remap_linux_install.subprocess.run", return_value=completed
            ) as run,
            mock.patch("tools.remap_linux_install.decode_document") as decode,
            self.assertRaisesRegex(RuntimeError, "changed during execution"),
        ):
            _ = remap_linux_install.helper_json(Path("."), helper, ("status",))

        run.assert_called_once()
        decode.assert_not_called()

    def test_helper_timeout_reports_unknown_outcome_and_requires_recovery(self) -> None:
        helper = TrustedHelper(
            path=Path("/run/remap-bootstrap-safe/remap-linux-system"),
            identity=file_identity(),
        )
        timeout = subprocess.TimeoutExpired(str(helper.path), 120)
        with (
            mock.patch(
                "tools.remap_linux_install.open_verified_helper",
                return_value=nullcontext(7),
            ),
            mock.patch("tools.remap_linux_install.subprocess.run", side_effect=timeout),
            mock.patch("tools.remap_linux_install.verify_pinned_helper") as verify,
            mock.patch("tools.remap_linux_install.decode_document") as decode,
            self.assertRaisesRegex(RuntimeError, "outcome is unknown.*make recover"),
        ):
            _ = remap_linux_install.helper_json(Path("."), helper, ("status",))

        verify.assert_not_called()
        decode.assert_not_called()

    def test_install_carries_exact_token_without_implicit_recovery(self) -> None:
        status = LinuxStatus(
            active_generation_id=None,
            previous_generation_id=None,
            link_index=None,
            owner_uid=None,
            recovery_required=False,
            installation_state="absent",
            backend=None,
            interface_name=None,
            link_candidates=(
                LinkCandidate(2, "enp0s1", "network_manager", "supported_primary"),
            ),
            hint=None,
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        final = LinuxStatus(
            active_generation_id=GENERATION,
            previous_generation_id=None,
            link_index=2,
            owner_uid=501,
            recovery_required=False,
            installation_state="active",
            backend="network_manager",
            interface_name="enp0s1",
            link_candidates=(
                LinkCandidate(2, "enp0s1", "network_manager", "supported_primary"),
            ),
            hint=None,
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        build = LinuxBuild(
            cli=Path("remap"),
            daemon=Path("remapd"),
            helper=Path("remap-linux-system"),
            assets=Path("assets"),
        )
        calls: list[tuple[str, ...]] = []

        def exchange(
            _root: Path,
            _helper: object,
            arguments: tuple[str, ...],
            *,
            source_manifest: object | None = None,
        ) -> dict[str, object]:
            del source_manifest
            calls.append(arguments)
            if arguments == ("status",):
                return (
                    status_document(active=False)
                    if len(calls) == 1
                    else status_document()
                )
            if arguments[0:2] == ("preview", "install"):
                return preview_document()
            if arguments[0] == "install":
                return success("install", {"schemaVersion": 1})
            raise AssertionError(arguments)

        with (
            mock.patch("tools.remap_linux_install.require_linux_bootstrap"),
            mock.patch("tools.remap_linux_install.require_public_command_slot"),
            mock.patch(
                "tools.remap_linux_install.native_account",
                return_value=NativeAccount("person", "people", 501),
            ),
            mock.patch(
                "tools.remap_linux_install.build_native_products", return_value=build
            ),
            mock.patch("tools.remap_linux_install.authorize_administrator"),
            mock.patch(
                "tools.remap_linux_install.pin_source_manifest",
                return_value=nullcontext(PinnedSourceManifest((), SOURCE_DIGEST)),
            ),
            mock.patch(
                "tools.remap_linux_install.bootstrap_helper",
                return_value=nullcontext(build.helper),
            ),
            mock.patch("tools.remap_linux_install.lifecycle_status") as decode_status,
            mock.patch("tools.remap_linux_install._operation_link", return_value=2),
            mock.patch(
                "tools.remap_linux_install._install_arguments",
                return_value=("--link", "2"),
            ),
            mock.patch("tools.remap_linux_install.helper_json", side_effect=exchange),
            mock.patch(
                "tools.remap_linux_install.confirm_approval", return_value=TOKEN
            ),
            mock.patch("tools.remap_linux_install.verify_installed_product"),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            decode_status.side_effect = (status, final, final)
            remap_linux_install.install_or_update(Path("."), "0.1.1", "install")

        mutation = next(arguments for arguments in calls if arguments[0] == "install")
        self.assertEqual(mutation[-2:], ("--approval-token", TOKEN))
        self.assertFalse(any(arguments[0] == "recover" for arguments in calls))

    def test_no_op_rechecks_native_identity_without_approval_or_commit(self) -> None:
        build = LinuxBuild(
            Path("remap"), Path("remapd"), Path("helper"), Path("assets")
        )
        preview = preview_document()
        preview_data = payload(preview)
        preview_data["effects"] = []
        preview_data["hasEffects"] = False
        preview_data["publications"] = []
        exchanges = iter((status_document(active=False), preview, status_document()))

        def exchange_result(
            _root: Path,
            _helper: object,
            _arguments: tuple[str, ...],
            *,
            source_manifest: object | None = None,
        ) -> dict[str, object]:
            del source_manifest
            return next(exchanges)

        with (
            mock.patch("tools.remap_linux_install.require_linux_bootstrap"),
            mock.patch("tools.remap_linux_install.require_public_command_slot"),
            mock.patch(
                "tools.remap_linux_install.native_account",
                return_value=NativeAccount("person", "people", 501),
            ),
            mock.patch(
                "tools.remap_linux_install.build_native_products", return_value=build
            ),
            mock.patch("tools.remap_linux_install.authorize_administrator"),
            mock.patch(
                "tools.remap_linux_install.pin_source_manifest",
                return_value=nullcontext(PinnedSourceManifest((), SOURCE_DIGEST)),
            ),
            mock.patch(
                "tools.remap_linux_install.bootstrap_helper",
                return_value=nullcontext(build.helper),
            ),
            mock.patch("tools.remap_linux_install._install_arguments", return_value=()),
            mock.patch(
                "tools.remap_linux_install.helper_json",
                side_effect=exchange_result,
            ) as exchange,
            mock.patch("tools.remap_linux_install.confirm_approval") as approval,
            mock.patch("tools.remap_linux_install.verify_installed_product") as verify,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            remap_linux_install.install_or_update(Path("."), "0.1.1", "install")

        self.assertEqual(exchange.call_count, 3)
        approval.assert_not_called()
        verify.assert_called_once()

    def test_pending_recovery_blocks_before_preview_or_mutation(self) -> None:
        dirty = LinuxStatus(
            active_generation_id=GENERATION,
            previous_generation_id=None,
            link_index=2,
            owner_uid=501,
            recovery_required=True,
            installation_state="recovery_required",
            backend="systemd_networkd",
            interface_name="eth0",
            link_candidates=(),
            hint="Run make recover.",
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        build = LinuxBuild(
            Path("remap"), Path("remapd"), Path("helper"), Path("assets")
        )
        with (
            mock.patch("tools.remap_linux_install.require_linux_bootstrap"),
            mock.patch("tools.remap_linux_install.require_public_command_slot"),
            mock.patch(
                "tools.remap_linux_install.native_account",
                return_value=NativeAccount("person", "people", 501),
            ),
            mock.patch(
                "tools.remap_linux_install.build_native_products", return_value=build
            ),
            mock.patch("tools.remap_linux_install.authorize_administrator"),
            mock.patch(
                "tools.remap_linux_install.pin_source_manifest",
                return_value=nullcontext(PinnedSourceManifest((), SOURCE_DIGEST)),
            ),
            mock.patch(
                "tools.remap_linux_install.bootstrap_helper",
                return_value=nullcontext(build.helper),
            ),
            mock.patch("tools.remap_linux_install.helper_json") as exchange,
            mock.patch(
                "tools.remap_linux_install.lifecycle_status", return_value=dirty
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO),
            self.assertRaisesRegex(RuntimeError, "make recover"),
        ):
            exchange.return_value = success("status", {})
            remap_linux_install.install_or_update(Path("."), "0.1.1", "update")

        self.assertEqual(exchange.call_count, 1)

    def test_recover_commits_the_exact_typed_residue_approval(self) -> None:
        dirty = LinuxStatus(
            active_generation_id=None,
            previous_generation_id=None,
            link_index=None,
            owner_uid=None,
            recovery_required=True,
            installation_state="recovery_required",
            backend=None,
            interface_name=None,
            link_candidates=(),
            hint="Review and recover the verified bootstrap residue.",
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        clean = LinuxStatus(
            active_generation_id=None,
            previous_generation_id=None,
            link_index=None,
            owner_uid=None,
            recovery_required=False,
            installation_state="absent",
            backend=None,
            interface_name=None,
            link_candidates=(),
            hint=None,
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        helper = TrustedHelper(Path("/run/reviewed-helper"), file_identity())
        calls: list[tuple[str, ...]] = []

        def exchange(
            _root: Path,
            _helper: object,
            arguments: tuple[str, ...],
            *,
            source_manifest: object | None = None,
        ) -> dict[str, object]:
            del source_manifest
            self.assertIs(_helper, helper)
            calls.append(arguments)
            if arguments == ("status",):
                return success("status", {})
            if arguments == ("preview", "recover", "--all"):
                return recovery_document([bootstrap_residue("a")])
            if arguments == ("recover", "--all", "--approval-token", TOKEN):
                return success("recover", {})
            raise AssertionError(arguments)

        with (
            mock.patch("tools.remap_linux_install.require_linux_bootstrap"),
            mock.patch(
                "tools.remap_linux_install.build_native_helper",
                return_value=Path("helper-source"),
            ),
            mock.patch("tools.remap_linux_install.authorize_administrator"),
            mock.patch(
                "tools.remap_linux_install.native_account",
                return_value=NativeAccount("person", "people", 501),
            ),
            mock.patch(
                "tools.remap_linux_install.bootstrap_helper",
                return_value=nullcontext(helper),
            ),
            mock.patch("tools.remap_linux_install.helper_json", side_effect=exchange),
            mock.patch(
                "tools.remap_linux_install.lifecycle_status",
                side_effect=(dirty, clean, clean),
            ),
            mock.patch(
                "tools.remap_linux_install.confirm_approval", return_value=TOKEN
            ),
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            remap_linux_install.recover(Path("."))

        self.assertIn(("preview", "recover", "--all"), calls)
        self.assertIn(("recover", "--all", "--approval-token", TOKEN), calls)

    def test_installed_doctor_requires_complete_authenticated_runtime(self) -> None:
        document: dict[str, object] = {
            "command": "doctor",
            "ok": True,
            "result": {
                "dns_listener": True,
                "http_gateway": True,
                "native_install": True,
                "revision": 3,
                "telemetry": "none",
                "version": "0.1.1",
            },
            "schema": "remap.cli/v1",
        }

        remap_linux_install.verify_doctor(document, "0.1.1")
        result = payload_result(document)
        result["dns_listener"] = False
        with self.assertRaisesRegex(RuntimeError, "full readiness"):
            remap_linux_install.verify_doctor(document, "0.1.1")

    def test_uninstall_verification_rejects_owned_directory_residue(self) -> None:
        status = LinuxStatus(
            active_generation_id=None,
            previous_generation_id=None,
            link_index=None,
            owner_uid=None,
            recovery_required=False,
            installation_state="absent",
            backend=None,
            interface_name=None,
            link_candidates=(),
            hint=None,
            distribution_id="ubuntu",
            distribution_version="24.04",
            resolver_environment="systemd_resolved_supported",
        )
        with tempfile.TemporaryDirectory(prefix="remap-linux-uninstall-") as directory:
            root = Path(directory)
            product = root / "libexec/remap"
            policy = root / "share/doc/remap"
            with (
                mock.patch.object(
                    remap_linux_install, "SYSTEM_CLI", root / "bin/remap"
                ),
                mock.patch.object(
                    remap_linux_install, "SYSTEM_CURRENT", product / "current"
                ),
                mock.patch.object(
                    remap_linux_install,
                    "SYSTEM_GENERATION_ROOT",
                    product / "generations",
                ),
                mock.patch.object(remap_linux_install, "SYSTEM_PRODUCT_ROOT", product),
                mock.patch.object(remap_linux_install, "SYSTEM_STATE", root / "state"),
                mock.patch.object(
                    remap_linux_install, "SYSTEM_POLICY_DIRECTORY", policy
                ),
                mock.patch.object(
                    remap_linux_install, "SYSTEM_MAN_DIRECTORY", root / "man"
                ),
                mock.patch.object(
                    remap_linux_install,
                    "SYSTEM_COMPLETIONS",
                    cast("dict[str, Path]", {}),
                ),
                mock.patch.object(remap_linux_install, "SYSTEM_UNITS", ()),
                mock.patch.object(remap_linux_install, "MANPAGE_NAMES", ("remap.1",)),
            ):
                remap_linux_install.verify_uninstalled(status)
                for residue in (product, policy):
                    with self.subTest(residue=residue):
                        residue.mkdir(parents=True)
                        with self.assertRaisesRegex(RuntimeError, "owned path"):
                            remap_linux_install.verify_uninstalled(status)
                        residue.rmdir()


def status_document(*, active: bool = True) -> dict[str, object]:
    return success(
        "status",
        {
            "activeGenerationID": GENERATION if active else None,
            "backend": "network_manager" if active else None,
            "distribution": {"id": "ubuntu", "versionID": "24.04"},
            "hint": None,
            "installationState": "active" if active else "absent",
            "interfaceName": "enp0s1" if active else None,
            "linkCandidates": [
                {
                    "backend": "network_manager",
                    "interfaceName": "enp0s1",
                    "linkIndex": 2,
                    "selectionState": "supported_primary",
                }
            ],
            "linkIndex": 2 if active else None,
            "ownerUID": 501 if active else None,
            "previousGenerationID": PREVIOUS if active else None,
            "recoveryRequired": False,
            "resolverEnvironment": "systemd_resolved",
            "schemaVersion": 1,
            "services": [
                {"state": "active", "unit": "remap-resolver.service"},
                {"state": "active", "unit": "remapd.service"},
            ],
            "stateResidue": None,
        },
    )


def preview_document(*, operation: str = "install") -> dict[str, object]:
    return success(
        "preview",
        {
            "approvalToken": TOKEN,
            "backend": "network_manager",
            "effects": ["activate\u001bresolver"],
            "generationID": GENERATION,
            "hasEffects": True,
            "interfaceName": "enp0s1",
            "linkIndex": 2,
            "operation": operation,
            "previousGenerationID": None,
            "publications": [
                {
                    "action": "create",
                    "nextGenerationID": GENERATION,
                    "path": "/usr/bin/remap",
                    "previousGenerationID": None,
                }
            ],
            "resolverEnvironment": "systemd_resolved",
            "schemaVersion": 1,
            "sourceManifestSHA256": SOURCE_DIGEST if operation != "uninstall" else None,
        },
    )


def recovery_document(residues: list[dict[str, object]]) -> dict[str, object]:
    effects: list[str] = []
    for residue in residues:
        raw_helper = residue.get("helper")
        if isinstance(raw_helper, dict):
            helper = cast("dict[str, object]", raw_helper)
            effects.append("remove verified bootstrap helper " + str(helper["path"]))
        effects.append(
            "remove verified bootstrap directory "
            + str(directory_payload(residue)["path"])
        )
    return success(
        "preview-recovery",
        {
            "approvalToken": TOKEN,
            "bootstrapResidues": residues,
            "effects": effects,
            "generationID": None,
            "hasEffects": bool(effects),
            "installationPhase": None,
            "schemaVersion": 1,
            "stateResidue": None,
        },
    )


def state_recovery_document() -> dict[str, object]:
    document = recovery_document([])
    data = payload(document)
    data["stateResidue"] = {
        "directory": "/var/lib/remap-system",
        "entries": [
            {
                "byteLength": 19,
                "digest": list(range(32)),
                "path": "/var/lib/remap-system/.installation.new",
            }
        ],
        "removeDirectory": False,
    }
    data["effects"] = [
        "remove verified interrupted lifecycle state from /var/lib/remap-system"
    ]
    data["hasEffects"] = True
    return document


def bootstrap_residue(suffix: str) -> dict[str, object]:
    directory = f"/run/remap-bootstrap-{suffix * 32}"
    xattr = {
        "byteLength": 32,
        "digest": list(range(32)),
        "name": "security.selinux",
    }
    return {
        "directory": {
            "device": 7,
            "inode": 11,
            "mode": 0o711,
            "ownerGid": 0,
            "ownerUid": 0,
            "path": directory,
            "xattrs": [xattr],
        },
        "helper": {
            "byteLength": 4096,
            "device": 7,
            "inode": 12,
            "links": 1,
            "mode": 0o555,
            "ownerGid": 0,
            "ownerUid": 0,
            "path": f"{directory}/remap-linux-system",
            "sha256": "d" * 64,
            "xattrs": [],
        },
    }


def directory_payload(residue: dict[str, object]) -> dict[str, object]:
    directory = residue["directory"]
    if not isinstance(directory, dict):
        raise TypeError
    return cast("dict[str, object]", directory)


def helper_payload(residue: dict[str, object]) -> dict[str, object]:
    helper = residue["helper"]
    if not isinstance(helper, dict):
        raise TypeError
    return cast("dict[str, object]", helper)


def xattr_payload(directory: dict[str, object]) -> dict[str, object]:
    xattrs = directory["xattrs"]
    if not isinstance(xattrs, list) or not xattrs or not isinstance(xattrs[0], dict):
        raise TypeError
    return cast("dict[str, object]", xattrs[0])


def state_payload(document: dict[str, object]) -> dict[str, object]:
    state = payload(document)["stateResidue"]
    if not isinstance(state, dict):
        raise TypeError
    return cast("dict[str, object]", state)


def state_entry_payload(document: dict[str, object]) -> dict[str, object]:
    entries = state_payload(document)["entries"]
    if not isinstance(entries, list) or not entries or not isinstance(entries[0], dict):
        raise TypeError
    return cast("dict[str, object]", entries[0])


def success(command: str, data: dict[str, object]) -> dict[str, object]:
    return {"command": command, "data": data, "ok": True, "schemaVersion": 1}


def payload(document: dict[str, object]) -> dict[str, object]:
    value = document["data"]
    if not isinstance(value, dict):
        raise TypeError
    return cast("dict[str, object]", value)


def payload_result(document: dict[str, object]) -> dict[str, object]:
    value = document["result"]
    if not isinstance(value, dict):
        raise TypeError
    return cast("dict[str, object]", value)


def file_identity() -> FileIdentity:
    return FileIdentity(
        device=1,
        inode=2,
        mode=0o555,
        owner_uid=0,
        owner_gid=0,
        links=1,
        size=1024,
        modified_ns=3,
        changed_ns=4,
        digest="b" * 64,
        xattrs=(),
    )


if __name__ == "__main__":
    _ = unittest.main()
