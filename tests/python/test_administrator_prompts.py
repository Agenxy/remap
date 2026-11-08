# SPDX-License-Identifier: GPL-3.0-or-later
"""sudo says who is asking for an administrator password and what it approves."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path
from unittest import mock

from tools import (
    remap_linux_bootstrap,
    remap_linux_install,
    remap_macos_verified_package_install,
)
from tools.remap_lifecycle_approval import (
    ADMINISTRATOR_PURPOSES,
    SUDO,
    administrator_command,
    administrator_prompt,
)


class AdministratorPromptTests(unittest.TestCase):
    def test_each_prompt_names_remap_its_purpose_and_the_account(self) -> None:
        for operation, purpose in ADMINISTRATOR_PURPOSES.items():
            with self.subTest(operation=operation):
                prompt = administrator_prompt(operation)
                self.assertTrue(prompt.startswith("Remap needs administrator approval"))
                self.assertIn(f" to {purpose}. ", prompt)
                self.assertTrue(prompt.endswith(" Password for %p: "))
                # sudo expands every other `%` escape, so none may appear by accident.
                self.assertEqual(prompt.count("%"), 1)

    def test_validation_and_commands_carry_the_prompt(self) -> None:
        prompt = administrator_prompt("install")
        self.assertEqual(
            administrator_command("install"), ("/usr/bin/sudo", "-p", prompt, "-v")
        )
        self.assertEqual(
            administrator_command("install", "/bin/mkdir", "/x"),
            ("/usr/bin/sudo", "-p", prompt, "/bin/mkdir", "/x"),
        )

    def test_linux_authorization_says_what_it_approves(self) -> None:
        with (
            mock.patch("tools.remap_linux_install._run") as run,
            mock.patch(
                "tools.remap_linux_install.sudo_expands_prompt", return_value=True
            ),
        ):
            remap_linux_install.authorize_administrator(Path("."), "uninstall")

        run.assert_called_once_with(administrator_command("uninstall"), Path("."))

    def test_a_sudo_that_may_not_expand_the_prompt_keeps_its_own(self) -> None:
        with (
            mock.patch("tools.remap_linux_install._run") as run,
            mock.patch(
                "tools.remap_linux_install.sudo_expands_prompt", return_value=False
            ),
        ):
            remap_linux_install.authorize_administrator(Path("."), "uninstall")

        run.assert_called_once_with(("/usr/bin/sudo", "-v"), Path("."))

    def test_only_the_original_sudo_is_trusted_to_expand_escapes(self) -> None:
        cases = {
            "Sudo version 1.9.16p2\nSudoers policy plugin version 1.9.16p2\n": True,
            "sudo-rs 0.2.8\n": False,
            "": False,
        }
        for output, expected in cases.items():
            with (
                self.subTest(output=output),
                mock.patch(
                    "tools.remap_linux_bootstrap.subprocess.run",
                    return_value=subprocess.CompletedProcess((), 0, output, ""),
                ),
            ):
                self.assertIs(remap_linux_bootstrap.sudo_expands_prompt(), expected)
        with mock.patch(
            "tools.remap_linux_bootstrap.subprocess.run", side_effect=OSError
        ):
            self.assertFalse(remap_linux_bootstrap.sudo_expands_prompt())

    def test_linux_bootstrap_and_install_check_and_run_one_sudo(self) -> None:
        for module in (remap_linux_bootstrap, remap_linux_install):
            with self.subTest(module=module.__name__):
                source = Path(module.__file__ or "").read_text(encoding="utf-8")
                self.assertNotIn(str(SUDO), source)
                self.assertNotIn("\nSUDO = ", source)
                self.assertIn("from tools.remap_lifecycle_approval import ", source)

    def test_the_package_installer_reaches_sudo_only_through_the_prompt(self) -> None:
        source = Path(remap_macos_verified_package_install.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"/usr/bin/sudo"', source)
        self.assertIn('administrator_command("install-package", *command)', source)


if __name__ == "__main__":
    _ = unittest.main()
