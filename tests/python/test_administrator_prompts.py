# SPDX-License-Identifier: GPL-3.0-or-later
"""sudo says who is asking for an administrator password and what it approves."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from tools import remap_linux_install, remap_macos_verified_package_install
from tools.remap_lifecycle_approval import (
    ADMINISTRATOR_PURPOSES,
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
        with mock.patch("tools.remap_linux_install._run") as run:
            remap_linux_install.authorize_administrator(Path("."), "uninstall")

        run.assert_called_once_with(administrator_command("uninstall"), Path("."))

    def test_the_package_installer_reaches_sudo_only_through_the_prompt(self) -> None:
        source = Path(remap_macos_verified_package_install.__file__).read_text(
            encoding="utf-8"
        )
        self.assertNotIn('"/usr/bin/sudo"', source)
        self.assertIn('administrator_command("install-package", *command)', source)


if __name__ == "__main__":
    _ = unittest.main()
