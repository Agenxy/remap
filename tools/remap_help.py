"""Stable Make-facing help for Remap's typed task runner."""

from __future__ import annotations


def print_task_help() -> None:
    """Print the complete development and installation task catalog."""
    print(
        """Remap development

  make setup-install Install only the pinned tools needed for native install
  make setup         Install all pinned contributor and browser tools
  make format        Format first-party Rust, Swift, Python, and TypeScript code
  make check         Run the complete local release and evidence gate
  make test          Run all Rust, Swift, Python, and browser tests
  make quality       Enforce structural and repository policy
  make dependencies  Audit advisories, licenses, sources, and versions
  make docs          Build warning-free API documentation
  make package-macos Build the target-Mac-self-signed installer (release key required)
  make release-evidence        Build crates and create unsigned local evidence
  make release-evidence-verify Verify existing crate bytes and evidence
  make install       Preview, install, activate, and verify native Remap
  make update        Preview and transactionally update native Remap
  make recover       Preview lifecycle recovery and verified crash cleanup
  make uninstall     Remove native Remap while preserving user data
  make install-cli   Install only the portable remap CLI for development
  make install-check Verify install and uninstall in an isolated prefix
  make run-macos     Build and launch a project-local native Remap.app
  make verify-macos  Build, launch, and prove the native app remains running

CLI-only installation defaults to PREFIX=~/.local. Native installation asks
for administrator approval. macOS requires the exact full Xcode build in
platforms/macos/XCODE_VERSION. Linux selects exactly one supported primary DNS
link; otherwise use REMAP_LINUX_LINK=<interface index> from its typed candidate
list. The index identifies the host interface whose DNS scope Remap will own. See
docs/tutorials/first-map-linux.md for the complete native workflow."""
    )
