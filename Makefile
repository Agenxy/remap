.DEFAULT_GOAL := help
TASK := mise exec -- uv run python -m tools.remap_tasks
NATIVE_TASK = MISE_AUTO_INSTALL=0 \
	"$$(MISE_AUTO_INSTALL=0 mise which uv)" run \
	--python "$$(MISE_AUTO_INSTALL=0 mise which python)" \
	python -m tools.remap_tasks
MISE_VERSION := 2026.8.10
export PREFIX REMAP_INSTALL_ROOT REMAP_LINUX_LINK

.PHONY: help setup setup-install _require-mise format check test quality dependencies docs package-macos release-evidence release-evidence-verify install install-cli install-system install-check recover run-macos verify-macos update uninstall uninstall-cli uninstall-system

help:
	@printf '%s\n' \
		'Remap development' \
		'' \
		'  make setup-install Install only the pinned tools needed for native install' \
		'  make setup         Install all pinned contributor and browser tools' \
		'  make format        Format first-party Rust, Swift, Python, and TypeScript code' \
		'  make check         Run the complete local release and evidence gate' \
		'  make test          Run all Rust, Swift, Python, and browser tests' \
		'  make quality       Enforce structural and repository policy' \
		'  make dependencies  Audit advisories, licenses, sources, and versions' \
		'  make docs          Build warning-free API documentation' \
		'  make package-macos Build the target-Mac-self-signed installer (release key required)' \
		'  make release-evidence        Build crates and create unsigned local evidence' \
		'  make release-evidence-verify Verify existing crate bytes and evidence' \
		'  make install       Preview, install, activate, and verify native Remap' \
		'  make update        Preview and transactionally update native Remap' \
		'  make recover       Preview lifecycle recovery and verified crash cleanup' \
		'  make uninstall     Remove native Remap while preserving user data' \
		'  make install-cli   Install only the portable remap CLI for development' \
		'  make install-check Verify install and uninstall in an isolated prefix' \
		'  make run-macos     Build and launch a project-local native Remap.app' \
		'  make verify-macos  Build, launch, and prove the native app remains running' \
		'' \
		'CLI-only installation defaults to PREFIX=~/.local. Native installation asks' \
		'for administrator approval. macOS requires the exact full Xcode build in' \
		'platforms/macos/XCODE_VERSION. Linux selects exactly one supported primary DNS' \
		'link; otherwise use REMAP_LINUX_LINK=<interface index> from its typed candidate' \
		'list. The index identifies the host interface whose DNS scope Remap will own. See' \
		'docs/tutorials/first-map-linux.md for the complete native workflow.'

_require-mise:
	@if ! command -v mise >/dev/null 2>&1; then \
		printf '%s\n' \
			'mise $(MISE_VERSION) is required to install Remap development tools.' \
			'Install that exact release from:' \
			'https://github.com/jdx/mise/releases/tag/v$(MISE_VERSION)' \
			'Native macOS installation also requires the exact full Xcode build' \
			'pinned in platforms/macos/XCODE_VERSION; command-line tools alone are insufficient.' \
			'Then run make setup-install and retry your command.' >&2; \
		exit 2; \
	fi
	@actual="$$(mise --version | awk '{print $$1}')"; \
	if [ "$$actual" != '$(MISE_VERSION)' ]; then \
		printf '%s\n' \
			"mise $$actual is selected; Remap requires $(MISE_VERSION)." \
			'For a standalone mise install, run:' \
		'mise self-update $(MISE_VERSION) --yes --no-plugins' \
		'For a package-managed install, update it through that manager.' >&2; \
		exit 2; \
	fi

setup-install: _require-mise
	@mise install rust python uv
	@$(NATIVE_TASK) setup-install

setup: _require-mise
	@mise install
	@mise exec -- bun install --frozen-lockfile
	@mise exec -- bunx playwright install chromium webkit

format:
	@$(TASK) format

check:
	@$(TASK) check

test:
	@$(TASK) test

quality:
	@$(TASK) quality

dependencies:
	@$(TASK) dependencies

docs:
	@$(TASK) docs

package-macos: _require-mise
	@$(TASK) package-macos

release-evidence: _require-mise
	@$(TASK) release-evidence

release-evidence-verify: _require-mise
	@$(TASK) release-evidence-verify

install: _require-mise
	@$(NATIVE_TASK) install

install-cli: _require-mise
	@$(NATIVE_TASK) install-cli

install-system: _require-mise
	@$(NATIVE_TASK) install-system

install-check: _require-mise
	@$(NATIVE_TASK) install-check

run-macos:
	@$(TASK) run-macos

verify-macos:
	@$(TASK) verify-macos

update: _require-mise
	@$(NATIVE_TASK) update

recover: _require-mise
	@$(NATIVE_TASK) recover

uninstall: _require-mise
	@$(NATIVE_TASK) uninstall

uninstall-cli: _require-mise
	@$(NATIVE_TASK) uninstall-cli

uninstall-system: _require-mise
	@$(NATIVE_TASK) uninstall-system
