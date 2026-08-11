.DEFAULT_GOAL := help
PORTAL_INSTALL_ROOT ?= $(HOME)/.local
# Keep this explicit selector synchronized with mise.toml. It prevents rustup's
# inherited-toolchain warning during `cargo install`.
RUST_TOOLCHAIN := 1.97.1

.PHONY: help setup format check test quality dependencies docs install

help:
	@printf '%s\n' \
	  'Portal development' \
	  '' \
	  '  make setup         Install exactly pinned tools' \
	  '  make format        Format first-party Rust code' \
	  '  make check         Run the complete local quality suite' \
	  '  make test          Run all Rust tests' \
	  '  make quality       Enforce structural ceilings' \
	  '  make dependencies  Audit advisories, licenses, sources, and versions' \
	  '  make docs          Build warning-free Rust documentation' \
	  '  make install       Install the portal CLI with Cargo'

setup:
	mise install

format:
	mise exec -- cargo fmt --all

check:
	mise exec -- cargo fmt --all --check
	mise exec -- cargo clippy --workspace --all-targets --all-features
	mise exec -- cargo test --workspace --all-targets
	mise exec -- cargo run --quiet -p portal-quality -- check
	mise exec -- cargo deny check
	RUSTDOCFLAGS='-D warnings' mise exec -- cargo doc --workspace --no-deps

test:
	mise exec -- cargo test --workspace --all-targets

quality:
	mise exec -- cargo run --quiet -p portal-quality -- check

dependencies:
	mise exec -- cargo deny check

docs:
	RUSTDOCFLAGS='-D warnings' mise exec -- cargo doc --workspace --no-deps

install:
	mise exec -- cargo +$(RUST_TOOLCHAIN) install --locked --path crates/portal-cli --root '$(PORTAL_INSTALL_ROOT)'
