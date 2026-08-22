# Contributing to Remap

Thank you for helping. Remap welcomes careful bug reports, design criticism,
documentation, tests, accessibility improvements, platform work, and code.

Read [VALUES.md](VALUES.md), [SECURITY.md](SECURITY.md), and
[the engineering standard](docs/engineering/STANDARDS.md) before making a large
change. Architecture and security boundaries are deliberate; changes to them
start with an ADR rather than an implementation surprise.

## Development setup

Remap pins tools exactly with `mise`. Development requires GNU Make and the
exact `mise` release named by `make setup`. Native macOS work also requires the
full Xcode version and build in
[`platforms/macos/XCODE_VERSION`](platforms/macos/XCODE_VERSION); Xcode's
command-line-tools-only package is insufficient, although the IDE need not be
opened. The supported entry point installs every other pinned development
dependency and runs the complete release gate:

```text
make setup
make check
```

People installing the native source product without a contributor environment
can use `make setup-install`. It installs only the pinned Rust, Python, and `uv`
tools needed by `make install`, then verifies the exact selected Xcode. It does
not download the browser test runtimes or contributor linters.

`make install` builds, previews, installs, activates, and verifies the complete
native macOS product. `make install-cli` writes only the `remap` binary to
`~/.local/bin` by default. Override that development-only prefix with
`REMAP_INSTALL_ROOT=/another/prefix`; the selected `bin` directory must already
be on `PATH`.

`make` provides a familiar, discoverable front door for common commands. Its
targets remain thin: substantive behavior belongs in a typed native tool such
as `remap-quality`. Shell is appropriate for initial bootstrap and concise
terminal composition, not as a hidden product implementation. Python
automation, when justified, uses a locked `uv` project; process execution stays
explicit, minimal, and limited to genuine tool boundaries.

## Change discipline

- Keep one coherent purpose per change.
- Add tests and documentation with behavior.
- Use conventional commit subjects such as `feat:`, `fix:`, `docs:`, and
  `refactor:`.
- Treat every warning as an error.
- Do not weaken gates, exclusions, baselines, tests, security invariants, or
  acceptance criteria to make a change pass.
- Do not introduce a dependency, unsafe block, build script, shellout, network
  service, data collection, entitlement, or privilege without an explicit need
  and review of its permanent cost.
- Preserve Apache-2.0 notices and identify third-party work accurately.

## Writing and interface work

Use direct, specific language. Error messages state what failed, why it matters,
and the next useful action. Help text should let a technically capable newcomer
discover the product without external documentation. Avoid jokes in failure
paths, generic enthusiasm, anthropomorphic software, and filler that obscures
facts.

Accessibility and internationalization are design inputs. Do not encode meaning
only through color, assume a particular locale, or make structured output parse
human prose.
