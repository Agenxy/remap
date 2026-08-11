# Contributing to Portal

Thank you for helping. Portal welcomes careful bug reports, design criticism,
documentation, tests, accessibility improvements, platform work, and code.

Read [VALUES.md](VALUES.md), [SECURITY.md](SECURITY.md), and
[the engineering standard](docs/engineering/STANDARDS.md) before making a large
change. Architecture and security boundaries are deliberate; changes to them
start with an ADR rather than an implementation surprise.

## Development setup

Portal pins tools exactly with `mise`:

```text
mise install
mise exec -- cargo fmt --all --check
mise exec -- cargo clippy --workspace --all-targets --all-features
mise exec -- cargo test --workspace --all-targets
mise exec -- cargo run -p portal-quality -- check
mise exec -- cargo deny check
```

`make install` writes the `portal` binary to `~/.local/bin` by default. Override
the prefix with `PORTAL_INSTALL_ROOT=/another/prefix`; the selected prefix must
already have its `bin` directory on `PATH`.

`make` provides a familiar, discoverable front door for common commands. Its
targets remain thin: substantive behavior belongs in a typed native tool such
as `portal-quality`. Shell is appropriate for initial bootstrap and concise
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
