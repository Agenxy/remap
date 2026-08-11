# Engineering standard

Status: enforced baseline. Limits ratchet downward as the codebase matures.

## Tool and dependency policy

Use the latest suitable stable release of each language, tool, and library,
verified against its authoritative release source and pinned exactly. Previews
are acceptable only when the project deliberately depends on a preview platform
surface, as with the active macOS/Xcode development environment.

`mise.toml` is the tool-version source of truth. `Cargo.lock` is committed.
Crate requirements are exact. Automated updates still require normal tests,
security review, changelog inspection, and performance consideration.

Dependencies are a permanent attack and maintenance surface. Prefer the
standard library or a focused, established crate when either is clearly better
than bespoke security-sensitive machinery. Reject dependencies whose purpose,
license, provenance, maintenance, build behavior, or transitive cost is unclear.

Portal does not depend on proprietary or paid services. Network protocols and
storage formats must have open implementations and a practical migration path.

## Warnings and static analysis

All compiler, Clippy, rustdoc, dependency, license, advisory, and project-quality
warnings are errors. Suppressions are not routine development tools. A justified
exception must be narrow, documented beside the canonical gate configuration,
owned, time-bounded, and unable to conceal unrelated findings.

Unsafe Rust is denied by default. A future interop crate may opt into narrowly
scoped unsafe code only with written invariants, safe public wrappers, boundary
tests, sanitizers where applicable, and review of unwind, ownership, alignment,
aliasing, threading, and lifetime behavior.

## Structural ceilings

The native `portal-quality` analyzer enforces the same starting ceilings used by
K7:

| Metric | Maximum |
|---|---:|
| Source file | 1,024 lines |
| Function or method | 128 lines |
| Struct, enum, trait, or implementation body | 512 lines |
| Function parameters | 8 |
| Cyclomatic complexity | 16 |
| Control-flow nesting | 8 |

These are ceilings, not targets. Splitting code must improve cohesion and names,
not scatter one concept across arbitrary files. Generated and vendored code must
remain outside first-party source paths and carry explicit provenance.

When a new implementation language enters the repository, its native parser or
first-class analyzer must enforce equivalent limits in the same change. Swift
will use current SwiftLint structural rules plus Portal-owned checks for any gap.
Python, if introduced, runs only through a locked `uv` project with Ruff and
Pyright in strict mode.

## Native integration

Product code does not invoke shell commands, shell interpreters, Apple command-
line utilities, or helper scripts to approximate a native API. Platform behavior
belongs behind typed interfaces using Swift/Apple frameworks on macOS and native
Rust or maintained bindings on Linux.

Cross-language boundaries prefer in-process native bindings with a small,
versioned contract. A process boundary remains correct when it is also an
authority, fault-isolation, privilege, or lifecycle boundary; it is never chosen
merely because bindings were inconvenient.

Substantive repository automation is typed Rust by default. Python is
appropriate for domains it serves well and always runs through a locked `uv`
project. Make is welcome as a discoverable orchestration surface whose targets
delegate to those maintained tools. Shell is the terminal lingua franca and is
reasonable for thin composition and bootstrap before prerequisites exist.

The boundary is architectural rather than ideological: do not bury business
logic, security decisions, error interpretation, or native platform integration
inside fragile command chains. Subprocesses are acceptable at genuine tool and
process boundaries when their inputs, outputs, errors, cancellation, and
lifecycle are explicit. They are not a substitute for an available native API.

## Security and privacy

Threat modeling begins with authority, data, trust, and parser boundaries.
Untrusted sizes and counts are bounded before allocation. Parsing separates
validation from effects. Secrets use native protected storage, remain out of
arguments and logs, and have explicit creation, rotation, revocation, and
destruction paths.

Routine logs describe component state without mapped names, upstreams, peer
addresses, user traffic, or request bodies. Metrics are local and aggregate by
default. Diagnostics are inspectable before export.

Security-sensitive code receives property tests, fuzzing, malformed-input tests,
and platform evidence appropriate to its boundary. Parser and authorization
failures are fail-closed; DNS interception fails open for names Portal does not
own. Those are different properties and must not be conflated.

## Performance and efficiency

Measure before claiming performance. Establish budgets for latency, allocation,
binary size, startup, idle resource use, throughput, and tail behavior at the
milestone that introduces the relevant path. Benchmarks use realistic payloads
and report environment and revision.

Avoid unnecessary copies and allocations at packet and streaming boundaries,
but do not exchange memory safety or clarity for speculative micro-optimization.
Backpressure, cancellation, bounded queues, timeouts, and resource ownership are
part of correctness.

## Interface quality

Human output is concise, legible, and useful by default. Machine output uses a
versioned stable JSON envelope. Progress and diagnostics go to standard error;
structured results alone go to standard output. Color is automatic, optional,
and never the only carrier of meaning.

Every error has a stable category, plain description, relevant context that is
safe to display, and a concrete next action when one exists. Destructive or
trust-changing commands show exact scope and support preview before commitment.

Top-level and subcommand help are treated as tested interfaces. Completion,
manual pages, examples, tutorials, accessibility, internationalization, and
uninstall documentation mature with the command they describe, not after the
product is considered finished.
