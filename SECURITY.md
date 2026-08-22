# Security

Remap changes system-wide name resolution and may terminate local TLS. A flaw
can redirect traffic, disclose routing configuration, weaken trust, or disrupt
network access. Security work is therefore ordinary product work, not a final
release phase.

## Reporting a vulnerability

Please report suspected vulnerabilities privately. If the project is hosted on
a forge with private security advisories, use that facility. Otherwise contact
a maintainer through a previously established private channel. Do not include
real user mappings, traffic, credentials, private keys, or unrelated machine
data in the report.

Include, when available:

- A concise description and affected component.
- A minimal reproducer using synthetic names and addresses.
- Security impact and required preconditions.
- The observed and expected behavior.
- Toolchain, operating system, architecture, and Remap revision.
- A proposed fix or mitigation, if you have one.

We will acknowledge good-faith reports, preserve credit if desired, avoid
retaliation for responsible research, and communicate uncertainty honestly.

## Security invariants

- `remapd` is the sole writer of authoritative state.
- Every local mutation is authenticated and authorized.
- DNS consumers receive complete, versioned, immutable snapshots.
- Unmapped DNS fails open; failure of a mapped upstream never silently falls
  through to a public destination.
- The gateway binds loopback only unless public ingress is explicitly enabled.
- Apple signing, the local HTTPS CA, and peer identity use separate keys.
- Private keys are non-exportable where native hardware-backed custody satisfies
  availability and lifecycle requirements.
- Inputs crossing DNS, HTTP, IPC, persistence, FFI, and replication boundaries
  are bounded and validated before use.
- No plaintext secret persistence, secret command-line arguments, or sensitive
  logging.
- Installation, trust, peer enrollment, ingress, update, and removal are
  separate, explicit operations.

## Security readiness bar

Remap is not security-ready because a build or unit suite is green. A privileged
or network-facing release requires all of the following evidence:

- The repository threat model is current for the exact source snapshot, and an
  authority, privilege, wire, persistence, or trust change has a matching ADR.
- No known critical, high, P0, or P1 security finding remains open. Lower-severity
  findings must stay fail-closed, have bounded impact, and be recorded rather
  than silently accepted as release debt.
- Every attacker-controlled boundary has deterministic malformed-input,
  substitution, race, cancellation, timeout, resource-bound, and crash-recovery
  tests appropriate to that boundary. Security-sensitive changes receive an
  independent adversarial review after the implementation is line-stable.
- Privileged lifecycle work is exercised on each supported operating system
  through clean install, state drift, update, rollback, restart, interrupted
  recovery, and exact uninstall restoration. Mocks do not substitute for those
  platform exits.
- Public artifacts come from a clean immutable revision and pass required CI,
  exact dependency and license policy, artifact manifests, SBOM and provenance
  verification, platform signing, and notarization where applicable.

Missing evidence blocks the corresponding readiness claim. A local source
installation, a signed public distribution, and a production-supported platform
are separate claims and are evaluated independently.

## Dependency and release policy

Dependencies must be necessary, current, permissively licensed, pinned in the
lockfile, sourced from an approved public registry, and free of known security
advisories. Build scripts, native code, unsafe code, and new transitive trees
receive explicit review. Release artifacts will eventually include an SBOM,
provenance, signatures, deterministic manifests, and verified uninstall paths.

No security control is weakened to make a gate pass. Time-limited exceptions,
if ever unavoidable, require an owner, reason, expiry, and public remediation
plan.
