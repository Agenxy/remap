# ADR-0031: A Supgang release role may authenticate a Remap package, beside the native key

## Status

Proposed, 2026-10-28, for the owner's review. It consumes Supgang ADR 0007
(release and code-signing roles, Agenxy/supgang#13) and ADR 0005 (owner-action
authority, Agenxy/supgang#12), both proposed. It extends ADR-0014 and ADR-0029
on what may authenticate a package, and it pairs with ADR-0022, whose
`remap.system.update` operation authorizes an update but does not authenticate
it. Nothing here is implemented, and nothing may be until the gates under
"Before anything is built" are met.

## Context

Every Remap release today waits for the owner to be at the release-building
Mac: the Secure Enclave release key (ADR-0029) asks for Touch ID on each
signature. On 27 October the 0.2.0 release stalled on exactly that, and the
owner asked that Supgang "provide auth/certs so this can happen without me at
the computer".

Supgang ADR 0007 answers with a release role: a root-signed grant naming 1 to
3 role keys for one consumer, under which a release is a signed CBOR
statement. Its default presence mode, `carried-device`, moves the owner's
approval of each release to a device the owner carries. The owner still
approves every release, but from anywhere. ADR 0007 leaves two decisions to
each consumer, where the authority bundle sits in its staging area and
whether its native path gains the same rollback high-water mark, and it
folds in five conditions Remap set on 27 October.

Remap's single authority check is `PortableReleaseVerifier.verifySignature`.
It authenticates the canonical `release-manifest.json`, and every later check
is keyed to those bytes: the manifest binds each payload file's path, kind,
hash, size and mode, and the payload must equal its entries. The staging root
is today exactly `payload`, `release-manifest.json` and
`release-manifest.json.sig`. The manifest carries a product version and an
architecture but no channel, and the native installer refuses no version, so
any natively signed package can be installed by the owner in person.

## Decision

### Two authorities, either sufficient, neither a fallback for the other

A staged release is authentic when one of these holds:

1. **Native.** `release-manifest.json.sig` verifies against the pin compiled
   into the installer (ADR-0029). This is the default and does not change.
2. **Release role.** This Mac's owner has enrolled a Supgang release role, and
   the staged statement and authority bundle pass every check below.

The order is fixed:

- If a native signature is staged, it is verified first. If it verifies, the
  package is accepted, and staged role files are not parsed at all. If it is
  present and fails, the package is refused, even when role files are also
  staged. A damaged or substituted signature is evidence of tampering, and it
  never falls through to another authority.
- With no native signature staged, the role path must pass. With no role
  enrolled, or with no role files staged, the package is refused as unsigned.
- Every refusal names the authority that refused and why. Nothing is ever
  accepted by default.

### Where the statement and bundle sit in staging

The staging root is exactly one of three sets. Any other entry, or a missing
one, refuses the package as it does today:

| Set | Entries |
| --- | --- |
| Native only | `payload`, `release-manifest.json`, `release-manifest.json.sig` |
| Role only | `payload`, `release-manifest.json`, `release-statement.cbor`, `release-authority.cbor` |
| Both | all five |

- `release-statement.cbor` is the ADR 0007 release statement, signed under
  `supgang/release/v1`, with at most 64 KiB.
- `release-authority.cbor` holds the root-signed role grant, the root-signed
  status, and the ADR 0005 grant for the assertion key, with at most 256 KiB.
- Both are mode 0400 and owned by root, under the same protected-ancestry and
  unique-file reads as the manifest.

The root helper reads authority only from staging. It never runs `supgang`,
links Supgang code, or reaches the network. The user-side orchestrator,
`remap-install`, may obtain the bundle from Supgang when it is installed, or
take a `release-authority.cbor` shipped beside the package, and stages it. The
transport is irrelevant, because every part of the bundle is root-signed, and
a bundle that does not verify fails only the role path.

### What the role path checks

The role path is Remap's own Swift verifier inside the portable installer. It
uses CryptoKit for P-256 and Ed25519 and a strict canonical-CBOR reader that
admits definite lengths, shortest integer encodings, sorted map keys and the
exact field set of each type, and nothing else. It checks, in order:

1. The enrolment record below exists and names a hive and a role.
2. The grant is a `supgang/root-step/v1` role grant signed by the pinned hive
   root, with `kind` `release`, the enrolled `role_id`, `consumer_id` exactly
   `org.agenxy.Remap` (the manifest's `productIdentifier`, byte for byte),
   `package_format` `remap-package-v1`, and `not_before` ≤ now < `not_after`.
3. The status is root-signed on the same hive, shows the role and every signer
   device unrevoked, and is no older than the enrolled maximum age.
4. The statement names the same role, consumer, format and an enrolled channel
   that the grant also lists. It carries signatures from at least `threshold`
   distinct role keys, and `issued_at` ≤ now < `expires_at`, at most 30 days
   apart.
5. For `presence: carried-device`, the statement's ADR 0005 assertion names
   consumer `org.agenxy.supgang`, operation `release.sign`, and the
   statement's digest without that field. It verifies under an owner-held
   assertion key that the bundle's ADR 0005 grant authorizes. A statement
   that claims `unattended` is accepted only if the grant says `unattended`
   and every signer's custody is `hardware`.
6. The statement's `version` equals the manifest's `productVersion`, parses as
   SemVer 2.0, is at least the grant's `min_version`, and exceeds the floor
   below.
7. Exactly one artifact names `macos` and this Mac's architecture, and its
   length and SHA-256 equal the staged `release-manifest.json` bytes. The
   manifest is then decoded and the payload compared exactly as on the native
   path.

### Rollback: one floor for the role path, the native path unchanged

The role path refuses any version below the grant's `min_version`, and any
version that is not strictly greater than both of:

- the version of the installed generation, however it was installed;
- the enrolled channel's high-water mark, the highest version ever accepted by
  the role on that channel.

The high-water mark is advanced in the same root transaction that commits the
new generation, so a failed install leaves it where it was. It never moves
down, including when the owner downgrades in person.

The native path does **not** gain a refusing high-water mark. Downgrade stays
an owner-present native operation, as ADR-0022 left it. Because the role
floor includes the installed version, a native install raises what the role
path will accept next. After a native downgrade, the role still cannot
republish anything at or below its old high-water mark.

The verifier also keeps the latest `issued_at` of any status it accepted. A
status or statement older than that one, or a clock that reads earlier than
it, is refused, so winding back the clock cannot revive an expired grant.

### Enrolment is in person, and disabling needs no ceremony

The opt-in is root-owned state that nothing in a package or staging area can
write:
`/Library/Application Support/Agenxy/Remap/Install/release-authority-v1.json`,
root:wheel 0600. It holds the hive fingerprint, the role id, the accepted
channels, the maximum status age, the per-channel high-water marks and the
latest accepted status time.

- `remap-system release-role enrol` writes it. Enrolling takes `sudo` and the
  local presence prompt (ADR-0017), the owner's 15 October rule for any
  pinning. The owner must also confirm the hive and role fingerprints out of
  band against Supgang on a second device. Remote owner-action authority
  (ADR-0022) can never enrol, because enrolling is what makes remote authority
  meaningful.
- The maximum status age is at most 7 days, and 7 days is the default until
  the owner chooses otherwise.
- `remap-system release-role disable` deletes the record under `sudo` alone.
  It only ever removes trust, so it needs no presence prompt, and the native
  path keeps working.
- Uninstall removes it, as it removes the ADR-0022 pin.

### Channels

Remap has had one channel in practice, and the manifest carries none. Remap
names its default channel `stable`, and every package a native install
accepts is treated as `stable`. An `unattended` role must, by ADR 0007,
exclude the default channel, so an unattended role can never publish to
`stable` on Remap. A channel name is a property of the statement and the
enrolment, never of the manifest, so `remap-package-v1` is unchanged.

### The code-signing role is not decided here

ADR 0007's code-signing role, and dropping the installer package and the
per-Mac trust steps, belong to Remap's distribution ADR. That ADR waits on a
measurement: whether a launchd daemon loads, and whether a TCC prompt names
the product, under a certificate the target Mac has never held.

## Before anything is built

- Supgang publishes the frozen wire specification and test vectors that ADR
  0007 requires, for the grant, status, statement and assertion, valid and
  tampered. Remap vendors them with their SHA-256 recorded, and its verifier
  passes every one. Remap adds its own vectors for each refusal above: a
  wrong-case `consumer_id`, two matching artifacts, a SemVer-invalid version, a
  floor equal to the installed version, an unparsed staged role file beside a
  failing native signature, and a clock behind the last accepted status.
- ADR 0005's status-freshness gap is closed. Without an expiring root status,
  revoking a role key cannot reach a Mac.
- The two-Mac acceptance in ADR 0007 passes. Until it does, no `doctor`,
  `--help`, MCP output or installer message offers enrolment.

## Consequences

- With a `carried-device` role enrolled, the owner approves a Remap release
  from a carried phone, and a target Mac accepts it with nobody at the release Mac.
  Combined with ADR-0022's remote `remap.system.update`, an update can reach a
  Mac the owner is away from, with one carried-device approval for
  authenticity and one for the update.
- A Mac that never enrols behaves exactly as today. Supgang stays optional:
  Remap builds, signs, installs and updates with no Supgang present.
- The hive root becomes able to name who may publish Remap to enrolled Macs.
  While Supgang's root is a single file-held key (ADR 0004's threshold root
  not yet built), that is weaker custody than the Enclave release key, and
  enrolment says so.
- A natively signed old package can still be installed by the owner in
  person. That was already true and remains the deliberate downgrade path.
- The staging contract gains two optional entries, and the portable installer
  gains a CBOR reader and the CryptoKit role verifier. Both sit within the K7
  ceilings, and both are tested only against real vectors, never fakes.

## Open for the owner

- Whether the first release accepts `unattended` roles at all.
- The default maximum status age, proposed as 7 days.
- Whether any channel besides `stable` is wanted now, and its name.
