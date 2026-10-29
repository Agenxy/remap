# ADR-0031: A Supgang release role may authenticate a Remap package, beside the native key

## Status

Proposed, 2026-10-28, for the owner's review. It consumes Supgang ADR 0007
(release and code-signing roles, Agenxy/supgang#13), accepted by the owner on
28 and 29 October and amended in Agenxy/supgang#16 (ed18ffc), and ADR 0005 (owner-action authority, Agenxy/supgang#12). It extends ADR-0014 and ADR-0029
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
- `release-authority.cbor` is ADR 0007's authority bundle, the array
  `[1, role_step, role_sig, owner_step, owner_sig, status]`, with at most
  262144 bytes. `role_step` is the root-signed role grant; `owner_step` is the
  ADR 0005 grant for the owner's assertion key, and it and `owner_sig` are
  both null or both present; `status` is the root-signed status.
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
   A grant signed by any root other than the pinned one, including a
   successor the old root names, refuses the role path. Following a root
   succession takes a new enrolment.
3. The status is root-signed on the same hive, lists the role and every
   signer device as active, and is no older than the enrolled maximum age.
   Remap checks membership in the status, never serial numbers.
4. The statement names the same role, consumer, format and an enrolled channel
   that the grant also lists. It carries signatures from at least `threshold`
   distinct role keys, and `issued_at` ≤ now < `expires_at`, at most 30 days
   apart.
5. Presence, as ADR 0007 fixes it. The statement digest is
   SHA-256(`supgang/release/v1\0` || content), and the role signers sign
   those same prefixed bytes. The assertion is null exactly when the grant's
   presence is `unattended`.
   - For `carried-device`, the ADR 0005 assertion names consumer
     `org.agenxy.supgang` and operation `release.sign`. Its request digest is
     SHA-256(`supgang/action-request/v1\0` || statement content), over the
     content itself, not the statement digest. It verifies under the owner's
     assertion key that the bundle's `owner_step` authorizes, and its
     `challenge_digest` is non-null.
   - The assertion is judged as of signing, not installation. Its
     `issued_at` is at or after the statement's `issued_at` and before the
     statement's `expires_at`. The owner grant was valid at that `issued_at`
     and is active in the current status. The assertion's own expiry is
     never compared with the time of installation, because a package may be
     installed days after the owner approved it.
   - For `unattended`, every signer's custody is `hardware`, the grant lasts
     at most 90 days, and the statement's channel is never `stable`. Remap
     refuses an unattended statement on `stable` even if a grant were to list
     it.
6. The statement's `version` is ADR 0007's `[major, minor, patch, pre]`,
   where `pre` is null or `[label, number]`. Rendered as `M.m.p` or
   `M.m.p-label.number`, it must equal the manifest's `productVersion` byte
   for byte, so a manifest version of any other form cannot take the role
   path. Ordering is SemVer for that form. The version must be at least the
   grant's `min_version` and exceed the floor below.
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
accepts is treated as `stable`. Its only other channel is `preview` (below). An `unattended` role must, by ADR 0007,
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
  0007 requires, for the grant, status, statement, assertion and authority
  bundle. For each record they include valid cases, single-fault tampered
  cases, and encoding refusals: a non-shortest integer, an indefinite length,
  a tag, trailing bytes and an extra field. Remap vendors the frozen set with
  its manifest's SHA-256 recorded, and its verifier passes every one. Draft
  vectors are never vendored. Remap adds its own vectors for each refusal above: a
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

## Decided by the owner

Supgang ADR 0007 was accepted on 28 and 29 October:

- `unattended` roles are in the first release, within the bounds in check 5:
  hardware keys only, never `stable`, and 90 days at most.
- The maximum status age is 7 days. A consumer may require shorter, and Remap
  keeps 7 days as its default.

## The second channel is `preview`

The owner asked on 29 October that decisions inside a goal be made on their
technical merits rather than wait for approval. This one is Remap's:

- Remap's second channel is `preview`, for releases built and signed without
  a person, typically by CI. It is named for what a Mac opts into, not for a
  schedule.
- A Mac accepts `preview` only if its owner lists it at enrolment. It is
  never a default, and `stable` stays the only channel a native install
  implies.
- A `preview` version is a SemVer pre-release of the next stable version, such
  as `0.3.0-preview.4`. That makes a later stable release of the same version
  newer, by SemVer precedence, on a Mac that follows both channels.
- `unattended` roles may publish only to `preview`. Grants and Remap's own
  refusal on `stable` both enforce this.

The owner can rename or withdraw it before anything is built.
