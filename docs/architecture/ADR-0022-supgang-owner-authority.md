# ADR-0022: Supgang owner authority for Remap's privileged operations

## Status

Proposed, 2026-10-14. This extends ADR-0006 (native resolution and privilege)
and ADR-0016 (peers are Supgang's). It depends on Supgang ADR 0005 (owner action
authority), which is itself Proposed (see "Dependencies on Supgang"). Nothing
here is implemented. Supgang stays an optional provider: Remap's native
authority is the default and works with no Supgang installed.

## Context

On or around 2026-10-13 the macOS resolver restored ordinary DNS, which
ADR-0006 allows after sustained failure. Every mapped name stopped resolving.
The only way back was `remap-system activate`, which requires root and the
active console user (`requireRoot`, `requireActiveConsoleUser`). So the owner
had to be at the machine with an administrator password.

The owner stated two requirements on 2026-10-14:

- Permissions and security settings must be administrable from any of the
  owner's machines, without physical presence, and the result must still be
  secure.
- Supgang is the identity, certificate, permissions and auth provider for
  every Agenxy tool. It certifies that an action comes from an authorized user
  using that user's keys, ID and entitlements, so the owner does not approve
  in person once per tool.

Supgang already has the necessary parts: a self-certifying hive root, per-device
Ed25519 keys under root-signed, expiring membership certificates, a monotonic
revocation set, and, on its trust roadmap, *authorization roles* that the root
grants by name ("who may sign what, for which targets"). It does not yet have
an administration role, and its ADR 0001 states that delegated administration
is not implemented. K7 is adding the same seam to its ADR 0159. K7's own
authority stays the default there, and a `supgang` mode accepts
Supgang-issued owner authority, can only narrow it, and fails closed on
revocation.

## Decision

**A privileged Remap operation is authorized by root at the console, or by
an owner signature that Supgang can verify. Being at the console is no
longer the only way.**

### Two authorities, one boundary

- **Native** (today's behavior) stays the default and always works. Remap
  must keep working on a machine with no Supgang, in the same way K7 must.
- **Supgang** is an opt-in mode. The root-owned Remap helper accepts a
  request signed by one of the owner's Supgang devices instead of
  root-at-console.

Both modes reach the same root-owned entry point, and both perform the same
transactional, compare-and-restore operation. The mode changes only who may
ask.

### What the Supgang mode covers

There is a closed list of named operations. Adding one requires an amendment
to this ADR.

| Operation | Effect |
| --- | --- |
| `remap.dns.activate` | `remap-system activate` with the installed version, owner UID and system socket |
| `remap.dns.deactivate` | `remap-system deactivate` (compare-and-restore) |

Both operations require owner presence (ADR 0005 `required` mode). Each one is
approved through a target-issued challenge, signed by an owner-presence key on
the device the owner carries, with Touch ID for every signature. Remap's
verifier refuses a `policy` grant for either operation, whatever the grant
itself allows. Supgang never prompts for presence on the target.

Mapping edits are not on the list: they are already per-user authority held
by `remapd` (ADR-0003). Enabling Supgang mode, choosing the trust anchor, and
changing or removing it are also off the list. Those stay native-only, so a
remote signature can never widen which signatures are accepted.

### Turning Supgang mode on

The owner decided on 2026-10-15 that Supgang is "a secure alternative without
compromising security", with "strong auth/verification ... to even initially
set this up so it can't be hijacked". Turning the mode on is the one step that
creates remote authority, so it is the step an attacker would aim at. It must
meet all of the following:

- **Local only.** It goes through the native authority on the target: root,
  the active console user, *and* a LocalAuthentication prompt (Touch ID or
  the login password) on that machine. No owner assertion can enable the
  mode, pin a hive or change a pin, and neither can anything that arrives
  over Supgang or any other network.
- **No trust on first use.** Before pinning, the target shows the hive's
  fingerprint, `HiveId` and root key. The owner confirms that it matches the
  fingerprint shown on a device already enrolled in that hive, the way an SSH
  host key or a messaging safety number is compared. The target never pins a
  hive just because it learned of it over the network.
- **The pin is exact.** It binds the `HiveId` and the root key, plus Remap's
  local allowlist of operations and scope, which may only be narrower than
  any grant. Changing or removing the pin repeats the same local ceremony.
- **It is visible.** Enabling, re-pinning and disabling are recorded in the
  root-owned store and shown by `remap doctor` and `remap system status`. If
  the mode is on, every status read says so, together with the pinned
  fingerprint.

This is the one in-person step the design keeps, and it happens once per
machine, before the owner travels.

### What a valid request is

The target accepts a request only when all of the following hold:

1. **The request is signed.** It is a Supgang ADR 0005 owner-action assertion,
   which is normative for its encoding: a versioned, canonical CBOR structure
   under a Supgang domain-separated signature, made by a key that the grant
   names. A device-key signature proves control of that key. It does not
   prove that a person was present, unless a key provider that enforces
   presence is required. All Agenxy tools use the same envelope,
   including K7's `supgang` mode, and Supgang defines it. It binds:
   - the pinned `HiveId`;
   - the signer's credential and the identifier of the grant it relies on;
   - the target `NodeId`;
   - the consumer, `org.agenxy.remap`;
   - the exact operation;
   - the SHA-256 of the canonical arguments together with the preconditions
     the target observed;
   - a random nonce;
   - `issued_at` and `expires_at`.

   For Remap, the preconditions are the resolver plan the target last
   reported (`remap-system plan`). A signature made for one network state
   therefore cannot be replayed against another.
2. **The hive is pinned.** The signer holds a current membership certificate
   in the hive whose `HiveId` this machine pinned when Supgang mode was
   enabled.
3. **The signer is specifically granted.** The hive root has issued a
   Remap-namespaced grant: consumer `org.agenxy.remap`, this ADR's closed
   operation list, and a scope that is either this exact `NodeId` or an
   explicit "all nodes in this hive" tag. The grant names one specific owner
   key or device. Membership alone is never enough: it proves which device
   signed, not that the owner was present. There is no rule that every
   member is an administrator.
4. **Revocation is fresh.** The signer is absent from a revocation status the
   target can prove is fresh. If freshness cannot be established, the request
   is refused. See "Revocation freshness".
5. **The request is fresh and unused.** `expires_at - issued_at` is at most
   five minutes. This cap is Remap's own policy, not part of the envelope. The
   request has not expired, and the target consumes the nonce durably, in
   root-owned storage, *before* it executes. A crash between the two
   therefore cannot leave a replayable request.

### Revocation freshness

Supgang's current revocation snapshot is root-signed with a serial and an
`issued_at`. It has no expiry, and nothing proves that no newer revocation
exists. Anti-entropy carries the latest state a node knows of. It does not
guarantee how fresh that state is. Supgang therefore cannot yet support any
numeric staleness bound.

Until Supgang issues a signed status lease, or a checkpoint with a defined
refresh path, **every Supgang-mode request is refused**. The mode is fully
specified here but cannot authorize anything until that primitive exists.
This is the intended, fail-closed outcome. Remap does not substitute its own
freshness heuristic.

On 2026-10-15 the owner chose how renewal is bounded: three configurable,
root-signed caps. One caps renewals made without presence, one caps renewals
approved remotely with presence, and a global cap forces physical
re-certification. The issuer keeps a monotonic, signed count, and the target
keeps a high-water record that the action key cannot reset. When the total cap
is used up, the next renewal needs a physical re-certification epoch. The last
lease issued before that still expires on its normal schedule. A revocation
therefore reaches a disconnected target no later than the expiry of that final
lease (Supgang ADR 0005). Remap's helper accepts a lease
only when it falls within those caps, as ADR 0005 specifies them.

Verification is portable Rust policy code in `remap-protocol`, called by the
root-owned Swift helper. Swift owns the entitlement-bearing entry point and
Rust owns the policy, as AGENTS.md requires.

### How a request arrives

Remap opens no new listener for this, and the gateway stays loopback-only.
None of Supgang's current channels is suitable. Its QUIC stream kinds are
Sync, Update and Service. Service is an opt-in TCP tunnel, not a way to
deliver privileged commands. Supgang's local control socket is same-UID,
not root-only. Supgang proposes:

- a new typed, size-bounded **action stream** over its authenticated QUIC;
- handoff to Remap's root helper through OS-approved local IPC.

**Arrival confers no authority.** The helper independently checks the pinned
root, the grant, the signature, freshness, the nonce and the exact
operation, whichever channel delivered the request. The channel only
transports it.

### What the owner sees

Every accepted or refused request is recorded in the root-owned activation
store. It also appears in `remap doctor` and `remap system status`, with the
signing device, the operation and the outcome. A refusal names the condition
that failed.

## Consequences

- The owner can bring DNS back on any of their machines from any other one,
  with one signature and no administrator password on the target. This is the
  Oct 13 failure, recoverable remotely.
- A stolen owner device that holds a Remap grant can change DNS on every node
  in that grant's scope until it is revoked. Four things bound that risk: the
  grant's scope, the five-minute expiry, the fresh-revocation requirement,
  and Supgang's hardware-held keys and threshold root (Supgang ADRs 0003 and
  0004). This ADR adds no bound beyond those. Grants are namespaced per tool,
  so a Remap grant authorizes nothing in K7, and the reverse.
- Supgang mode cannot be used until Supgang can prove that its revocation
  status is fresh. Until then the native path is the only one that works.
- A one-time, in-person step remains: enabling Supgang mode and pinning the
  hive on each machine. After that, no further in-person step is needed.
- Remap now depends on Supgang for administration as well as for peer
  routing. It does so only in the opt-in mode, so the dependency stays
  optional.

## Dependencies on Supgang

On 2026-10-14 the Supgang lead audited Supgang's source, then proposed
Supgang ADR 0005 (owner action authority) as a draft. Remap reviewed it and
found it compatible. That draft is Proposed, and none of the following exists
in Supgang yet:

1. A grant operation in the threshold root (`threshold/step.rs` has none)
   that issues tool-namespaced, scope-bound grants to named owner keys.
2. A shared owner-assertion envelope: canonical CBOR, domain-separated.
3. A signed revocation status lease or checkpoint with a defined refresh path.
4. A typed action stream over QUIC, and its local handoff.

Remap's review of ADR 0005 raised two gaps:

- A requester cannot build the request digest without the target's resolver
  plan, so the target needs either a bounded observe exchange or a
  target-issued challenge. Remap prefers the challenge.
- A status lease that can only be renewed from home would make this mode
  fail exactly when the owner is away.

This ADR stays Proposed until ADR 0005 is accepted. No Remap code treats any
of these shapes as stable before then.

## Not decided here

Whether the resolver should re-arm itself after a fallback, or only raise a
loud alert, is a separate change. So is making `remap doctor` state why
forwarding is off. Neither changes an authority boundary.
