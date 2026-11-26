# ADR-0006: Native resolution and least-privilege runtime

Status: accepted for implementation, August 2026.

## Context

Remap must make arbitrary names work in Safari, command-line clients, and native
applications. A resolver that answers only a private suffix, an `/etc/hosts`
editor, or a browser extension would contradict that promise. Mapped HTTP
services also need ports 80 and 443 so the user-facing name does not expose an
implementation port.

macOS offers a first-class DNS proxy through Network Extension, but production
activation requires an Apple-issued provisioning profile containing the
Network Extension entitlement. A locally generated signing identity cannot
grant that entitlement. Remap still needs a transparent, fully open source path
for developers and power users who build it themselves.

DNS, low ports, system resolver configuration, the per-user mapping authority,
and private CA material do not belong in one permanently privileged process.
Installation privilege is not permission to run ordinary routing logic as root.

## Decision

### One portable data plane, two native macOS resolver adapters

The Rust `remap-network` crate owns the bounded DNS decision engine, unmatched
forwarding, HTTP gateway, upstream TLS client, immutable snapshot consumption,
and portable lifecycle semantics. Platform adapters obtain native sockets or
flows and feed them into that same implementation. They do not maintain a
second mapping model.

The preferred distributed macOS product uses a Swift
`NEDNSProxyProvider` System Extension. The containing app activates and
configures it with Network Extension and System Extension APIs. Every target is
signed with the narrowest proven entitlement and an Apple-issued profile. The
provider fails open for names Remap does not own and fails closed rather than
inventing an answer for a mapped name it cannot validate.

The source-build and recovery backend uses native SystemConfiguration APIs and
a launchd-managed service. It changes DNS server configuration on explicitly
selected network services, preserving the exact prior configuration in a
versioned, permissioned activation record. It never invokes `networksetup`,
`scutil`, `pfctl`, a shell script, or `/etc/hosts`.

Both backends are visible product states. `remap doctor` and the native app
identify the active backend, approval state, bound listeners, captured upstream
resolvers, registry revision, and a safe recovery action. They never claim that
a source build has a Network Extension entitlement.

### launchd owns privileged sockets; request handling never acquires privilege

The source-build service is started by a root-owned launchd definition. launchd
binds the declared loopback DNS and gateway sockets and starts the job as the
declared non-root account. Remap adopts exactly one descriptor for each named
socket through `launch_activate_socket`, validates its address and type, and
refuses to run if its effective identity is root.

The registry, control socket, snapshots, DNS parsing, forwarding, HTTP proxying,
TLS, and CA operations run as the selected user. A failure at any privilege
transition closes all pre-bound sockets and exits. There is no fallback that
continues as root.

The audited adapter contains the only descriptor-adoption unsafe boundary. It
documents ownership, closes malformed descriptor sets, exposes owned safe Rust
types, and validates the sockets before the asynchronous runtime starts. There
is no macOS bind-then-drop fallback.

### Resolver activation is transactional and reversible

The native configurator serializes activation under a root-owned lock. Before
changing a network service it records:

- stable service and interface identifiers;
- the exact prior DNS dictionary, including absence;
- captured non-loopback upstream servers in deterministic order;
- the intended Remap backend and listener identity;
- a schema version and integrity digest; and
- the activating user and product build.

It validates that the local DNS listener answers a nonce probe before committing
the SystemConfiguration preference change. After commit it verifies the dynamic
store and a mapped/unmapped DNS probe. Any failure restores the recorded
configuration before returning. Deactivation uses compare-and-restore: it
restores only fields still owned by the recorded Remap activation and reports a
conflict instead of overwriting a user's later network change.

Network changes are observed through `SCDynamicStore`. Newly active services
are activated from their own captured state; removed services are retired.
Upstream changes publish a complete replacement set to the DNS forwarder before
the system service points at loopback, preventing self-recursion.

The launchd daemon image contains no install-time fallback resolver. It starts
with a dormant forwarding plan and accepts only the current, root-published
generation. The supervisor watches both native network state and the daemon's
private socket directory, so a daemon replacement causes immediate
republication. A transient incomplete network observation preserves the last
complete generation. Sustained failure restores ordinary macOS DNS with native
SystemConfiguration APIs before invalidating the daemon plan; mapped names may
become unavailable, but public connectivity no longer depends on Remap.

The initial source backend supports exactly one active DNS service scope. It
refuses multiple scopes rather than flattening VPN or split-DNS routing into a
global race. Native scoped forwarding and network-change reconciliation are
required before that restriction can be relaxed.

### Source installation has explicit publication and garbage-collection authority

The source installer serializes lifecycle work by locking the stable,
root-owned Agenxy organization directory. The lock does not live inside the
Remap subtree it may remove. Product and generation directories grant search
permission without directory listing; journals and other recovery state remain
owner-only.

Every public file, link, and potentially absent parent directory is declared in
the signed manifest. File and link publication never creates implicit parents.
Directory publication stages a private root-owned sibling containing an exact
product-and-path marker, then uses an exclusive atomic rename. A compatible
pre-existing directory is usable but never adopted. Update reuses product-bound
directory provenance across generations. Uninstall retires and removes only a
marked directory that is still empty, deepest first; a directory containing
unrelated content is preserved and ownership is relinquished.

Generation removal is a journaled sequence: verify the canonical manifest,
retire the exact generation, delete individually verified entries, then remove
the empty generation root. Terminal journals first move into a digest-named
protected namespace and are deleted record by record. Quarantined staging trees
follow the same manifest-verified deletion rules. Recovery resumes every
partial phase idempotently. Complete uninstall removes exact empty journal,
generation, install, and product directories without recursive deletion; the
shared organization directory remains as the stable lock authority.

Preview and commitment are separate native authority operations. Each preview
returns a canonical approval token bound to the operation, package manifest,
active and installed generations, exact classified publication effects,
launchd observations, DNS observations, and recovery state. Install, update,
uninstall, and recovery recompute that token before preparation and again under
the installer lock. A mismatch performs no effect. Interactive orchestration
accepts only the displayed approval phrase; noninteractive orchestration accepts
only the complete token on standard input. Neither path has an environment or
flag bypass. The source and installed CLI paths preview and approve recovery
independently; another CLI lifecycle operation never performs implicit
recovery. Reopening the same authenticated Apple Installer package after its
own interrupted transaction may settle that exact journal before continuing.
That package repair is bounded to verified Remap-owned state and still
revalidates the native recovery token under the lifecycle lock; it cannot adopt
foreign files or authorize a different product operation.

### One active interactive owner on macOS

Ports 53, 80, and 443 are host-wide. The first production implementation allows
one explicitly activated interactive user at a time. Activation verifies the
current console user and refuses an ambiguous fast-user-switching handoff. A
future multi-user broker requires a separate authorization and routing ADR; it
will not be inferred from Host headers or process ancestry.

### Native app is control and recovery, not decoration

The Swift app shows mappings, exact resolution decisions, service health,
backend approval, trust state, and peer state from versioned contracts. It can
preview, apply, enable, disable, activate, deactivate, repair, export
diagnostics, and completely uninstall. Destructive and trust-changing actions
show exact scope and require explicit confirmation. Accessibility labels,
keyboard operation, reduced motion, high contrast, localization, and actionable
errors are release requirements.

## Security invariants

- Network listeners bind only loopback unless a separately reviewed peer route
  explicitly opts into another interface.
- Resolver configuration and activation records are root-owned, non-symlink,
  bounded, versioned, and restored conditionally.
- The privileged bootstrap never reads mapping names, upstream URLs, request
  bodies, CA private keys, or traffic.
- Source installation discloses its pre-preview bootstrap step. Descriptor-pinned
  bytes first enter a root-private directory under
  `/Library/PrivilegedHelperTools`; only the exact SHA-256- and code-verified
  inode becomes the root-owned, non-writable executable. It is removed when
  orchestration exits. Crash leftovers may instead be partial or invalid private
  staging bytes. Recovery binds exact no-follow identity, metadata, activity,
  and SHA-256 before approval and removal, and never executes those bytes.
  Staging the bootstrap is not approval to mutate Remap product state.
- The unprivileged authority authenticates control peers by operating-system
  identity and remains the only registry writer.
- Unmatched DNS preserves normal resolution; mapped failures never silently
  fall through to a public answer for the same name.
- Routine diagnostics and logs exclude names, targets, addresses, headers, and
  traffic. Export is explicit and inspectable.
- Install, update, rollback, deactivate, and uninstall are separately tested
  state transitions with interruption recovery.
- Every privileged lifecycle mutation is bound to a freshly recomputed exact
  preview, and unfinished or collectible lifecycle state requires a separate
  recovery approval before another operation.
- Public parent directories are either provenance-bound Remap creations or
  unowned compatible system directories; an empty directory alone is never
  evidence of Remap ownership.

## Verification requirements

The macOS gate must prove on a clean host:

- a source build can install, request the required privilege, activate, and
  later remove itself without orphaned launchd, DNS, trust, or data state;
- the signed product uses the declared System Extension and entitlements;
- Safari, `dig`, `curl`, SSH, and a native client observe exact, wildcard, bare,
  arbitrary-TLD, direct-address, routed-service, and unmapped behavior;
- network-interface changes, sleep/wake, user logout, daemon crash, provider
  crash, update, rollback, and interrupted uninstall converge to a documented
  state;
- the runtime user is non-root after socket acquisition and cannot regain root;
- conflicting manual DNS changes are reported and never overwritten during
  restore; and
- packet, connection, queue, timeout, memory, startup, idle, throughput, and
  tail-latency budgets pass under measured load.

The source bootstrap deliberately treats a concurrently approved recovery of
its root-private pre-publication stage as a bounded failed attempt. No
unverified bytes become public, no helper executes, and no product state changes;
the operator retries after the other lifecycle command settles. Once the helper
inode is publishable, its shared activity lease prevents recovery from removing
it. Signed distribution does not use this source-bootstrap path.

## Consequences

The Apple-provisioned path is the cleanest experience, but lack of an Apple
profile does not reduce Remap to a demo. The source-build backend is a real,
native, reversible implementation with a smaller privileged bootstrap and the
same data plane.

This requires more lifecycle engineering than writing `/etc/hosts` or launching
a root proxy. That cost is part of the product: arbitrary names, normal ports,
privacy, recovery, and honest native behavior are inseparable.
