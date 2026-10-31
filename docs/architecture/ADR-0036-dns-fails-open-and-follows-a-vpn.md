# ADR-0036: Remap DNS fails open when its upstreams stop answering, and follows a VPN's DNS

## Status

Accepted pending owner review, 2026-10-31. It amends the `remap.system/v1`
result (ADR-0006, ADR-0025) with one optional field, refines ADR-0024's
split-DNS refusal, and amends the ADR-0025 amendment on what a commit whose
verification fails restores. The SystemConfiguration effects are proven
against the model in the Swift tests and the daemon's liveness over real
sockets; neither has yet run against a live VPN on a Mac.

Amended 2026-10-31: the Linux supervisor now acts on the verdict too
("Linux restores ordinary DNS the same way" below). That amendment adds two
phases to the `remap.linux-resolver/v2` activation record (ADR-0008) and
applies ADR-0030's damping on Linux. Its native effects are proven against a
modelled systemd-resolved link in the `remap-linux` tests; neither it nor the
`NetworkManager` path has yet run on a live Linux host.

## Context

On 31 October at about 01:15Z the owner's Mac had Private Internet Access
connected over OpenVPN, resolving through 10.0.0.243. Its DNS leak
protection drops port-53 traffic to anything else. Remap's macOS DNS was
active: every network service pointed at 127.0.0.1, and `remapd` forwarded
names it does not own to the router, 192.168.1.254, and the ISP's IPv6
resolver. The VPN dropped both. `dig @127.0.0.1 github.com` answered
SERVFAIL and all DNS on the Mac failed, while Remap's health said ready.
Deactivating Remap then restored the router on Wi-Fi, which the VPN also
blocks, and the owner had to reconnect the VPN.

That breaks the invariant in `AGENTS.md` that DNS consumers fail open for
names they do not own. Three things let it happen.

- The daemon never noticed that its upstreams had stopped answering. Every
  forwarded query timed out and became SERVFAIL, and nothing reported it.
- The supervisor judged health by the system channel alone. A daemon that
  answers the channel while every forwarded name fails looked ready.
- Nothing followed a VPN. When a VPN publishes its own DNS, macOS resolves
  through it, or through Remap if Remap's persisted configuration wins.
  The installed build reacted to the first by pointing the service back at
  loopback on every reconciliation, a write war with any VPN that re-asserts
  its DNS, and to the second by forwarding to upstreams the VPN blocks.
  ADR-0024 also refused two services with DNS as split DNS, and a VPN's
  tunnel beside Wi-Fi is exactly that.

## Decision

### The daemon judges whether its upstreams answer

Every forwarded exchange ends answered or unanswered. It is answered when
any upstream returns a related response other than REFUSED, a truncated one
included. It is unanswered when every upstream timed out, refused (a
REFUSED answer, or a refused connection), or was unreachable. A REFUSED
answer now falls through to the next upstream and is relayed only when every
upstream refuses. An exchange that a newer plan cancelled says nothing about
liveness and is not counted.

The verdict that every upstream has stopped answering needs four unanswered
exchanges with no answer between them, the first and last at least two
seconds apart, inside a thirty-second evidence window. One lost packet, one
slow upstream, and one burst of parallel queries lost together therefore
never trip it. The thresholds are `UpstreamLivenessPolicy`, part of
`DnsRuntimeConfig` and validated with it.

The verdict belongs to the upstream set, not the generation. Republishing
the same set, as a supervisor does when it re-arms after a bypass, keeps
the verdict, so re-arming cannot put the Mac back on resolvers known to be
dead. Any other set starts with no evidence. Only an answered exchange
clears it. While no client traffic arrives, such as after a bypass, the
runtime sends one root `NS` query to that set every five seconds, and only
while the verdict holds. It does so after a bypass has invalidated the plan
too, through a plan that is never published and so never forwards a client
query, so the verdict is already clear when the supervisor republishes the
set. The probe carries no name a person chose.

### The verdict reaches the supervisor and the person

`SystemResult` gains `upstream_failure`: the dominant cause (`timed_out`,
`refused`, or `unreachable`), the unanswered count, and the milliseconds
since the first of them. It never carries an address. It is sent only while
the verdict holds, so steady-state responses stay byte-identical to the
original contract, as `highest_accepted_generation` did. A current Swift
supervisor decodes a missing field as absent and an older one ignores the
key. The Linux supervisor is built from the same Rust crate and decodes it;
an older Linux helper, which rejects unknown fields, would refuse a result
carrying it, a combination the Linux lifecycle does not produce because it
replaces the daemon and the helper together (ADR-0025). The Linux supervisor
acts on it as the next sections describe, and `remap status` reports it on
both platforms.

`RegistryStatus` gains `dns_upstream`, the diagnostic
`E_DNS_UPSTREAM_UNANSWERED`, whose message begins "upstream DNS not
answering" and names the cause, the count, and the span. `remap status`
prints it as `Upstream   DNS not answering` with a `Cause` line, `remap
doctor` adds the same lines and a `dns_upstream` JSON key, and the MCP status
summary names it. The MCP status resource notifies when it appears or
clears, not on every changed count.

### Unanswered upstreams are a fault, so ordinary DNS returns at once

When the daemon reports the verdict, reconciliation throws before it commits
a prepared activation, so Remap never becomes, or stays, the resolver macOS
uses over upstreams that do not answer. The supervisor reports
`E_RESOLVER_UPSTREAM_UNANSWERED` and treats it like a channel failure: it
restores ordinary DNS at once through the existing safe bypass, without
the ADR-0025 grace window, because the daemon has already waited its own
window. Re-arming is damped exactly as ADR-0030 sets, and each re-arm
attempt republishes the same set, sees the verdict, and commits nothing
until the probe finds an answer or the network offers a different set. From
the first unanswered query to ordinary DNS takes the daemon's window, at
least two seconds and four queries, plus at most one five-second
reconciliation interval. `remap-system status` explains the reason as
"upstream DNS not answering".

### Linux restores ordinary DNS the same way

Linux had no safe bypass before this amendment. A supervisor whose daemon
failed exited and left the link on loopback until systemd restarted it, and
the only restoration was deactivation, which removes the activation record.
Deactivation cannot serve as the bypass: in the `active` installation phase
the runtime gate refuses to start the units without a durable activation
record (ADR-0008), and only an installer's lease may create a new one. So the
bypass keeps the record.

- **Bypass.** When the daemon's result carries `upstream_failure`, the
  supervisor restores the link's captured state through the restoration
  deactivation uses: the typed systemd-resolved or systemd-networkd link
  methods field by field, or `NetworkManager`'s compare-and-swap `Reapply` of
  the prior DNS properties. The record moves through a journaled `bypassing`
  phase to `bypassed` instead of being removed, and the daemon's plan is
  invalidated. A crash part way through resumes as a bypass, never as a
  deactivation.
- **Never over a foreign change.** The bypass starts only when a fresh
  observation shows the link, and for `NetworkManager` the full applied
  connection, still exactly in Remap's owned state. Otherwise it writes
  nothing. ADR-0008's rebase then captures the other agent's change, and its
  servers become the upstreams, a different set the daemon judges afresh.
- **While bypassed Remap owns nothing on the link.** The supervisor neither
  compares nor rebases the link, so whatever its manager sets since is the
  network's own. It only probes the daemon, once per one-second
  reconciliation. Uninstall forgets a bypassed record without writing to the
  link; its journal names the bypassed activation as the plan to invalidate,
  which the daemon, holding none, accepts.
- **Re-arming is damped exactly as ADR-0030 sets.** The daemon must answer
  every probe for 5 seconds of awake time. A bypass within 5 minutes of a
  re-arm doubles the period, up to 5 minutes, and 5 minutes armed forgets the
  earlier bypasses. Linux's monotonic clock does not advance while the host
  is suspended, so it measures awake time as macOS's suspending clock does. At
  the end of the period the supervisor takes a stable observation of the link
  (three identical samples, 25 ms apart, within 150 ms) and works out the
  upstreams a capture would give. If the daemon still reports the verdict and
  those are the same set, ignoring order as the daemon does, nothing is
  written and the period starts again. Otherwise the link is captured afresh
  under the same activation identity with a strictly newer generation,
  Remap's state is applied, and the plan is published. A failed probe or a
  re-arm that did not apply also starts the period again. A supervisor that
  restarts while bypassed remembers no earlier bypass and owes the base
  period. Unlike a restarted macOS supervisor it does not try at once: an
  update or repair that starts it accepts the bypassed record as it found it,
  and must not see the record rewritten during that acceptance.
- **What a person sees.** The supervisor's journal says "upstream DNS not
  answering", with the cause, the count, the span, and the period, and says
  when Remap DNS re-armed; it never names an address. The native lifecycle
  status stays `active` and its hint says that ordinary DNS is in effect and
  that Remap DNS returns by itself. `remap status` reports
  `E_DNS_UPSTREAM_UNANSWERED` as on macOS.

From the first unanswered query to ordinary DNS takes the daemon's window
plus at most one one-second reconciliation.

#### The activation record gains two phases

`remap.linux-resolver/v2` keeps its schema string and gains
`bypassing { completed_steps }` and `bypassed`. The store admits `active` to
`bypassing` at step 0, one step at a time, step 3 to `bypassed`, and a
rewritten `bypassed` record. It replaces a `bypassed` record only with a
freshly captured `applying` record that keeps the activation identity, the
owner, and the owned state at a strictly newer generation. A helper built
before this amendment rejects a record in either phase. The Linux lifecycle
replaces the helper together with the daemon, and an update rollback re-arms
a bypassed record, while it holds the resolver authority, before it hands the
link to the previous generation's supervisor; that supervisor may then keep
upstreams that do not answer until the next update. The lifecycle treats
`bypassed` as settled, like `active`: it needs no recovery, the daemon is
expected to hold no plan, and an install, update, or repair accepts a started
supervisor whose record is bypassed and whose daemon holds no plan.

A channel failure on Linux still stops the supervisor and leaves the link on
loopback until systemd restarts it. Restoring ordinary DNS for that fault as
well would use this same bypass, but it is a separate decision.

### Remap tells its own writes from another agent's by the record

Remap writes exactly two values to a service's persisted DNS protocol: the
`installedConfiguration` and the `priorConfiguration` its integrity-covered
activation record holds. It never writes the dynamic store. So for a service
the record owns:

- persisted DNS equal to neither recorded value was written by someone else;
- the dynamic store, and the global resolver it produces, is never Remap's
  write; and
- a global resolver other than loopback while every owned service holds
  Remap's installed configuration means another agent's DNS is layered above
  Remap's.

Which resolver macOS actually uses is read from the same snapshot: the
global resolver is loopback, or it is exactly one service's effective
resolver, with macOS's own primary service breaking a tie, or no configured
service has those servers and the primary service exists only in the
dynamic store, as a VPN's tunnel often does, or no service accounts for it.
A tunnel that is primary but publishes no DNS of its own therefore never
hides the configured service whose resolver macOS still uses. `NetworkSnapshot` gains the primary service ID
from `State:/Network/Global/IPv4` for this.

### Remap follows the resolver macOS uses

- **A VPN publishes its DNS for a service Remap owns, below Remap's.** The
  service's effective resolver becomes the VPN's while macOS still resolves
  through loopback. Reconciliation already prefers a service's live
  resolver, so the VPN's servers become the upstreams and Remap keeps
  answering its names. When the VPN disconnects and withdraws its DNS, the
  service's DHCP resolver becomes the upstream again. Nothing is written.
- **A VPN's own service becomes the one macOS uses.** When the global
  resolver identifies it and Remap can configure it, Remap hands the
  activation to it exactly as ADR-0024 hands off to a tethered service:
  capture, publish, one compare-and-set commit, verify, converge. When the
  VPN disconnects, the same rule hands the activation back.
- **Two services with DNS are split DNS only when macOS's resolver does not
  say which one it uses.** This replaces ADR-0024's count rule. With the
  global resolver at loopback, the recorded service holding Remap's
  configuration carries DNS whatever else is up; with it on one service,
  that service does. When no single service accounts for it,
  `unsupportedResolverScope` is refused as before.

### When following is unsafe, Remap writes nothing and says why

Some cases can only be won by writing over another agent's value, and an
agent that re-asserts its DNS would answer with another write. Remap does
not start that exchange. It defers instead: reconciliation throws a
`ResolverDeferral`, the supervisor reports the new state `deferred` with a
stable code and logs it, no bypass is recorded, and no SystemConfiguration
write is made. Ordinary DNS through the other agent's resolver is already
what macOS uses, so failing open needs no write. Where macOS uses servers,
they are published as the upstreams, so a lookup that still reaches Remap
goes where every other lookup goes.

- `E_RESOLVER_HELD_ELSEWHERE`: Remap's configuration is in place, but a VPN's
  dynamic DNS outranks it, or the primary service is one Remap cannot
  configure. Remap answers its names again when that agent lets go, at the
  next reconciliation, because its configuration is still in place.
- `E_RESOLVER_DNS_CHANGED_ELSEWHERE`: another agent replaced the persisted
  DNS of a service Remap owns. Remap leaves it. A VPN that saved the
  configuration it replaced restores Remap's when it disconnects, and Remap
  is then on the path again with nothing to undo.

Re-arming is held the same way. A prepared record is not committed while a
service outside the preferences is primary. A commit whose verification
fails because every owned service holds Remap's configuration and another
agent's resolver for one of them, or outside them, wins anyway keeps the
record active and defers, instead of restoring: the active record already
lists what is installed, which is the property the ADR-0025 amendment
protects, and restoring would be one more write against that agent at every
re-arm. A commit that did not apply, or a global resolver no service
accounts for, still restores as before. And an active record that macOS
does not use is committed again only when Remap's own restore left a service
at its prior state, as the installer race in `ResolverReconciler` does;
otherwise it defers. So under a VPN that holds the resolver, Remap writes at
most once, and a VPN that re-asserts its DNS never meets a second write.

### Restoration never overwrites a foreign change

ADR-0024's compare-and-restore already guarantees this, and the case that
broke the owner's Mac is now a test: the prior configuration was captured
before the VPN connected, and the VPN changed the service while Remap was
active. Deactivation and safe bypass both report `configurationConflict`,
change nothing, and keep the record. Once the VPN disconnects and restores
the configuration it saved, which is Remap's, deactivation restores the
original capture, not the VPN's. A VPN's dynamic DNS is never touched by a
restore, which writes only the persisted value Remap recorded.

Following does not re-capture a foreign configuration as a service's prior
state. Doing so would leave the record restoring the VPN's resolver after
the VPN had gone, which is the failure the owner saw, in reverse.

### Turning DNS off on purpose is its own state (amended 2026-10-31)

During the outage the owner deactivated Remap DNS with `remap-system
deactivate`. The next morning another agent read `remap system status`,
saw "DNS: inactive (0 effective service(s))" and "Recovery needed: no",
could not tell a deliberate turn-off from a fault, and investigated a
problem that did not exist. Status now names four states, never one word
for three of them: active; falling back to ordinary DNS on its own, which
keeps its prepared activation and its bypass record; turned off by the
owner; and not activated.

`remap-system deactivate` restores ordinary DNS exactly as before, then
writes `dns-turned-off-v1.json` beside the activation record: the time, the
command, and the activation's owner UID and product version, which are what
turning it back on needs. It holds no name and no address. It follows the
bypass record's pattern: root-owned, written by exclusive temporary file and
atomic rename with the directory synchronized, covered by a SHA-256 digest
of its canonical payload, and refused when it is a symlink, has another
owner or mode, is oversized, or names an unknown command. Unlike the bypass
record it is 0644, inside the 0711 product directory, so the owner's
unprivileged `remapd` and CLI can read it. A record that cannot be written
never undoes the deactivation; the command warns. Activation removes it
before it changes anything, and so does the installer's own deactivation
around an update, a rollback, or uninstall: from then on the installer, not
the owner's earlier command, decides DNS. Uninstall therefore leaves no new
file in a directory exact removal must empty, and "not installed" already
says DNS is gone; recording uninstall as a turn-off was considered and
rejected for that reason.

`remap-system status` says "Native DNS is turned off by the owner at
2026-10-31T01:20Z (`remap-system deactivate`)" with a `Turn on` line giving
the exact `sudo ... remap-system activate --owner-uid ... --product-version
... --system-socket ...` command, and its JSON gains `dnsTurnedOff`. `remap
system status` gains the installer status key `dnsTurnedOff` and says the
same on its DNS line. `remapd` reads and verifies the record for `remap
status`, `remap doctor`, and MCP status, which gain `dns_turned_off`
(`turned_off_at`, `turned_off_at_ms`, `command`, `turn_on`), and reports it
only while no resolver plan is active, so a stale record can never
contradict a supervisor that has re-armed. `remap doctor`'s Lookup line says
"off (turned off by the owner at ...)" instead of a bare "unresolved".

## Alternatives considered

Overlaying loopback once on a VPN's persisted change and re-capturing the
VPN's configuration as the prior state keeps Remap's names answering while
the VPN is connected. It was rejected because the restore target then
depends on whether the VPN is still connected, which the record cannot know,
and because the VPN's own save and restore already composes with Remap's
compare-and-set when Remap stays out of the way.

Publishing Remap's names as supplemental match domains in the dynamic store,
pointed at loopback, would let Remap answer its names under any VPN without
owning the global resolver. It is the cooperative design for the
Network Extension backend's future, but it is a new platform contract
covering single-label, wildcard, and shadowing names, and it does not belong
in an urgent fix.

On Linux, deactivating on the verdict and activating again once the
upstreams answer would have reused existing transactions. It was rejected
because the runtime gate refuses to start the units in the `active`
installation phase without a record, only an installer's lease may create
one, and a removed record would leave a restarted supervisor no identity to
re-arm under.

## Consequences

Upstreams that stop answering now cost at most a few seconds of failed
lookups before ordinary DNS returns, where they used to cost every lookup
until a person intervened. The daemon sends one small probe per five seconds
while its upstreams are judged dead and none otherwise. `PRIVACY.md` lists
it.

Under a VPN, Remap's names keep answering when the VPN's DNS sits below
Remap's persisted configuration or on a service Remap can configure. When a
VPN's DNS outranks Remap's, Remap's names are not answered until the VPN
lets go, and every other name resolves through the VPN as the VPN intends.
That is a fail-open state, reported as such, never a failure of public DNS.

Acceptance for the turned-off state: `DNSTurnedOffTests.swift` checks the
record's canonical bytes, which `crates/remapd/src/native_dns.rs` verifies
byte for byte, the write, read, and clear, every refusal, and the four status
states; `RemapLifecycleCommandTests.swift` the `remap system status` line;
`native_dns.rs` and `crates/remapd/tests/dns_upstream_status.rs` that the
daemon reports a verified record only while no plan is active; and the CLI
and MCP tests the status, doctor, and summary wording.

Acceptance: `crates/remap-network/src/liveness.rs` tests the thresholds,
the window, the cause, and that the verdict follows the upstream set;
`crates/remap-network/tests/upstream_liveness.rs` proves over real UDP
sockets that silent upstreams trip it and an answer clears it with no client
traffic, that one lost packet does not, that refusals are reported as such,
that a REFUSED upstream falls through to the next, and that a different set
starts clean. `crates/remapd/src/system_control.rs` proves the verdict
reaches the system channel without an address, and
`crates/remapd/tests/dns_upstream_status.rs` that `remap status` says
"upstream DNS not answering" and stops saying it. In Swift,
`ResolverUpstreamLivenessTests.swift` drives the supervisor: an immediate
bypass, no re-arm while the same set is unanswered, re-arm once it answers or
the set changes, and the status line. `ResolverForeignDNSTests.swift` drives
the model with a VPN's dynamic DNS below and above Remap's, a VPN service
macOS uses, a tunnel outside the preferences, and a persisted foreign
change, and shows zero writes under every re-assertion, following back on
disconnect, and the exact restore sequence above.

On Linux, `crates/remap-linux/src/transaction_tests.rs` drives the
systemd-resolved transaction over a modelled link: a bypass restores the
capture and keeps the activation; a foreign change refuses it with no write
and no save; an interrupted bypass finishes as a bypass; a bypassed record
survives recovery after the network changed its DNS; re-arming captures the
network afresh under the same activation at a newer generation; re-arming and
releasing refuse a record that is not bypassed; and releasing writes nothing
to the link. `record.rs` and `record_store.rs` test the new phases' encoding
and every admitted and refused transition. `crates/remap-linux/src/fallback.rs`
tests the damping: one healthy probe never re-arms, a failed probe or a
blocked attempt restarts the period, repeated bypasses go 5, 10, 20, 40, 80,
160, then 300 seconds, five minutes armed resets it, a retried bypass is the
same fault, a restarted supervisor owes the base period, and the
verdict follows the set in any order. `resolver_fallback_tests.rs` in
`remap-linux-system` tests the re-arm gate, a link with no forwardable DNS,
the journal line, which refusals are tolerated, the resumed state, the
expected daemon plan, lifecycle acceptance of a bypass with no plan, and the
status hint. The `NetworkManager` bypass and
re-arm compile against the real D-Bus types but have no model to run
against.

Two judgements are deliberate. An upstream that answers REFUSED to every
query counts as not answering, since it serves no name; the probe clears the
verdict if it still answers the root, and ADR-0030 damps any return. And a
re-arm commit that configd has not applied within its three-second
verification looks like an outranked one, so the record stays active and
defers until configd applies it, instead of restoring; both states are
fail-open and neither writes again.

Only a live VPN on a real Mac can show which layer a given VPN writes, how
configd ranks it against Remap's persisted configuration, whether a tunnel
service's pushed resolvers stay visible once Remap's loopback is set on it,
and whether configd republishing preferences disturbs a VPN's dynamic DNS.
