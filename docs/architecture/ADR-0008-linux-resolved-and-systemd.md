# ADR-0008: Reversible Linux resolver ownership and systemd activation

Status: accepted vertical slice; the supported distribution matrix remains
incomplete, August 2026.

## Context

Remap must route arbitrary names on Linux without editing `/etc/hosts`,
rewriting `/etc/resolv.conf` behind its owner, or running the portable DNS and
HTTP daemon as root. Resolver configuration may belong to systemd-networkd,
NetworkManager, a VPN, or an operator. Low ports need host-level ownership,
while request parsing, mapping storage, and forwarding do not need elevated
privilege.

`systemd-resolved` exposes the live resolver view, but its `RevertLink` method
does not restore the exact state Remap observed. It discards runtime state and
asks another manager to reconstruct it. Direct `SetLink*` calls can likewise be
rejected when systemd-networkd or NetworkManager owns the link. A safe design
must identify the native owner, mutate through that owner, journal every effect,
and compare before restoring.

## Decision

### Support one explicit systemd-resolved link

The first installable path accepts exactly one operator-selected link index.
The typed zbus 5.19.0 adapter reads the complete ordered `DNSEx`, `Domains`, and
`DefaultRoute` values from `org.freedesktop.resolve1`. `DNSEx` preserves address
family, raw address, port, and DNS-over-TLS server name; reducing it to the older
`DNS` property would make exact restoration impossible.

Remap detects the selected interface through the native interface-index API and
then checks ownership on the system bus:

- an unmanaged resolved link uses the resolved manager's typed `SetLink*`
  methods;
- a systemd-networkd-managed link uses that link object's typed `SetDNSEx`,
  `SetDomains`, and `SetDefaultRoute` methods; and
- a NetworkManager-managed device uses `GetAppliedConnection` and `Reapply`
  with the exact applied version identifier and the preserve-external-IP flag.

If NetworkManager and systemd-networkd both claim the selected link, activation
fails closed. Remap does not infer a winning LAN, VPN, or split-DNS scope.

For NetworkManager, the record stores the exact presence and typed values of
both modern `dns-data` and legacy `dns`, plus `dns-search`, `ignore-auto-dns`,
and `dns-priority` for the IPv4 and IPv6 setting sections. Before reapply, Remap
canonically serializes the complete applied-connection tree and records its
digest. It also records a protected digest of every field outside that owned
DNS set. NetworkManager may normalize redundant empty arrays, so ownership is
verified as the protected digest plus exact normalized owned DNS values, not as
an assumed byte-for-byte result. Restoration patches the prior values and
presence into the current owned connection, uses the live version identifier as
a compare-and-swap, and requires both the original complete-connection digest
and the original resolved link state afterward. Any unrelated applied-setting
change blocks restoration.

The owned state points the link at `127.0.0.1:53`, adds the route-only root
domain, and marks the link as a DNS default route. The daemon forwards unmapped
queries to a bounded list of captured, non-loopback upstreams. A mapped lookup
never falls through to public DNS.

### Treat resolver changes as an ownership transaction

One versioned activation record contains:

- a unique activation identifier, strictly increasing generation, activating
  UID, and creation time;
- the exact native manager kind and stable interface name (plus the full
  applied-connection identity for NetworkManager);
- the complete captured link state;
- the complete Remap-owned link state; and
- an applying, active, aborting, or restoring phase with durable step counts.

The record is capped at 16 KiB, rejects unknown fields and schemas, and carries
a SHA-256 corruption digest. The digest is not an authentication mechanism.
Authenticity comes from a root-owned mode-0700 directory and root-owned
mode-0600 regular files with one hard link. The store walks the absolute path
descriptor by descriptor with `O_NOFOLLOW`, holds a native file lock, publishes
an exclusive temporary file with `fsync`, atomically renames it, and synchronizes
the directory.

The applying record is durable before the first D-Bus effect. DNS, domains, and
default-route state change in that order. Remap reads the whole state after
every effect, requires the exact expected value, and durably advances progress.
An ambiguous first activation enters an explicit aborting phase so a zero-step
journal cannot strand a live effect. Recovery accepts only the recorded state or
the exact next state; all other values are ownership conflicts.

Deactivation starts only when the live state exactly equals the recorded owned
state. It restores the captured fields in reverse order, verifies every complete
snapshot, compares the activation identity before record removal, and never
uses `RevertLink`.

The supervisor watches the selected link while active. A stable native
replacement state is rebased under the same activation identifier with a
strictly newer generation. Rebase compares each observed field with both the
prior captured state and Remap's owned state. A field that still equals the
owned value retains its prior captured value; only a field that differs from
owned replaces that part of the restoration snapshot. This prevents a
DNS-only manager update from laundering Remap's still-owned route-all domain
into the state later restored to the host. The merged restoration snapshot is
published by an active-to-active compare-and-swap before any D-Bus effect, then
owned state is re-applied and the daemon receives the new upstream plan. A
crash during re-application therefore leaves an active record whose next
reconciliation preserves already captured external fields and idempotently
finishes ownership. Before update rollback can start a retained older
supervisor, the current lifecycle helper acquires the resolver authority,
converges this record to exact owned state, and retains the authority until the
old-generation handoff. Every generation records its resolver-rebase
capability, exact manager kind, and interface identity in the
integrity-covered generation manifest. The generated supervisor unit repeats
that identity on its command line, and every startup sample re-proves it
through typed manager inspection. Update preview fails without effects when the
installed generation lacks the current capability; legacy records remain
readable for status and exact uninstall. A rollback target therefore always
implements the same field-merge contract rather than merely inheriting a safe
snapshot once and then running an older reconciler. Unexplained multiple,
reused, or changed link scopes are not selected automatically.

Cold-start and lifecycle rebasing use the full manager-aware stability gate.
The resolver unit pulls and orders after `network-online.target`, but does not
treat target activation alone as readiness. A systemd-networkd link must report
the exact `configured` administrative state; a NetworkManager device must
remain managed and `activated`. Three identical complete observations spaced
over one second are required before startup capture, rollback convergence, or
uninstall restoration. NetworkManager's observation binds both the resolved
view and the applied-connection version and digest. The transaction re-reads
and compares that exact observation before it can publish a record; no product
lifecycle caller performs a one-shot active rebase. Staggered boot-time DNS,
domain, or default-route fields therefore reset the candidate instead of
becoming the uninstall baseline.

After startup has established one exact Active owner, the supervisor registers
a signal match for the selected resolved-link object plus owner changes for
resolved and the selected native manager. It does not subscribe to unrelated
NetworkManager devices, access points, or networkd links. A one-entry queue
coalesces signals for 10 milliseconds. Each ingress task blocks once one
notification is pending and drains at most 64 already-ready messages per
batch, so an always-ready signal source cannot spin the single-thread runtime.
Sustained signal traffic can trigger at most four full observations per second.
Active drift must then appear in
three identical complete manager-aware observations: the event-triggered
observation and two additional observations 25 milliseconds apart within a
150-millisecond scheduled bound. The final transaction comparison remains
unchanged. A one-second full observation is the safety audit and missed-signal
fallback, not a high-frequency polling loop. Each signal stream is supervised;
closure or read failure is journal-visible, drops the bounded monitor, leaves
the periodic audit running, and rebuilds a fresh connection and exact match set
after a bounded delay.

The complete supervisor startup, recovery, stability, and publication sequence
runs on one dedicated bounded worker; steady supervision then transfers the
native transaction to one dedicated transaction-owner worker. Each accepts at
most one command in flight. D-Bus methods have a 100-millisecond reply deadline
and read commands have a 150-millisecond caller deadline. A shutdown signal
cancels startup only at read-only checkpoints. Once a native transaction effect
begins, the worker finishes exact plan publication, journaled compensation, or
a surfaced recoverable outcome, and the caller retains that settled result
before returning; no effectful future is dropped. A timed-out read is retried
by a later event or audit. A timed-out rebase is an explicit unknown outcome and is never
interpreted as no effect.
These bounds keep the runtime and shutdown path responsive; native round-trip,
record I/O, and durable mutation latency remain separately observed evidence.

### Keep traffic handling non-root

systemd owns three loopback listeners:

- UDP DNS at `127.0.0.1:53`, named `dns-udp`;
- TCP DNS at `127.0.0.1:53`, named `dns-tcp`; and
- HTTP at `127.0.0.1:80`, named `http`.

First-install preview and the commit's initial re-prepare each bind-probe the
complete fixed descriptor set. Preview releases its probes with the read-only
plan; commit carries the same reservation through locked approval recomputation,
staging, and manager reload, then hands the namespace to one systemd start
transaction. A pre-existing DNS or HTTP owner therefore produces a typed,
no-effect conflict naming the exact descriptor and address. Forward update
quiesces the resolver and daemon, stops each socket, and immediately reserves
the complete descriptor set before publication. After reloading the new unit
definitions, it resets hidden systemd start-rate state while runtime authority
is absent, then grants the new generation and releases all reservations into one
captured systemd transaction. This creates a bounded listener pause but prevents
traffic from starting the daemon against a partially reserved namespace. A
replayed update rollback carries missing reservations until the previous current
link and unit definitions are restored, tops up the partial set if another
owned socket stops, then transfers each exact descriptor into PID 1. It revokes
transactional start authority and proves the resolver and daemon inactive with
no pending systemd job before re-establishing the previous service. Start
transactions retain the
generation lease until their exact systemd jobs settle; ambiguous or failed
starts are quiesced before the lease can be released. A failed first install
enters absent rollback directly and never requires a broken new socket unit to
activate before it can be removed. A foreign binder that wins an unavoidable
stop-to-bind handoff is preserved and fails the transaction closed. Abrupt-power
behavior still requires the live evidence called out below.

`remapd --systemd-sockets` runs as the declared non-root service account. Before
starting its async runtime, it requires the current `LISTEN_PID`, exactly three
descriptors starting at fd 3, and the exact unique `LISTEN_FDNAMES` set. It
validates family, socket type, address, port, listening state, nonblocking, and
close-on-exec flags. It also clears and verifies `SO_REUSEADDR` on the UDP DNS
descriptor so a later reuse-enabled process cannot co-bind the listener; TCP
retains systemd's reuse policy for safe restart after accepted connections.
Extras, duplicates, name substitution, root execution, and ordinary per-user
descriptor inheritance are rejected.

The daemon may start without upstream DNS configuration. A separate private
mode-0600 Unix socket accepts only the root supervisor through peer credentials.
The bounded, versioned protocol publishes the first resolver plan and later
strictly increasing updates without command-line secrets or stale unit
arguments. Malformed, oversized, unauthorized, substituted, or replayed plans
are rejected.

The daemon has no capabilities. Its unit enables `NoNewPrivileges` and applies
systemd filesystem, device, namespace, kernel, address-family, personality,
realtime, and executable-memory restrictions. The narrow root resolver service
does not parse DNS or HTTP, read mappings, or hold user keys. It is restricted
to the capabilities and paths needed for D-Bus resolver mutation and the
private control channel.

### Install immutable, ownership-checked generations

`remap-linux-system` implements native install, update, rollback, and uninstall
without invoking external commands. Each installation stages one immutable
generation under `/usr/libexec/remap/generations/<uuid>` and records every
artifact's relative path, mode, byte length, and SHA-256 digest in a bounded
root-owned installation record. Source binaries must be bounded, non-writable
ELF regular files owned by root or the activating user. Text assets must be
bounded UTF-8 regular files; LICENSE and NOTICE must be byte-identical to the
canonical project files.

One atomic `current` symlink publishes the generation. Exact owned symlinks
expose the CLI, 22 manpages, Bash/Fish/Zsh completions, LICENSE, NOTICE, and five
systemd unit definitions. Five definition links and five matching target-wants
links are one exact create-only publication set; no D-Bus enable operation may
replace an existing owner. Update keeps the active and immediately previous
generations, proves supervisor health after publication, and rolls back the
exact prior generation if publication or activation fails. systemd reload,
start, stop, and unit-state checks use the typed D-Bus manager API. Definition
and wants-link ownership is verified directly before every manager reload or
runtime acceptance.

Every generated socket, daemon, and resolver unit also executes the native
`authorize-runtime` gate before startup. Durable `active` and health-accepted
`pruning` records authorize ordinary boot. A live `published`, `rolling_back`,
or `uninstalling` transaction requires a generation-bound runtime lease held by
the native installer; the kernel releases that lease on process exit and `/run`
does not survive reboot. A failed transaction therefore cannot silently retake
ports or resolver ownership during boot.

The version-5 installation journal is durable before the first generation or
product byte. `staging` records make every exact artifact subset discoverable;
recovery verifies the manifest, ownership, type, mode, length, and digest of
each node before removing it. Publication remains rollback-oriented until
health acceptance. A durable `rolling_back` phase records the exact next
compensating effect, including restoration of the prior `current` link and
installation record. A separate durable `pruning` phase makes second-update
generation removal replayable without losing the exact prior active record.

Uninstall verifies all digests and links before effects, restores resolver state
before stopping the daemon, invalidates its private plan, and then advances a
durable next-effect journal through strict service shutdown, exact definition,
wants-link, and public-path removal, manager reload, subset-idempotent
generation removal, and final record removal. A crash immediately before or
after an effect replays that same effect;
substituted or foreign nodes block recovery rather than being deleted. A crash
after final record removal leaves bounded, digest-bound lifecycle-state residue
that status exposes and only a separately previewed recovery removes. The
per-user mapping database remains user data and is not deleted.

Lifecycle and resolver serialization inodes live in the root-owned mode-0700
`/run/remap-lifecycle-authority` directory. Product uninstall and recovery never
unlink that authority directory or either lock. This prevents an old lock holder
and a newly created path inode from simultaneously authorizing mutations. The
ephemeral authority disappears only with the operating system's `/run` lifecycle.

### Bind source review, approval, and commit

The public source workflow never executes a user-writable helper as root. It
opens and reviews the built helper, stages the exact SHA-256-matched bytes with
absolute operating-system tools into an unpredictable, exclusive root-owned
directory under `/run`, pins the destination inode and metadata, and rechecks
that identity before and after every invocation. The bootstrap directory and
helper are removed only after their exact identities are revalidated. Any
unknown helper outcome is reported as requiring explicit recovery.

Crash residue under the exact randomized bootstrap namespace is never removed
by ordinary install, update, or uninstall. Native status detects at most 32
inactive candidates after verifying exact directory and helper ownership, mode,
link count, device, inode, SHA-256, and bounded approved extended attributes.
The bootstrap holds advisory leases across staging, execution, and cleanup;
native inspection excludes a live helper. `make recover` separately previews
and token-binds each exact inactive path, revalidates it while holding the
native lifecycle and runtime locks, removes only that helper and directory,
and durably synchronizes `/run`.

The reviewed helper is copied into an anonymous sealable Linux file, sealed
against write, growth, shrink, and further seal changes, and revalidated by
descriptor before its `/proc/<pid>/fd/<fd>` path is given to the absolute GNU
install tool. The original user path is never the privileged copy source.

The same authority extends to generation inputs. The workflow opens all 26
binary and asset sources with no-follow semantics, requires one hard link and
non-writable exact metadata, and holds every descriptor through preview,
approval, and commit. A language-neutral SHA-256 manifest covers the sorted
logical path, installed mode, byte length, and bytes of every source. The
native helper recomputes that digest from descriptor-rooted reads during
preview and again under the installation lock before any effect. The complete
digest is a typed preview field and an independent approval-token input.

`status` and `inspect` return a bounded versioned document containing native
distribution, resolver-owner, link-candidate, installation, recovery, and
service state. Only one candidate with usable non-loopback DNS and
`DefaultRoute=true` may be selected automatically; every ambiguous case
requires an explicit link index. Install, update, uninstall, and recovery have
separate previews. Their 64-character approval token binds the deterministic
generation, exact publication set, resolver and service state, recorded
directory provenance, recovery state, and classified effects. Commit
recomputes the plan before opening the transaction and again while holding the
native lock. Recovery is never implicit.

Generic manual and completion directories are bounded allowlisted lifecycle
state. Each generation records whether an exact root-owned mode-0755 directory
preexisted or Remap created it. Remap-created directories receive a random
root-controlled ownership-marker extended attribute and record that marker with the
filesystem inode and birth identity. A preview includes every
created or removable directory as a typed publication. Update rejects identity
loss rather than laundering it into pre-existing provenance. Uninstall removes
only recorded Remap-created directories after exact identity revalidation and
only when their contents remain Remap-owned; shared, foreign, replaced, and
unverifiable directories are preserved.

## Authority and multi-user behavior

Resolver interception and ports 53 and 80 are host-wide. One dedicated daemon
account and one root-owned activation record represent one activating user. A
second activation receives an ownership conflict. Supporting simultaneous user
authorities requires a separate broker and decision record; storing a second
host-wide record would not make the collision safe.

## Verification evidence

Automated adversarial tests cover exact state round trips, bounds, malformed
addresses and domains, unknown schemas and fields, digest tampering, weak file
metadata, hard-link and symlink attacks, multiple scopes, compare-and-restore
conflicts, ambiguous D-Bus outcomes, activation abort, generation rebase,
descriptor substitution, inherited-environment rejection, private-channel
authorization, dormant startup, plan update, replay, restart, and deterministic
hardened units. Root-only lifecycle tests inject failures around the individual
directory create, mode, parent synchronization, file create, write, mode,
content synchronization, no-replace publication, and directory synchronization
primitives used by first-install and update staging. Journal-model tests verify
the rollback and uninstall next-effect order, but do not stand in for a live
crash replay of systemd and resolver effects. Root tests also reject foreign and
substituted generation nodes and exercise three contenders against the
permanent lifecycle and resolver lock inodes. Full effect replay remains a
release acceptance gate.

The capability-3 artifact passed a fresh disposable Ubuntu 24.04
systemd-networkd install, cold-reboot, and uninstall sequence after the
adversarial transaction review reached P0/P1 clean. Installation bound link 2,
`eth0`, and systemd-networkd into the generation and activation records; system
DNS, mapped HTTP, generated assets, non-root service identity, and exact socket
ownership passed. Cold boot retained the same activation identity and exact
manager, interface, captured baseline, owned/live fields, and daemon plan while
advancing once to a legitimate strictly newer resolver generation. Eleven
one-second samples were byte-identical afterward, and PID 1 reported one clean
resolver start with no stop, failure, or restart. Exact uninstall restored
`192.168.5.2`, non-route-only `attlocal.net`, and the prior default-route value;
removed every owned product, unit, publication, activation, and install path;
and retained user mappings plus the deliberately permanent authority locks.

The broader update and NetworkManager evidence below was collected with an
earlier capability-2 transaction revision. It remains evidence for the native
integration, but the complete capability-3 update/fault and NetworkManager
matrices must still be rerun before a production claim.

A disposable Ubuntu 24.04 systemd VM exercised the managed
systemd-networkd path from PID 1:

- installation enabled and started the generated socket and service units;
- the daemon ran as a non-root account while serving inherited UDP 53, TCP 53,
  and HTTP 80 listeners;
- the supervisor captured `192.168.5.2`, `attlocal.net`, and the exact default
  route, then resolved a Remap name through the host stub with `dig`;
- an HTTP mapping reached the expected upstream with `curl`;
- a clean shell discovered `/usr/bin/remap`, help, status, doctor, all manuals,
  and the installed policy files;
- daemon and resolver-supervisor restarts retained mappings and forwarding;
- two updates switched the canonical generation, retained exactly two
  generations, and pruned the oldest;
- a native networkd change to `1.1.1.1` and `transition.test` caused a durable
  resolver rebase, a private daemon-plan update, and successful DNS after both
  the transition and a subsequent restart;
- a deliberately invalid-link update rolled back to the exact prior generation
  while DNS and HTTP remained available; and
- uninstall restored the post-transition resolver state exactly, removed the
  CLI, manuals, completions, policy files, units, publications, generations,
  and records, and left only the user's mapping data.

The same environment also demonstrated fail-closed behavior: an early direct
resolved mutation was rejected because networkd owned the link, an ambiguous
activation was recovered through the abort phase, and interrupted uninstall
ordering did not overwrite the resolver record. These failures drove the
manager adapter and transaction ordering rather than being waived.

A second live fixture installed NetworkManager 1.46 and activated a real
NetworkManager-managed dummy device while the original networkd uplink remained
untouched. It exercised the same PID-1 installer and data plane through
NetworkManager's applied-connection D-Bus API. System `dig`, mapped HTTP, and
non-root daemon checks passed. Reapplying a changed connection from
`1.1.1.1`/`nm-before.test` to `9.9.9.9`/`nm-transition.test` advanced the durable
generation, republished the private upstream plan, and reapplied loopback
ownership. A restart, two updates with exact two-generation retention, and an
invalid-link update rollback all retained DNS and HTTP service. Uninstall
restored the post-transition DNS, domain, and default-route values exactly and
removed every owned installation and state path. The original networkd
`192.168.5.2`/`attlocal.net` state and both systemd-resolved and the fixture DNS
service remained active.

The NetworkManager proof also forced two recovery cases. The first reapply
showed that NetworkManager 1.46 normalizes the modern and legacy DNS properties;
the durable zero-step record recovered the ambiguous live effect and restored
the prior connection. A second run caught the legacy IPv4 integer's native byte
representation. It again restored exactly before the final normalized model was
accepted. Those failures are retained as adversarial model tests.

This evidence is a live vertical-slice proof, not a supported-distribution
matrix or a blanket Linux production claim.

## Known limitations and required acceptance

- The NetworkManager proof used a real managed dummy device, not an Ubuntu
  Desktop image with the primary uplink, Wi-Fi roaming, or an active VPN. Those
  ordinary Desktop paths still need live acceptance. A global DNS policy that
  prevents the applied connection from producing Remap's exact resolved state
  fails closed during activation.
- VPN and simultaneous split-DNS scopes, link replacement, sleep/resume, and
  multiple eligible links need native event-driven selection and live recovery
  proof. The current install requires one explicit stable link.
- HTTPS listener activation and local certificate authority integration are not
  in this slice. Port 443 is therefore not installed.
- Listener ownership is IPv4 loopback only. Existing local port-53 or port-80
  owners are preserved and rejected by native first-install reservation;
  policy for deliberately sharing or replacing them is outside this slice.
  Dual-stack behavior still needs explicit design and tests.
- Systems without systemd-resolved, and distributions without compatible
  systemd-networkd or NetworkManager semantics, remain unsupported. Remap will not hide a
  `resolv.conf` rewrite or command-line fallback behind this API.
- Native status detects missing resolver authority and active filesystem
  integrity drift, but the current recovery contract deliberately blocks those
  cases for administrator review instead of guessing at repair ownership. A
  separately previewed, exact repair-or-preserve workflow is still required.
- A primary-uplink Ubuntu Desktop image, additional distributions and systemd versions,
  browser acceptance, native SSH and database clients, VPN transitions,
  suspend/resume, crash loops, abrupt power-loss recovery, and package-manager
  integration remain required release evidence.

## Consequences

Linux now has reversible systemd-networkd and NetworkManager implementation
vertical slices over systemd-resolved, with a non-root traffic plane and a
narrow native privileged boundary. Current-journal live acceptance is still a
release gate. The record, recovery, immutable-generation,
and private-plan machinery is deliberate permanent complexity: without it,
“disable” and “uninstall” would be best-effort cleanup rather than verified
restoration.

Remap must continue to report unsupported native ownership honestly. The next
Linux milestone is broader primary-uplink, VPN, lifecycle, and distribution
acceptance, not a fallback that weakens resolver ownership.
