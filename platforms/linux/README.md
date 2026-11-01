# Linux platform

Remap has native Linux implementation vertical slices for a single explicit
systemd-networkd- or NetworkManager-managed link exposed through
systemd-resolved. The current transaction revision is not yet production-ready
or live-accepted.

The implementation is split along privilege boundaries:

- `remap-linux` provides typed systemd-resolved, systemd-networkd, and
  NetworkManager D-Bus adapters; exact reversible resolver transactions;
  descriptor-rooted root-owned records; resolver-owner detection; lifecycle
  policy; and hardened systemd socket contracts.
- `remap-linux-system` is the narrow root lifecycle program. It installs,
  updates, rolls back, uninstalls, supervises resolver ownership, and delivers
  bounded upstream plans over a root-authenticated private Unix socket.
- `remapd` runs as a dedicated non-root account. It adopts exact systemd-owned
  DNS and HTTP descriptors and continues to own mapping, DNS, HTTP, and control
  protocol behavior.

The native installer publishes immutable generations, the `remap` command, 18
manpages, Bash/Fish/Zsh completions, LICENSE, NOTICE, and hardened systemd units.
Unit definitions and their target-wants links are exact create-only
publications; D-Bus is used for reload, start, stop, and state observation, not
forceful enablement. Remap-created public directories carry a random
root-controlled ownership marker plus filesystem birth identity, so replacement
is detected rather than inferred from a pathname.
First install bind-probes the complete fixed loopback listener set during
preview. Commit creates its reservation during initial re-prepare and carries
those same descriptors through locked approval validation and staging,
releasing them only into one systemd activation transaction. An existing DNS or
HTTP listener is preserved and reported as a typed conflict before Remap
publishes or starts anything. Forward update exact-quiesces the runtime, stops
each socket, and immediately reserves the complete listener set. After reload it
resets hidden systemd start-rate state without runtime authority, then releases
the full reservation into one captured start transaction. This bounded pause
prevents traffic-triggered daemon startup against a partial namespace. Replay
carries and tops up partial reservations while restoring the prior current
link and unit definitions. It transfers every missing descriptor into PID 1,
revokes start authority, and proves the daemon has no pending systemd job before
starting the prior service. Failed or ambiguous
systemd starts settle under the held authority; a failed first install proceeds
directly to absent rollback instead of depending on the broken unit. These
listener-ownership guarantees cover the exact retained PID 1 sockets or held
process reservations; abrupt-power replay remains an explicit acceptance gap. On
adoption, Remap clears and verifies UDP address reuse to prevent a later
reuse-enabled DNS process from co-binding the listener, while retaining TCP
reuse semantics needed for clean restarts.
It preserves the immediately previous generation for transactional rollback.
Uninstall restores the latest captured native resolver state before removing
only verified Remap-owned files; it deliberately retains user mapping data.
Generation staging and uninstall are durably journaled before their first
effect. Recovery removes only manifest-matched partial artifacts, replays the
recorded next uninstall effect, and requires a separate state-bound approval.
Stable lifecycle and resolver lock inodes remain under the ephemeral root-owned
`/run/remap-lifecycle-authority` directory so cleanup cannot split transaction
serialization.

Resolver capture and rebase are manager-readiness gated. The generated
supervisor pulls `network-online.target`, requires systemd-networkd to report
the selected link `configured` or NetworkManager to report its exact device
managed and `activated`, and requires three identical complete observations
over one second for startup and lifecycle restoration. After one exact Active
owner exists, bounded native-manager signals trigger a fast three-observation
steady-state check; a one-second observation remains the missed-signal safety
audit instead of becoming a high-frequency polling loop. The fast path watches
only the exact resolved-link object and the selected managers' owner changes,
blocks each ingress stream once one notification is pending, drains at most 64
already-ready signals per batch, and coalesces floods to at most four
event-triggered checks per second in addition to the audit. The audit keeps
running while a failed signal monitor reconnects from a fresh bus connection.
The complete startup transaction and later blocking manager calls run through
single-command bounded workers. Shutdown stops at read-only checkpoints; after
a native effect begins it waits for exact publication, journaled compensation,
or a surfaced recoverable result and retains that outcome before returning. No
worker can mutate afterward and no unbounded work queue can form. The final observation
is compared again before any durable record replacement. Capability-3
generations and activation records bind the exact manager kind and stable
interface name, and the generated unit repeats that identity on every
supervisor start. Partial DNS, domain, and default-route arrival during boot—or
a late manager/interface change—therefore cannot silently replace the exact
state later restored on uninstall. Update rollback and uninstall keep the full
stabilized observation path rather than a one-shot rebase.

The capability-3 artifact has fresh disposable Ubuntu 24.04 systemd-networkd
evidence for clean installation, exact manager/interface-bound activation,
system DNS and HTTP routing, generated assets, a cold reboot, and exact
uninstall. Boot produced one legitimate strictly newer resolver generation
under the same activation identity; the manager, interface, captured baseline,
owned/live state, and daemon plan remained exact, then stayed byte-stable for
more than ten supervisor ticks with no unit restart. Uninstall restored the
original DNS, domain, and default-route fields and removed every owned product
path while retaining user mappings and permanent authority locks.

An earlier capability-2 transaction revision exercised two-update
pruning, sustained-traffic cutover, native networkd DNS transition and reverse,
manual daemon/supervisor restarts, and deterministic failed-update rollback. A
real NetworkManager 1.46 managed-device fixture exercised applied-connection
compare-and-swap, normalized modern and legacy DNS fields, exact transition
rebasing, restart, update pruning, failed-update rollback, and exact uninstall
restoration without disturbing the original networkd uplink. Those results
remain integration evidence, but the corresponding capability-3 update and
NetworkManager matrices are still release gates.

A primary-uplink Ubuntu Desktop image, Wi-Fi roaming, VPN and multi-link split
DNS, IPv6 listeners, HTTPS/port 443, non-resolved hosts, browser/native-client
acceptance, power-loss recovery, and wider distribution packaging still require
implementation and live proof. Remap does not shell out to resolver tools or
silently edit `/etc/hosts` or `/etc/resolv.conf`.

Active installation-integrity drift or a missing resolver-authority record is
reported as recovery-required but currently blocks automatic recovery. Remap
will not guess that a replacement path or unowned runtime belongs to it; an
exact, separately approved repair-or-preserve workflow remains required.

See
[`ADR-0008`](../../docs/architecture/ADR-0008-linux-resolved-and-systemd.md) for
the ownership model, verification evidence, and exact remaining limits.
