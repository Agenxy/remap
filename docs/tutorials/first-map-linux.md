# First native mapping on Linux

This tutorial exercises the installed Linux product through the native
resolver owner, system DNS, and exact removal. It does not treat a built binary,
an open port, or a direct query to a private listener as proof that the host is
using Remap.

## Supported starting point

Use a systemd host with systemd-resolved active, Linux memfd seals, and an
accessible procfs descriptor view. `make setup-install` proves the sealed-source
bootstrap boundary before any product build or administrator request. The
selected interface must be owned by a backend Remap reports as supported.
Remap does not edit `/etc/hosts`, replace `/etc/resolv.conf`, or run
`resolvectl`, `nmcli`, or an ad-hoc shell installer behind this workflow.

Run these commands as the non-root person whose mappings should control the
host. The lifecycle task asks for administrator authorization when it reaches
the native root boundary. Do not run the complete Make workflow from a root
shell.

Minimal Ubuntu 24.04 images do not include a compiler or `make`. Install the
host build prerequisites and the native resolver package before invoking the
Make front door:

```sh
sudo apt-get update
sudo apt-get install build-essential cmake pkg-config systemd-resolved
sudo systemctl enable --now systemd-resolved
```

These are Ubuntu operating-system packages, not Remap services. On another
supported distribution, install its equivalent compiler, linker, Make, CMake,
pkg-config, and systemd-resolved packages. If another local DNS service owns
Remap's required loopback listeners, the native preview stops before approval
or effects and identifies the exact conflicting address; choose which service
should own that listener rather than disabling it implicitly.

## Select one resolver scope

Linux resolver ownership is link-scoped. If native inspection proves exactly
one supported primary DNS link, Remap selects it. If several links are
candidates, the install stops before mutation and lists their numeric indexes,
interface names, native backends, and selection states. Rerun with the one you
intend Remap to own:

```sh
make setup-install
REMAP_LINUX_LINK=2 make install
```

If the link is missing, ambiguous, or unsupported, the native preflight stops
before mutation and reports the observed distribution, resolver environment,
interface, manager backend, and a concrete next action. Remap never guesses a
different LAN, VPN, or split-DNS scope.

Read the complete install preview. It identifies the selected link and backend,
captured resolver-state classification, immutable generation, public paths,
systemd units, service transitions, and recovery state. At an interactive
terminal, type the exact `approve <token-prefix>` phrase shown after the
preview. EOF and every other response cancel the operation without mutation.

An automation controller receives the same preview but must return the complete
64-character token on standard input. It cannot use an environment variable,
command flag, or `--yes` shortcut. The native root helper recomputes the token
before effects and again while holding the lifecycle lock, so a stale review
cannot authorize changed state.

Before the preview, Remap discloses a narrow bootstrap step. It copies the
descriptor-pinned helper bytes into a sealed anonymous Linux file, verifies its
seals and exact `/proc/<pid>/fd/<fd>` identity, and gives the privileged
operating-system installer only that immutable descriptor path. The mutable
build pathname never crosses the administrator boundary. Remap then verifies
the root-owned staged helper's exact digest and non-writable metadata around
every privileged call and removes only that copy and directory on normal exit.
The active helper remains leased, and `/run` is leased across staging and exact
cleanup, so recovery cannot mistake current work for crash residue.

The install preview prints the complete canonical SHA-256 manifest for all 26
descriptor-pinned binaries and assets. That digest remains pinned through
approval and commit and is independently included in the native approval
token. The bootstrap copy still cannot authorize installation.

## Verify the installed surface

Open a fresh shell and check the public command, runtime, manuals, and generated
completion surface:

```sh
command -v remap
remap --version
remap doctor
man remap
remap completions zsh >/dev/null
```

The native install must make `command -v remap` select `/usr/bin/remap`. The
doctor result must identify a complete native installation, authenticated
daemon control, active DNS and HTTP listeners, and the current registry
revision. The native lifecycle status separately identifies the selected Linux
backend. A receipt or unit file alone is not acceptance.

Some minimized Ubuntu images intentionally divert `man` to a message that asks
the administrator to run `unminimize`. Remap still installs the complete manual
family on those hosts, and `remap manpage` can emit the current top-level source
without changing the operating-system image. Run Ubuntu's `unminimize` command
if you want its normal system manual viewer and database restored.

## Map a DNS name and a routed service

Choose a synthetic suffix that a browser will send through normal system name
resolution:

```sh
remap set resolver.remap.test 192.0.2.25
remap set app.remap.test http://127.0.0.1:8080
remap resolve resolver.remap.test
```

Then use ordinary clients, not a direct private-listener address:

```sh
getent ahosts resolver.remap.test
curl --fail --show-error http://app.remap.test/
```

The address example uses a documentation-only IP. Replace it with a service you
control when checking reachability. The HTTP example assumes a local service is
already listening on port 8080. Certificate, origin, redirect, cookie, and
content-security failures remain visible by design.

## Update and interruption recovery

An update reuses the installed account, group, owner UID, and link. It presents
a new exact preview and requires a fresh state-bound approval:

```sh
make update
```

If any lifecycle operation is interrupted, install, update, and uninstall stop
without implicitly recovering it. Review recovery separately:

```sh
make recover
```

Recovery identifies the interrupted installation phase and generation, then
enumerates the exact resolver, publication, and service effects required to
converge it. For verified bootstrap crash residue, the same preview lists every
canonical `/run/remap-bootstrap-<32 hex>` directory, device and inode, exact
mode and owner, bounded extended-attribute identities, and the optional
helper's size, link count, and full SHA-256. Its separate token binds that typed
snapshot and the exact helper-then-directory removals. Commit rescans under the
native lock, excludes any live leased helper, and fails closed if an approved
identity changed. Normal install, update, and uninstall never remove prior
residue implicitly. Interrupted native state files are likewise listed by exact
path, byte length, and full SHA-256 identity before their bounded cleanup is
approved. After recovery verifies that no unfinished lifecycle state remains,
rerun the original command to obtain a new preview.

## Remove native Remap

Remove only the manifest-owned system installation while preserving the user's
mapping database:

```sh
make uninstall
```

Review the exact resolver restoration, unit removal, public paths, and retained
user-data statement before approving. A successful uninstall restores the
latest native resolver state that Remap owns, removes the CLI, manuals,
completions, notices, units, publications, immutable generations, and lifecycle
records, then verifies the exact native resolver restoration and clean final
lifecycle status. It does not depend on an Internet hostname being reachable.
Unknown or modified paths fail closed instead of being deleted.

Uninstall intentionally retains only two empty synchronization files in the
root-owned volatile `/run/remap-lifecycle-authority` directory. Stable lock
inodes prevent two lifecycle commands from bypassing one another during removal
and recreation. They contain no mapping data, credentials, executable code, or
product configuration and disappear when the host clears `/run`.

Complete mapping-data deletion is a separate user-authorized operation and is
not part of `make uninstall`.
