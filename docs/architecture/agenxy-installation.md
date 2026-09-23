# Agenxy installation discipline

Status: adopted 2026-09-22. Canonical copy kept identically in every Agenxy repository.

Every Agenxy product installs itself: a binary in a place the operating system will
run it, a background service the owner can start and stop, and an identity the machine
displays. This document is what an installer must do, and what it must never do. It
exists because installation failures on this platform do not look like failures. They
look like success: the service manager reports the job running, the process exists, the
log is empty, and nothing works.

Every rule below was measured on the owner's hardware on 2026-09-21 and 2026-09-22
while installing Compass, Supgang and Remap. None is theoretical.

## Why this is one document and not one crate

A shared installer crate would make every product depend on one, and the sovereignty
invariant is that no Agenxy tool has a critical dependency on anything outside itself.
So this is a specification with required behaviours and required tests, implemented
separately in each product, and enforced by each product's own quality gate. The gate
is the part that stops a future agent getting it wrong: a rule nobody checks is a
comment.

## The failures this prevents

### 1. A program in a directory the platform guards never starts

macOS guards `~/Desktop`, `~/Documents`, `~/Downloads` and iCloud Drive with per
application consent. A launchd agent holds no consent for them. A daemon whose program
lives there **hangs inside `dyld`, before `main`**, opening its own binary:

```
dyld4::prepare → makeLaunchLoader → getOnDiskBinarySliceOffset
  → mapFileReadOnly → open → __open
```

`launchctl print` says `state = running`, `last exit code = (never exited)`, the process
is in `ps`, the log file is empty, and the service serves nothing, for ever.

**Required:** an installer refuses a program path inside a guarded directory, names the
directory, and says where to put it instead. It refuses at install time, while the owner
can still choose, never at first start.

A fixed, non-configurable installation root outside those directories satisfies this
rule by construction if the installer derives every service program from that root,
rejects a different program in the definition, and refuses symlink traversal into an
owner-controlled tree. A source checkout under Desktop is not the installed program.
Test the rejection with a guarded path and name the admitted destination in the error.

### 2. Overwriting a running binary in place produces one that cannot start

Every arm64 Mach-O is ad-hoc signed by the linker, and the kernel caches the code
signature by path. Writing new bytes over an existing binary invalidates that cache
against the file's new content, and the next execution is **killed at launch**:

```
$ cp new/supgang ~/.local/bin/supgang && supgang --version
$ echo $?
137
```

Identical bytes run correctly from another path. The symptom is silence: no message, no
log, exit 137.

**Required:** an installer never writes over a binary in place. It writes a new file and
renames it, or removes the old path first, so the installed program always has a fresh
inode. The same rule applies to any signed bundle.

Prefer immutable generations: create every file exclusively in a private stage, verify
its manifest, then publish the generation and exchange its public links atomically.
Verify declared files, hashes, modes and ownership before publication; a matching
generation name alone is not evidence of a complete image. Do not overwrite a generation
that already exists. A rollback must retain enough verified prior state to restore it.

### 3. A service manager releases a job later than it says it does

`launchctl bootout` returns before launchd has finished tearing the job down.
`launchctl print` then reports `state = SIGTERMed`, and a `bootstrap` inside that window
fails:

```
Bootstrap failed: 5: Input/output error
```

The old job is stopped, the replacement is refused, and **the product is left down**.
This is reachable from any stop-then-start operation: install over an existing
installation, refresh, and restart.

**Required:** after asking a manager to stop a job, an installer waits, bounded, until
the job is actually gone before starting the replacement, and fails saying so if it
never goes. A stop-then-start operation that leaves nothing running is a bug, not a
partial success.

Observe the exact departing job while waiting. If another program or definition takes
its label, stop with an ownership collision instead of stopping or adopting it. Apply
this contract to installer helpers as well as the product daemon. Job disappearance
allows replacement to begin; acceptance still requires the replacement to answer its
authenticated protocol and the intended system effect to be observed. If replacement
fails, restore the prior generation or report the unresolved recovery state explicitly.

### 4. A definition file replaced non-atomically can be read half-written

A service manager may read a definition at any moment.

**Required:** definitions are written to a temporary file in the same directory, synced,
and renamed over the destination. A failed write leaves the previous definition intact.
Every definition an installer writes is byte-deterministic from its inputs, so the same
settings produce the same file and a diff means a real change.

An atomic exchange is also valid. Verify the displaced definition before disposal, and
retain it or its verified immutable source until the transaction commits, so rollback
cannot overwrite an unrelated replacement. Sync the
containing directory as well as the staged file, and verify ownership and mode. A
definition loaded from a boot-time public copy belongs to an immutable generation only
when its program and its bytes match that generation's definition.

### 5. Embedded assets outside the crate root publish a package that does not build

`include_str!("../../../assets/…")` compiles locally and passes every test. `cargo
package` carries only what is under the crate root, so the published crate is missing the
file and fails to build for everyone who installs it.

**Required:** an asset a crate embeds lives inside that crate. Each workspace's gate runs
`cargo package` so this is caught before publication, not after.

Generated `OUT_DIR` assets are permitted when their build inputs are packaged inside the
crate. Verify the extracted archives with their dependencies, without access to the
source checkout; producing an archive with `--no-verify` alone is insufficient.

### 6. An upgraded client meeting an older running service must say so

After an upgrade the old service is still running. A client that expects an endpoint the
old build does not serve must report that plainly, not fail parsing a page it did not
expect.

**Required:** version-sensitive client calls check what answered them, and name the
mismatch and its remedy.

## What an installer must also do

- **State what is installed, and whether it is the thing that is running.** A service's
  reported pid and the pid of the process actually answering its socket are two facts,
  and they disagree exactly when it matters. Report both, and say which.
- **Report manager state the definition does not contain.** `launchctl disable` and
  `systemctl is-enabled`, and systemd's lingering, persist outside the definition file.
  An installer that does not report them leaves the owner with a service that silently
  refuses to start.
- **Never change persistent manager state as a side effect.** Enabling lingering, or
  leaving a job disabled, is the owner's decision. Report, do not decide.
- **Name every identity the machine will display.** The service label, the unit
  description and journal identifier, the log file path. A manager default where a
  product name belongs is a defect.
- **Refuse a configuration the daemon itself would refuse**, at install time, rather than
  writing a definition that cannot start.
- **Keep privileged work to the smallest step that needs it**, with the owner's approval
  bound to the exact change, as Remap's lifecycle does.
- **Revalidate approval under the transaction lock.** Bind the preview to the operation,
  source manifest, previous generation, publications and observed system state. State
  drift invalidates approval. Journal effects durably and verify recovery and rollback;
  a token is not a replacement for device-owner authentication.
- **Declare lifecycle capabilities for each distribution.** A source image and a prebuilt
  image may carry different helpers. Verify every declared component before publication,
  state which lifecycle interface is available, and distinguish an intentionally absent
  client from a damaged image when evidence permits. A missing client must never direct
  the owner back to a recovery command that depends on that same client.

## Required tests

Each product's suite must contain, named so a regression names itself:

1. A guarded-directory program is refused, with the directory in the message.
2. A definition is replaced atomically, leaving no temporary file and the correct mode.
3. Each definition renderer is byte-exact against a literal, and deterministic.
4. Each renderer refuses control characters and anything the manager would silently alter.
5. Each manager status parser reads its own fields at the right depth, and is not fooled
   by a nested one.
6. `status` reports "installed but not running", "running but not the service's", and
   "disabled by the owner" distinctly.
7. Every pure function above is tested **on every platform**, not only the one it targets.
8. Delayed teardown, teardown timeout and a different job appearing under the departing
   label cannot lead to premature bootstrap or mutation of the other job.
9. A missing declared executable prevents generation publication; an existing executable
   or symlink cannot be truncated by a staging copy.

## What this document does not yet require: integrity

Everything above is about **reliability**: an installation that works, and that says so
truthfully. None of it establishes **what** is being installed.

As of 2026-09-22, Compass and Supgang install a binary the owner already has, by copying
it, with no verification of its origin. Remap verifies a generation's manifest, hashes,
modes and ownership before publishing it, which is far stronger, but the manifest is
still one the same installer produced: it detects a damaged or incomplete image, not a
substituted one. No product yet refuses an artifact that is intact but not the owner's.

The sovereign answer is not an Apple Developer certificate or any other issuer outside
the owner's control. It is the hive root: Supgang already carries a signed-release
mechanism, and the sovereign-trust roadmap names code signing as a root-granted role,
where a key is authorised to sign named products and members pin the role rather than a
bare member chain. The end state is that every Agenxy product installs only artifacts
signed under that role, and refuses anything else by default.

Until that exists, this document claims reliability and says plainly that it does not
claim provenance. A product must not describe its installation as verified on the
strength of the rules above alone.

## Enforcement

Each repository's quality gate must:

- run `cargo package` for every publishable crate;
- run the installer's own tests on macOS and on Linux;
- reject a source file that writes over an existing binary path without removing or
  renaming it first, where that is statically detectable.

A product that cannot yet satisfy a rule says so in its own documentation, naming the
rule. Silence is not an exemption.
