# Agenxy installation discipline

Status: adopted 2026-09-22. Canonical copy kept identically in every Agenxy repository.

Every Agenxy product installs itself: a binary in a place the operating system will
run it, a background service the owner can start and stop, and an identity the machine
displays. This document is what an installer must do, and what it must never do. It
exists because installation failures on this platform do not look like failures. They
look like success: the service manager reports the job running, the process exists, the
log is empty, and nothing works.

Every rule below was measured on the owner's hardware from 2026-09-21 to 2026-09-23
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

**Required:** an installer never writes over a binary in place, and the installed program
always has a fresh inode. Prepare and validate the replacement first, then publish it by
an atomic rename or a generation switch. Removing the old path before the replacement is
ready is **not** sufficient on its own: it leaves a window with nothing installed and
nothing to go back to, and a failure inside that window has destroyed the working
installation to no purpose. The same rule applies to any signed bundle.

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

### 7. A program that loses its signing identity cannot say its own name

Supgang embeds its product name and network explanation, and its installer signs with
`org.agenxy.supgang.runtime`, the identifier in its plist. Twice, a hand-copy from
`target/release` replaced that installed signature with the linker's ad-hoc signature.
macOS then asked the owner:

> Allow "<unknown>" to find devices on local networks?

Compass had no identity to preserve. Its installed daemon reported
`Identifier=compassd-007b5d2c6695c2fd` and `Signature=adhoc`; `otool` found no
`__TEXT,__info_plist` section. A service asking to find devices on the network could
name neither itself nor its reason for being there.

**Required:** an installed program keeps the code signature and signing identifier its
product chose. The installer either signs what it installs or preserves an existing
product signature, and verifies it before publication. A plain copy from a build
directory does not preserve the installed product's signature. The embedded plist and
the signing identifier agree; each product asserts its own identifier in a test rather
than accepting the linker's default. A service that uses the local network embeds its
name and a plain explanation in `NSLocalNetworkUsageDescription`.

Development never requires a human. Without a signing identity, a contributor may
install the linker's ad-hoc signed binaries; the installer says plainly that macOS
cannot name them in a permission prompt. This exception is stated, never mistaken for
an installation carrying the product's chosen signing identity.

### 8. A gate that has only ever run on a developed machine tests the machine, not the clone

Remap's development gate was split so it needs no network, no reviewed toolchain and
nothing installed outside the repository. It passed everywhere it was run. Run on a Mac
that had never held the repository, the first documented command failed:

```
mise ERROR Config files in ~/remap-gate-test/mise.toml are not trusted.
```

`make setup` began by calling the toolchain manager, which refuses to read a
configuration file it has not been told to trust, so every later call failed with it.
Past that, the quality gate handed a Swift linter a cache path under `target/` and
expected the linter to create the directory. It does not:

```
error: Specified cache file directory does not exist: .../target
```

Nothing has built at that point in the gate, so `target/` did not exist. Neither failure
is visible on a machine that has built the product before, which was every machine the
gate had ever run on.

**Required:** a development gate runs to completion in a fresh clone on a machine with
no product state: nothing built, no toolchain configuration trusted, no signing identity,
and a keychain that cannot be unlocked. It asks nothing of anyone, and it needs no
network where nothing is actually missing: a private tool home built to hold generated
configuration shares the machine's package cache rather than discarding it. Whatever the
gate needs, the gate creates: a directory it hands to a tool, and the trust a toolchain
manager requires to read the repository's own configuration.

**The fix belongs wherever the documented entry point reaches it.** Trust could not live
in the Python task runner, because that runner is itself invoked through the toolchain
manager and so needs the trust it would establish. It belongs in the prerequisite every
target declares. A fix placed in a layer the documented command never reaches is not a
fix, and a test that calls the inner function directly will not notice.

Both properties are proven by running the gate on such a machine, comparing signing
identities and trust settings before and after, and running it again with the package
manager forced offline. Reading the code and concluding it would pass is not proof.

**A clean-machine test is easy to contaminate with your own earlier attempt.** The first
run of this proof reported success at a path where the config had been trusted by hand
minutes before; the toolchain manager keys trust by **path**, so the entry survived
deleting and re-cloning the directory. Verify at a path never used before, delete the
state the tool keeps outside the repository, and confirm the starting condition rather
than assuming a fresh clone implies it.

### 9. A prompt the owner cannot answer is a prompt that should not exist

macOS asked:

> `remap-release-xar-signer` wants to sign using key **"stdin"** in your keychain.
> To allow this, enter the "login" keychain password.

Two defects in one dialog. The key is called `stdin` because the installer identity was
imported with `security import /dev/stdin`, and macOS labels an imported key after the
path it was read from; the product had chosen the name `Remap Release Installer` and put
it in the PKCS#12, and the dialog still showed none of it. And the dialog appeared at all
during a development build, because the key's access list did not name the program that
was asking, so a person had to authorise a step that protects nobody on the machine that
built it.

The owner is asked to weigh a request they cannot evaluate: not what is being signed, not
which key, not on whose behalf. The only safe answer to an illegible prompt is Deny, which
is also the answer that stops the work.

**Required:** every identity, key, credential, service and process a product creates is
named for what it is and which product it belongs to, in whatever field the platform will
show a person: the keychain item's label, the launchd label and unit description, the
signing identifier, the embedded plist, the process name, the log identifier. A platform
default, an input path, a temporary file name, or an empty field where a name belongs is a
defect, not a cosmetic one. Where a product's own name for a credential does not reach the
system dialog, that is a bug in how it was created, and it is fixed at creation.

**And:** a development path never asks for a credential at all. An authorisation that
protects whoever installs an artifact belongs to the release path, which is also the only
place a prompt can be legible, because there the owner is deliberately making something for
other people. See rule 8.

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
10. The product's plist parses with its version substituted on every platform; on macOS
    the built executable contains that plist. Its declared identifier equals the
    installer's signing identifier, and the product asserts the expected value. Signing
    and strict verification precede publication; a failure leaves the prior binaries
    intact. The development path installs without an identity and states its limitation.

11. The gate's own prerequisites are created by the gate: a cache directory named for a
    tool exists before that tool runs, and the toolchain configuration is trusted before
    any other call to that toolchain manager. The trust test asserts against the
    **documented entry point**, not only the inner function, and resolves that entry
    point's variables before looking for the tool's name in a recipe. A private tool home
    shares the machine's package cache. Each test fails when its fix is reverted, and
    that reversion is performed rather than assumed.

12. Every name the platform will show a person is asserted against the product's chosen
    value: the keychain label of any identity the product imports, the service label and
    description, the signing identifier, and the embedded plist name. A test that reads
    back a platform default, an input path such as `stdin`, or an empty field fails.

## What this document does not yet require: integrity

Everything above is about **reliability**: an installation that works, and that says so
truthfully. None of it establishes **what** is being installed.

As of 2026-09-22 the mechanisms exist unevenly, and each product's honest answer differs.

Remap's package path is the strongest and does check provenance: `install-package-macos`
verifies a detached signature over the package and installs from root-owned staging, and
the signing identity is one created locally and trusted by the administrator, so no issuer
outside the owner is involved. Its source path builds from a checkout instead, where
provenance is whatever that checkout was. Separately, every install publishes a generation
whose declared files, hashes, modes and ownership are verified first, which catches a
damaged or incomplete image but, being a manifest the same installer produced, not a
substituted one.

Supgang's TUF design decides this properly for Supgang's own updates, and nothing else
installs through it.

Compass copies a binary and verifies nothing about where it came from.

The sovereign answer is not an Apple Developer certificate or any other issuer outside
the owner's control, and most of it already exists. Supgang's `docs/security/secure-updates.md`
decides update trust through TUF: roles with thresholds, root and targets keys held
offline in separate physical custody, reproducibility checks before signing, a redacted
record of each ceremony, and a client that refuses rollback, freeze, fast-forward and
mix-and-match. It requires no account, no Agenxy server, no Apple service, no public
certificate authority and no public address to decide whether an artifact is authentic.

Note what that design also decides, because it constrains the answer: **update authority
is separate from hive authority**, and the hive root, device, transport and each TUF role
key must never be derived from one another or reused. The sovereign-trust roadmap's
code-signing role is therefore an authorisation the root grants to a separate signing key,
naming what that key may sign, which members pin. The root does not sign artifacts itself.

So the open question is narrower than it looks: this machinery guards Supgang's own
updates, and nothing else installs through it. What each product owes is to verify an
artifact against a pinned role before installing it, and to refuse anything else by
default. Until it does, its installation is not verified, whatever else is true of it.

### A sibling that supplies trust is a convenience, never a dependency

There is a tempting shortcut in all of this: let Supgang own identity, and have the other
products ask it for one. That is the wrong shape, and it is worth naming because the
sibling rule points at it. Each product mints and holds its own identity, in hardware
where the machine has it, and every install path works on a machine that has never heard
of any other Agenxy tool. A product that cannot sign or install without a sibling running
has made that sibling a single point of failure, which the sovereignty invariant forbids
whether the dependency is a company or a program of the owner's own.

What a sibling legitimately adds is the owner's **presence**. Installing on a machine
otherwise means someone standing at it to approve a trust decision, and across a gang of
computers that does not scale. A trust broker that can vouch for the owner remotely
removes the visit, not the sovereign path underneath it.

That places the requirements on the broker rather than on the product asking. Because it
is reached over a network, it must establish that the requester is the same owner before
it vouches for anything, and it must hold what it vouches with in hardware that will not
surrender it.

**The gap is measured, not hypothetical.** Remap's portable macOS package signs its
products on the machine that receives them, which needs a local code signing identity,
which needs a trust setting. Driven over SSH on a second Mac on 2026-09-24, the package's
own postinstall reached that step and stopped:

```text
Installation stopped safely: The operating system could not trust Remap's local
signing certificate: Operation not permitted.
```

The trust setting is not optional decoration. On macOS 27 an untrusted self-signed
identity does not appear in `security find-identity -v -p codesigning` at all, and
`codesign` refuses it with `errSecInternalComponent`; both were observed directly. And
`SecTrustSettingsSetTrustSettings` will not record one without interactive approval, under
sudo or inside the installer's own script sandbox. So this install path cannot complete
without a person at that machine, and no amount of privilege substitutes for presence.
That is the exact thing a broker exists to remove, and it is why the broker's own security
is the whole question: whatever it vouches with is what a person would otherwise have
travelled to approve.

**A broker removes the question, it does not answer the prompt.** There is a wrong way to
read the paragraph above: make the broker satisfy `authenticate-admin` on the owner's
behalf, by holding an admin password or by installing an authorisation plugin into
`SecurityAgent`. Both put the broker inside the operating system's authentication path, so
compromising it compromises administrative authority on every machine it serves, which is
the hijack this section exists to prevent. Reaching the same machine over Screen Sharing is
not an answer either: that is the same person typing the same password, at a distance.

The right shape removes the authorisation entirely. The target needs a trust setting only
because it *mints* a signature locally, and `codesign` refuses an untrusted identity. It
does not need one to *accept* a signature. Measured on 2026-09-24: a binary signed on one
Mac with a certificate the second Mac has never held passes `codesign --verify --strict`
there ("valid on disk", "satisfies its Designated Requirement"), reports its chosen
identifier, and runs. Remap's own product verifier asks for exactly that, a
certificate-backed identity under strict validation, and never for system trust.

So an artifact that arrives already signed by a key the owner's root certified needs no
local minting, no local trust setting, and no authorisation right. The broker's job is to
hold that signing key in hardware and to certify it to the machines that will accept it,
which is what a code-signing role granted by the root already means. Nobody authenticates
to macOS on the owner's behalf, because macOS is never asked.

This is designed rather than hypothetical: Supgang's ADR 0003 certifies subordinate keys
with a purpose and a stated custody, and its sovereign-trust roadmap names code signing as
a role the root grants, ordered immediately after the ADR 0003 primitive and the threshold
root. What is not yet true is that the primitive is operational: live identity is still
file held.

Not yet proven, and worth proving before this is relied on: that a launchd daemon loads,
and that a permission prompt names the product, under a certificate the machine does not
hold. Execution and strict verification are measured; those two are not.

### Supgang is the provider, and no tool may require it

Owner's direction, 2026-10-14: Supgang is the identity, certificate, permissions and
authentication provider for every Agenxy tool. It certifies that an action comes from an
authorised user, using that user's keys, identity and entitlements, so the owner does not
approve in person for each tool separately. Every tool supports it as that provider, and a
tool with a native mechanism of its own offers a mode that uses Supgang instead.

The owner settled the emphasis the same week, and it is the emphasis rather than the idea
that matters: Supgang is meant as an optional provider, not the default, so that it does
not become a dependency and every tool stays independent. So, precisely: **each tool's own
identity, approvals and TLS remain its default; Supgang is an opt-in provider mode; and no
tool may require it.** A product that cannot install, sign or start because Supgang is
absent has made one program a single point of failure for all of them, which is what the
sovereignty invariant exists to prevent, and being the owner's own program does not help.
Supgang is what removes the owner's journey to the machine when it is there and has been
turned on, and nothing is lost when it is not.

**Administering security from another node.** The owner's signature over the exact request
replaces the requirement to be at the console. "Exact" is the whole of it, so the contract
says what a signature must cover: the request itself, in a form with one meaning; the node
it is addressed to, so a signature for one machine does not act on another; the authority
being exercised, named rather than implied; and a freshness bound with single use, so a
signature captured in transit cannot be replayed later or at a second node. A signature
over a request that does not name its target and its moment is a reusable credential
wearing a signature's clothes.

**What a signature cannot do, which belongs here because it will be assumed.** An owner
signature replaces a requirement *Agenxy* imposes. It cannot replace an authorisation the
operating system imposes: macOS will not record an administrator-domain trust setting
without interactive approval, under sudo and inside an installer's own script sandbox
alike, and no signature of the owner's changes that. Those requirements are removed by
designing them out, as the section above does for code signing, and never by substituting
a signature for a prompt the product does not own. A tool that claims otherwise is wrong in
a way that will only be discovered on a machine nobody is sitting at.

**A convenience that can be hijacked is worse than no convenience**, since it converts a
decision the owner would have made in person into one an attacker can make remotely, on
every machine at once. So: the broker is optional, the product is whole without it, the
broker authenticates the owner over the network, its own keys live in a Secure Enclave or
TPM, and a product asking a broker for an identity is never a reason to hold its own key
less carefully.

Until that exists, this document claims reliability and says plainly that it does not
claim provenance. A product must not describe its installation as verified on the
strength of the rules above alone.

## Enforcement

Each repository's quality gate must:

- run `cargo package` for every publishable crate;
- run the installer's own tests on macOS and on Linux;
- reject a source file that writes over an existing binary path without removing or
  renaming it first, where that is statically detectable.

No gate can check rule 8 from inside a machine that already satisfies it, so each
product's development gate is run on a machine holding no product state before a release,
and the result is recorded with the identities and trust settings observed before and
after. A gate verified only where the product has already been built is unverified.

A product that cannot yet satisfy a rule says so in its own documentation, naming the
rule. Silence is not an exemption.
