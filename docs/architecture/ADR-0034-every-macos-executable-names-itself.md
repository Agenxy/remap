# ADR-0034: Every macOS executable names itself, and every name macOS shows is Remap's

## Status

Accepted, 2026-10-30. It applies rules 7, 9 and 12 of
[the Agenxy installation discipline](agenxy-installation.md) to the names macOS
shows the owner. It changes the build of every macOS executable, which is a
platform contract, and records four related surfaces this change measured and
deliberately left alone.

## Context

Remap's installed jobs appear in System Settings under Login Items, in
Background Items. Read on the owner's Mac on 30 October with `sfltool dumpbtm`,
which needs no privilege:

```text
 Name: remapd
 Developer Name: Agenxy Local
 Type: legacy daemon (0x10010)
 Identifier: 16.org.agenxy.Remap.daemon
 Executable Path: /Library/Application Support/Agenxy/Remap/Install/Generations/0.2.0-…/libexec/remapd
```

The resolver supervisor is listed as `remap-resolver` and the lifecycle service
as `org.agenxy.Remap.installer-service`, all three under the developer
"Agenxy Local". Two facts follow:

- The developer is the organisation (`O`) of the certificate that signed the
  executable. Every identity Remap creates said `O = Agenxy Local`.
- Each item is named after its executable's file name. A bare Mach-O executable
  has no bundle, so there is nothing else to name it by.

The same absence reaches every other place macOS names a program. A
LocalAuthentication dialog says "<program> is trying to <reason>."; a keychain
access dialog says "<program> wants to use …". Neither the Swift helpers nor
`remapd` and `remap` carried any bundle information: `codesign -dv` reported
`Info.plist=not bound` and an identifier the signer supplied by hand.

## Decision

### Each executable embeds an Info.plist

Every macOS executable Remap builds carries an `Info.plist` in its
`__TEXT,__info_plist` section, which macOS reads as the bundle information of an
executable that has no bundle. It declares `CFBundleIdentifier`, `CFBundleName`,
`CFBundleDisplayName`, `CFBundleInfoDictionaryVersion`,
`CFBundleDevelopmentRegion` and `NSHumanReadableCopyright`.

| Executable | `CFBundleIdentifier` | `CFBundleName` |
|---|---|---|
| `remap` | `org.agenxy.Remap.cli` | Remap CLI |
| `remapd` | `org.agenxy.Remap.daemon` | Remap Service |
| `remap-install` | `org.agenxy.Remap.install-bootstrap` | Remap Installer |
| `remap-installer-bootstrap` | `org.agenxy.Remap.installer-bootstrap` | Remap Installer Bootstrap |
| `remap-installer-service` | `org.agenxy.Remap.installer-service` | Remap Installer Service |
| `remap-lifecycle` | `org.agenxy.Remap.lifecycle-cli` | Remap Lifecycle |
| `remap-portable-installer` | `org.agenxy.Remap.portable-installer` | Remap Package Installer |
| `remap-release-key` | `org.agenxy.Remap.release-key` | Remap Release Key |
| `remap-release-xar-signer` | `org.agenxy.Remap.release-xar-signer` | Remap Release Signer |
| `remap-resolver` | `org.agenxy.Remap.resolver` | Remap DNS Resolver |
| `remap-system` | `org.agenxy.Remap.system` | Remap System Configuration |

The identifier is exactly the signing identifier every installer already gives
that executable, recorded once in `PRODUCT_IDENTIFIERS` in
`tools/remap_macos_portable_package.py`. That equality is load-bearing, not
tidiness: `codesign` takes the identifier from an embedded plist in preference
to `--prefix` plus the file name, measured on this Mac, so the source install's
batch signing now reads it from the plist. `_finalize_signed_copy` already
refuses a signed product whose identifier differs from the expected one.

The Swift helpers keep their plists beside their sources, excluded from them,
and `Package.swift` passes `-sectcreate __TEXT __info_plist <path>` to the
linker for each executable target. `remapd` and `remap` generate theirs in a
build script with the crate version substituted, and link it only when the
target is macOS. The portable core gains no Apple dependency: a section in the
executable is a property of how it is linked, not an API it calls, and Linux
builds link nothing.

The Swift plists carry no version. The Swift package has no version input, the
product version lives in the Cargo workspace, and a literal copied into nine
plists would drift with the first release that forgot one. An absent key is
true; a stale one is not. The Rust plists, which the build derives from that
same version, carry it.

`tests/python/test_macos_product_identity.py` holds every plist to its signing
identifier, a distinct `Remap …` name, and an embedding in the build. A test in
each Rust crate finds the plist inside the built executable.

### Every identity names Remap as its organisation

The certificates of `Remap Local Codesign`, `Remap Build Signing` and
`Remap Local Installer` say `O = Remap`. The release installer identity keeps
`O = Agenxy`: it names the publisher, which is true, and its certificate is
pinned in `docs/release`. An existing identity keeps the organisation it was
created with; nothing rewrites a certificate an owner already trusts.

## Considered and not adopted

### `AssociatedBundleIdentifiers`

A launchd definition may name the app it belongs to, and Login Items then lists
the job under the app rather than under a developer. Apple documents the
association as verified by the Team Identifier of the job and the app. Remap's
code is self-signed and has none (`TeamIdentifier=not set`), and no
definition on this Mac pairs that key with team-less code, so there was nothing
to measure against. Adding a key whose effect cannot be shown would also widen
the definition validators' allowlists (`MacOSLaunchdPropertyList.swift`,
`tools/remap_macos_installer_package.py`) for no demonstrated result.

**Needs measurement on a real Mac:** install a generation whose daemon
definition adds `AssociatedBundleIdentifiers = ["org.agenxy.Remap"]`, open
Login Items, and see whether `remapd` moves under Remap.app. If it does, adopt
it in a change of its own that widens the allowlists.

### A Distribution file for the installer package

A product archive with a Distribution file gives Installer.app a title, welcome
and conclusion. Remap's package is a component package that ADR-0015 makes
byte-deterministic by canonicalising its XAR table, and that the release key and
the Apple installer signature both sign. Wrapping it with `productbuild` nests
the component inside a second XAR, which `canonicalize_xar_metadata`,
`_verify_package`, the release XAR signer and the native production-contract
test all assume it does not have. That is a change to a signed release
artifact's structure, and it has to be proved by building and installing a
release package, which needs the release key and the owner present. It is not
taken as polish.

### An `os_log` subsystem for `remapd`

`remapd` writes to standard error, which launchd sends to `/dev/null`. Writing to
the unified log from Rust means calling `os_log` through FFI, which is `unsafe`
and belongs only in a narrowly scoped interop crate under AGENTS.md. Until that
crate exists the daemon keeps no log under launchd; the Swift resolver
supervisor already logs under the subsystem `org.agenxy.Remap`.

### The user data directory `org.Agenxy.Remap`

Each owner's registry lives in `~/Library/Application Support/org.Agenxy.Remap`.
Every other Remap identifier is `org.agenxy.Remap…`, and the capital `A` is the
only place the organisation is spelled that way. The directory is visible in
Finder, but renaming it moves the authoritative registry, its journals and the
control socket, and every installed launchd definition names it. Proposed, not
done: a later release that reads both names, migrates once under the daemon's
own lock while it is stopped, and records the migration in the registry so it
never runs twice. It needs its own decision.

### The `/Applications/Remap.app` symlink

`/Applications/Remap.app` is a link into the active generation, declared in the
signed manifest like every other publication, which is how an update replaces
the app atomically and a rollback restores it. Finder badges a linked app with
an alias arrow, and Spotlight and Launchpad may not index it. Publishing a real
bundle there instead changes how a generation is published, retired and rolled
back, which is ADR-0006's and ADR-0012's contract, not polish.

**Needs measurement on a real Mac:** whether Spotlight finds Remap and
Launchpad lists it while the app is published as a link.

## Consequences

Every newly built executable is bound to an Info.plist (`codesign -dv` reports
`Info.plist entries=…`), and its signature covers it. A generation built before
this change has no plist, and the next update replaces it.

**Needs measurement on a real Mac** after an install built from this change:

- Login Items: is each Remap job still named after its file (`remapd`), or now
  after its `CFBundleName` (`Remap Service`)? Is its developer "Remap" for a
  newly created identity?
- The presence dialog of `make install` and `remap system`: does it name
  "Remap Installer" or "Remap Lifecycle", or still the file name?
- `remap-release-key sign`: does its Touch ID dialog name "Remap Release Key"?

What macOS shows in each is the evidence. If a surface still shows the file name,
the plist stays, because code signing binds it and it is correct, and the
surface is recorded here as one that reads the file name.
