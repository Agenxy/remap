# ADR-0020: Distinct names for distinct signing roles

## Status

Accepted, 2026-09-24.

## Context

Two different components of Remap created a code signing identity named
`Remap Local Codesign`:

- `tools/remap_macos_signing.py`, on a machine that **builds** Remap, in that user's
  login keychain.
- `PortableCodeSigningIdentity.swift`, on a machine that **receives** a portable package,
  in the System keychain, where the installer runs as root and needs no login password.

Both roles are legitimate and a developer's Mac performs both, so such a machine ends up
holding two usable identities under one name. `codesign --sign` resolves a name against
the whole keychain search list, so it then refuses to choose:

```text
Remap Local Codesign: ambiguous (matches "Remap Local Codesign" in
.../login.keychain-db and "Remap Local Codesign" in /Library/Keychains/System.keychain)
```

Every component already refused ambiguity, and every one of those checks was scoped to a
single keychain: `resolve_identity` to the login keychain, `PortableCodeSigningIdentity`
and `MacOSLocalCodeSigningIdentityCleanup` to the System keychain. Each was correct about
the space it examined and none examined the space `codesign` actually searches.

Remap was never the victim of this, because it signs by fingerprint with an explicit
`--keychain`. It was the cause: nothing prevented it creating the second identity, and an
owner or any other tool signing by name would have been stuck.

## Decision

A signing role gets a name of its own.

The build-time identity is renamed to **`Remap Build Signing`**. The identity the portable
installer creates on a receiving Mac keeps **`Remap Local Codesign`**, because that is the
one an owner encounters, and the README, the macOS platform README and the first-map
tutorial describe it by that name.

Independently, `ensure_local_codesigning_identity` refuses before reading a keychain, and
before it could create anything, when more than one usable identity carries the product's
name anywhere `codesign` would look. The refusal names every fingerprint and the command
that removes one. This stays even though the collision it was written for cannot now
occur: nothing prevents a future name from colliding, and a machine holding two identities
of one name is invalid whatever produced it.

## Consequences

A machine that already holds a build identity named `Remap Local Codesign` keeps it, and
it is ignored rather than reused, because the tooling now looks for a different name. It
is inert but untidy, and removing it is the owner's decision since it is the certificate
their past builds were signed by. `sudo security delete-certificate -Z <fingerprint>
<keychain>` removes one when they choose.

ADR-0014 and ADR-0019 refer to the build identity by its former name. They are records of
decisions taken then and are left as written.

Not addressed here: the same scope mismatch may exist for other names this product puts in
a keychain, the release installer identity in particular. Each should be checked against
the space its consumer resolves in, not the space it is stored in.
