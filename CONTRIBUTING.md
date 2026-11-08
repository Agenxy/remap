# Contributing

Two things are worth knowing before you spend time.

## Licence

Remap is GPL-3.0-or-later, and a commercial licence is offered alongside it for people
who cannot accept copyleft terms. See [COMMERCIAL-LICENSING](COMMERCIAL-LICENSING.md).

Offering both is possible only while one party holds the rights to the whole work.
Contributions therefore need a contributor licence agreement or a copyright assignment
before they can be merged. Raise the change first and the paperwork can be sorted out
around it rather than ahead of it; nobody should fill in a form for a typo.

That asks something of you the GPL alone would not, which is worth saying plainly. The
alternative is a project that cannot be offered commercially at all, and the dual
licence is what is meant to keep it maintained.

## New files

Every first-party source file carries, as its first line after any shebang:

```
SPDX-License-Identifier: GPL-3.0-or-later
```

in whatever comment syntax the language uses.

## The gates

`make check` judges this working copy and needs no network, no reviewed toolchain and
nothing installed outside the repository. Run it before you call a change done.

`make release-check` adds everything that protects a machine other than this one:
dependency freshness, the enforced Xcode pin, release evidence, the isolated install
check and the signed native package contract. It is the gate a release must pass.
