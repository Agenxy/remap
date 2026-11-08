# SPDX-License-Identifier: GPL-3.0-or-later
"""Which key signs a Remap package, and the rule that keeps the three kinds apart.

A development package is signed by a passphrase-less file key that anyone who can read the
file can use. A release package is signed by a P-256 key generated inside this Mac's Secure
Enclave, which will not surrender it, and every signature needs the owner present. A
rehearsal package is signed by its own Enclave key, which needs no one present, so that a
rehearsal builds unattended. Each kind has its own pin under `docs/release`, its own
compiled-in installer key, and its own signer. Nothing here lets one kind's key, pin, or
signer stand in for another's (ADR-0029, ADR-0035).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Protocol

DEVELOPMENT_KEY_MARKER = "remap-release-development-only"
REHEARSAL_KEY_MARKER = "remap-release-rehearsal-only"
DEVELOPMENT_PACKAGE_VARIABLE = "REMAP_DEVELOPMENT_PACKAGE"
DEVELOPMENT_KEY_VARIABLE = "REMAP_RELEASE_SIGNING_KEY"
RELEASE_KEY_VARIABLE = "REMAP_RELEASE_SE_KEY"
REHEARSAL_PACKAGE_VARIABLE = "REMAP_REHEARSAL_PACKAGE"
REHEARSAL_KEY_VARIABLE = "REMAP_REHEARSAL_SE_KEY"
RELEASE_PIN = Path("docs/release/remap-release-signing-key.pub")
DEVELOPMENT_PIN = Path("docs/release/remap-development-signing-key.pub")
REHEARSAL_PIN = Path("docs/release/remap-rehearsal-signing-key.pub")
RELEASE_KEY_TYPE = "ecdsa-sha2-nistp256"
PUBLIC_KEY_TYPES = frozenset({"ssh-ed25519", RELEASE_KEY_TYPE})
MAXIMUM_KEY_BLOB_BYTES = 4096
EXPORTABLE_KEY_PREFIXES = (b"-----BEGIN", b"openssh-key-v1", b"PuTTY-User-Key-File")
# `remap-release-key` labels a rehearsal key's blob with this line and a release key's
# blob not at all, so neither blob can be handed to the other kind (ADR-0035).
REHEARSAL_BLOB_LABEL = b"remap-release-rehearsal-key-v1\n"
SWIFT_DEVELOPMENT_CONDITION = "REMAP_DEVELOPMENT_PACKAGE"
SWIFT_REHEARSAL_CONDITION = "REMAP_REHEARSAL_PACKAGE"
# The installer source holds every committed pin as a literal. Until the rehearsal pin is
# committed its branch is this error, and `make rehearsal-key` replaces it in that commit.
SWIFT_VERIFIER = Path(
    "platforms/macos/Sources/RemapPortableInstaller/PortableReleaseManifest.swift"
)
REHEARSAL_SWIFT_PENDING = (
    '#error("The rehearsal signing pin is not committed yet (ADR-0035).")'
)
REHEARSAL_SWIFT_BRANCH = re.compile(
    r"(?P<head>\n    #elseif REMAP_REHEARSAL_PACKAGE\n)(?P<body>.*?)(?P<tail>\n    #else\n)",
    re.DOTALL,
)
# A rotated rehearsal key's fingerprint, one per line; the documented steps refuse it.
REHEARSAL_REVOKED = Path("docs/release/remap-rehearsal-revoked-fingerprints.txt")
REHEARSAL_PIN_MISSING = (
    f"the rehearsal pin {REHEARSAL_PIN} has not been committed. That is expected until "
    + "the owner approves the interim rehearsal signer; docs/release/REHEARSAL.md has the "
    + "one command that creates the key and writes the pin, and the commit that pins it."
)


class PackageKind(Enum):
    """The three kinds of package, which are never mixed."""

    DEVELOPMENT = "development"
    REHEARSAL = "rehearsal"
    RELEASE = "release"


PINS = {
    PackageKind.DEVELOPMENT: DEVELOPMENT_PIN,
    PackageKind.REHEARSAL: REHEARSAL_PIN,
    PackageKind.RELEASE: RELEASE_PIN,
}


@dataclass(frozen=True)
class DevelopmentSigning:
    """Sign with the development file key, for a package installed where it was built."""

    key: Path

    @property
    def kind(self) -> PackageKind:
        return PackageKind.DEVELOPMENT


@dataclass(frozen=True)
class ReleaseSigning:
    """Sign with the Secure Enclave key whose device-bound blob is at `key_blob`."""

    key_blob: Path

    @property
    def kind(self) -> PackageKind:
        return PackageKind.RELEASE


@dataclass(frozen=True)
class RehearsalSigning:
    """Sign with the rehearsal Secure Enclave key, which needs no one present."""

    key_blob: Path

    @property
    def kind(self) -> PackageKind:
        return PackageKind.REHEARSAL


PackageSigning = DevelopmentSigning | ReleaseSigning | RehearsalSigning


class Signer(Protocol):
    """Produces one armoured SSHSIG signature over a message stream."""

    def sign(self, message: BinaryIO, *, namespace: str) -> bytes: ...


def selected_signing(environment: Mapping[str, str]) -> PackageSigning:
    """Choose the signer from the environment, refusing any mixture of the kinds."""
    development = bool(environment.get(DEVELOPMENT_PACKAGE_VARIABLE))
    rehearsal = bool(environment.get(REHEARSAL_PACKAGE_VARIABLE))
    if development and rehearsal:
        raise RuntimeError(
            f"{DEVELOPMENT_PACKAGE_VARIABLE} and {REHEARSAL_PACKAGE_VARIABLE} select two "
            + "kinds of package at once. A package is exactly one kind; unset one of them."
        )
    if rehearsal:
        return _selected_rehearsal(environment)
    if environment.get(REHEARSAL_KEY_VARIABLE):
        raise RuntimeError(
            f"{REHEARSAL_KEY_VARIABLE} names the rehearsal key, which signs only a "
            + f"rehearsal package. Set {REHEARSAL_PACKAGE_VARIABLE}=1 to build one, or "
            + "unset it."
        )
    if development:
        return _selected_development(environment)
    return _selected_release(environment)


def _selected_rehearsal(environment: Mapping[str, str]) -> RehearsalSigning:
    for variable in (RELEASE_KEY_VARIABLE, DEVELOPMENT_KEY_VARIABLE):
        if environment.get(variable):
            raise RuntimeError(
                f"{variable} names another kind's key, but {REHEARSAL_PACKAGE_VARIABLE} "
                + "asks for a rehearsal package. A rehearsal is signed only by the "
                + f"rehearsal key; unset {variable}."
            )
    key_blob = environment.get(REHEARSAL_KEY_VARIABLE)
    if not key_blob:
        raise RuntimeError(
            f"{REHEARSAL_KEY_VARIABLE} must name the Secure Enclave key blob of Remap's "
            + "dedicated rehearsal key"
        )
    return RehearsalSigning(Path(key_blob).expanduser())


def _selected_development(environment: Mapping[str, str]) -> DevelopmentSigning:
    file_key = environment.get(DEVELOPMENT_KEY_VARIABLE)
    if environment.get(RELEASE_KEY_VARIABLE):
        raise RuntimeError(
            f"{RELEASE_KEY_VARIABLE} names the release key, but "
            + f"{DEVELOPMENT_PACKAGE_VARIABLE} asks for a development package. The "
            + "release key never signs a development package; unset one of them."
        )
    if not file_key:
        raise RuntimeError(
            f"{DEVELOPMENT_KEY_VARIABLE} must name Remap's dedicated development "
            + "key; a personal SSH key is never selected automatically"
        )
    return DevelopmentSigning(Path(file_key).expanduser())


def _selected_release(environment: Mapping[str, str]) -> ReleaseSigning:
    if environment.get(DEVELOPMENT_KEY_VARIABLE):
        raise RuntimeError(
            f"{DEVELOPMENT_KEY_VARIABLE} names a key held in a file, and a file key can "
            + f"never sign a release. Set {RELEASE_KEY_VARIABLE} to the Secure Enclave "
            + f"key blob, or {DEVELOPMENT_PACKAGE_VARIABLE}=1 to build a development "
            + "package for this machine."
        )
    key_blob = environment.get(RELEASE_KEY_VARIABLE)
    if not key_blob:
        raise RuntimeError(
            f"{RELEASE_KEY_VARIABLE} must name the Secure Enclave key blob of Remap's "
            + "dedicated release key; a personal SSH key is never selected automatically"
        )
    return ReleaseSigning(Path(key_blob).expanduser())


def pinned_public_key(root: Path, kind: PackageKind) -> str:
    """The committed public key line that a package of this kind must verify against.

    The rehearsal pin is committed only once the owner approves its signer, so its absence
    is reported as that, not as a missing file.
    """
    pin = root / PINS[kind]
    if kind is PackageKind.REHEARSAL and not (pin.exists() or pin.is_symlink()):
        raise RuntimeError(REHEARSAL_PIN_MISSING)
    return pin.read_text(encoding="utf-8")


def committed_pins(root: Path) -> dict[PackageKind, str]:
    """Every pin that is committed: always release and development, rehearsal once approved."""
    return {
        kind: pinned_public_key(root, kind)
        for kind, pin in PINS.items()
        if kind is not PackageKind.REHEARSAL or (root / pin).exists()
    }


def is_development_marked(public_key: str) -> bool:
    """Whether a pin announces itself as a development key.

    The comment field is not part of what a pin matches, so it is free to carry this
    statement, and it travels with the repository.
    """
    return DEVELOPMENT_KEY_MARKER in public_key


def is_rehearsal_marked(public_key: str) -> bool:
    """Whether a pin announces itself as the rehearsal key, which signs no release."""
    return REHEARSAL_KEY_MARKER in public_key


def canonical_public_key(value: str) -> str:
    """The `type base64` of one OpenSSH public key line whose blob is of that type."""
    fields = value.strip().split()
    if len(fields) not in {2, 3} or fields[0] not in PUBLIC_KEY_TYPES:
        raise RuntimeError(
            "the Remap public key is not one canonical Ed25519 or P-256 OpenSSH key"
        )
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except binascii.Error as error:
        raise RuntimeError("the Remap public key is not valid base64") from error
    declared = fields[0].encode()
    if (
        blob[:4] != len(declared).to_bytes(4, "big")
        or blob[4 : 4 + len(declared)] != declared
    ):
        raise RuntimeError("the Remap public key blob does not match its declared type")
    return " ".join(fields[:2])


def preflight(root: Path, signing: PackageSigning) -> None:
    """Refuse a mismatched key or pin before anything is built."""
    match signing:
        case DevelopmentSigning(key=key):
            _preflight_development(root, key)
        case ReleaseSigning(key_blob=key_blob):
            _preflight_release(root, key_blob)
        case RehearsalSigning(key_blob=key_blob):
            _preflight_rehearsal(root, key_blob)


def open_signer(
    root: Path, signing: PackageSigning, *, release_key_tool: Path
) -> Signer:
    """Return the signer for this kind, having proved it is the pinned key."""
    match signing:
        case DevelopmentSigning(key=key):
            return FileKeySigner(key)
        case ReleaseSigning(key_blob=key_blob) | RehearsalSigning(key_blob=key_blob):
            signer = EnclaveSigner(release_key_tool, key_blob, signing.kind)
            # The pin's own type decides what a match means, so a rehearsal pin that a
            # later rotation makes Ed25519 is refused here rather than half-accepted.
            observed = canonical_public_key(signer.public_key())
            expected = canonical_public_key(pinned_public_key(root, signing.kind))
            if observed != expected:
                raise RuntimeError(
                    f"the Secure Enclave key at {key_blob} is not the pinned "
                    + f"{signing.kind.value} key in {PINS[signing.kind]}; nothing was signed"
                )
            return signer


def swift_build_arguments(kind: PackageKind) -> tuple[str, ...]:
    """The compile-time condition that selects the installer's one embedded pin."""
    match kind:
        case PackageKind.DEVELOPMENT:
            return ("-Xswiftc", f"-D{SWIFT_DEVELOPMENT_CONDITION}")
        case PackageKind.REHEARSAL:
            return ("-Xswiftc", f"-D{SWIFT_REHEARSAL_CONDITION}")
        case PackageKind.RELEASE:
            return ()


def verify_embedded_pin(installer: Path, root: Path, kind: PackageKind) -> None:
    """Require that a built installer embeds its own kind's key and no other kind's."""
    data = installer.read_bytes()
    pins = committed_pins(root)
    own = canonical_public_key(pinned_public_key(root, kind)).split()[1].encode()
    others = {
        canonical_public_key(pin).split()[1].encode()
        for other_kind, pin in pins.items()
        if other_kind is not kind
    }
    if own not in data or any(other != own and other in data for other in others):
        raise RuntimeError(
            f"the portable installer does not embed exactly the {kind.value} pin; "
            + "it was compiled for another kind of package"
        )


def fingerprint(public_key: str) -> str:
    """The `SHA256:` fingerprint `ssh-keygen -l -E sha256` prints for this key."""
    blob = base64.b64decode(canonical_public_key(public_key).split()[1], validate=True)
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
    return "SHA256:" + digest.rstrip("=")


def revoked_fingerprints(root: Path) -> frozenset[str]:
    """Every rehearsal fingerprint a rotation has revoked."""
    path = root / REHEARSAL_REVOKED
    if not path.exists():
        return frozenset()
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(
        line.split()[0] for line in lines if line.strip() and not line.startswith("#")
    )


def rehearsal_pin_line(public_key: str) -> str:
    """The one marked OpenSSH line a rehearsal pin must be, refusing anything else."""
    fields = public_key.removesuffix("\n").split(" ")
    if (
        public_key.count("\n") != 1
        or not public_key.endswith("\n")
        or len(fields) != 3
        or fields[2] != REHEARSAL_KEY_MARKER
        or canonical_public_key(public_key) != " ".join(fields[:2])
    ):
        raise RuntimeError(
            f"the rehearsal pin {REHEARSAL_PIN} must be one OpenSSH public key line "
            + f"whose comment is {REHEARSAL_KEY_MARKER}"
        )
    return public_key


def swift_pin_literal(public_key: str) -> str:
    """The pin as the Swift verifier writes every pin: a continued multi-line literal.

    Joining its continuation lines gives the pin file's line exactly, which is what the
    pin-consistency test checks for every kind.
    """
    key_type, blob, comment = (
        rehearsal_pin_line(public_key).removesuffix("\n").split(" ")
    )
    chunks = [blob[index : index + 70] for index in range(0, len(blob), 70)]
    lines = [f"{key_type} ", *chunks[:-1], f"{chunks[-1]} ", comment]
    body = "\\\n".join(f"        {line}" for line in lines)
    return f'        static let releasePublicKey = """\n{body}\n        """'


def rehearsal_swift_branch(source: str) -> str:
    """The body of the verifier's rehearsal branch: the pending error, or the literal."""
    match = REHEARSAL_SWIFT_BRANCH.search(source)
    if match is None:
        raise RuntimeError(f"{SWIFT_VERIFIER} has no rehearsal branch")
    return match.group("body")


def with_rehearsal_literal(source: str, public_key: str) -> str:
    """The verifier source with its rehearsal branch holding exactly this pin."""
    _ = rehearsal_swift_branch(source)
    literal = swift_pin_literal(public_key)
    return REHEARSAL_SWIFT_BRANCH.sub(
        lambda match: match.group("head") + literal + match.group("tail"),
        source,
        count=1,
    )


@dataclass(frozen=True)
class FileKeySigner:
    """Today's development path: `ssh-keygen -Y sign` with a key held in a file."""

    key: Path

    def sign(self, message: BinaryIO, *, namespace: str) -> bytes:
        result = subprocess.run(
            ("/usr/bin/ssh-keygen", "-Y", "sign", "-f", str(self.key), "-n", namespace),
            check=True,
            stdin=message,
            capture_output=True,
            timeout=120,
        )
        return result.stdout


@dataclass(frozen=True)
class EnclaveSigner:
    """`remap-release-key`, which asks the Secure Enclave for each signature.

    For the release key it also asks the owner, every time. For the rehearsal key the
    key's own access control asks no one.
    """

    tool: Path
    key_blob: Path
    kind: PackageKind = PackageKind.RELEASE

    def _kind_arguments(self) -> tuple[str, ...]:
        # The release invocation is exactly ADR-0029's; only a rehearsal names its kind.
        if self.kind is PackageKind.REHEARSAL:
            return ("--kind", "rehearsal")
        return ()

    def public_key(self) -> str:
        result = subprocess.run(
            (
                str(self.tool),
                "public-key",
                *self._kind_arguments(),
                "--key",
                str(self.key_blob),
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"remap-release-key could not read the {self.kind.value} key: "
                + result.stderr.strip()
            )
        return result.stdout

    def sign(self, message: BinaryIO, *, namespace: str) -> bytes:
        # For the release key, Touch ID or the login password is asked for here, once per
        # signature, so the timeout allows a person time to answer.
        result = subprocess.run(
            (
                str(self.tool),
                "sign",
                *self._kind_arguments(),
                "--key",
                str(self.key_blob),
                "-n",
                namespace,
            ),
            check=False,
            stdin=message,
            capture_output=True,
            timeout=300,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(
                f"the Secure Enclave did not sign the {self.kind.value}: {detail}"
            )
        return result.stdout


def _preflight_development(root: Path, key: Path) -> None:
    pin = pinned_public_key(root, PackageKind.DEVELOPMENT)
    if not is_development_marked(pin):
        raise RuntimeError(
            f"{DEVELOPMENT_PIN} must carry {DEVELOPMENT_KEY_MARKER}, so a development "
            + "pin can never be mistaken for a release pin"
        )
    information = key.lstat()
    public_only = key.suffix == ".pub"
    mode = stat.S_IMODE(information.st_mode)
    if (
        not key.is_absolute()
        or key.is_symlink()
        or not key.is_file()
        or information.st_nlink != 1
        or information.st_uid != os.getuid()
        or (mode & 0o022 if public_only else mode & 0o077)
    ):
        raise RuntimeError("the SSH development signing key has unsafe metadata")
    if public_only:
        observed = canonical_public_key(key.read_text(encoding="utf-8"))
    else:
        result = subprocess.run(
            ("/usr/bin/ssh-keygen", "-y", "-f", str(key)),
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
        observed = canonical_public_key(result.stdout)
    if observed != canonical_public_key(pin):
        raise RuntimeError(
            "the SSH development signing key does not match Remap's pinned "
            + f"development key in {DEVELOPMENT_PIN}"
        )


def _require_enclave_blob(key_blob: Path, kind: PackageKind) -> bytes:
    """One owner-only, bounded, non-exportable Enclave blob, labelled as its own kind."""
    variable = (
        REHEARSAL_KEY_VARIABLE
        if kind is PackageKind.REHEARSAL
        else RELEASE_KEY_VARIABLE
    )
    information = key_blob.lstat()
    if (
        not key_blob.is_absolute()
        or key_blob.is_symlink()
        or not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) & 0o077
        or not 0 < information.st_size <= MAXIMUM_KEY_BLOB_BYTES
    ):
        raise RuntimeError(
            f"{variable} must name one owner-only Secure Enclave key blob "
            + f"of at most {MAXIMUM_KEY_BLOB_BYTES} bytes"
        )
    data = key_blob.read_bytes()
    if data.lstrip().startswith(EXPORTABLE_KEY_PREFIXES):
        raise RuntimeError(
            f"{key_blob} is an exportable private key file, and a file key can never "
            + f"sign a {kind.value}. Create the {kind.value} key with "
            + "`remap-release-key create`."
        )
    labelled = data.startswith(REHEARSAL_BLOB_LABEL)
    if kind is PackageKind.REHEARSAL and not labelled:
        raise RuntimeError(
            f"{key_blob} is not a rehearsal key's blob; the release key never signs a "
            + "rehearsal. Create the rehearsal key with "
            + "`remap-release-key create --kind rehearsal`."
        )
    if kind is PackageKind.RELEASE and labelled:
        raise RuntimeError(
            f"{key_blob} is the rehearsal key's blob, and the rehearsal key never signs "
            + "a release"
        )
    return data


def _preflight_release(root: Path, key_blob: Path) -> None:
    _ = _require_enclave_blob(key_blob, PackageKind.RELEASE)
    pin = pinned_public_key(root, PackageKind.RELEASE)
    if is_development_marked(pin):
        raise RuntimeError(
            f"the release pin {RELEASE_PIN} is marked {DEVELOPMENT_KEY_MARKER}, so a "
            + "package built against it would carry a signature that proves nothing to "
            + "anyone else. Pin the Secure Enclave release key's public line there first."
        )
    if is_rehearsal_marked(pin):
        raise RuntimeError(
            f"the release pin {RELEASE_PIN} is marked {REHEARSAL_KEY_MARKER}; the "
            + "rehearsal key signs no release. Pin the Secure Enclave release key there."
        )
    if canonical_public_key(pin).split()[0] != RELEASE_KEY_TYPE:
        raise RuntimeError(
            f"the release pin {RELEASE_PIN} must be a {RELEASE_KEY_TYPE} key, the only "
            + "kind the Secure Enclave holds"
        )
    _require_distinct_pins(root)


def _preflight_rehearsal(root: Path, key_blob: Path) -> None:
    # The pin comes first: until the owner approves the signer there is none, and that,
    # not the blob, is what the person building needs to hear.
    pin = pinned_public_key(root, PackageKind.REHEARSAL)
    if not is_rehearsal_marked(pin) or is_development_marked(pin):
        raise RuntimeError(
            f"the rehearsal pin {REHEARSAL_PIN} must carry {REHEARSAL_KEY_MARKER}, and "
            + "only that marker, so it can never be mistaken for a release pin"
        )
    _ = rehearsal_pin_line(pin)
    if fingerprint(pin) in revoked_fingerprints(root):
        raise RuntimeError(
            f"the rehearsal pin {REHEARSAL_PIN} is listed in {REHEARSAL_REVOKED}; a "
            + "revoked key signs nothing. Rotate to a new key first."
        )
    _require_distinct_pins(root)
    branch = rehearsal_swift_branch((root / SWIFT_VERIFIER).read_text(encoding="utf-8"))
    if branch.strip() != swift_pin_literal(pin).strip():
        raise RuntimeError(
            f"the rehearsal branch of {SWIFT_VERIFIER} does not hold the committed "
            + "rehearsal pin; `make rehearsal-key` writes both in one commit"
        )
    _ = _require_enclave_blob(key_blob, PackageKind.REHEARSAL)


def _require_distinct_pins(root: Path) -> None:
    keys = [canonical_public_key(pin) for pin in committed_pins(root).values()]
    if len(set(keys)) != len(keys):
        raise RuntimeError(
            "two of the release, rehearsal, and development pins are the same key"
        )
