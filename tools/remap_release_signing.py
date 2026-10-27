"""Which key signs a Remap package, and the rule that keeps the two kinds apart.

A development package is signed by a passphrase-less file key that anyone who can read the
file can use. A release package is signed by a P-256 key generated inside this Mac's Secure
Enclave, which will not surrender it, and every signature needs the owner present. Each kind
has its own pin under `docs/release`, its own compiled-in installer key, and its own signer.
Nothing here lets one kind's key, pin, or signer stand in for the other's (ADR-0029).
"""

from __future__ import annotations

import base64
import binascii
import os
import stat
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import BinaryIO, Protocol

DEVELOPMENT_KEY_MARKER = "remap-release-development-only"
DEVELOPMENT_PACKAGE_VARIABLE = "REMAP_DEVELOPMENT_PACKAGE"
DEVELOPMENT_KEY_VARIABLE = "REMAP_RELEASE_SIGNING_KEY"
RELEASE_KEY_VARIABLE = "REMAP_RELEASE_SE_KEY"
RELEASE_PIN = Path("docs/release/remap-release-signing-key.pub")
DEVELOPMENT_PIN = Path("docs/release/remap-development-signing-key.pub")
RELEASE_KEY_TYPE = "ecdsa-sha2-nistp256"
PUBLIC_KEY_TYPES = frozenset({"ssh-ed25519", RELEASE_KEY_TYPE})
MAXIMUM_KEY_BLOB_BYTES = 4096
EXPORTABLE_KEY_PREFIXES = (b"-----BEGIN", b"openssh-key-v1", b"PuTTY-User-Key-File")
SWIFT_DEVELOPMENT_CONDITION = "REMAP_DEVELOPMENT_PACKAGE"


class PackageKind(Enum):
    """The two kinds of package, which are never mixed."""

    DEVELOPMENT = "development"
    RELEASE = "release"


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


PackageSigning = DevelopmentSigning | ReleaseSigning


class Signer(Protocol):
    """Produces one armoured SSHSIG signature over a message stream."""

    def sign(self, message: BinaryIO, *, namespace: str) -> bytes: ...


def selected_signing(environment: Mapping[str, str]) -> PackageSigning:
    """Choose the signer from the environment, refusing any mixture of the two kinds."""
    file_key = environment.get(DEVELOPMENT_KEY_VARIABLE)
    key_blob = environment.get(RELEASE_KEY_VARIABLE)
    if environment.get(DEVELOPMENT_PACKAGE_VARIABLE):
        if key_blob:
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
    if file_key:
        raise RuntimeError(
            f"{DEVELOPMENT_KEY_VARIABLE} names a key held in a file, and a file key can "
            + f"never sign a release. Set {RELEASE_KEY_VARIABLE} to the Secure Enclave "
            + f"key blob, or {DEVELOPMENT_PACKAGE_VARIABLE}=1 to build a development "
            + "package for this machine."
        )
    if not key_blob:
        raise RuntimeError(
            f"{RELEASE_KEY_VARIABLE} must name the Secure Enclave key blob of Remap's "
            + "dedicated release key; a personal SSH key is never selected automatically"
        )
    return ReleaseSigning(Path(key_blob).expanduser())


def pinned_public_key(root: Path, kind: PackageKind) -> str:
    """The committed public key line that a package of this kind must verify against."""
    pin = DEVELOPMENT_PIN if kind is PackageKind.DEVELOPMENT else RELEASE_PIN
    return (root / pin).read_text(encoding="utf-8")


def is_development_marked(public_key: str) -> bool:
    """Whether a pin announces itself as a development key.

    The comment field is not part of what a pin matches, so it is free to carry this
    statement, and it travels with the repository.
    """
    return DEVELOPMENT_KEY_MARKER in public_key


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


def open_signer(
    root: Path, signing: PackageSigning, *, release_key_tool: Path
) -> Signer:
    """Return the signer for this kind, having proved it is the pinned key."""
    match signing:
        case DevelopmentSigning(key=key):
            return FileKeySigner(key)
        case ReleaseSigning(key_blob=key_blob):
            signer = EnclaveSigner(release_key_tool, key_blob)
            observed = canonical_public_key(signer.public_key())
            expected = canonical_public_key(
                pinned_public_key(root, PackageKind.RELEASE)
            )
            if observed != expected:
                raise RuntimeError(
                    f"the Secure Enclave key at {key_blob} is not the pinned release key "
                    + f"in {RELEASE_PIN}; nothing was signed"
                )
            return signer


def swift_build_arguments(kind: PackageKind) -> tuple[str, ...]:
    """The compile-time condition that selects the installer's one embedded pin."""
    if kind is PackageKind.DEVELOPMENT:
        return ("-Xswiftc", f"-D{SWIFT_DEVELOPMENT_CONDITION}")
    return ()


def verify_embedded_pin(installer: Path, root: Path, kind: PackageKind) -> None:
    """Require that a built installer embeds its own kind's key and not the other's."""
    data = installer.read_bytes()
    own = canonical_public_key(pinned_public_key(root, kind)).split()[1].encode()
    other_kind = (
        PackageKind.RELEASE
        if kind is PackageKind.DEVELOPMENT
        else PackageKind.DEVELOPMENT
    )
    other = (
        canonical_public_key(pinned_public_key(root, other_kind)).split()[1].encode()
    )
    if own not in data or (other != own and other in data):
        raise RuntimeError(
            f"the portable installer does not embed exactly the {kind.value} pin; "
            + "it was compiled for the other kind of package"
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
    """`remap-release-key`, which asks the Secure Enclave and the owner for each signature."""

    tool: Path
    key_blob: Path

    def public_key(self) -> str:
        result = subprocess.run(
            (str(self.tool), "public-key", "--key", str(self.key_blob)),
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"remap-release-key could not read the release key: {result.stderr.strip()}"
            )
        return result.stdout

    def sign(self, message: BinaryIO, *, namespace: str) -> bytes:
        # Touch ID or the login password is asked for here, once per signature, so the
        # timeout allows a person time to answer.
        result = subprocess.run(
            (str(self.tool), "sign", "--key", str(self.key_blob), "-n", namespace),
            check=False,
            stdin=message,
            capture_output=True,
            timeout=300,
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", errors="replace").strip()
            raise RuntimeError(f"the Secure Enclave did not sign the release: {detail}")
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


def _preflight_release(root: Path, key_blob: Path) -> None:
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
            f"{RELEASE_KEY_VARIABLE} must name one owner-only Secure Enclave key blob "
            + f"of at most {MAXIMUM_KEY_BLOB_BYTES} bytes"
        )
    if key_blob.read_bytes().lstrip().startswith(EXPORTABLE_KEY_PREFIXES):
        raise RuntimeError(
            f"{key_blob} is an exportable private key file, and a file key can never "
            + "sign a release. Create the release key with `remap-release-key create`."
        )
    pin = pinned_public_key(root, PackageKind.RELEASE)
    if is_development_marked(pin):
        raise RuntimeError(
            f"the release pin {RELEASE_PIN} is marked {DEVELOPMENT_KEY_MARKER}, so a "
            + "package built against it would carry a signature that proves nothing to "
            + "anyone else. Pin the Secure Enclave release key's public line there first."
        )
    if canonical_public_key(pin).split()[0] != RELEASE_KEY_TYPE:
        raise RuntimeError(
            f"the release pin {RELEASE_PIN} must be a {RELEASE_KEY_TYPE} key, the only "
            + "kind the Secure Enclave holds"
        )
    development = canonical_public_key(pinned_public_key(root, PackageKind.DEVELOPMENT))
    if canonical_public_key(pin) == development:
        raise RuntimeError("the release pin and the development pin are the same key")
