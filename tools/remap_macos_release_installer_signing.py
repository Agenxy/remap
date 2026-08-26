"""Dedicated self-signed release authority for complete Remap Installer XARs."""

from __future__ import annotations

import hashlib
import plistlib
import re
import ssl
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from tools import remap_macos_installer_signing as local_signing
from tools.remap_macos_signing import login_keychain

IDENTITY_NAME = "Remap Release Installer"
PINNED_CERTIFICATE = Path("docs/release/remap-release-installer.pem")
CERTIFICATE_LIFETIME_DAYS = 3_650
IDENTITY_PATTERN = re.compile(
    r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"(?:\s+\([^)]*\))?\s*$'
)
SHA1_PATTERN = re.compile(r"^SHA-1 hash:\s*([0-9A-F]{40})\s*$", re.MULTILINE)
SHA256_PATTERN = re.compile(r"^SHA-256 hash:\s*([0-9A-F]{64})\s*$", re.MULTILINE)
PACKAGE_SHA256_PATTERN = re.compile(
    r"SHA256 Fingerprint:\s*((?:[0-9A-F]{2}\s*){32})",
    re.IGNORECASE,
)
USER_BASIC_POLICY = {
    "kSecTrustSettingsPolicy": bytes.fromhex("2A864886F763640102"),
    "kSecTrustSettingsPolicyName": "basicX509",
}


@dataclass(frozen=True)
class ReleaseInstallerSigningIdentity:
    """One nonextractable publisher identity usable only by productsign."""

    name: str
    sha1: str
    sha256: str
    keychain: Path


def ensure_release_installer_identity(root: Path) -> ReleaseInstallerSigningIdentity:
    """Resolve the exact identity matching the committed public certificate."""
    keychain = login_keychain()
    identity = _resolve(keychain)
    if identity is None:
        _create(keychain)
        identity = _resolve(keychain)
    if identity is None:
        raise RuntimeError("macOS did not create the Remap release Installer identity")
    _ensure_builder_trust(identity)
    pinned = root / PINNED_CERTIFICATE
    if not pinned.is_file() or pinned.is_symlink():
        raise RuntimeError(
            "the pinned Remap release Installer certificate is missing; "
            + "export and review the dedicated public certificate before packaging"
        )
    pinned_der = bytes(ssl.PEM_cert_to_DER_cert(pinned.read_text(encoding="ascii")))
    if (
        hashlib.sha1(pinned_der).hexdigest().upper() != identity.sha1
        or hashlib.sha256(pinned_der).hexdigest().upper() != identity.sha256
    ):
        raise RuntimeError(
            "the Remap release Installer identity does not match its pinned certificate"
        )
    return identity


def export_release_installer_certificate() -> str:
    """Return the exact public certificate for one-time repository pinning."""
    identity = _resolve(login_keychain())
    if identity is None:
        raise RuntimeError("the Remap release Installer identity is missing")
    certificate = _capture(
        (
            "/usr/bin/security",
            "find-certificate",
            "-c",
            IDENTITY_NAME,
            "-p",
            str(identity.keychain),
        )
    )
    der = bytes(ssl.PEM_cert_to_DER_cert(certificate))
    if hashlib.sha256(der).hexdigest().upper() != identity.sha256:
        raise RuntimeError("the exported release Installer certificate changed")
    return certificate


def _ensure_builder_trust(identity: ReleaseInstallerSigningIdentity) -> None:
    if _builder_trust_is_exact(identity):
        return
    certificate = _capture(
        (
            "/usr/bin/security",
            "find-certificate",
            "-c",
            IDENTITY_NAME,
            "-p",
            str(identity.keychain),
        )
    ).encode("ascii")
    _ = local_signing.run_binary(
        (
            "/usr/bin/security",
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-p",
            "basic",
            "-k",
            str(identity.keychain),
            "/dev/stdin",
        ),
        certificate,
    )
    if not _builder_trust_is_exact(identity):
        raise RuntimeError("macOS did not retain exact release Installer builder trust")


def _builder_trust_is_exact(identity: ReleaseInstallerSigningIdentity) -> bool:
    with tempfile.TemporaryDirectory(
        prefix="remap-release-installer-trust-"
    ) as directory:
        destination = Path(directory) / "user-trust.plist"
        result = subprocess.run(
            ("/usr/bin/security", "trust-settings-export", str(destination)),
            check=False,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0 or not destination.is_file():
            return False
        decoded = cast(object, plistlib.loads(destination.read_bytes()))
    if not isinstance(decoded, dict):
        return False
    trust_list = cast(dict[object, object], decoded).get("trustList")
    if not isinstance(trust_list, dict):
        return False
    entry = cast(dict[object, object], trust_list).get(identity.sha1)
    if not isinstance(entry, dict):
        return False
    return cast(dict[object, object], entry).get("trustSettings") == [USER_BASIC_POLICY]


def sign_package(
    unsigned: Path,
    signed: Path,
    identity: ReleaseInstallerSigningIdentity,
) -> None:
    """Sign the complete XAR and require its exact pinned signer fingerprint."""
    if signed.exists() or signed.is_symlink():
        raise RuntimeError(f"refusing to overwrite release Installer package {signed}")
    _run(
        (
            "/usr/bin/productsign",
            "--sign",
            identity.sha1,
            "--keychain",
            str(identity.keychain),
            "--timestamp=none",
            str(unsigned),
            str(signed),
        )
    )
    _verify_package_signature(signed, expected_sha256=identity.sha256)


def verify_package_signature(package: Path, pinned_certificate: Path) -> None:
    """Require the complete XAR to use the exact committed Installer certificate."""
    _verify_package_signature(
        package,
        expected_sha256=certificate_sha256(pinned_certificate),
    )


def certificate_sha256(pinned_certificate: Path) -> str:
    """Return the digest of one safe PEM-encoded Installer certificate."""
    if not pinned_certificate.is_file() or pinned_certificate.is_symlink():
        raise RuntimeError("the pinned release Installer certificate is unsafe")
    pinned_der = bytes(
        ssl.PEM_cert_to_DER_cert(pinned_certificate.read_text(encoding="ascii"))
    )
    return hashlib.sha256(pinned_der).hexdigest().upper()


def _verify_package_signature(package: Path, *, expected_sha256: str) -> None:
    output = _capture(("/usr/sbin/pkgutil", "--check-signature", str(package)))
    fingerprint_match = PACKAGE_SHA256_PATTERN.search(output)
    fingerprint = (
        "".join(fingerprint_match.group(1).split()).upper()
        if fingerprint_match is not None
        else ""
    )
    if IDENTITY_NAME.upper() not in output.upper() or fingerprint != expected_sha256:
        raise RuntimeError("the release package has the wrong Installer certificate")
    if "STATUS: SIGNED" not in output.upper():
        raise RuntimeError(
            "the release package does not have an intact Installer signature"
        )


def openssl_configuration() -> str:
    return f"""[ req ]
default_bits = 3072
default_md = sha256
prompt = no
distinguished_name = dn
x509_extensions = installer

[ dn ]
CN = {IDENTITY_NAME}
O = Agenxy
OU = Remap Release Signing

[ installer ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,{local_signing.INSTALLER_EKU}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


def _resolve(keychain: Path) -> ReleaseInstallerSigningIdentity | None:
    identities = _capture(
        (
            "/usr/bin/security",
            "find-identity",
            "-v",
            "-p",
            "basic",
            str(keychain),
        )
    )
    matches = [
        match.groups()
        for line in identities.splitlines()
        if (match := IDENTITY_PATTERN.fullmatch(line)) is not None
        and match.group(2) == IDENTITY_NAME
    ]
    certificates = _certificate_hashes(keychain)
    if not matches and not certificates:
        return None
    if len(matches) != 1 or len(certificates) != 1:
        raise RuntimeError("the Remap release Installer identity is ambiguous")
    sha1, name = matches[0]
    certificate_sha1, sha256 = certificates[0]
    if sha1 != certificate_sha1:
        raise RuntimeError("the release Installer private key and certificate differ")
    return ReleaseInstallerSigningIdentity(name, sha1, sha256, keychain)


def _certificate_hashes(keychain: Path) -> list[tuple[str, str]]:
    result = subprocess.run(
        (
            "/usr/bin/security",
            "find-certificate",
            "-a",
            "-Z",
            "-c",
            IDENTITY_NAME,
            str(keychain),
        ),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode not in {0, 44}:
        raise RuntimeError("macOS could not inspect the release Installer certificate")
    sha1_values = SHA1_PATTERN.findall(result.stdout)
    sha256_values = SHA256_PATTERN.findall(result.stdout)
    if len(sha1_values) != len(sha256_values):
        raise RuntimeError("macOS returned incomplete release Installer fingerprints")
    return list(zip(sha1_values, sha256_values, strict=True))


def _create(keychain: Path) -> None:
    material = local_signing.run_binary(
        (
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:3072",
            "-nodes",
            "-days",
            str(CERTIFICATE_LIFETIME_DAYS),
            "-config",
            "/dev/stdin",
            "-keyout",
            "/dev/stdout",
            "-out",
            "/dev/stdout",
        ),
        openssl_configuration().encode("utf-8"),
    )
    certificate = local_signing.one_pem_block(material, b"CERTIFICATE")
    private_key = local_signing.one_private_key(material)
    archive = local_signing.make_archive(
        certificate,
        private_key,
        identity_name=IDENTITY_NAME,
    )
    _ = local_signing.run_binary(
        (
            "/usr/bin/security",
            "import",
            "/dev/stdin",
            "-k",
            str(keychain),
            "-P",
            local_signing.ARCHIVE_TRANSPORT_PASSWORD,
            "-x",
            "-T",
            "/usr/bin/productsign",
            "-f",
            "pkcs12",
        ),
        archive,
    )


def _capture(arguments: tuple[str, ...]) -> str:
    return subprocess.run(
        arguments,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    ).stdout


def _run(arguments: tuple[str, ...]) -> None:
    _ = subprocess.run(arguments, check=True, capture_output=True, timeout=300)
