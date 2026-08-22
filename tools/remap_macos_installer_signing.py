"""Durable user-owned macOS Installer signing identity for Remap packages."""

from __future__ import annotations

import hashlib
import os
import plistlib
import re
import ssl
import stat
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from tools.remap_macos_signing import login_keychain

IDENTITY_NAME = "Remap Local Installer"
SYSTEM_KEYCHAIN = Path("/Library/Keychains/System.keychain")
CERTIFICATE_LIFETIME_DAYS = 3_650
ARCHIVE_TRANSPORT_PASSWORD = "remap-ephemeral-pipe"
INSTALLER_EKU = "1.2.840.113635.100.4.13"
ADMIN_BASIC_POLICY = {
    "kSecTrustSettingsPolicy": bytes.fromhex("2A864886F763640102"),
    "kSecTrustSettingsPolicyName": "basicX509",
}
IDENTITY_PATTERN = re.compile(r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s*$')
CERTIFICATE_SHA1_PATTERN = re.compile(
    r"^SHA-1 hash:\s*([0-9A-F]{40})\s*$", re.MULTILINE
)
CERTIFICATE_SHA256_PATTERN = re.compile(
    r"^SHA-256 hash:\s*([0-9A-F]{64})\s*$", re.MULTILINE
)
PACKAGE_SHA256_PATTERN = re.compile(
    r"SHA256 Fingerprint:\s*((?:[0-9A-F]{2}\s*){32})",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class LocalInstallerSigningIdentity:
    """One exact Keychain-backed identity used only by productsign."""

    name: str
    sha1: str
    sha256: str
    keychain: Path


def ensure_local_installer_identity() -> LocalInstallerSigningIdentity:
    """Return Remap's installer identity, creating it once when absent."""
    keychain = login_keychain()
    existing = resolve_identity(keychain)
    if existing is not None:
        ensure_administrator_trust(existing)
        return existing
    if _certificate_hashes(keychain):
        raise RuntimeError(
            f"{IDENTITY_NAME!r} exists without one usable private key. "
            + "Repair that exact Keychain item before packaging Remap."
        )
    create_identity(keychain)
    created = resolve_identity(keychain)
    if created is None:
        raise RuntimeError("macOS did not recognize the Remap installer identity")
    ensure_administrator_trust(created)
    return created


def ensure_administrator_trust(identity: LocalInstallerSigningIdentity) -> None:
    """Trust one exact public installer certificate for root PackageKit."""
    if _administrator_trust_is_exact(identity):
        return
    system_hashes = _certificate_hashes(SYSTEM_KEYCHAIN)
    if system_hashes:
        raise RuntimeError(
            f"the system keychain contains a conflicting {IDENTITY_NAME!r} certificate"
        )
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
    _require_certificate_identity(certificate, identity)
    _run_authorized(
        (
            "/usr/bin/security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-p",
            "basic",
            "-k",
            str(SYSTEM_KEYCHAIN),
            "/dev/stdin",
        ),
        certificate,
    )
    if not _administrator_trust_is_exact(identity):
        raise RuntimeError(
            "macOS did not establish exact administrator trust for the Remap "
            + "Installer identity"
        )


def sign_package(
    unsigned_package: Path,
    signed_package: Path,
    identity: LocalInstallerSigningIdentity,
) -> None:
    """Sign and independently verify exactly one native Installer package."""
    if signed_package.exists() or signed_package.is_symlink():
        raise RuntimeError(f"refusing to overwrite installer package {signed_package}")
    _run(
        (
            "/usr/bin/productsign",
            "--sign",
            identity.sha1,
            "--keychain",
            str(identity.keychain),
            str(unsigned_package),
            str(signed_package),
        )
    )
    created = _pinned_regular_file(signed_package)
    try:
        output = _capture(
            ("/usr/sbin/pkgutil", "--check-signature", str(signed_package))
        )
        normalized = output.upper()
        fingerprint_match = PACKAGE_SHA256_PATTERN.search(output)
        fingerprint = (
            "".join(fingerprint_match.group(1).split()).upper()
            if fingerprint_match is not None
            else ""
        )
        if identity.name.upper() not in normalized or fingerprint != identity.sha256:
            raise RuntimeError(
                "the signed Installer package has the wrong certificate identity"
            )
        if "TRUSTED ON THIS SYSTEM" not in normalized:
            raise RuntimeError(
                "macOS does not trust the local Remap Installer package system-wide"
            )
        if _pinned_regular_file(signed_package) != created:
            raise RuntimeError(
                "the signed Installer package changed during verification"
            )
    except Exception:
        _unlink_if_same_file(signed_package, created)
        raise


def _pinned_regular_file(path: Path) -> tuple[int, int]:
    information = path.lstat()
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_nlink != 1
        or information.st_uid != os.getuid()
    ):
        raise RuntimeError("the signed Installer package output is unsafe")
    return information.st_dev, information.st_ino


def _unlink_if_same_file(path: Path, expected: tuple[int, int]) -> None:
    try:
        if _pinned_regular_file(path) == expected:
            path.unlink()
    except FileNotFoundError:
        return


def resolve_identity(keychain: Path) -> LocalInstallerSigningIdentity | None:
    output = _capture(
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
        (fingerprint, name)
        for line in output.splitlines()
        if (match := IDENTITY_PATTERN.fullmatch(line)) is not None
        for fingerprint, name in [match.groups()]
        if name == IDENTITY_NAME
    ]
    if len(matches) > 1:
        raise RuntimeError(f"multiple usable identities are named {IDENTITY_NAME!r}")
    hashes = _certificate_hashes(keychain)
    if not matches:
        return None
    if len(hashes) != 1:
        raise RuntimeError(f"{IDENTITY_NAME!r} does not have one exact certificate")
    sha1, name = matches[0]
    certificate_sha1, certificate_sha256 = hashes[0]
    if sha1 != certificate_sha1:
        raise RuntimeError("the installer identity and certificate fingerprints differ")
    return LocalInstallerSigningIdentity(
        name=name,
        sha1=sha1,
        sha256=certificate_sha256,
        keychain=keychain,
    )


def create_identity(keychain: Path) -> None:
    """Create a nonextractable installer-only private key and trusted root."""
    material = _run_binary(
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
    certificate = _one_pem_block(material, b"CERTIFICATE")
    private_key = _one_private_key(material)
    archive = _make_archive(certificate, private_key)
    _ = _run_binary(
        (
            "/usr/bin/security",
            "import",
            "/dev/stdin",
            "-k",
            str(keychain),
            "-P",
            ARCHIVE_TRANSPORT_PASSWORD,
            "-x",
            "-T",
            "/usr/bin/productsign",
            "-f",
            "pkcs12",
        ),
        archive,
    )
    _ = _run_binary(
        (
            "/usr/bin/security",
            "add-trusted-cert",
            "-r",
            "trustRoot",
            "-p",
            "basic",
            "-k",
            str(keychain),
            "/dev/stdin",
        ),
        certificate,
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
O = Agenxy Local
OU = Remap Installer Signing

[ installer ]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,{INSTALLER_EKU}
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
"""


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
        raise RuntimeError("macOS could not inspect the Remap installer certificate")
    sha1_values = CERTIFICATE_SHA1_PATTERN.findall(result.stdout)
    sha256_values = CERTIFICATE_SHA256_PATTERN.findall(result.stdout)
    if len(sha1_values) != len(sha256_values):
        raise RuntimeError(
            "macOS returned incomplete installer certificate fingerprints"
        )
    return list(zip(sha1_values, sha256_values, strict=True))


def _administrator_trust_is_exact(
    identity: LocalInstallerSigningIdentity,
) -> bool:
    system_hashes = _certificate_hashes(SYSTEM_KEYCHAIN)
    if system_hashes != [(identity.sha1, identity.sha256)]:
        return False
    with tempfile.TemporaryDirectory(prefix="remap-installer-trust-read-") as directory:
        destination = Path(directory) / "admin-trust.plist"
        result = subprocess.run(
            (
                "/usr/bin/security",
                "trust-settings-export",
                "-d",
                str(destination),
            ),
            check=False,
            capture_output=True,
            timeout=30,
        )
        if result.returncode != 0 or not destination.is_file():
            return False
        decoded = cast(object, plistlib.loads(destination.read_bytes()))
    if not isinstance(decoded, dict):
        return False
    document = cast(dict[object, object], decoded)
    trust_list = document.get("trustList")
    if not isinstance(trust_list, dict):
        return False
    trust_document = cast(dict[object, object], trust_list)
    entry = trust_document.get(identity.sha1)
    if not isinstance(entry, dict):
        return False
    entry_document = cast(dict[object, object], entry)
    return entry_document.get("trustSettings") == [ADMIN_BASIC_POLICY]


def _one_pem_block(material: bytes, label: bytes) -> bytes:
    begin = b"-----BEGIN " + label + b"-----"
    end = b"-----END " + label + b"-----"
    start = material.find(begin)
    finish = material.find(end)
    if start < 0 or finish < start or material.find(begin, start + 1) >= 0:
        raise RuntimeError("OpenSSL returned ambiguous installer signing material")
    return material[start : finish + len(end)] + b"\n"


def _one_private_key(material: bytes) -> bytes:
    for label in (b"PRIVATE KEY", b"RSA PRIVATE KEY"):
        if b"-----BEGIN " + label + b"-----" in material:
            return _one_pem_block(material, label)
    raise RuntimeError("OpenSSL did not return one installer private key")


def _require_certificate_identity(
    certificate: bytes,
    identity: LocalInstallerSigningIdentity,
) -> None:
    der = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    encoded = bytes(der)
    if (
        hashlib.sha1(encoded).hexdigest().upper() != identity.sha1
        or hashlib.sha256(encoded).hexdigest().upper() != identity.sha256
    ):
        raise RuntimeError("the exported Installer certificate identity changed")


def _capture(arguments: tuple[str, ...]) -> str:
    return _run_result(arguments).stdout


def _run(arguments: tuple[str, ...]) -> None:
    _ = _run_result(arguments)


def _run_authorized(arguments: tuple[str, ...], input_bytes: bytes) -> None:
    try:
        _ = subprocess.run(
            ("/usr/bin/security", "execute-with-privileges", *arguments),
            check=True,
            input=input_bytes,
            capture_output=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as error:
        standard_error = cast(bytes | None, error.stderr)
        standard_output = cast(bytes | None, error.stdout)
        detail = (
            (standard_error or standard_output or b"")
            .decode("utf-8", errors="replace")
            .strip()
        )
        raise RuntimeError(
            "macOS did not authorize administrator trust for the local Remap "
            + f"Installer identity: {detail}"
        ) from error


def _run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
    try:
        result: subprocess.CompletedProcess[bytes] = subprocess.run(
            arguments,
            check=True,
            input=input_bytes,
            capture_output=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as error:
        standard_error = cast(bytes | None, error.stderr)
        standard_output = cast(bytes | None, error.stdout)
        detail = (
            (standard_error or standard_output or b"")
            .decode("utf-8", errors="replace")
            .strip()
        )
        raise RuntimeError(
            f"{Path(arguments[0]).name} failed while managing Remap installer signing: {detail}"
        ) from error
    return result.stdout


def _make_archive(certificate: bytes, private_key: bytes) -> bytes:
    certificate_reader, certificate_writer = os.pipe()
    key_reader, key_writer = os.pipe()
    try:
        _ = os.write(certificate_writer, certificate)
        _ = os.write(key_writer, private_key)
        os.close(certificate_writer)
        os.close(key_writer)
        certificate_writer = -1
        key_writer = -1
        result: subprocess.CompletedProcess[bytes] = subprocess.run(
            (
                "/usr/bin/openssl",
                "pkcs12",
                "-export",
                "-descert",
                "-name",
                IDENTITY_NAME,
                "-in",
                f"/dev/fd/{certificate_reader}",
                "-inkey",
                f"/dev/fd/{key_reader}",
                "-out",
                "/dev/stdout",
                "-passout",
                f"pass:{ARCHIVE_TRANSPORT_PASSWORD}",
            ),
            check=False,
            capture_output=True,
            pass_fds=(certificate_reader, key_reader),
            timeout=120,
        )
    finally:
        for descriptor in (
            certificate_reader,
            certificate_writer,
            key_reader,
            key_writer,
        ):
            if descriptor >= 0:
                os.close(descriptor)
    if result.returncode != 0:
        detail = (result.stderr or b"no diagnostic").decode("utf-8", errors="replace")
        raise RuntimeError(f"openssl failed: {detail.strip()}")
    return result.stdout


def _run_result(arguments: tuple[str, ...]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.CalledProcessError as error:
        standard_error = cast(str | None, error.stderr)
        standard_output = cast(str | None, error.stdout)
        detail = (standard_error or standard_output or "").strip()
        raise RuntimeError(
            f"{Path(arguments[0]).name} failed while managing Remap installer signing: {detail}"
        ) from error
