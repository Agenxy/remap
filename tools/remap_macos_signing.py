"""Durable user-owned macOS code-signing identity for Remap artifacts."""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

IDENTITY_NAME = "Remap Local Codesign"
CERTIFICATE_LIFETIME_DAYS = 3_650
ARCHIVE_TRANSPORT_PASSWORD = "remap-ephemeral-pipe"
MAXIMUM_COMMAND_OUTPUT_BYTES = 1_048_576
SHA1_PATTERN = re.compile(r"[0-9A-F]{40}\Z")
SHA256_PATTERN = re.compile(r"[0-9A-F]{64}\Z")
IDENTITY_PATTERN = re.compile(r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s*$')
CERTIFICATE_SHA1_PATTERN = re.compile(
    r"^SHA-1 hash:\s*([0-9A-F]{40})\s*$", re.MULTILINE
)
CERTIFICATE_SHA256_PATTERN = re.compile(
    r"^SHA-256 hash:\s*([0-9A-F]{64})\s*$", re.MULTILINE
)
DESIGNATED_ROOT_PATTERN = re.compile(r'certificate root = H"([0-9a-fA-F]{40})"')
HARDENED_RUNTIME_PATTERN = re.compile(
    r"^CodeDirectory\b.*\bflags=0x[0-9a-fA-F]+\([^)]*\bruntime\b[^)]*\)",
    re.MULTILINE,
)


@dataclass(frozen=True)
class LocalCodeSigningIdentity:
    """One exact, Keychain-backed signing identity owned by the local user."""

    name: str
    sha1: str
    sha256: str
    keychain: Path


def ensure_local_codesigning_identity() -> LocalCodeSigningIdentity:
    """Return Remap's durable identity, creating it once when absent."""
    keychain = login_keychain()
    existing = resolve_identity(keychain)
    if existing is not None:
        return existing
    if _certificate_hashes(keychain):
        raise RuntimeError(
            f"{IDENTITY_NAME!r} exists without one usable private signing key. "
            + "Repair that exact Keychain item before building Remap."
        )
    create_identity(keychain)
    created = resolve_identity(keychain)
    if created is None:
        raise RuntimeError(
            "macOS did not recognize the newly created Remap identity as usable"
        )
    return created


def login_keychain() -> Path:
    """Resolve the current user's login keychain without assuming its location."""
    output = _capture(("/usr/bin/security", "login-keychain"))
    value = output.strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    path = Path(value)
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise RuntimeError("macOS returned an unsafe login keychain path")
    return path


def verify_local_signature(
    path: Path,
    identity: LocalCodeSigningIdentity,
    identifier: str,
) -> str:
    """Verify an artifact's exact identifier, signer certificate, and CDHash."""
    _run(("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)))
    details = _capture(
        ("/usr/bin/codesign", "-d", "--verbose=4", str(path)),
        include_standard_error=True,
    )
    values = {
        key: value
        for line in details.splitlines()
        if "=" in line
        for key, value in [line.split("=", maxsplit=1)]
    }
    actual_identifier = values.get("Identifier")
    cdhash = values.get("CDHash")
    if actual_identifier != identifier:
        raise RuntimeError(f"the signed artifact has the wrong identifier: {path}")
    if values.get("Authority") != identity.name or values.get("Signature") == "adhoc":
        raise RuntimeError(f"the signed artifact does not use {identity.name}: {path}")
    if HARDENED_RUNTIME_PATTERN.search(details) is None:
        raise RuntimeError(
            f"the signed artifact does not use the hardened runtime: {path}"
        )
    if not cdhash or not re.fullmatch(r"[0-9a-f]{40,64}", cdhash):
        raise RuntimeError(f"codesign did not report a stable CDHash for {path}")
    requirement = _capture(
        ("/usr/bin/codesign", "-d", "-r-", str(path)),
        include_standard_error=True,
    )
    roots = DESIGNATED_ROOT_PATTERN.findall(requirement)
    if roots != [identity.sha1.lower()]:
        raise RuntimeError(
            f"the signed artifact has the wrong certificate root: {path}"
        )
    exact_requirement = (
        f'identifier "{identifier}" and certificate root = H"{identity.sha1.lower()}"'
    )
    _run(
        (
            "/usr/bin/codesign",
            "--verify",
            "--strict",
            f"-R={exact_requirement}",
            str(path),
        )
    )
    return cdhash


def sign_path(
    path: Path,
    identity: LocalCodeSigningIdentity,
    identifier: str | None = None,
) -> str:
    """Sign and immediately verify one executable or application bundle."""
    arguments = [
        "/usr/bin/codesign",
        "--force",
        "--sign",
        identity.sha1,
        "--keychain",
        str(identity.keychain),
        "--timestamp=none",
        "--options",
        "runtime",
    ]
    if identifier is not None:
        arguments.extend(("--identifier", identifier))
    arguments.append(str(path))
    _run(tuple(arguments))
    return verify_local_signature(
        path, identity, identifier or _bundle_identifier(path)
    )


def sign_paths(
    paths: tuple[Path, ...],
    identity: LocalCodeSigningIdentity,
    *,
    identifier_prefix: str,
) -> None:
    """Sign one reviewed artifact batch with a single Keychain authorization."""
    if not paths:
        raise RuntimeError("the Remap signing batch is empty")
    if not identifier_prefix.endswith("."):
        raise RuntimeError("the Remap signing identifier prefix is malformed")
    _run(
        (
            "/usr/bin/codesign",
            "--force",
            "--sign",
            identity.sha1,
            "--keychain",
            str(identity.keychain),
            "--timestamp=none",
            "--options",
            "runtime",
            "--prefix",
            identifier_prefix,
            *(str(path) for path in paths),
        )
    )


def resolve_identity(keychain: Path) -> LocalCodeSigningIdentity | None:
    output = _capture(
        (
            "/usr/bin/security",
            "find-identity",
            "-v",
            "-p",
            "codesigning",
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
        raise RuntimeError("the Remap identity and certificate fingerprints differ")
    return LocalCodeSigningIdentity(
        name=name,
        sha1=sha1,
        sha256=certificate_sha256,
        keychain=keychain,
    )


def _certificate_hashes(keychain: Path) -> list[tuple[str, str]]:
    result = _run_result(
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
    )
    if result.returncode not in {0, 44}:
        raise RuntimeError("macOS could not inspect the Remap signing certificate")
    sha1_values = CERTIFICATE_SHA1_PATTERN.findall(result.stdout)
    sha256_values = CERTIFICATE_SHA256_PATTERN.findall(result.stdout)
    if len(sha1_values) != len(sha256_values):
        raise RuntimeError("macOS returned incomplete Remap certificate fingerprints")
    return list(zip(sha1_values, sha256_values, strict=True))


def create_identity(keychain: Path) -> None:
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
            "/usr/bin/codesign",
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
            "codeSign",
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
x509_extensions = codesign

[ dn ]
CN = {IDENTITY_NAME}
O = Agenxy Local
OU = Remap Signing

[ codesign ]
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints = critical,CA:TRUE,pathlen:0
"""


def _bundle_identifier(path: Path) -> str:
    output = _capture(
        (
            "/usr/bin/codesign",
            "-d",
            "--verbose=4",
            str(path),
        ),
        include_standard_error=True,
    )
    for line in output.splitlines():
        if line.startswith("Identifier="):
            identifier = line.removeprefix("Identifier=")
            if identifier:
                return identifier
    raise RuntimeError(f"codesign did not report an identifier for {path}")


def _one_pem_block(material: bytes, label: bytes) -> bytes:
    begin = b"-----BEGIN " + label + b"-----"
    end = b"-----END " + label + b"-----"
    start = material.find(begin)
    finish = material.find(end)
    if start < 0 or finish < start or material.find(begin, start + 1) >= 0:
        raise RuntimeError("OpenSSL returned ambiguous code-signing material")
    return material[start : finish + len(end)] + b"\n"


def _one_private_key(material: bytes) -> bytes:
    for label in (b"PRIVATE KEY", b"RSA PRIVATE KEY"):
        if b"-----BEGIN " + label + b"-----" in material:
            return _one_pem_block(material, label)
    raise RuntimeError("OpenSSL did not return one code-signing private key")


def _capture(
    arguments: tuple[str, ...],
    *,
    include_standard_error: bool = False,
) -> str:
    result = _run_result(arguments)
    value = result.stdout + (result.stderr if include_standard_error else "")
    if len(value.encode("utf-8")) > MAXIMUM_COMMAND_OUTPUT_BYTES:
        raise RuntimeError(f"command output exceeded one MiB: {arguments[0]}")
    return value.strip()


def _run(arguments: tuple[str, ...]) -> None:
    _ = _run_result(arguments)


def _run_result(
    arguments: tuple[str, ...],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    result: subprocess.CompletedProcess[str] = subprocess.run(
        arguments,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or "no diagnostic"
        if len(detail.encode("utf-8")) > MAXIMUM_COMMAND_OUTPUT_BYTES:
            detail = "diagnostic exceeded one MiB"
        raise RuntimeError(f"{Path(arguments[0]).name} failed: {detail}")
    return result


def _run_binary(arguments: tuple[str, ...], input_bytes: bytes) -> bytes:
    result: subprocess.CompletedProcess[bytes] = subprocess.run(
        arguments,
        check=False,
        input=input_bytes,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or b"no diagnostic").decode(
            "utf-8", errors="replace"
        )
        raise RuntimeError(f"{Path(arguments[0]).name} failed: {detail.strip()}")
    if len(result.stdout) > MAXIMUM_COMMAND_OUTPUT_BYTES:
        raise RuntimeError(f"command output exceeded one MiB: {arguments[0]}")
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
