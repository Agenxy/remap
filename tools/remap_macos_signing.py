# SPDX-License-Identifier: GPL-3.0-or-later
"""Durable user-owned macOS code-signing identity for Remap artifacts."""

from __future__ import annotations

import hashlib
import os
import re
import secrets
import ssl
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

IDENTITY_NAME = "Remap Build Signing"
CERTIFICATE_LIFETIME_DAYS = 3_650
MAXIMUM_COMMAND_OUTPUT_BYTES = 1_048_576
# Set to "1" where nobody can answer a macOS authorization dialog (a hosted CI
# runner). `security add-trusted-cert` into the login keychain, and
# `security execute-with-privileges`, both raise one, and the gate then waits
# on it until its timeout. With the variable set, trust is recorded in the
# System keychain through non-interactive sudo instead, which the hosted
# runners grant without a password.
HEADLESS_TRUST_VARIABLE = "REMAP_HEADLESS_TRUST"
SYSTEM_KEYCHAIN = Path("/Library/Keychains/System.keychain")
SHA1_PATTERN = re.compile(r"[0-9A-F]{40}\Z")
SHA256_PATTERN = re.compile(r"[0-9A-F]{64}\Z")
# What each trust policy lets an identity do, as the owner is told it.
TRUST_PURPOSES = {
    "codeSign": "to sign Remap's programs on this Mac",
    "basic": "to sign Remap's installer packages on this Mac",
}
IDENTITY_PATTERN = re.compile(r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s*$')
UNTRUSTED_IDENTITY_PATTERN = re.compile(
    r'^\s*\d+\)\s+([0-9A-F]{40})\s+"([^"]+)"\s+\(CSSMERR_TP_NOT_TRUSTED\)\s*$'
)
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


def visible_identity_fingerprints() -> list[str]:
    """Every usable identity named `IDENTITY_NAME` that codesign can reach, by name.

    `resolve_identity` inspects one keychain, but `codesign --sign <name>` resolves
    against the whole search list, so a second identity of the same name in another
    keychain makes signing by name ambiguous and macOS chooses nothing:

        Remap Local Codesign: ambiguous (matches "Remap Local Codesign" in
        .../login.keychain-db and "Remap Local Codesign" in
        /Library/Keychains/System.keychain)

    That is how it was observed, when this identity and the one the portable installer
    creates on a target Mac shared a name across two keychains. They no longer do. This
    check remains because nothing stops a name colliding again, and because a machine
    holding two identities of one name is invalid whatever produced it. Remap itself
    signs by fingerprint with an explicit keychain, so it is never the victim, only ever
    the cause.
    """
    result = _run_result(
        ("/usr/bin/security", "find-identity", "-v", "-p", "codesigning"),
        check=False,
    )
    if result.returncode not in {0, 1}:
        raise RuntimeError("macOS could not enumerate usable code signing identities")
    return [
        fingerprint
        for line in result.stdout.splitlines()
        if (match := IDENTITY_PATTERN.fullmatch(line)) is not None
        for fingerprint, name in [match.groups()]
        if name == IDENTITY_NAME
    ]


def require_one_visible_identity() -> None:
    """Refuse a machine that holds more than one identity under the same name."""
    fingerprints = visible_identity_fingerprints()
    if len(fingerprints) <= 1:
        return
    listed = ", ".join(fingerprints)
    raise RuntimeError(
        f"{len(fingerprints)} usable identities are named {IDENTITY_NAME!r} on this "
        + f"machine ({listed}). `codesign --sign` by name cannot choose between them. "
        + "Remove all but the one this machine should sign with, with "
        + "`sudo security delete-certificate -Z <fingerprint> <keychain>`, and run again."
    )


def ensure_local_codesigning_identity() -> LocalCodeSigningIdentity:
    """Return Remap's durable identity, creating it once when absent."""
    # Before anything else, and before creating a second one: an ambiguous name is an
    # invalid configuration, and refusing it here is what stops this tool producing it.
    require_one_visible_identity()
    keychain = login_keychain()
    existing = resolve_identity(keychain)
    if existing is not None:
        return existing
    if _certificate_hashes(keychain):
        if not record_pending_trust(keychain):
            raise RuntimeError(
                f"{IDENTITY_NAME!r} exists without one usable private signing key. "
                + "Repair that exact Keychain item before building Remap."
            )
        resumed = resolve_identity(keychain)
        if resumed is None:
            raise RuntimeError(
                "macOS did not recognize the Remap identity once it was trusted"
            )
        return resumed
    create_identity(keychain)
    created = resolve_identity(keychain)
    if created is None:
        raise RuntimeError(
            "macOS did not recognize the newly created Remap identity as usable"
        )
    return created


def login_keychain() -> Path:
    """Resolve the keychain the local identities live in.

    On a machine with a user it is the login keychain. Headless, it is a
    keychain of this tool's own with a password only this run knows, because
    a key in the login keychain can only be used by codesign after the user
    approves it in a dialog nobody is there to answer.
    """
    if headless_trust():
        return headless_keychain()
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
    password = secrets.token_urlsafe(32)
    archive = _make_archive(certificate, private_key, password)
    import_identity_archive(
        keychain,
        name=IDENTITY_NAME,
        archive=archive,
        password=password,
        tool="/usr/bin/codesign",
        run=_run_binary,
    )
    allow_apple_tools(keychain, _run_binary)
    record_trust(
        keychain, certificate, policy="codeSign", name=IDENTITY_NAME, run=_run_binary
    )


def import_identity_archive(
    keychain: Path,
    *,
    name: str,
    archive: bytes,
    password: str,
    tool: str,
    run: Callable[[tuple[str, ...], bytes], bytes],
) -> None:
    """Import a PKCS#12 identity so macOS names its key after the identity.

    `security import` names the key in every later "wants to access key"
    dialog after the file it read, so an archive piped through stdin made
    macOS ask the owner about a key called "stdin": a request nobody can
    evaluate. With `-f pkcs12` it also labels the key "Imported Private Key"
    in Keychain Access. Measured on macOS 27: a file named `<name>.p12`,
    imported with its format inferred, gives the key both the label and the
    prompt name `name`. `security import` cannot read a named pipe, so the
    archive, encrypted under the caller's per-run password, is written to that
    file in a directory only this user can enter, and removed as soon as the
    import returns. Only `tool` may use the key without asking.
    """
    with tempfile.TemporaryDirectory(prefix="remap-identity-") as directory:
        source = Path(directory) / f"{name}.p12"
        descriptor = os.open(
            source, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(descriptor, "wb") as handle:
            _ = handle.write(archive)
        _ = run(
            (
                "/usr/bin/security",
                "import",
                str(source),
                "-k",
                str(keychain),
                "-P",
                password,
                "-x",
                "-T",
                tool,
            ),
            b"",
        )


def record_pending_trust(keychain: Path) -> bool:
    """Finish a creation that stopped before its trust setting was recorded.

    Trust is creation's last step and the one macOS asks the user about, so an
    unanswered dialog leaves the certificate and its key imported but untrusted.
    That exact state, and no other, is completed here: one certificate of this
    name, whose identity holds its private key and is refused only as untrusted.
    Returns False, changing nothing, for anything else.
    """
    output = _capture(
        ("/usr/bin/security", "find-identity", "-p", "codesigning", str(keychain))
    )
    pending = {
        match.group(1)
        for line in output.splitlines()
        if (match := UNTRUSTED_IDENTITY_PATTERN.fullmatch(line)) is not None
        and match.group(2) == IDENTITY_NAME
    }
    hashes = _certificate_hashes(keychain)
    if len(pending) != 1 or len(hashes) != 1 or hashes[0][0] not in pending:
        return False
    certificate = _capture(
        (
            "/usr/bin/security",
            "find-certificate",
            "-c",
            IDENTITY_NAME,
            "-p",
            str(keychain),
        )
    ).encode("ascii")
    der = ssl.PEM_cert_to_DER_cert(certificate.decode("ascii"))
    exported = (
        hashlib.sha1(der).hexdigest().upper(),
        hashlib.sha256(der).hexdigest().upper(),
    )
    if exported != hashes[0]:
        raise RuntimeError(
            "the exported Remap certificate is not the one in the keychain"
        )
    record_trust(
        keychain, certificate, policy="codeSign", name=IDENTITY_NAME, run=_run_binary
    )
    return True


def headless_trust() -> bool:
    """Whether trust changes must avoid macOS authorization dialogs."""
    return os.environ.get(HEADLESS_TRUST_VARIABLE) == "1"


def _headless_keychain_home() -> Path:
    runner_temp = os.environ.get("RUNNER_TEMP")
    return Path(runner_temp) if runner_temp else Path.home() / "Library/Keychains"


def headless_keychain() -> Path:
    """Create once, then return, a keychain this tool owns and can unlock.

    Its password is random, generated on creation, and kept beside it in a
    file only this user can read, because every tool in one gate run is a
    separate process and each must be able to unlock the keychain and record
    key partition lists without anybody typing.
    """
    home = _headless_keychain_home()
    keychain = home / "remap-headless.keychain-db"
    secret = home / "remap-headless.keychain-password"
    if keychain.is_file() and secret.is_file():
        password = secret.read_text(encoding="utf-8").strip()
        _run(("/usr/bin/security", "unlock-keychain", "-p", password, str(keychain)))
        return keychain
    password = os.urandom(24).hex()
    secret.touch(mode=0o600, exist_ok=False)
    _ = secret.write_text(password + "\n", encoding="utf-8")
    _run(("/usr/bin/security", "create-keychain", "-p", password, str(keychain)))
    # Never lock on a timer or on sleep: the gate is long, and a locked
    # keychain turns into the very dialog this exists to avoid.
    _run(("/usr/bin/security", "set-keychain-settings", str(keychain)))
    _run(("/usr/bin/security", "unlock-keychain", "-p", password, str(keychain)))
    existing = _capture(
        ("/usr/bin/security", "list-keychains", "-d", "user")
    ).splitlines()
    others = [line.strip().strip('"') for line in existing if line.strip()]
    _run(
        (
            "/usr/bin/security",
            "list-keychains",
            "-d",
            "user",
            "-s",
            str(keychain),
            *others,
        )
    )
    return keychain


def allow_apple_tools(
    keychain: Path, run: Callable[[tuple[str, ...], bytes], bytes]
) -> None:
    """Let Apple's signing tools use every key in the headless keychain.

    `security import -T` names the tool, and macOS still asks the user the
    first time that tool reaches for the key unless the key's partition list
    says Apple tools may. Interactive machines keep the question; headless
    ones have this run's password and answer it here. `run` is the caller's
    own binary runner, so its tests observe this call like the import.
    """
    if not headless_trust():
        return
    secret = _headless_keychain_home() / "remap-headless.keychain-password"
    password = secret.read_text(encoding="utf-8").strip()
    _ = run(
        (
            "/usr/bin/security",
            "set-key-partition-list",
            "-S",
            "apple-tool:,apple:,codesign:",
            "-s",
            "-k",
            password,
            str(keychain),
        ),
        b"",
    )


def record_trust(
    keychain: Path,
    certificate: bytes,
    *,
    policy: str,
    name: str,
    run: Callable[[tuple[str, ...], bytes], bytes],
) -> None:
    """Ask macOS, and through it the owner, to trust `name` for `policy`.

    macOS puts this question to the owner in a dialog, and `run` gives it two
    minutes. An unanswered dialog is an ordinary outcome, so it is reported as
    what happened and how to resume, never as a stack trace. The dialog itself
    says only that trust settings are changing, so the owner is told first
    which certificate it is about and what to choose.
    """
    if not headless_trust():
        print(trust_notice(name, policy), file=sys.stderr, flush=True)
    try:
        _ = run(trust_arguments(keychain, policy), certificate)
    except subprocess.TimeoutExpired:
        raise RuntimeError(
            f'macOS asked to trust the "{name}" certificate, and the dialog was not '
            + "answered within two minutes. Run the same command again at this Mac "
            + "and approve it; the build resumes at this step."
        ) from None


def trust_notice(name: str, policy: str) -> str:
    """The line printed just before macOS asks the owner to trust `name`."""
    return (
        "macOS will now ask to change your certificate trust settings so that it "
        + f'trusts "{name}" {TRUST_PURPOSES[policy]}. Choose Update Settings and '
        + "enter your login password to continue."
    )


def trust_arguments(keychain: Path, policy: str) -> tuple[str, ...]:
    """The command that records root trust for a PEM certificate on stdin.

    Interactive machines record it in the caller's keychain, which macOS
    confirms with the user. Headless ones record it in the System keychain
    through non-interactive sudo, because no dialog can be answered there.
    """
    if headless_trust():
        return (
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/security",
            "add-trusted-cert",
            "-d",
            "-r",
            "trustRoot",
            "-p",
            policy,
            "-k",
            str(SYSTEM_KEYCHAIN),
            "/dev/stdin",
        )
    return (
        "/usr/bin/security",
        "add-trusted-cert",
        "-r",
        "trustRoot",
        "-p",
        policy,
        "-k",
        str(keychain),
        "/dev/stdin",
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
O = Remap
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


def _make_archive(certificate: bytes, private_key: bytes, password: str) -> bytes:
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
                f"pass:{password}",
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
