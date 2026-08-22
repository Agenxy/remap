"""Descriptor-pinned, crash-recoverable macOS source-helper bootstrap."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import select
import signal
import stat
import subprocess
import time
from collections.abc import Generator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from tools.remap_macos_protocol import terminal_text
from tools.remap_native_package import has_extended_acl, list_extended_attributes

PRIVILEGED_HELPER_DIRECTORY = Path("/Library/PrivilegedHelperTools")
BOOTSTRAP_PREFIX = "org.agenxy.Remap.install."
BOOTSTRAP_STAGE_PREFIX = "org.agenxy.Remap.install-stage."
BOOTSTRAP_STAGE_CHILD = "candidate"
BOOTSTRAP_IDENTIFIER = "org.agenxy.Remap.install-bootstrap"
HELPER_TIMEOUT_SECONDS = 120
MAX_HELPER_OUTPUT_BYTES = 1_048_576
MAX_BOOTSTRAP_BYTES = 134_217_728
PROCESS_GROUP_GRACE_SECONDS = 0.25
PROCESS_REAP_TIMEOUT_SECONDS = 1.0
CDHASH_PATTERN = re.compile(r"[0-9a-f]{40,64}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True)
class ReviewedBootstrapSource:
    """One descriptor-pinned helper whose exact bytes crossed every review."""

    path: Path
    descriptor: int
    sha256: str
    byte_count: int
    identity: tuple[int, int, int, int, int, int, int, int, int]


@contextmanager
def bootstrap_helper(root: Path, source: Path, expected_cdhash: str):
    """Privately stage pinned bytes, publish, lease, and remove one helper."""
    verify_bootstrap_directory()
    inspect_bootstrap_residue()
    nonce = secrets.token_hex(16)
    destination = PRIVILEGED_HELPER_DIRECTORY / (BOOTSTRAP_PREFIX + nonce)
    staging = PRIVILEGED_HELPER_DIRECTORY / (BOOTSTRAP_STAGE_PREFIX + nonce)
    for path in (destination, staging):
        if path.exists() or path.is_symlink():
            raise RuntimeError("a random privileged-helper path already exists")
    notice = "Bootstrap preflight: privately staging one descriptor-pinned helper"
    notice += " under /Library/PrivilegedHelperTools. Unverified bytes remain"
    notice += " root-only; product mutation still requires separate approval."
    print(notice)
    with (
        reviewed_bootstrap_source(root, source, expected_cdhash) as reviewed,
        _published_bootstrap_helper(
            root, staging, destination, reviewed, expected_cdhash
        ) as helper,
    ):
        yield helper


@contextmanager
def reviewed_bootstrap_source(root: Path, source: Path, expected_cdhash: str):
    """Hold the exact reviewed helper vnode across privileged staging."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        information = os.fstat(descriptor)
        identity = _source_identity(information)
        unexpected = set(list_extended_attributes(descriptor, source)) - {
            "com.apple.provenance"
        }
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != os.getuid()
            or information.st_nlink != 1
            or stat.S_IMODE(information.st_mode) != 0o500
            or not 0 < information.st_size <= MAX_BOOTSTRAP_BYTES
            or getattr(information, "st_flags", 0) != 0
            or has_extended_acl(descriptor, source)
            or unexpected
        ):
            raise RuntimeError("the reviewed bootstrap source has unsafe metadata")
        identifier, cdhash = verified_code_identity(source, root=root)
        if identifier != BOOTSTRAP_IDENTIFIER or cdhash != expected_cdhash:
            raise RuntimeError("the reviewed bootstrap source has the wrong identity")
        reviewed = ReviewedBootstrapSource(
            source,
            descriptor,
            sha256_descriptor(descriptor),
            information.st_size,
            identity,
        )
        require_reviewed_source_unchanged(source, reviewed)
        try:
            yield reviewed
        finally:
            require_reviewed_source_unchanged(source, reviewed)
    finally:
        os.close(descriptor)


@contextmanager
def _published_bootstrap_helper(
    root: Path,
    staging: Path,
    destination: Path,
    source: ReviewedBootstrapSource,
    expected_cdhash: str,
):
    """Keep unverified bytes private and publish only the exact signed helper."""
    child = staging / BOOTSTRAP_STAGE_CHILD
    staging_created = False
    published = False
    lease_descriptor: int | None = None
    published_identity: tuple[int, int] | None = None
    try:
        run(
            ("/usr/bin/sudo", "-n", "/bin/mkdir", "-m", "0700", str(staging)), root=root
        )
        staging_created = True
        run(
            ("/usr/bin/sudo", "-n", "/usr/sbin/chown", "root:wheel", str(staging)),
            root=root,
        )
        run(
            (
                "/usr/bin/sudo",
                "-n",
                "/usr/bin/install",
                "-o",
                "root",
                "-g",
                "wheel",
                "-m",
                "0600",
                "/dev/null",
                str(child),
            ),
            root=root,
        )
        _ = os.lseek(source.descriptor, 0, os.SEEK_SET)
        run_with_input_descriptor(
            ("/usr/bin/sudo", "-n", "/usr/bin/tee", str(child)),
            source.descriptor,
            source.byte_count,
            root=root,
        )
        require_reviewed_source_unchanged(source.path, source)
        run(("/usr/bin/sudo", "-n", "/bin/chmod", "-N", str(child)), root=root)
        run(
            ("/usr/bin/sudo", "-n", "/usr/sbin/chown", "root:wheel", str(child)),
            root=root,
        )
        run(("/usr/bin/sudo", "-n", "/bin/chmod", "0400", str(child)), root=root)
        verify_private_staged_helper(
            root,
            child,
            source.sha256,
            source.byte_count,
            expected_cdhash,
        )
        run(("/usr/bin/sudo", "-n", "/bin/chmod", "0711", str(staging)), root=root)
        run(("/usr/bin/sudo", "-n", "/bin/chmod", "0555", str(child)), root=root)
        lease_descriptor = os.open(child, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        fcntl.flock(lease_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        published_identity = file_identity(os.fstat(lease_descriptor))
        require_exact_open_file(
            child, lease_descriptor, published_identity, source.sha256
        )
        identifier, cdhash = verified_code_identity(child, root=root)
        if identifier != BOOTSTRAP_IDENTIFIER or cdhash != expected_cdhash:
            raise RuntimeError("the publishable bootstrap stage changed code identity")
        require_path_identity(child, published_identity)
        run(
            ("/usr/bin/sudo", "-n", "/bin/mv", "-n", str(child), str(destination)),
            root=root,
        )
        require_path_absent(child)
        require_path_identity(destination, published_identity)
        published = True
        run(("/usr/bin/sudo", "-n", "/bin/rmdir", str(staging)), root=root)
        staging_created = False
        require_exact_open_file(
            destination, lease_descriptor, published_identity, source.sha256
        )
        identifier, cdhash = verified_code_identity(destination, root=root)
        if identifier != BOOTSTRAP_IDENTIFIER or cdhash != expected_cdhash:
            raise RuntimeError("the published bootstrap helper changed code identity")
        require_path_identity(destination, published_identity)
        yield destination
    finally:
        try:
            if published:
                assert lease_descriptor is not None
                assert published_identity is not None
                unlink_exact_published_helper(
                    root, destination, lease_descriptor, published_identity
                )
        finally:
            try:
                if staging_created:
                    cleanup_private_bootstrap_stage(root, staging, child)
            finally:
                if lease_descriptor is not None:
                    os.close(lease_descriptor)


def file_identity(information: os.stat_result) -> tuple[int, int]:
    """Return the stable filesystem identity used across atomic publication."""
    return information.st_dev, information.st_ino


def require_path_absent(path: Path) -> None:
    """Require a no-clobber move to have consumed the exact staged child."""
    try:
        _ = path.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("the no-clobber bootstrap publication did not consume its stage")


def require_path_identity(path: Path, expected: tuple[int, int]) -> None:
    """Require one pathname to resolve to the already-open regular vnode."""
    try:
        information = path.lstat()
    except OSError as error:
        raise RuntimeError("the privileged bootstrap path changed identity") from error
    if not stat.S_ISREG(information.st_mode) or file_identity(information) != expected:
        raise RuntimeError("the privileged bootstrap path changed identity")


def require_exact_open_file(
    path: Path,
    descriptor: int,
    expected_identity: tuple[int, int],
    expected_sha256: str,
) -> None:
    """Bind path, metadata, and bytes to the open publication lease."""
    information = os.fstat(descriptor)
    if (
        file_identity(information) != expected_identity
        or not stat.S_ISREG(information.st_mode)
        or information.st_uid != 0
        or information.st_gid != 0
        or information.st_nlink != 1
        or stat.S_IMODE(information.st_mode) != 0o555
        or getattr(information, "st_flags", 0) != 0
        or sha256_descriptor(descriptor) != expected_sha256
    ):
        raise RuntimeError("the open privileged bootstrap helper changed")
    require_path_identity(path, expected_identity)


def unlink_exact_published_helper(
    root: Path,
    destination: Path,
    descriptor: int,
    expected_identity: tuple[int, int],
) -> None:
    """Remove the published vnode by identity, without trusting its code bytes."""
    if file_identity(os.fstat(descriptor)) != expected_identity:
        raise RuntimeError("the open privileged bootstrap helper changed identity")
    require_path_identity(destination, expected_identity)
    run(("/usr/bin/sudo", "-n", "/bin/unlink", str(destination)), root=root)
    try:
        _ = destination.lstat()
    except FileNotFoundError:
        return
    raise RuntimeError("the exact privileged bootstrap helper was not removed")


def _source_identity(
    information: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int, int]:
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_gid,
        information.st_nlink,
        information.st_size,
        information.st_mtime_ns,
        information.st_ctime_ns,
    )


def require_reviewed_source_unchanged(
    path: Path, reviewed: ReviewedBootstrapSource
) -> None:
    try:
        current = path.lstat()
    except OSError as error:
        raise RuntimeError("the reviewed bootstrap source path changed") from error
    if (
        _source_identity(current) != reviewed.identity
        or sha256_descriptor(reviewed.descriptor) != reviewed.sha256
    ):
        raise RuntimeError("the reviewed bootstrap source changed identity or bytes")


def sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = 0
    while True:
        data = os.pread(descriptor, 1_048_576, offset)
        if not data:
            return digest.hexdigest()
        digest.update(data)
        offset += len(data)
        if offset > MAX_BOOTSTRAP_BYTES:
            raise RuntimeError("the reviewed bootstrap source exceeds its size bound")


def run_with_input_descriptor(
    arguments: Sequence[str], descriptor: int, byte_count: int, *, root: Path
) -> None:
    """Send exactly the reviewed byte count, never an attacker-extended EOF."""
    if not 0 < byte_count <= MAX_BOOTSTRAP_BYTES:
        raise RuntimeError("the reviewed bootstrap transfer size is unsafe")
    deadline = time.monotonic() + HELPER_TIMEOUT_SECONDS
    read_descriptor, write_descriptor = os.pipe()
    os.set_blocking(write_descriptor, False)
    try:
        process = subprocess.Popen(
            arguments,
            cwd=root,
            stdin=read_descriptor,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except BaseException:
        os.close(read_descriptor)
        os.close(write_descriptor)
        raise
    os.close(read_descriptor)
    transfer_error: Exception | None = None
    try:
        offset = 0
        while offset < byte_count:
            data = os.pread(descriptor, min(1_048_576, byte_count - offset), offset)
            if not data:
                raise RuntimeError(
                    "the reviewed bootstrap source shrank during transfer"
                )
            written = 0
            while written < len(data):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, HELPER_TIMEOUT_SECONDS)
                try:
                    count = os.write(write_descriptor, data[written:])
                except BlockingIOError:
                    _readable, writable, _exceptional = select.select(
                        [], [write_descriptor], [], remaining
                    )
                    if not writable:
                        raise subprocess.TimeoutExpired(
                            arguments, HELPER_TIMEOUT_SECONDS
                        )
                    continue
                if count == 0:
                    raise BrokenPipeError(
                        "the privileged bootstrap sink stopped reading"
                    )
                written += count
            offset += len(data)
        if os.pread(descriptor, 1, byte_count):
            raise RuntimeError("the reviewed bootstrap source grew during transfer")
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        transfer_error = error
    finally:
        os.close(write_descriptor)
    if transfer_error is not None:
        terminate_process_group(process, deadline)
        raise transfer_error
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        kill_process_group_and_reap(process)
        raise subprocess.TimeoutExpired(arguments, HELPER_TIMEOUT_SECONDS)
    try:
        _standard_output, standard_error = process.communicate(timeout=remaining)
    except subprocess.TimeoutExpired:
        kill_process_group_and_reap(process)
        raise
    if len(standard_error) > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError("the native tool returned more than one MiB")
    if process.returncode != 0:
        raise subprocess.CalledProcessError(
            process.returncode,
            arguments,
            stderr=standard_error,
        )


def terminate_process_group(process: subprocess.Popen[bytes], deadline: float) -> None:
    """Terminate every command descendant and settle within a fixed bound."""
    signal_process_group(process, signal.SIGTERM)
    remaining = min(
        PROCESS_GROUP_GRACE_SECONDS,
        max(0.0, deadline - time.monotonic()),
    )
    if remaining > 0:
        try:
            _ = process.communicate(timeout=remaining)
            return
        except subprocess.TimeoutExpired:
            pass
    kill_process_group_and_reap(process)


def kill_process_group_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Kill the isolated command group and never reap without a deadline."""
    signal_process_group(process, signal.SIGKILL)
    try:
        _ = process.communicate(timeout=PROCESS_REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        if process.stderr is not None:
            process.stderr.close()
        raise RuntimeError(
            "the privileged bootstrap command tree could not be reaped"
        ) from error


def signal_process_group(
    process: subprocess.Popen[bytes], value: signal.Signals
) -> None:
    """Signal the session created for exactly one privileged command tree."""
    try:
        os.killpg(process.pid, value)
    except ProcessLookupError:
        return


def verify_private_staged_helper(
    root: Path,
    path: Path,
    expected_sha256: str,
    expected_byte_count: int,
    expected_cdhash: str,
) -> None:
    """Verify exact root-private bytes before they become publicly reachable."""
    metadata = capture(
        (
            "/usr/bin/sudo",
            "-n",
            "/usr/bin/stat",
            "-f",
            "%z:%u:%g:%l:%Lp:%HT",
            str(path),
        ),
        root=root,
    )
    fields = metadata.split(":")
    if (
        fields != [str(expected_byte_count), "0", "0", "1", "400", "Regular File"]
        or not 0 < expected_byte_count <= MAX_BOOTSTRAP_BYTES
    ):
        raise RuntimeError("the private bootstrap stage has unsafe size or metadata")
    output = capture(
        ("/usr/bin/sudo", "-n", "/usr/bin/shasum", "-a", "256", str(path)),
        root=root,
    )
    digest = output.split(maxsplit=1)[0] if output else ""
    if digest != expected_sha256 or not SHA256_PATTERN.fullmatch(digest):
        raise RuntimeError("the private bootstrap stage has the wrong SHA-256")
    identifier, cdhash = verified_code_identity(path, privileged=True, root=root)
    if identifier != BOOTSTRAP_IDENTIFIER or cdhash != expected_cdhash:
        raise RuntimeError("the private bootstrap stage has the wrong code identity")


def cleanup_private_bootstrap_stage(root: Path, staging: Path, child: Path) -> None:
    """Remove only the exact random private stage armed by this process."""
    for command in (
        ("/usr/bin/sudo", "-n", "/bin/unlink", str(child)),
        ("/usr/bin/sudo", "-n", "/bin/rmdir", str(staging)),
    ):
        run_cleanup(command, root=root)
    if staging.exists() or staging.is_symlink():
        raise RuntimeError("the exact private bootstrap stage was not removed")


def run_cleanup(arguments: Sequence[str], *, root: Path) -> None:
    _ = subprocess.run(
        arguments,
        cwd=root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=HELPER_TIMEOUT_SECONDS,
    )


def verify_bootstrap_directory() -> None:
    descriptor = os.open(
        PRIVILEGED_HELPER_DIRECTORY,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        information = os.fstat(descriptor)
        unexpected = set(
            list_extended_attributes(descriptor, PRIVILEGED_HELPER_DIRECTORY)
        ) - {"com.apple.provenance"}
        if (
            not stat.S_ISDIR(information.st_mode)
            or information.st_uid != 0
            or information.st_gid != 0
            or stat.S_IMODE(information.st_mode) & 0o022
            or getattr(information, "st_flags", 0) != 0
            or os.access(PRIVILEGED_HELPER_DIRECTORY, os.W_OK)
            or has_extended_acl(descriptor, PRIVILEGED_HELPER_DIRECTORY)
            or unexpected
        ):
            raise RuntimeError("the privileged-helper directory has unsafe metadata")
    finally:
        os.close(descriptor)


def verify_bootstrap_file(
    path: Path, expected_cdhash: str | None, expected_sha256: str | None = None
) -> str:
    with validated_bootstrap_descriptor(path) as descriptor:
        if (
            expected_sha256 is not None
            and sha256_descriptor(descriptor) != expected_sha256
        ):
            raise RuntimeError(
                "the privileged bootstrap helper bytes do not match the reviewed build"
            )
    identifier, actual_cdhash = verified_code_identity(path)
    if identifier != BOOTSTRAP_IDENTIFIER:
        raise RuntimeError("the privileged bootstrap helper has an unrelated identity")
    if expected_cdhash is not None and actual_cdhash != expected_cdhash:
        raise RuntimeError(
            "the privileged bootstrap helper does not match the reviewed build"
        )
    return actual_cdhash


@contextmanager
def validated_bootstrap_descriptor(path: Path) -> Generator[int]:
    """Open and validate a public candidate without trusting or executing bytes."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        information = os.fstat(descriptor)
        unexpected = set(list_extended_attributes(descriptor, path)) - {
            "com.apple.provenance"
        }
        if (
            not stat.S_ISREG(information.st_mode)
            or information.st_uid != 0
            or information.st_gid != 0
            or information.st_nlink != 1
            or stat.S_IMODE(information.st_mode) != 0o555
            or getattr(information, "st_flags", 0) != 0
            or os.access(path, os.W_OK)
            or has_extended_acl(descriptor, path)
            or unexpected
        ):
            raise RuntimeError("the privileged bootstrap helper has unsafe metadata")
        yield descriptor
    finally:
        os.close(descriptor)


def inspect_bootstrap_residue() -> None:
    candidates = sorted(
        path
        for path in PRIVILEGED_HELPER_DIRECTORY.iterdir()
        if path.name.startswith(BOOTSTRAP_PREFIX)
        or path.name.startswith(BOOTSTRAP_STAGE_PREFIX)
    )
    if len(candidates) > 32:
        raise RuntimeError(
            "too many privileged Remap bootstrap candidates require inspection"
        )
    for path in candidates:
        if path.name.startswith(BOOTSTRAP_STAGE_PREFIX):
            _inspect_stage(path)
            continue
        _inspect_direct_candidate(path)


def _inspect_direct_candidate(path: Path) -> None:
    with validated_bootstrap_descriptor(path) as descriptor:
        digest = sha256_descriptor(descriptor)
    try:
        identifier, cdhash = verified_code_identity(path)
        classification = (
            f"verified CDHash {cdhash}"
            if identifier == BOOTSTRAP_IDENTIFIER
            else "invalid code identity"
        )
    except (OSError, RuntimeError, subprocess.SubprocessError):
        classification = "invalid code identity"
    safe = terminal_text(str(path))
    detail = f"{safe} ({classification}, SHA-256 {digest})."
    print("Bootstrap residue retained for explicit recovery: " + detail)


def _inspect_stage(path: Path) -> None:
    suffix = path.name.removeprefix(BOOTSTRAP_STAGE_PREFIX)
    information = path.lstat()
    if (
        len(suffix) != 32
        or not all(character in "0123456789abcdef" for character in suffix)
        or not stat.S_ISDIR(information.st_mode)
        or information.st_uid != 0
        or information.st_gid != 0
        or stat.S_IMODE(information.st_mode) not in {0o700, 0o711}
    ):
        raise RuntimeError("a private bootstrap stage has unsafe metadata")
    safe_path = terminal_text(str(path))
    mode = stat.S_IMODE(information.st_mode)
    detail = f"{safe_path} (root:wheel {mode:04o}; bytes are not executed here)."
    print("Private bootstrap stage retained for explicit recovery: " + detail)


def verified_code_identity(
    path: Path, *, privileged: bool = False, root: Path | None = None
) -> tuple[str, str]:
    prefix = ("/usr/bin/sudo", "-n") if privileged else ()
    working_root = root or path.parent
    run(
        (*prefix, "/usr/bin/codesign", "--verify", "--strict", str(path)),
        root=working_root,
    )
    details = capture(
        (*prefix, "/usr/bin/codesign", "-d", "--verbose=4", str(path)),
        root=working_root,
        include_standard_error=True,
    )
    values = {
        key: value
        for line in details.splitlines()
        if "=" in line
        for key, value in [line.split("=", maxsplit=1)]
    }
    identifier = values.get("Identifier")
    cdhash = values.get("CDHash")
    if not identifier or not cdhash or not CDHASH_PATTERN.fullmatch(cdhash):
        raise RuntimeError(f"codesign did not report a stable identity for {path}")
    return identifier, cdhash


def capture(
    arguments: Sequence[str],
    *,
    root: Path,
    include_standard_error: bool = False,
) -> str:
    result = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    output = result.stdout + (result.stderr if include_standard_error else "")
    if len(output.encode("utf-8")) > MAX_HELPER_OUTPUT_BYTES:
        raise RuntimeError("the native tool returned more than one MiB")
    return output.strip()


def run(arguments: Sequence[str], *, root: Path) -> None:
    _ = subprocess.run(arguments, cwd=root, check=True, timeout=HELPER_TIMEOUT_SECONDS)
