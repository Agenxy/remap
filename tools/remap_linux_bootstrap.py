"""Root-owned bootstrap boundary for Remap's native Linux lifecycle helper."""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import secrets
import stat
import subprocess
import sys
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from tools.remap_linux_protocol import terminal_text

SUDO = Path("/usr/bin/sudo")
INSTALL = Path("/usr/bin/install")
MKDIR = Path("/usr/bin/mkdir")
UNLINK = Path("/usr/bin/unlink")
RMDIR = Path("/usr/bin/rmdir")
RUNTIME_ROOT = Path("/run")
PROC_ROOT = Path("/proc")
BOOTSTRAP_DIRECTORY_PREFIX = "remap-bootstrap-"
BOOTSTRAP_HELPER_NAME = "remap-linux-system"
MAX_BOOTSTRAP_HELPER_BYTES = 128 * 1024 * 1024
MEMFD_CLOEXEC = 0x0001
MEMFD_ALLOW_SEALING = 0x0002
F_ADD_SEALS = 1_033
F_GET_SEALS = 1_034
F_SEAL_SEAL = 0x0001
F_SEAL_SHRINK = 0x0002
F_SEAL_GROW = 0x0004
F_SEAL_WRITE = 0x0008
REQUIRED_MEMFD_SEALS = F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE
ALLOWED_PLATFORM_XATTRS = frozenset(
    {"security.evm", "security.ima", "security.selinux"}
)
ACL_XATTRS = frozenset({"system.posix_acl_access", "system.posix_acl_default"})


@dataclass(frozen=True)
class FileIdentity:
    """Exact metadata and contents pinned for one reviewed regular file."""

    device: int
    inode: int
    mode: int
    owner_uid: int
    owner_gid: int
    links: int
    size: int
    modified_ns: int
    changed_ns: int
    digest: str
    xattrs: tuple[tuple[str, bytes], ...]


@dataclass(frozen=True)
class TrustedHelper:
    """A root-owned helper whose path and complete identity are pinned."""

    path: Path
    identity: FileIdentity


@dataclass(frozen=True)
class SealedHelperSource:
    """One immutable anonymous file and its validated procfs read path."""

    path: Path
    descriptor: int


def verify_bootstrap_environment() -> None:
    """Require absolute host tools and a non-writable root runtime directory."""
    required = (SUDO, INSTALL, MKDIR, UNLINK, RMDIR)
    missing = tuple(
        path for path in required if not path.is_file() or not os.access(path, os.X_OK)
    )
    if missing:
        names = ", ".join(str(path) for path in missing)
        raise RuntimeError(
            f"native Linux installation requires {names}; install the operating "
            + "system's sudo and coreutils packages, then retry"
        )
    verify_trusted_directory(RUNTIME_ROOT, expected_mode=None)
    verify_sealed_source_support()


def verify_sealed_source_support() -> None:
    """Prove this kernel and procfs can preserve the sealed-source boundary."""
    descriptor = _create_sealable_memfd()
    content = b"Remap sealed bootstrap preflight\n"
    try:
        _ = os.write(descriptor, content)
        os.fchmod(descriptor, 0o500)
        _ = fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_MEMFD_SEALS)
        information = os.fstat(descriptor)
        reviewed = FileIdentity(
            device=information.st_dev,
            inode=information.st_ino,
            mode=0o500,
            owner_uid=information.st_uid,
            owner_gid=information.st_gid,
            links=0,
            size=len(content),
            modified_ns=information.st_mtime_ns,
            changed_ns=information.st_ctime_ns,
            digest=hashlib.sha256(content).hexdigest(),
            xattrs=(),
        )
        sealed = SealedHelperSource(
            path=PROC_ROOT / str(os.getpid()) / "fd" / str(descriptor),
            descriptor=descriptor,
        )
        verify_sealed_helper_source(sealed, reviewed)
        try:
            _ = os.pwrite(descriptor, b"x", 0)
        except OSError as error:
            if error.errno != errno.EPERM:
                raise RuntimeError(
                    "the Linux kernel returned an unexpected memfd seal result"
                ) from error
        else:
            raise RuntimeError("the Linux kernel did not enforce the memfd write seal")
    finally:
        os.close(descriptor)


@contextmanager
def bootstrap_helper(
    root: Path, source: Path, source_uid: int
) -> Generator[TrustedHelper, None, None]:
    """Stage, pin, yield, and exactly remove one root-owned helper."""
    verify_trusted_directory(RUNTIME_ROOT, expected_mode=None)
    source_descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        reviewed = review_helper_source(source, source_descriptor, source_uid)
        with (
            sealed_helper_source(source, source_descriptor, reviewed) as sealed_source,
            _staged_helper(
                root,
                sealed_source,
                source,
                source_descriptor,
                reviewed,
            ) as helper,
        ):
            yield helper
    finally:
        os.close(source_descriptor)


@contextmanager
def _staged_helper(
    root: Path,
    sealed_source: SealedHelperSource,
    reviewed_path: Path,
    reviewed_descriptor: int,
    reviewed_identity: FileIdentity,
) -> Generator[TrustedHelper, None, None]:
    """Create one leased root helper from immutable reviewed bytes."""
    directory = RUNTIME_ROOT / (BOOTSTRAP_DIRECTORY_PREFIX + secrets.token_hex(16))
    destination = directory / BOOTSTRAP_HELPER_NAME
    staged_helper: TrustedHelper | None = None
    lease_descriptor: int | None = None
    runtime_lease_descriptor: int | None = None
    directory_created = False
    try:
        runtime_lease_descriptor = open_runtime_lease()
        inspect_bootstrap_residue()
        if directory.exists() or directory.is_symlink():
            raise RuntimeError("the random Linux bootstrap directory already exists")
        print(
            "Bootstrap preflight: staging one root-owned, content-verified helper "
            + f"under {RUNTIME_ROOT}. It is removed when this command returns; "
            + "product mutation still requires the separate preview approval."
        )
        _run(
            (
                str(SUDO),
                "-n",
                "--",
                str(MKDIR),
                "--mode=0711",
                "--",
                str(directory),
            ),
            root,
        )
        directory_created = True
        verify_trusted_directory(directory, expected_mode=0o711)
        verify_reviewed_helper_source(
            reviewed_path, reviewed_descriptor, reviewed_identity
        )
        verify_sealed_helper_source(sealed_source, reviewed_identity)
        _run(
            (
                str(SUDO),
                "-n",
                "--",
                str(INSTALL),
                "--owner=root",
                "--group=root",
                "--mode=0555",
                "--",
                str(sealed_source.path),
                str(destination),
            ),
            root,
        )
        staged_helper = capture_trusted_helper(
            destination, expected_digest=None, expected_mode=0o555
        )
        verify_reviewed_helper_source(
            reviewed_path, reviewed_descriptor, reviewed_identity
        )
        verify_sealed_helper_source(sealed_source, reviewed_identity)
        if staged_helper.identity.digest != reviewed_identity.digest:
            raise RuntimeError(
                "the root-owned Linux bootstrap helper differs from the reviewed source"
            )
        lease_descriptor = os.open(
            staged_helper.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
        )
        fcntl.flock(lease_descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        os.close(runtime_lease_descriptor)
        runtime_lease_descriptor = None
        yield staged_helper
    finally:
        try:
            if directory_created and runtime_lease_descriptor is None:
                runtime_lease_descriptor = open_runtime_lease()
            if staged_helper is not None:
                verify_pinned_helper(staged_helper)
                _run(
                    (
                        str(SUDO),
                        "-n",
                        "--",
                        str(UNLINK),
                        str(staged_helper.path),
                    ),
                    root,
                )
                if destination.exists() or destination.is_symlink():
                    raise RuntimeError(
                        "the exact Linux bootstrap helper was not removed"
                    )
            if directory_created:
                verify_trusted_directory(directory, expected_mode=0o711)
                _run((str(SUDO), "-n", "--", str(RMDIR), str(directory)), root)
                if directory.exists() or directory.is_symlink():
                    raise RuntimeError(
                        "the exact Linux bootstrap directory was not removed"
                    )
        finally:
            if lease_descriptor is not None:
                os.close(lease_descriptor)
            if runtime_lease_descriptor is not None:
                os.close(runtime_lease_descriptor)


@contextmanager
def sealed_helper_source(
    source_path: Path,
    source_descriptor: int,
    reviewed: FileIdentity,
) -> Generator[SealedHelperSource, None, None]:
    """Copy reviewed bytes into one immutable memfd and expose only its proc path."""
    descriptor = _create_sealable_memfd()
    sealed = SealedHelperSource(
        path=PROC_ROOT / str(os.getpid()) / "fd" / str(descriptor),
        descriptor=descriptor,
    )
    try:
        _copy_descriptor(source_descriptor, descriptor, reviewed.size)
        os.fchmod(descriptor, 0o500)
        _ = fcntl.fcntl(descriptor, F_ADD_SEALS, REQUIRED_MEMFD_SEALS)
        verify_reviewed_helper_source(source_path, source_descriptor, reviewed)
        verify_sealed_helper_source(sealed, reviewed)
        yield sealed
    finally:
        os.close(descriptor)


def _create_sealable_memfd() -> int:
    if sys.platform != "linux":
        raise RuntimeError("sealed Linux bootstrap sources require Linux")
    creator_value = getattr(os, "memfd_create", None)
    if not callable(creator_value):
        raise OSError(
            "this Linux Python runtime does not provide memfd_create; upgrade "
            + "Python or use a supported distribution"
        )
    creator = cast("Callable[[str, int], int]", creator_value)
    return creator(
        "remap-linux-system",
        MEMFD_CLOEXEC | MEMFD_ALLOW_SEALING,
    )


def verify_sealed_helper_source(
    sealed: SealedHelperSource, reviewed: FileIdentity
) -> None:
    """Revalidate immutable bytes, seals, metadata, and the exact procfs path."""
    information = os.fstat(sealed.descriptor)
    seals = fcntl.fcntl(sealed.descriptor, F_GET_SEALS)
    descriptor_flags = fcntl.fcntl(sealed.descriptor, fcntl.F_GETFD)
    expected_path = PROC_ROOT / str(os.getpid()) / "fd" / str(sealed.descriptor)
    if (
        seals != REQUIRED_MEMFD_SEALS
        or descriptor_flags & fcntl.FD_CLOEXEC == 0
        or sealed.path != expected_path
        or not stat.S_ISREG(information.st_mode)
        or stat.S_IMODE(information.st_mode) != 0o500
        or information.st_uid != reviewed.owner_uid
        or information.st_gid != reviewed.owner_gid
        or information.st_nlink != 0
        or information.st_size != reviewed.size
        or os.listxattr(sealed.descriptor)
        or _descriptor_digest(sealed.descriptor) != reviewed.digest
    ):
        raise RuntimeError("the sealed Linux bootstrap source changed before use")
    _verify_proc_descriptor_path(sealed)


def _copy_descriptor(source: int, destination: int, expected_size: int) -> None:
    offset = 0
    while offset < expected_size:
        chunk = os.pread(source, min(1024 * 1024, expected_size - offset), offset)
        if not chunk:
            break
        written = 0
        while written < len(chunk):
            count = os.write(destination, chunk[written:])
            if count <= 0:
                raise RuntimeError("the sealed Linux helper copy made no progress")
            written += count
        offset += len(chunk)
    if offset != expected_size or os.pread(source, 1, offset):
        raise RuntimeError("the reviewed Linux helper changed size while sealing")


def _verify_proc_descriptor_path(sealed: SealedHelperSource) -> None:
    proc_descriptor = os.open(
        PROC_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    pid_descriptor: int | None = None
    fd_directory_descriptor: int | None = None
    opened_descriptor: int | None = None
    try:
        _verify_trusted_directory_descriptor(
            PROC_ROOT, proc_descriptor, expected_mode=None
        )
        pid_descriptor = os.open(
            str(os.getpid()),
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=proc_descriptor,
        )
        _require_owned_proc_directory(pid_descriptor)
        fd_directory_descriptor = os.open(
            "fd",
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=pid_descriptor,
        )
        _require_owned_proc_directory(fd_directory_descriptor)
        link = os.stat(
            str(sealed.descriptor),
            dir_fd=fd_directory_descriptor,
            follow_symlinks=False,
        )
        if not stat.S_ISLNK(link.st_mode) or link.st_uid != os.getuid():
            raise RuntimeError("the sealed Linux helper procfs link is unsafe")
        opened_descriptor = os.open(
            str(sealed.descriptor),
            os.O_RDONLY | os.O_CLOEXEC,
            dir_fd=fd_directory_descriptor,
        )
        expected = os.fstat(sealed.descriptor)
        actual = os.fstat(opened_descriptor)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError("the sealed Linux helper procfs path changed")
    finally:
        if opened_descriptor is not None:
            os.close(opened_descriptor)
        if fd_directory_descriptor is not None:
            os.close(fd_directory_descriptor)
        if pid_descriptor is not None:
            os.close(pid_descriptor)
        os.close(proc_descriptor)


def _require_owned_proc_directory(descriptor: int) -> None:
    information = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != os.getuid()
        or stat.S_IMODE(information.st_mode) & 0o022
    ):
        raise RuntimeError("the sealed Linux helper procfs ancestry is unsafe")


def open_runtime_lease() -> int:
    """Open and share-lock the verified runtime root around one staging edge."""
    verify_trusted_directory(RUNTIME_ROOT, expected_mode=None)
    descriptor = os.open(
        RUNTIME_ROOT,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        _verify_trusted_directory_descriptor(
            RUNTIME_ROOT, descriptor, expected_mode=None
        )
    except BlockingIOError as error:
        os.close(descriptor)
        raise RuntimeError(
            "another native Linux bootstrap or recovery transaction is active; "
            + "wait for it to finish, then retry"
        ) from error
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def inspect_bootstrap_residue() -> None:
    """Disclose verified crash residue without deleting or executing it."""
    candidates = sorted(
        path
        for path in RUNTIME_ROOT.iterdir()
        if path.name.startswith(BOOTSTRAP_DIRECTORY_PREFIX)
    )
    if len(candidates) > 32:
        raise RuntimeError("too many Linux bootstrap candidates require inspection")
    for directory in candidates:
        if not _is_bootstrap_directory_name(directory.name):
            raise RuntimeError(
                "an unexpected Linux bootstrap namespace entry requires "
                + f"administrator inspection: {terminal_text(str(directory))}"
            )
        verify_trusted_directory(directory, expected_mode=0o711)
        path = directory / BOOTSTRAP_HELPER_NAME
        if not path.exists() and not path.is_symlink():
            print(
                "Bootstrap directory retained for native content inspection: "
                + f"{terminal_text(str(directory))}."
            )
            continue
        helper = capture_trusted_helper(path, expected_digest=None, expected_mode=0o555)
        print(
            "Bootstrap residue retained for explicit inspection: "
            + f"{terminal_text(str(path))} (SHA-256 {helper.identity.digest})."
        )


def _is_bootstrap_directory_name(name: str) -> bool:
    suffix = name.removeprefix(BOOTSTRAP_DIRECTORY_PREFIX)
    return (
        name.startswith(BOOTSTRAP_DIRECTORY_PREFIX)
        and len(suffix) == 32
        and all(character in "0123456789abcdef" for character in suffix)
    )


def review_helper_source(path: Path, descriptor: int, owner_uid: int) -> FileIdentity:
    identity = file_identity(descriptor)
    require_path_matches_descriptor(path, descriptor)
    if (
        identity.owner_uid != owner_uid
        or identity.links != 1
        or identity.mode != 0o500
        or identity.xattrs
    ):
        raise RuntimeError(
            "the reviewed Linux helper source has unsafe ownership or metadata"
        )
    return identity


def verify_reviewed_helper_source(
    path: Path, descriptor: int, expected: FileIdentity
) -> None:
    require_path_matches_descriptor(path, descriptor)
    if file_identity(descriptor) != expected:
        raise RuntimeError("the reviewed Linux helper source changed while staging")


def capture_trusted_helper(
    path: Path, *, expected_digest: str | None, expected_mode: int
) -> TrustedHelper:
    verify_root_owned_ancestry(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        identity = file_identity(descriptor)
        require_path_matches_descriptor(path, descriptor)
    finally:
        os.close(descriptor)
    if (
        identity.owner_uid != 0
        or identity.owner_gid != 0
        or identity.links != 1
        or identity.mode != expected_mode
        or {name for name, _value in identity.xattrs} - ALLOWED_PLATFORM_XATTRS
        or expected_digest is not None
        and identity.digest != expected_digest
    ):
        raise RuntimeError(
            "the privileged Linux helper has unsafe identity or metadata"
        )
    return TrustedHelper(path=path, identity=identity)


@contextmanager
def open_verified_helper(
    helper: TrustedHelper,
) -> Generator[int, None, None]:
    verify_root_owned_ancestry(helper.path.parent)
    descriptor = os.open(helper.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH | fcntl.LOCK_NB)
        require_path_matches_descriptor(helper.path, descriptor)
        if file_identity(descriptor) != helper.identity:
            raise RuntimeError("the privileged Linux helper changed before execution")
        yield descriptor
    finally:
        os.close(descriptor)


def verify_pinned_helper(helper: TrustedHelper) -> None:
    descriptor = os.open(helper.path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        require_path_matches_descriptor(helper.path, descriptor)
        if file_identity(descriptor) != helper.identity:
            raise RuntimeError("the privileged Linux helper changed during execution")
    finally:
        os.close(descriptor)


def verify_root_owned_ancestry(directory: Path) -> None:
    resolved = directory if directory.is_absolute() else directory.resolve(strict=True)
    current = Path(resolved.anchor)
    verify_trusted_directory(current, expected_mode=None)
    for component in resolved.parts[1:]:
        current /= component
        verify_trusted_directory(current, expected_mode=None)


def verify_trusted_directory(path: Path, expected_mode: int | None) -> None:
    descriptor = open_metadata_directory(path)
    try:
        first = os.fstat(descriptor)
        require_path_matches_descriptor(path, descriptor)
        names = set(os.listxattr(path, follow_symlinks=False))
        require_path_matches_descriptor(path, descriptor)
        second = os.fstat(descriptor)
        if _directory_identity(first) != _directory_identity(second):
            raise RuntimeError(f"the trusted Linux directory changed: {path}")
        _validate_trusted_directory(path, second, names, expected_mode)
    finally:
        os.close(descriptor)


def open_metadata_directory(path: Path) -> int:
    path_flag = getattr(os, "O_PATH", None)
    if sys.platform == "linux" and not isinstance(path_flag, int):
        raise OSError("this Linux Python runtime does not expose O_PATH")
    access = path_flag if isinstance(path_flag, int) else os.O_RDONLY
    return os.open(path, access | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)


def _verify_trusted_directory_descriptor(
    path: Path, descriptor: int, expected_mode: int | None
) -> None:
    first = os.fstat(descriptor)
    names = set(os.listxattr(descriptor))
    require_path_matches_descriptor(path, descriptor)
    second = os.fstat(descriptor)
    if _directory_identity(first) != _directory_identity(second):
        raise RuntimeError(f"the trusted Linux directory changed: {path}")
    _validate_trusted_directory(path, second, names, expected_mode)


def _validate_trusted_directory(
    path: Path,
    information: os.stat_result,
    names: set[str],
    expected_mode: int | None,
) -> None:
    mode = stat.S_IMODE(information.st_mode)
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_uid != 0
        or information.st_gid != 0
        or mode & 0o022
        or expected_mode is not None
        and mode != expected_mode
        or names & ACL_XATTRS
        or names - ALLOWED_PLATFORM_XATTRS
    ):
        raise RuntimeError(f"the trusted Linux directory has unsafe metadata: {path}")


def _directory_identity(information: os.stat_result) -> tuple[int, ...]:
    return (
        information.st_dev,
        information.st_ino,
        information.st_mode,
        information.st_uid,
        information.st_gid,
        information.st_nlink,
        information.st_ctime_ns,
    )


def file_identity(descriptor: int) -> FileIdentity:
    information = os.fstat(descriptor)
    if (
        not stat.S_ISREG(information.st_mode)
        or information.st_size <= 0
        or information.st_size > MAX_BOOTSTRAP_HELPER_BYTES
    ):
        raise RuntimeError("the Linux helper is not a bounded regular file")
    xattrs = tuple(
        (name, os.getxattr(descriptor, name))
        for name in sorted(os.listxattr(descriptor))
    )
    return FileIdentity(
        device=information.st_dev,
        inode=information.st_ino,
        mode=stat.S_IMODE(information.st_mode),
        owner_uid=information.st_uid,
        owner_gid=information.st_gid,
        links=information.st_nlink,
        size=information.st_size,
        modified_ns=information.st_mtime_ns,
        changed_ns=information.st_ctime_ns,
        digest=_descriptor_digest(descriptor),
        xattrs=xattrs,
    )


def require_path_matches_descriptor(path: Path, descriptor: int) -> None:
    path_information = path.lstat()
    descriptor_information = os.fstat(descriptor)
    if (
        path_information.st_dev != descriptor_information.st_dev
        or path_information.st_ino != descriptor_information.st_ino
        or stat.S_IFMT(path_information.st_mode)
        != stat.S_IFMT(descriptor_information.st_mode)
    ):
        raise RuntimeError(f"the trusted Linux path changed while open: {path}")


def _descriptor_digest(descriptor: int) -> str:
    digest = hashlib.sha256()
    offset = os.lseek(descriptor, 0, os.SEEK_CUR)
    try:
        _ = os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
    finally:
        _ = os.lseek(descriptor, offset, os.SEEK_SET)
    return digest.hexdigest()


def _run(arguments: tuple[str, ...], root: Path) -> None:
    _ = subprocess.run(arguments, cwd=root, check=True)
