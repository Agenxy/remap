"""Deterministic source image and manifest for the native macOS installer."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import plistlib
import re
import shutil
import stat
import sys
from ctypes import (
    CDLL,
    POINTER,
    byref,
    c_char_p,
    c_int,
    c_size_t,
    c_ssize_t,
    c_void_p,
    create_string_buffer,
    get_errno,
)
from dataclasses import dataclass
from errno import ENOENT
from functools import cache
from pathlib import Path
from typing import cast

PRODUCT_IDENTIFIER = "org.agenxy.Remap"
DAEMON_LABEL = f"{PRODUCT_IDENTIFIER}.daemon"
RESOLVER_LABEL = f"{PRODUCT_IDENTIFIER}.resolver"
INSTALL_ROOT = Path("/Library/Application Support/Agenxy/Remap/Install")
CURRENT_ROOT = INSTALL_ROOT / "current"
GENERATIONS_ROOT = INSTALL_ROOT / "Generations"
SYSTEM_SOCKET = Path("/var/run/org.agenxy.Remap.system.sock")
INSTALL_CONFIGURATION = ".remap-macos-install-v2.json"
GENERATION_ID_PLACEHOLDER = "{generationID}"


@dataclass(frozen=True)
class NativeProductFiles:
    """Already built and signed inputs for one native source package."""

    app: Path
    cli: Path
    daemon: Path
    installer: Path
    resolver: Path
    system_tool: Path
    manpages: Path
    completions: dict[str, Path]
    license: Path
    notice: Path
    signing_certificate_sha256: str


@dataclass(frozen=True)
class NativePackage:
    """One immutable payload plus its canonical external manifest."""

    root: Path
    payload: Path
    manifest: Path
    manifest_digest: str
    generation_id: str


def assemble(
    root: Path,
    files: NativeProductFiles,
    *,
    product_version: str,
    account_name: str,
    owner_uid: int,
    group_name: str,
    data_directory: Path,
    upstreams: list[str],
    previous_generation_id: str | None,
) -> NativePackage:
    """Build an immutable, manifest-addressed payload without privileged effects."""
    _validate_empty_private_root(root)
    payload = root / "payload"
    payload.mkdir(mode=0o700)
    _copy_inputs(payload, files)
    configuration = _install_configuration(
        owner_uid=owner_uid,
        data_directory=data_directory,
        signing_certificate_sha256=files.signing_certificate_sha256,
    )
    _write_install_configuration(payload, configuration)
    generation_id = _generation_id(
        product_version=product_version,
        entries=_manifest_entries(payload),
        account_name=account_name,
        owner_uid=owner_uid,
        group_name=group_name,
        data_directory=data_directory,
        upstreams=upstreams,
    )
    _write_launchd_documents(
        payload,
        generation_id=generation_id,
        account_name=account_name,
        owner_uid=owner_uid,
        group_name=group_name,
        data_directory=data_directory,
        upstreams=upstreams,
    )
    entries = _manifest_entries(payload)
    manifest = _manifest_document(
        generation_id=generation_id,
        product_version=product_version,
        previous_generation_id=previous_generation_id,
        entries=entries,
    )
    manifest_bytes = canonical_json(manifest)
    manifest_path = root / "manifest.json"
    _ = manifest_path.write_bytes(manifest_bytes)
    os.chmod(manifest_path, 0o400)
    _sanitize_package_tree(root)
    return NativePackage(
        root=root,
        payload=payload,
        manifest=manifest_path,
        manifest_digest=hashlib.sha256(manifest_bytes).hexdigest(),
        generation_id=generation_id,
    )


def canonical_json(value: object) -> bytes:
    """Match Swift's sorted, compact canonical JSON representation."""
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def daemon_launchd_document(
    *,
    generation_id: str,
    account_name: str,
    group_name: str,
    data_directory: Path,
    upstreams: list[str],
) -> dict[str, object]:
    """Return the least-privilege launchd definition for the user authority."""
    _ = _validated_upstream_endpoints(upstreams)
    arguments = [
        str(GENERATIONS_ROOT / generation_id / "libexec/remapd"),
        "--data-dir",
        str(data_directory),
        "--dns-listen",
        "127.0.0.1:53",
    ]
    arguments.extend(
        (
            "--http-listen",
            "127.0.0.1:80",
            "--system-socket",
            str(SYSTEM_SOCKET),
            "--launchd-sockets",
        )
    )
    stream = _tcp_socket()
    return {
        "GroupName": group_name,
        "HardResourceLimits": {"Core": 0, "NumberOfFiles": 4096},
        "KeepAlive": True,
        "Label": DAEMON_LABEL,
        "ProcessType": "Background",
        "ProgramArguments": arguments,
        "RunAtLoad": True,
        "Sockets": {
            "remap-dns-tcp": {**stream, "SockServiceName": "53"},
            "remap-dns-udp": {
                "SockFamily": "IPv4",
                "SockNodeName": "127.0.0.1",
                "SockProtocol": "UDP",
                "SockServiceName": "53",
                "SockType": "dgram",
            },
            "remap-http": {**stream, "SockServiceName": "80"},
            "remap-system": {
                "SockPathMode": 0o600,
                "SockPathName": str(SYSTEM_SOCKET),
                "SockType": "stream",
            },
        },
        "SoftResourceLimits": {"NumberOfFiles": 4096},
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "ThrottleInterval": 5,
        "Umask": 0o077,
        "UserName": account_name,
        "WorkingDirectory": str(data_directory),
    }


def _validated_upstream_endpoints(upstreams: list[str]) -> list[str]:
    if not 1 <= len(upstreams) <= 4:
        raise ValueError("the launchd resolver requires one to four upstreams")
    validated: list[str] = []
    for endpoint in upstreams:
        if endpoint.startswith("[") and endpoint.endswith("]:53"):
            address_value = endpoint[1:-4]
            expected_version = 6
        elif endpoint.endswith(":53"):
            address_value = endpoint[:-3]
            expected_version = 4
        else:
            raise ValueError("the launchd resolver upstream is not a port-53 endpoint")
        try:
            address = ipaddress.ip_address(address_value)
        except ValueError as error:
            raise ValueError(
                "the launchd resolver upstream is not an IP address"
            ) from error
        canonical = (
            f"[{address.compressed}]:53" if address.version == 6 else f"{address}:53"
        )
        if (
            address.version != expected_version
            or canonical != endpoint
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
        ):
            raise ValueError("the launchd resolver upstream is unsafe or non-canonical")
        if endpoint in validated:
            raise ValueError("the launchd resolver upstream set contains a duplicate")
        validated.append(endpoint)
    return validated


def resolver_launchd_document(
    *, generation_id: str, owner_uid: int, data_directory: Path
) -> dict[str, object]:
    """Return the narrow root resolver-reconciliation service definition."""
    _ = data_directory
    return {
        "HardResourceLimits": {"Core": 0, "NumberOfFiles": 128},
        "KeepAlive": True,
        "Label": RESOLVER_LABEL,
        "ProcessType": "Background",
        "ProgramArguments": [
            str(GENERATIONS_ROOT / generation_id / "libexec/remap-resolver"),
            "run",
            "--owner-uid",
            str(owner_uid),
            "--system-socket",
            str(SYSTEM_SOCKET),
        ],
        "RunAtLoad": True,
        "SoftResourceLimits": {"NumberOfFiles": 128},
        "StandardErrorPath": "/dev/null",
        "StandardOutPath": "/dev/null",
        "ThrottleInterval": 5,
        "Umask": 0o077,
    }


def _copy_inputs(payload: Path, files: NativeProductFiles) -> None:
    _copy_file(files.cli, payload / "bin/remap", executable=True)
    _copy_file(files.daemon, payload / "libexec/remapd", executable=True)
    _copy_file(
        files.installer,
        payload / "libexec/remap-install",
        executable=True,
    )
    _copy_file(files.resolver, payload / "libexec/remap-resolver", executable=True)
    _copy_file(files.system_tool, payload / "libexec/remap-system", executable=True)
    _copy_tree(files.app, payload / "app/Remap.app")
    _copy_tree(files.manpages, payload / "share/man/man1")
    _copy_file(
        files.license,
        payload / "share/licenses/remap/LICENSE",
        executable=False,
    )
    _copy_file(
        files.notice,
        payload / "share/licenses/remap/NOTICE",
        executable=False,
    )
    for shell, source in sorted(files.completions.items()):
        _copy_file(source, payload / _completion_path(shell), executable=False)


def _copy_file(source: Path, destination: Path, *, executable: bool) -> None:
    information = source.lstat()
    if not stat.S_ISREG(information.st_mode) or information.st_nlink != 1:
        raise RuntimeError(f"package source is not a unique regular file: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _ = shutil.copyfile(source, destination, follow_symlinks=False)
    os.chmod(destination, 0o500 if executable else 0o400)


def _copy_tree(source: Path, destination: Path) -> None:
    _reject_special_tree(source)
    _ = shutil.copytree(source, destination, copy_function=shutil.copyfile)
    os.chmod(destination, 0o500)
    for path in destination.rglob("*"):
        if path.is_dir():
            os.chmod(path, 0o500)
        else:
            source_mode = (source / path.relative_to(destination)).stat().st_mode
            executable = bool(source_mode & 0o111)
            os.chmod(path, 0o500 if executable else 0o400)


def _reject_special_tree(root: Path) -> None:
    information = root.lstat()
    if not stat.S_ISDIR(information.st_mode):
        raise RuntimeError(f"package tree is not a directory: {root}")
    for path in root.rglob("*"):
        information = path.lstat()
        if not (stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode)):
            raise RuntimeError(f"package tree contains a link or special file: {path}")
        if stat.S_ISREG(information.st_mode) and information.st_nlink != 1:
            raise RuntimeError(f"package tree contains a hard-linked file: {path}")


def _write_launchd_documents(
    payload: Path,
    *,
    generation_id: str,
    account_name: str,
    owner_uid: int,
    group_name: str,
    data_directory: Path,
    upstreams: list[str],
) -> None:
    documents = {
        f"launchd/{DAEMON_LABEL}.plist": daemon_launchd_document(
            generation_id=generation_id,
            account_name=account_name,
            group_name=group_name,
            data_directory=data_directory,
            upstreams=upstreams,
        ),
        f"launchd/{RESOLVER_LABEL}.plist": resolver_launchd_document(
            generation_id=generation_id,
            owner_uid=owner_uid,
            data_directory=data_directory,
        ),
    }
    for relative, document in documents.items():
        destination = payload / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _ = destination.write_bytes(
            plistlib.dumps(document, fmt=plistlib.FMT_XML, sort_keys=True)
        )
        os.chmod(destination, 0o400)


def _manifest_entries(payload: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(payload.rglob("*")):
        relative = path.relative_to(payload).as_posix()
        information = path.lstat()
        if stat.S_ISDIR(information.st_mode):
            entries.append(_directory_entry(relative))
            continue
        if not stat.S_ISREG(information.st_mode):
            raise RuntimeError(f"payload contains an unsupported node: {relative}")
        data = path.read_bytes()
        entries.append(
            {
                "byteCount": len(data),
                "groupGID": 0,
                "kind": "regularFile",
                "mode": 0o555 if information.st_mode & 0o111 else 0o444,
                "ownerUID": 0,
                "path": relative,
                "role": _role(relative),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return entries


def _install_configuration(
    *,
    owner_uid: int,
    data_directory: Path,
    signing_certificate_sha256: str,
) -> dict[str, object]:
    if not re.fullmatch(r"[0-9a-f]{64}", signing_certificate_sha256):
        raise ValueError(
            "the local signing certificate requires a lowercase SHA-256 digest"
        )
    return {
        "controlSocket": str(data_directory / "control.sock"),
        "dataDirectory": str(data_directory),
        "dnsPort": 53,
        "httpPort": 80,
        "ownerUID": owner_uid,
        "schemaVersion": 2,
        "signingCertificateSHA256": signing_certificate_sha256,
    }


def _write_install_configuration(
    payload: Path, configuration: dict[str, object]
) -> None:
    destination = payload / INSTALL_CONFIGURATION
    _ = destination.write_bytes(canonical_json(configuration))
    os.chmod(destination, 0o400)


def _directory_entry(relative: str) -> dict[str, object]:
    return {
        "groupGID": 0,
        "kind": "directory",
        "mode": 0o555,
        "ownerUID": 0,
        "path": relative,
        "role": _role(relative),
    }


def _manifest_document(
    *,
    generation_id: str,
    product_version: str,
    previous_generation_id: str | None,
    entries: list[dict[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {
        "entries": entries,
        "generationID": generation_id,
        "productIdentifier": PRODUCT_IDENTIFIER,
        "productVersion": product_version,
        "publications": _publications(generation_id, entries),
        "schemaVersion": 1,
    }
    if previous_generation_id is not None:
        document["previousGenerationID"] = previous_generation_id
    return document


def _publications(
    generation_id: str, entries: list[dict[str, object]]
) -> list[dict[str, object]]:
    publications = _publication_contract(generation_id)
    for publication in publications:
        path = _publication_path(publication)
        if not path.startswith("Library/LaunchDaemons/"):
            continue
        label = Path(path).stem
        relative = f"launchd/{label}.plist"
        entry = next(entry for entry in entries if _entry_path(entry) == relative)
        publication["byteCount"] = entry["byteCount"]
        publication["sha256"] = entry["sha256"]
    return sorted(publications, key=_publication_path)


def _publication_contract(generation_id: str) -> list[dict[str, object]]:
    """Return every public path and ownership field independent of payload bytes."""
    directory_paths = (
        "usr/local",
        "usr/local/bin",
        "usr/local/share",
        "usr/local/share/bash-completion",
        "usr/local/share/bash-completion/completions",
        "usr/local/share/fish",
        "usr/local/share/fish/vendor_completions.d",
        "usr/local/share/licenses",
        "usr/local/share/licenses/remap",
        "usr/local/share/man",
        "usr/local/share/man/man1",
        "usr/local/share/zsh",
        "usr/local/share/zsh/site-functions",
    )
    targets = {
        "Applications/Remap.app": str(CURRENT_ROOT / "app/Remap.app"),
        "usr/local/bin/remap": str(CURRENT_ROOT / "bin/remap"),
        "usr/local/share/licenses/remap/LICENSE": str(
            CURRENT_ROOT / "share/licenses/remap/LICENSE"
        ),
        "usr/local/share/licenses/remap/NOTICE": str(
            CURRENT_ROOT / "share/licenses/remap/NOTICE"
        ),
        "usr/local/share/bash-completion/completions/remap": str(
            CURRENT_ROOT / "share/completions/remap.bash"
        ),
        "usr/local/share/fish/vendor_completions.d/remap.fish": str(
            CURRENT_ROOT / "share/completions/remap.fish"
        ),
        "usr/local/share/zsh/site-functions/_remap": str(
            CURRENT_ROOT / "share/completions/remap.zsh"
        ),
    }
    targets.update(
        {
            f"usr/local/share/man/man1/{name}": str(
                CURRENT_ROOT / f"share/man/man1/{name}"
            )
            for name in MANPAGE_NAMES
        }
    )
    targets[str(INSTALL_ROOT.relative_to("/") / "current")] = str(
        INSTALL_ROOT / f"Generations/{generation_id}"
    )
    publications: list[dict[str, object]] = [
        {
            "generationID": generation_id,
            "groupGID": 0,
            "kind": "directory",
            "mode": 0o755,
            "ownerUID": 0,
            "path": path,
        }
        for path in directory_paths
    ]
    publications.extend(
        [
            {
                "generationID": generation_id,
                "kind": "symbolicLink",
                "path": path,
                "target": target,
            }
            for path, target in sorted(targets.items())
        ]
    )
    for label in (DAEMON_LABEL, RESOLVER_LABEL):
        relative = f"launchd/{label}.plist"
        source = GENERATIONS_ROOT.relative_to("/") / generation_id / relative
        publications.append(
            {
                "generationID": generation_id,
                "groupGID": 0,
                "kind": "regularFile",
                "mode": 0o444,
                "ownerUID": 0,
                "path": f"Library/LaunchDaemons/{label}.plist",
                "source": source.as_posix(),
            }
        )
    return sorted(publications, key=_publication_path)


def _entry_path(entry: dict[str, object]) -> str:
    path = entry["path"]
    if not isinstance(path, str):
        raise TypeError("manifest entry path must be a string")
    return path


def _publication_path(publication: dict[str, object]) -> str:
    path = publication["path"]
    if not isinstance(path, str):
        raise TypeError("publication path must be a string")
    return path


def _generation_id(
    *,
    product_version: str,
    entries: list[dict[str, object]],
    account_name: str,
    owner_uid: int,
    group_name: str,
    data_directory: Path,
    upstreams: list[str],
) -> str:
    launchd = {
        DAEMON_LABEL: daemon_launchd_document(
            generation_id=GENERATION_ID_PLACEHOLDER,
            account_name=account_name,
            group_name=group_name,
            data_directory=data_directory,
            upstreams=upstreams,
        ),
        RESOLVER_LABEL: resolver_launchd_document(
            generation_id=GENERATION_ID_PLACEHOLDER,
            owner_uid=owner_uid,
            data_directory=data_directory,
        ),
    }
    seed = {
        "accountName": account_name,
        "entries": entries,
        "groupName": group_name,
        "launchd": launchd,
        "publicationContract": _publication_contract(GENERATION_ID_PLACEHOLDER),
        "productVersion": product_version,
    }
    digest = hashlib.sha256(canonical_json(seed)).hexdigest()
    return f"{product_version}-{digest}"


def _role(path: str) -> str:
    if path == "bin/remap":
        return "commandLineTool"
    if path == "libexec/remapd":
        return "daemon"
    if path == "libexec/remap-resolver":
        return "daemon"
    if path.startswith("app/"):
        return "application"
    return "support"


def _completion_path(shell: str) -> Path:
    if shell not in {"bash", "fish", "zsh"}:
        raise ValueError(f"unsupported completion shell: {shell}")
    return Path(f"share/completions/remap.{shell}")


def _tcp_socket() -> dict[str, object]:
    return {
        "SockFamily": "IPv4",
        "SockNodeName": "127.0.0.1",
        "SockPassive": True,
        "SockProtocol": "TCP",
        "SockType": "stream",
    }


def _validate_empty_private_root(root: Path) -> None:
    information = root.lstat()
    mode = stat.S_IMODE(information.st_mode)
    if not stat.S_ISDIR(information.st_mode) or mode & 0o077 or any(root.iterdir()):
        raise RuntimeError("native package root must be an empty private directory")


def _sanitize_package_tree(root: Path) -> None:
    """Remove inherited extended metadata from every private package node."""
    for path in (*sorted(root.rglob("*")), root):
        information = path.lstat()
        if not (stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode)):
            raise RuntimeError(f"native package contains an unsafe node: {path}")
        if stat.S_ISDIR(information.st_mode):
            os.chmod(path, 0o700 if path == root else 0o500)
        if hasattr(os, "chflags"):
            os.chflags(path, 0, follow_symlinks=False)
        _sanitize_node_metadata(
            path,
            directory=stat.S_ISDIR(information.st_mode),
        )


def _sanitize_node_metadata(path: Path, *, directory: bool) -> None:
    """Clear untrusted xattrs and ACLs through a no-follow descriptor."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
    if directory:
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        for name in list_extended_attributes(descriptor, path):
            if name != _DARWIN_PROVENANCE_ATTRIBUTE:
                _remove_extended_attribute(descriptor, path, name)
        if sys.platform == "darwin":
            _clear_extended_acl(descriptor, path)
        unexpected = set(list_extended_attributes(descriptor, path)) - {
            _DARWIN_PROVENANCE_ATTRIBUTE
        }
        if unexpected:
            raise RuntimeError(
                f"native package retained extended attributes {sorted(unexpected)}: {path}"
            )
    finally:
        os.close(descriptor)


def list_extended_attributes(descriptor: int, path: Path) -> list[str]:
    """List one already-open package node's xattrs without following a path."""
    if sys.platform != "darwin":
        return os.listxattr(descriptor)
    size = cast("int", _darwin_libc().flistxattr(descriptor, None, 0, 0))
    if size < 0:
        raise OSError(get_errno(), f"could not list extended attributes on {path}")
    if size == 0:
        return []
    buffer = create_string_buffer(size)
    received = cast(
        "int",
        _darwin_libc().flistxattr(descriptor, buffer, size, 0),
    )
    if received < 0:
        raise OSError(get_errno(), f"could not read extended attributes on {path}")
    return [name.decode("utf-8") for name in buffer.raw[:received].split(b"\0") if name]


def has_extended_acl(descriptor: int, path: Path) -> bool:
    """Return whether an already-open Darwin node has an extended ACL."""
    if sys.platform != "darwin":
        return False
    access_control_list = cast(
        "int | None",
        _darwin_libc().acl_get_fd_np(descriptor, _ACL_TYPE_EXTENDED),
    )
    if not access_control_list:
        if get_errno() == ENOENT:
            return False
        raise OSError(get_errno(), f"could not inspect the ACL on {path}")
    try:
        entry = c_void_p()
        result = cast(
            "int",
            _darwin_libc().acl_get_entry(
                access_control_list,
                _ACL_FIRST_ENTRY,
                byref(entry),
            ),
        )
        if result < 0:
            raise OSError(get_errno(), f"could not read the ACL on {path}")
        return result == 0
    finally:
        _ = cast("int", _darwin_libc().acl_free(access_control_list))


def _remove_extended_attribute(descriptor: int, path: Path, name: str) -> None:
    if sys.platform != "darwin":
        os.removexattr(descriptor, name)
        return
    if _darwin_libc().fremovexattr(descriptor, name.encode("utf-8"), 0) != 0:
        raise OSError(
            get_errno(),
            f"could not remove extended attribute {name!r} from {path}",
        )


def _clear_extended_acl(descriptor: int, path: Path) -> None:
    """Clear a Darwin NFSv4 ACL through the native descriptor API."""
    acl = cast("int | None", _darwin_libc().acl_init(0))
    if not acl:
        raise OSError(get_errno(), f"could not allocate an empty ACL for {path}")
    try:
        if _darwin_libc().acl_set_fd_np(descriptor, acl, _ACL_TYPE_EXTENDED) != 0:
            raise OSError(get_errno(), f"could not clear the ACL on {path}")
    finally:
        _ = cast("int", _darwin_libc().acl_free(acl))


@cache
def _darwin_libc() -> CDLL:
    """Return typed Darwin ACL functions from the current process image."""
    library = CDLL(None, use_errno=True)
    library.acl_init.argtypes = [c_int]
    library.acl_init.restype = c_void_p
    library.acl_set_fd_np.argtypes = [c_int, c_void_p, c_int]
    library.acl_set_fd_np.restype = c_int
    library.acl_free.argtypes = [c_void_p]
    library.acl_free.restype = c_int
    library.acl_get_fd_np.argtypes = [c_int, c_int]
    library.acl_get_fd_np.restype = c_void_p
    library.acl_get_entry.argtypes = [c_void_p, c_int, POINTER(c_void_p)]
    library.acl_get_entry.restype = c_int
    library.flistxattr.argtypes = [c_int, c_void_p, c_size_t, c_int]
    library.flistxattr.restype = c_ssize_t
    library.fremovexattr.argtypes = [c_int, c_char_p, c_int]
    library.fremovexattr.restype = c_int
    return library


_ACL_TYPE_EXTENDED = 0x0000_0100
_ACL_FIRST_ENTRY = 0
_DARWIN_PROVENANCE_ATTRIBUTE = "com.apple.provenance"


MANPAGE_NAMES = (
    "remap-apply.1",
    "remap-completions.1",
    "remap-daemon.1",
    "remap-disable.1",
    "remap-doctor.1",
    "remap-enable.1",
    "remap-get.1",
    "remap-list.1",
    "remap-manpage.1",
    "remap-manpages.1",
    "remap-mcp.1",
    "remap-preview.1",
    "remap-remove.1",
    "remap-resolve.1",
    "remap-set.1",
    "remap-status.1",
    "remap-system-recover.1",
    "remap-system-status.1",
    "remap-system-uninstall.1",
    "remap-system.1",
    "remap-validate.1",
    "remap.1",
)
