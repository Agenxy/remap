"""Pure native macOS install models shared by Remap's typed task runner."""

from __future__ import annotations

import grp
import ipaddress
import os
import pwd
import struct
from collections.abc import Sequence
from pathlib import Path
from typing import cast

SYSTEM_LABEL = "com.agenxy.remap"
SYSTEM_PLIST = Path("/Library/LaunchDaemons/com.agenxy.remap.plist")
SYSTEM_LIBEXEC = Path("/usr/local/libexec/agenxy/remap")
SYSTEM_CLI = Path("/usr/local/bin/remap")
SYSTEM_MANPAGE = Path("/usr/local/share/man/man1/remap.1")
SYSTEM_COMPLETIONS = {
    "bash": Path("/usr/local/share/bash-completion/completions/remap"),
    "fish": Path("/usr/local/share/fish/vendor_completions.d/remap.fish"),
    "zsh": Path("/usr/local/share/zsh/site-functions/_remap"),
}


def launchd_document(
    account: pwd.struct_passwd,
    data_dir: Path,
    upstreams: Sequence[str],
) -> dict[str, object]:
    """Create the deterministic least-privilege launchd service definition."""
    arguments = [
        str(SYSTEM_LIBEXEC / "remapd"),
        "--data-dir",
        str(data_dir),
        "--dns-listen",
        "127.0.0.1:53",
    ]
    for upstream in upstreams:
        arguments.extend(("--dns-upstream", upstream))
    arguments.extend(("--http-listen", "127.0.0.1:80", "--launchd-sockets"))
    stream = {
        "SockFamily": "IPv4",
        "SockNodeName": "127.0.0.1",
        "SockPassive": True,
        "SockProtocol": "TCP",
        "SockType": "stream",
    }
    group_name = grp.getgrgid(account.pw_gid).gr_name
    return {
        "Label": SYSTEM_LABEL,
        "ProgramArguments": arguments,
        "UserName": account.pw_name,
        "GroupName": group_name,
        "RunAtLoad": True,
        "KeepAlive": True,
        "ProcessType": "Background",
        "ThrottleInterval": 5,
        "Umask": 0o077,
        "WorkingDirectory": str(data_dir),
        "StandardOutPath": "/dev/null",
        "StandardErrorPath": "/dev/null",
        "SoftResourceLimits": {"NumberOfFiles": 4096},
        "HardResourceLimits": {"Core": 0, "NumberOfFiles": 4096},
        "Sockets": {
            "remap-dns-udp": {
                "SockFamily": "IPv4",
                "SockNodeName": "127.0.0.1",
                "SockServiceName": "53",
                "SockProtocol": "UDP",
                "SockType": "dgram",
            },
            "remap-dns-tcp": {**stream, "SockServiceName": "53"},
            "remap-http": {**stream, "SockServiceName": "80"},
        },
    }


def activation_upstreams(record: dict[str, object]) -> list[str]:
    """Recover the trusted pre-loopback upstream set for a safe upgrade."""
    payload = record.get("payload")
    if not isinstance(payload, dict):
        raise TypeError("native activation status omitted its payload")
    services = cast("dict[str, object]", payload).get("services")
    if not isinstance(services, list):
        raise TypeError("native activation status omitted its service records")
    values: list[str] = []
    seen: set[str] = set()
    for item in cast("list[object]", services):
        if not isinstance(item, dict):
            raise TypeError("native activation status returned an invalid service")
        upstreams = cast("dict[str, object]", item).get("upstreams")
        if not isinstance(upstreams, list):
            raise TypeError("native activation status omitted service upstreams")
        for value in cast("list[object]", upstreams):
            if not isinstance(value, str):
                raise TypeError(
                    "native activation status returned a non-string upstream"
                )
            if value not in seen:
                seen.add(value)
                values.append(value)
    rendered: list[str] = []
    for value in values:
        address = ipaddress.ip_address(value)
        if address.is_loopback or address.is_unspecified or address.is_multicast:
            raise RuntimeError("native activation status contains an unsafe upstream")
        rendered.append(f"[{address}]:53" if address.version == 6 else f"{address}:53")
    if not (1 <= len(rendered) <= 4):
        raise RuntimeError(
            "native activation status contains an invalid upstream count"
        )
    return rendered


def dns_query(identifier: int) -> bytes:
    """Build one bounded DNS A query for the reserved invalid namespace."""
    nonce = os.urandom(8).hex().encode("ascii")
    label = b"probe-" + nonce
    question = bytes((len(label),)) + label + b"\x07invalid\x00"
    return (
        struct.pack("!HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
        + question
        + struct.pack("!HH", 1, 1)
    )
