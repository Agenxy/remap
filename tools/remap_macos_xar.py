"""Bounded deterministic XAR normalization for native macOS packages."""

from __future__ import annotations

import hashlib
import os
import struct
import subprocess
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path
from typing import cast

from tools.remap_release_artifacts import (
    MAXIMUM_FILE_BYTES,
    verify_release_artifact,
)

NORMALIZED_PACKAGE_TIME = "2000-01-01T00:00:00"
XAR_HEADER = struct.Struct(">IHHQQI")
XAR_MAGIC = 0x78617221


def canonicalize_xar_metadata(
    package: Path,
    *,
    signature_signer: Path | None = None,
    certificate_sha256: str | None = None,
    keychain: Path | None = None,
) -> None:
    """Replace volatile XAR metadata and, for signed XARs, its RSA signature."""
    compressed, plain_size, heap = _read_xar(package)
    document = _decompress_table(compressed, plain_size=plain_size, heap=heap)
    root, table = _parse_table(document)
    signature_size = _xar_signature_size(
        table,
        signature_signer=signature_signer,
        certificate_sha256=certificate_sha256,
        keychain=keychain,
    )
    heap = _strip_extended_signature(table, heap, signature_size=signature_size)
    _normalize_table(table)
    canonical = cast(bytes, ET.tostring(root, encoding="utf-8", xml_declaration=True))
    canonical_compressed = zlib.compress(canonical, level=9)
    signature = _canonical_xar_signature(
        canonical_compressed,
        signature_signer=signature_signer,
        certificate_sha256=certificate_sha256,
        keychain=keychain,
        expected_size=signature_size,
    )
    _write_xar(
        package,
        canonical=canonical,
        compressed=canonical_compressed,
        heap=heap,
        signature=signature,
        previous_signature_size=signature_size,
    )


def _read_xar(package: Path) -> tuple[bytes, int, bytes]:
    verify_release_artifact(package, maximum_bytes=MAXIMUM_FILE_BYTES * 2)
    with package.open("rb") as input_file:
        header = input_file.read(XAR_HEADER.size)
        if len(header) != XAR_HEADER.size:
            raise RuntimeError("the portable package has a truncated XAR header")
        magic, header_size, version, compressed_size, plain_size, checksum_kind = cast(
            "tuple[int, int, int, int, int, int]", XAR_HEADER.unpack(header)
        )
        if (
            magic != XAR_MAGIC
            or header_size != XAR_HEADER.size
            or version != 1
            or checksum_kind != 1
            or compressed_size <= 0
            or plain_size <= 0
            or compressed_size > MAXIMUM_FILE_BYTES
            or plain_size > MAXIMUM_FILE_BYTES
        ):
            raise RuntimeError("the portable package has an unsupported XAR header")
        compressed = input_file.read(compressed_size)
        heap = input_file.read(MAXIMUM_FILE_BYTES * 2 + 1)
    if len(compressed) != compressed_size or len(heap) < hashlib.sha1().digest_size:
        raise RuntimeError("the portable package has a truncated XAR body")
    if len(heap) > MAXIMUM_FILE_BYTES * 2:
        raise RuntimeError("the portable package XAR heap exceeds its byte ceiling")
    return compressed, plain_size, heap


def _decompress_table(compressed: bytes, *, plain_size: int, heap: bytes) -> bytes:
    try:
        document = zlib.decompress(compressed)
    except zlib.error as error:
        raise RuntimeError(
            "the portable package XAR table is not valid zlib"
        ) from error
    if len(document) != plain_size or hashlib.sha1(compressed).digest() != heap[:20]:
        raise RuntimeError("the portable package XAR table checksum is invalid")
    return document


def _parse_table(document: bytes) -> tuple[ET.Element, ET.Element]:
    try:
        root = ET.fromstring(document)
    except ET.ParseError as error:
        raise RuntimeError("the portable package XAR table is not valid XML") from error
    table = root.find("toc")
    if root.tag != "xar" or table is None:
        raise RuntimeError("the portable package XAR table has the wrong root")
    return root, table


def _normalize_table(table: ET.Element) -> None:
    _require_xar_text(table, "creation-time", NORMALIZED_PACKAGE_TIME)
    for entry in table.findall("file"):
        if entry.find("inode") is None:
            continue
        identifier = entry.get("id")
        if identifier is None or not identifier.isdigit():
            raise RuntimeError(
                "the portable package XAR entry has no canonical identity"
            )
        for name, value in (
            ("inode", identifier),
            ("deviceno", "0"),
            ("uid", "0"),
            ("user", "root"),
            ("gid", "0"),
            ("group", "wheel"),
        ):
            _require_xar_text(entry, name, value)
        for name in ("atime", "mtime", "ctime"):
            _require_xar_text(entry, name, f"{NORMALIZED_PACKAGE_TIME}Z")
        finder_time = entry.find("FinderCreateTime")
        if finder_time is None:
            raise RuntimeError("the portable package XAR entry has no creation time")
        _require_xar_text(finder_time, "time", NORMALIZED_PACKAGE_TIME)
        _require_xar_text(finder_time, "nanoseconds", "0")


def _strip_extended_signature(
    table: ET.Element, heap: bytes, *, signature_size: int
) -> bytes:
    extended = table.findall("x-signature")
    if not extended:
        _shift_payload_offsets(
            table,
            minimum=hashlib.sha1().digest_size + signature_size,
            shift=0,
        )
        return heap
    if len(extended) != 1 or signature_size == 0:
        raise RuntimeError("the portable package has an unsafe extended signature")
    record = extended[0]
    offset_text = record.findtext("offset")
    size_text = record.findtext("size")
    if (
        record.get("style") != "CMS"
        or offset_text is None
        or size_text is None
        or not offset_text.isdigit()
        or not size_text.isdigit()
    ):
        raise RuntimeError("the portable package has an unsafe extended signature")
    offset = int(offset_text)
    size = int(size_text)
    if offset != hashlib.sha1().digest_size + signature_size or size <= 0:
        raise RuntimeError(
            "the portable package has an unsafe extended signature layout"
        )
    end = offset + size
    if end > len(heap):
        raise RuntimeError("the portable package has a truncated extended signature")
    table.remove(record)
    _shift_payload_offsets(table, minimum=end, shift=size)
    return heap[:offset] + heap[end:]


def _shift_payload_offsets(table: ET.Element, *, minimum: int, shift: int) -> None:
    for element in table.findall(".//file//offset"):
        if element.text is None or not element.text.isdigit():
            raise RuntimeError("the portable package has an unsafe heap offset")
        value = int(element.text)
        if value < minimum:
            raise RuntimeError(
                "the portable package payload overlaps its signed metadata"
            )
        element.text = str(value - shift)


def _xar_signature_size(
    table: ET.Element,
    *,
    signature_signer: Path | None,
    certificate_sha256: str | None,
    keychain: Path | None,
) -> int:
    signature = table.find("signature")
    if all(value is None for value in (signature_signer, certificate_sha256, keychain)):
        if signature is None:
            return 0
        raise RuntimeError("the signed XAR requires its native signature authority")
    if (
        signature_signer is None
        or certificate_sha256 is None
        or keychain is None
        or signature is None
        or signature.get("style") != "RSA"
        or signature.findtext("offset") != "20"
    ):
        raise RuntimeError("the portable package has an unsafe XAR signature layout")
    size = signature.findtext("size")
    if size is None or not size.isdigit() or int(size) != 384:
        raise RuntimeError("the portable package has an unsafe XAR signature size")
    return int(size)


def _canonical_xar_signature(
    compressed: bytes,
    *,
    signature_signer: Path | None,
    certificate_sha256: str | None,
    keychain: Path | None,
    expected_size: int,
) -> bytes | None:
    if signature_signer is None or certificate_sha256 is None or keychain is None:
        return None
    result = subprocess.run(
        (str(signature_signer), certificate_sha256, str(keychain)),
        input=compressed,
        check=False,
        capture_output=True,
        timeout=120,
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) != expected_size:
        raise RuntimeError("the native XAR signer rejected the canonical package table")
    return result.stdout


def _write_xar(
    package: Path,
    *,
    canonical: bytes,
    compressed: bytes,
    heap: bytes,
    signature: bytes | None,
    previous_signature_size: int,
) -> None:
    header = XAR_HEADER.pack(
        XAR_MAGIC,
        XAR_HEADER.size,
        1,
        len(compressed),
        len(canonical),
        1,
    )
    destination = package.with_name(f"{package.name}.canonical")
    try:
        with destination.open("xb") as output_file:
            _ = output_file.write(header)
            _ = output_file.write(compressed)
            _ = output_file.write(hashlib.sha1(compressed).digest())
            if signature is not None:
                _ = output_file.write(signature)
                _ = output_file.write(heap[20 + previous_signature_size :])
            else:
                _ = output_file.write(heap[20:])
            output_file.flush()
            os.fsync(output_file.fileno())
        os.chmod(destination, 0o400)
        os.replace(destination, package)
    except BaseException:
        if destination.exists() and not destination.is_symlink():
            destination.unlink()
        raise


def _require_xar_text(parent: ET.Element, name: str, value: str) -> None:
    matches = parent.findall(name)
    if len(matches) != 1:
        raise RuntimeError(f"the portable package XAR metadata is missing {name}")
    matches[0].text = value
