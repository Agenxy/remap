"""Build Remap's prebuilt, target-Mac-self-signed Apple Installer package."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import plistlib
import shutil
import stat
import struct
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from tools.remap_app import build as build_app
from tools.remap_app import verify_structure as verify_app_structure
from tools.remap_freshness import verify_selected_xcode
from tools.remap_macos_artifact import expected_macos_sdk, normalize_macos_sdk_metadata
from tools.remap_macos_package_metadata import (
    normalize_package_extended_attributes,
    normalize_package_timestamps,
    verify_payload_member_names,
)
from tools.remap_macos_release_installer_signing import (
    ReleaseInstallerSigningIdentity,
)
from tools.remap_macos_release_installer_signing import (
    sign_package as sign_release_installer_package,
)
from tools.remap_native_package import MANPAGE_NAMES
from tools.remap_release_artifacts import (
    MAXIMUM_FILE_BYTES,
    MAXIMUM_SIGNATURE_BYTES,
    open_release_artifact,
    publish_release_artifacts,
    verify_release_artifact,
)

PACKAGE_IDENTIFIER = "org.agenxy.Remap.PortableInstaller"
RELEASE_NAMESPACE = "remap-release"
PACKAGE_NAMESPACE = "remap-package-v1"
RELEASE_SIGNER_IDENTITY = "remap-release"
NORMALIZED_PACKAGE_TIME = "2000-01-01T00:00:00"
XAR_HEADER = struct.Struct(">IHHQQI")
XAR_MAGIC = 0x78617221
LOCAL_BUILD_PATH_MARKERS = (b"/Users/", b"/private/var/folders/")


@dataclass(frozen=True)
class PortablePackage:
    """One verified native package and its external release identity."""

    path: Path
    sha256: str
    signature_path: Path
    signature_sha256: str
    release_manifest_sha256: str
    architecture: str
    product_version: str


def build(
    root: Path,
    *,
    product_version: str,
    output: Path,
    signing_key: Path,
    installer_identity: ReleaseInstallerSigningIdentity,
) -> PortablePackage:
    """Build and verify one no-shell portable package without a paid identity."""
    verify_selected_xcode()
    architecture = _architecture()
    validate_version(product_version)
    _validate_signing_key(signing_key, root=root)
    output_signature = output.with_suffix(output.suffix + ".sig")
    for artifact in (output, output_signature):
        if artifact.exists() or artifact.is_symlink():
            raise RuntimeError(f"refusing to overwrite release artifact {artifact}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="remap-portable-package-") as directory:
        workspace = Path(directory)
        os.chmod(workspace, 0o700)
        products = _build_products(root, product_version, workspace)
        package_root = workspace / "package-root"
        scripts = workspace / "scripts"
        package_root.mkdir(mode=0o700)
        scripts.mkdir(mode=0o700)
        staged = _payload_path(
            package_root,
            Path("/Library/Application Support/Agenxy/Remap/Portable/Staged"),
        )
        staged.mkdir(parents=True, mode=0o700)
        _normalize_parent_modes(package_root, staged)
        release_payload = staged / "payload"
        _stage_release_payload(products, release_payload, root)
        entries = release_entries(release_payload)
        manifest = release_manifest(product_version, architecture, entries)
        manifest_bytes = canonical_release_json(manifest)
        manifest_path = staged / "release-manifest.json"
        _ = manifest_path.write_bytes(manifest_bytes)
        os.chmod(manifest_path, 0o400)
        _sign_file(manifest_path, signing_key, namespace=RELEASE_NAMESPACE)
        signature = manifest_path.with_suffix(manifest_path.suffix + ".sig")
        os.chmod(signature, 0o400)
        portable_installer = products / "remap-portable-installer"
        for script in ("preinstall", "postinstall"):
            _copy_file(portable_installer, scripts / script, mode=0o555)
        _verify_tree(staged)
        _verify_tree(scripts, script_root=True)
        component_plist = workspace / "components.plist"
        with component_plist.open("wb") as output_file:
            plistlib.dump([], output_file, sort_keys=True)
        os.chmod(component_plist, 0o400)
        for package_input in (package_root, scripts, component_plist):
            normalize_package_timestamps(package_input)
            normalize_package_extended_attributes(package_input)
        unsigned = workspace / "Remap.pkg"
        _run_pkgbuild(
            (
                "/usr/bin/pkgbuild",
                "--root",
                str(package_root),
                "--scripts",
                str(scripts),
                "--identifier",
                PACKAGE_IDENTIFIER,
                "--version",
                product_version,
                "--install-location",
                "/",
                "--ownership",
                "recommended",
                "--component-plist",
                str(component_plist),
                str(unsigned),
            ),
            root=root,
            environment={**os.environ, "COPYFILE_DISABLE": "1"},
        )
        canonicalize_xar_metadata(unsigned)
        _verify_package(
            unsigned,
            workspace / "expanded",
            product_version=product_version,
            expected_manifest=manifest_bytes,
        )
        signed = workspace / "Remap-signed.pkg"
        sign_release_installer_package(unsigned, signed, installer_identity)
        _verify_package(
            signed,
            workspace / "signed-expanded",
            product_version=product_version,
            expected_manifest=manifest_bytes,
            require_unsigned=False,
        )
        _sign_file(signed, signing_key, namespace=PACKAGE_NAMESPACE)
        signed_signature = signed.with_suffix(signed.suffix + ".sig")
        os.chmod(signed_signature, 0o400)
        pinned_public_key = (
            root / "docs/release/remap-release-signing-key.pub"
        ).read_text(encoding="utf-8")
        verify_detached_package_signature(
            signed,
            signed_signature,
            public_key=pinned_public_key,
        )
        publish_release_artifacts(
            package=signed,
            signature=signed_signature,
            output=output,
            output_signature=output_signature,
        )
        verify_detached_package_signature(
            output,
            output_signature,
            public_key=pinned_public_key,
        )
    return PortablePackage(
        path=output,
        sha256=_sha256(output),
        signature_path=output_signature,
        signature_sha256=_sha256(output_signature),
        release_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        architecture=architecture,
        product_version=product_version,
    )


def _build_products(root: Path, version: str, workspace: Path) -> Path:
    rust_environment = dict(os.environ)
    _ = rust_environment.pop("RUSTFLAGS", None)
    rust_environment["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(
        (
            f"--remap-path-prefix={root.resolve()}=/usr/src/remap",
            f"--remap-path-prefix={Path.home()}=/usr/src/remap-build",
        )
    )
    rust_environment["CARGO_INCREMENTAL"] = "0"
    _run(
        (
            "mise",
            "exec",
            "--",
            "cargo",
            "build",
            "--release",
            "--locked",
            "-p",
            "remap",
            "-p",
            "remapd",
        ),
        root=root,
        environment=rust_environment,
    )
    _run(
        (
            "xcrun",
            "swift",
            "build",
            "--configuration",
            "release",
            "--package-path",
            "platforms/macos",
        ),
        root=root,
    )
    swift_bin = Path(
        _capture(
            (
                "xcrun",
                "swift",
                "build",
                "--show-bin-path",
                "--configuration",
                "release",
                "--package-path",
                "platforms/macos",
            ),
            root=root,
        )
    )
    swift_names = (
        "remap-install",
        "remap-installer-bootstrap",
        "remap-installer-service",
        "remap-lifecycle",
        "remap-portable-installer",
        "remap-resolver",
        "remap-system",
    )
    normalize_macos_sdk_metadata(
        tuple(swift_bin / name for name in swift_names),
        expected_sdk=expected_macos_sdk(root),
        minimum_macos="15.0",
    )
    products = workspace / "products"
    products.mkdir(mode=0o700)
    app = build_app(root, version, release=True, sign=False)
    verify_app_structure(root, app)
    binaries = {
        "remap": root / "target/release/remap",
        "remapd": root / "target/release/remapd",
        **{name: swift_bin / name for name in swift_names},
    }
    for name, source in binaries.items():
        _copy_file(source, products / name, mode=0o500)
    _copy_tree(app, products / "Remap.app")
    identifiers = {
        "remap": "org.agenxy.Remap.cli",
        "remapd": "org.agenxy.Remap.daemon",
        "remap-install": "org.agenxy.Remap.install-bootstrap",
        "remap-installer-bootstrap": "org.agenxy.Remap.installer-bootstrap",
        "remap-installer-service": "org.agenxy.Remap.installer-service",
        "remap-lifecycle": "org.agenxy.Remap.lifecycle-cli",
        "remap-portable-installer": "org.agenxy.Remap.portable-installer",
        "remap-resolver": "org.agenxy.Remap.resolver",
        "remap-system": "org.agenxy.Remap.system",
    }
    for name, identifier in identifiers.items():
        _strip_and_ad_hoc_sign(products / name, identifier=identifier, root=root)
    app = products / "Remap.app"
    _remove_copied_bundle_signature(app)
    _strip_mach_o(app / "Contents/MacOS/Remap", root=root)
    _ad_hoc_sign(app, identifier="org.agenxy.Remap", root=root)
    verify_no_local_build_paths(app / "Contents/MacOS/Remap")
    verify_app_structure(root, app)
    cli = products / "remap"
    manpages = products / "manpages"
    _run((str(cli), "manpages", str(manpages)), root=root)
    if sorted(path.name for path in manpages.glob("*.1")) != sorted(MANPAGE_NAMES):
        raise RuntimeError("the portable CLI did not produce its exact 22-page manual")
    for shell in ("bash", "fish", "zsh"):
        result = subprocess.run(
            (str(cli), "completions", shell),
            cwd=root,
            check=True,
            capture_output=True,
            timeout=30,
        )
        destination = products / f"remap.{shell}"
        _ = destination.write_bytes(result.stdout)
        os.chmod(destination, 0o400)
    return products


def _strip_and_ad_hoc_sign(path: Path, *, identifier: str, root: Path) -> None:
    _strip_mach_o(path, root=root)
    _ad_hoc_sign(path, identifier=identifier, root=root)
    verify_no_local_build_paths(path)


def _strip_mach_o(path: Path, *, root: Path) -> None:
    os.chmod(path, 0o700)
    _run(("/usr/bin/codesign", "--remove-signature", str(path)), root=root)
    _run(("/usr/bin/xcrun", "strip", "-S", str(path)), root=root)


def _remove_copied_bundle_signature(app: Path) -> None:
    signature = app / "Contents/_CodeSignature"
    if not signature.exists():
        return
    if signature.is_symlink() or not signature.is_dir():
        raise RuntimeError("the copied app has an unsafe code-signature directory")
    children = list(signature.iterdir())
    if len(children) != 1 or children[0].name != "CodeResources":
        raise RuntimeError("the copied app has an unexpected code-signature tree")
    resources = children[0]
    information = resources.lstat()
    if resources.is_symlink() or not resources.is_file() or information.st_nlink != 1:
        raise RuntimeError("the copied app has unsafe code-signature resources")
    os.chmod(resources, 0o600)
    resources.unlink()
    signature.rmdir()


def _ad_hoc_sign(path: Path, *, identifier: str, root: Path) -> None:
    _run(
        (
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--identifier",
            identifier,
            str(path),
        ),
        root=root,
    )
    _run(
        ("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(path)),
        root=root,
    )
    if path.is_file():
        os.chmod(path, 0o500)


def verify_no_local_build_paths(path: Path) -> None:
    data = path.read_bytes()
    if any(marker in data for marker in LOCAL_BUILD_PATH_MARKERS):
        raise RuntimeError(f"release executable contains a local build path: {path}")


def _stage_release_payload(products: Path, destination: Path, root: Path) -> None:
    product = destination / "product"
    lifecycle = destination / "lifecycle"
    product.mkdir(parents=True, mode=0o700)
    lifecycle.mkdir(mode=0o700)
    for directory in (
        "app",
        "bin",
        "libexec",
        "share/completions",
        "share/licenses/remap",
        "share/man/man1",
    ):
        (product / directory).mkdir(parents=True, exist_ok=True, mode=0o700)
    _copy_tree(products / "Remap.app", product / "app/Remap.app")
    _copy_file(products / "remap", product / "bin/remap", mode=0o500)
    for name, destination_name in (
        ("remap-install", "remap-install"),
        ("remap-lifecycle", "remap-lifecycle"),
        ("remap-resolver", "remap-resolver"),
        ("remap-system", "remap-system"),
        ("remapd", "remapd"),
    ):
        _copy_file(products / name, product / f"libexec/{destination_name}", mode=0o500)
    for shell in ("bash", "fish", "zsh"):
        _copy_file(
            products / f"remap.{shell}",
            product / f"share/completions/remap.{shell}",
            mode=0o400,
        )
    for name in ("LICENSE", "NOTICE"):
        _copy_file(root / name, product / f"share/licenses/remap/{name}", mode=0o400)
    for name in MANPAGE_NAMES:
        _copy_file(
            products / "manpages" / name, product / f"share/man/man1/{name}", mode=0o400
        )
    _copy_file(
        products / "remap-installer-bootstrap",
        lifecycle / "remap-installer-bootstrap",
        mode=0o500,
    )
    _copy_file(
        products / "remap-installer-service",
        lifecycle / "remap-installer-service",
        mode=0o500,
    )
    for directory in (destination, *destination.rglob("*")):
        if directory.is_dir() and not directory.is_symlink():
            os.chmod(directory, 0o700)


def release_entries(root: Path) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        information = path.lstat()
        if path.is_symlink():
            raise RuntimeError(f"portable release input is a symlink: {relative}")
        mode = stat.S_IMODE(information.st_mode)
        if path.is_dir():
            if mode != 0o700:
                raise RuntimeError(
                    f"portable release directory has wrong mode: {relative}"
                )
            entries.append({"kind": "directory", "mode": mode, "path": relative})
        elif path.is_file() and information.st_nlink == 1:
            if mode not in {0o400, 0o500} or information.st_size > MAXIMUM_FILE_BYTES:
                raise RuntimeError(
                    f"portable release file has unsafe metadata: {relative}"
                )
            entries.append(
                {
                    "byteCount": information.st_size,
                    "kind": "regularFile",
                    "mode": mode,
                    "path": relative,
                    "sha256": _sha256(path),
                }
            )
        else:
            raise RuntimeError(
                f"portable release input is not a unique regular node: {relative}"
            )
    return entries


def release_manifest(
    version: str,
    architecture: str,
    entries: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "architecture": architecture,
        "entries": entries,
        "minimumMacOSVersion": "15.0",
        "productIdentifier": "org.agenxy.Remap",
        "productVersion": version,
        "schemaVersion": 1,
    }


def _sign_file(path: Path, private_key: Path, *, namespace: str) -> None:
    signature = path.with_suffix(path.suffix + ".sig")
    with path.open("rb") as input_file:
        result = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-Y",
                "sign",
                "-f",
                str(private_key),
                "-n",
                namespace,
            ),
            cwd=path.parent,
            check=True,
            stdin=input_file,
            capture_output=True,
            timeout=120,
        )
    if not result.stdout or len(result.stdout) > MAXIMUM_SIGNATURE_BYTES:
        raise RuntimeError("ssh-keygen returned an unsafe release signature")
    with signature.open("xb") as output_file:
        _ = output_file.write(result.stdout)
        output_file.flush()
        os.fsync(output_file.fileno())
    os.chmod(signature, 0o400)


def verify_detached_package_signature(
    package: Path,
    signature: Path,
    *,
    public_key: str,
    expected_package_owner_uid: int | None = None,
) -> None:
    """Verify the complete package bytes under Remap's package namespace."""
    canonical_key = canonical_release_public_key(public_key)
    with (
        open_release_artifact(
            package,
            maximum_bytes=MAXIMUM_FILE_BYTES * 2,
            expected_owner_uid=expected_package_owner_uid,
        ) as input_file,
        open_release_artifact(
            signature, maximum_bytes=MAXIMUM_SIGNATURE_BYTES
        ) as signature_file,
        tempfile.TemporaryDirectory(prefix="remap-package-verification-") as directory,
    ):
        workspace = Path(directory)
        os.chmod(workspace, 0o700)
        allowed_signers = workspace / "allowed-signers"
        _ = allowed_signers.write_text(
            f"{RELEASE_SIGNER_IDENTITY} {canonical_key}\n",
            encoding="utf-8",
        )
        os.chmod(allowed_signers, 0o400)
        private_signature = workspace / "package.sig"
        with private_signature.open("xb") as output_file:
            shutil.copyfileobj(signature_file, output_file, length=4096)
            output_file.flush()
            os.fsync(output_file.fileno())
        os.chmod(private_signature, 0o400)
        result = subprocess.run(
            (
                "/usr/bin/ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(allowed_signers),
                "-I",
                RELEASE_SIGNER_IDENTITY,
                "-n",
                PACKAGE_NAMESPACE,
                "-s",
                str(private_signature),
            ),
            cwd=workspace,
            stdin=input_file,
            check=False,
            capture_output=True,
            timeout=120,
        )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"the detached package signature is invalid: {detail}")


def _verify_package(
    package: Path,
    expanded: Path,
    *,
    product_version: str,
    expected_manifest: bytes,
    require_unsigned: bool = True,
) -> None:
    signature = subprocess.run(
        ("/usr/sbin/pkgutil", "--check-signature", str(package)),
        cwd=package.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if require_unsigned and (
        signature.returncode != 1 or "Status: no signature" not in signature.stdout
    ):
        raise RuntimeError(
            "the portable package does not have the expected unsigned identity"
        )
    if not require_unsigned and signature.returncode != 0:
        raise RuntimeError("the portable package lost its complete XAR signature")
    payload_listing = subprocess.run(
        ("/usr/sbin/pkgutil", "--payload-files", str(package)),
        cwd=package.parent,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if payload_listing.returncode != 0 or payload_listing.stderr:
        raise RuntimeError("the portable package payload listing failed")
    verify_payload_member_names(payload_listing.stdout)
    _run(
        ("/usr/sbin/pkgutil", "--expand-full", str(package), str(expanded)),
        root=package.parent,
    )
    if (expanded / "PackageInfo").is_file():
        component = expanded
    else:
        components = [path for path in expanded.iterdir() if path.suffix == ".pkg"]
        if len(components) != 1:
            raise RuntimeError("portable package expansion is ambiguous")
        component = components[0]
    package_info = component / "PackageInfo"
    document = package_info.read_text(encoding="utf-8")
    if (
        f'identifier="{PACKAGE_IDENTIFIER}"' not in document
        or f'version="{product_version}"' not in document
    ):
        raise RuntimeError("portable package identity is not exact")
    scripts = component / "Scripts"
    for name in ("preinstall", "postinstall"):
        path = scripts / name
        if path.read_bytes()[:4] not in {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"}:
            raise RuntimeError(
                "portable package scripts are not native Mach-O executables"
            )
        verify_no_local_build_paths(path)
        _run(
            ("/usr/bin/codesign", "--verify", "--strict", str(path)),
            root=package.parent,
        )
    payload = (
        component / "Payload/Library/Application Support/Agenxy/Remap/Portable/Staged"
    )
    if (payload / "release-manifest.json").read_bytes() != expected_manifest:
        raise RuntimeError("portable package manifest changed during pkgbuild")
    for path in payload.rglob("*"):
        if path.is_file() and path.read_bytes()[:4] in {
            b"\xcf\xfa\xed\xfe",
            b"\xfe\xed\xfa\xcf",
        }:
            verify_no_local_build_paths(path)
            _run(
                ("/usr/bin/codesign", "--verify", "--strict", str(path)),
                root=package.parent,
            )
    _verify_tree(payload)


def _normalize_parent_modes(package_root: Path, leaf: Path) -> None:
    for path in (leaf, *leaf.parents):
        if path == package_root.parent:
            break
        if path == package_root:
            os.chmod(path, 0o700)
        elif path.name in {"Staged", "Portable", "Remap"}:
            os.chmod(path, 0o700 if path.name != "Remap" else 0o711)
        else:
            os.chmod(path, 0o755)


def _verify_tree(root: Path, *, script_root: bool = False) -> None:
    for path in (root, *root.rglob("*")):
        information = path.lstat()
        if path.is_symlink() or (path.is_file() and information.st_nlink != 1):
            raise RuntimeError(f"portable package tree contains an unsafe node: {path}")
        mode = stat.S_IMODE(information.st_mode)
        if path.is_dir():
            allowed = {0o700} if path == root or script_root else {0o700, 0o711, 0o755}
        elif script_root:
            allowed = {0o555}
        else:
            allowed = {0o400, 0o500}
        if mode not in allowed:
            raise RuntimeError(
                f"portable package node has unsafe mode {mode:o}: {path}"
            )


def canonicalize_xar_metadata(package: Path) -> None:
    """Replace pkgbuild's volatile outer XAR metadata without changing its heap."""
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
    try:
        document = zlib.decompress(compressed)
    except zlib.error as error:
        raise RuntimeError(
            "the portable package XAR table is not valid zlib"
        ) from error
    if len(document) != plain_size or hashlib.sha1(compressed).digest() != heap[:20]:
        raise RuntimeError("the portable package XAR table checksum is invalid")
    try:
        root = ET.fromstring(document)
    except ET.ParseError as error:
        raise RuntimeError("the portable package XAR table is not valid XML") from error
    table = root.find("toc")
    if root.tag != "xar" or table is None:
        raise RuntimeError("the portable package XAR table has the wrong root")
    _require_xar_text(table, "creation-time", NORMALIZED_PACKAGE_TIME)
    for entry in table.findall("file"):
        inode = entry.find("inode")
        if inode is None:
            continue
        identifier = entry.get("id")
        if identifier is None or not identifier.isdigit():
            raise RuntimeError(
                "the portable package XAR entry has no canonical identity"
            )
        _require_xar_text(entry, "inode", identifier)
        _require_xar_text(entry, "deviceno", "0")
        _require_xar_text(entry, "uid", "0")
        _require_xar_text(entry, "user", "root")
        _require_xar_text(entry, "gid", "0")
        _require_xar_text(entry, "group", "wheel")
        for name in ("atime", "mtime", "ctime"):
            _require_xar_text(entry, name, f"{NORMALIZED_PACKAGE_TIME}Z")
        finder_time = entry.find("FinderCreateTime")
        if finder_time is None:
            raise RuntimeError("the portable package XAR entry has no creation time")
        _require_xar_text(finder_time, "time", NORMALIZED_PACKAGE_TIME)
        _require_xar_text(finder_time, "nanoseconds", "0")
    canonical = cast(bytes, ET.tostring(root, encoding="utf-8", xml_declaration=True))
    canonical_compressed = zlib.compress(canonical, level=9)
    canonical_header = XAR_HEADER.pack(
        XAR_MAGIC,
        XAR_HEADER.size,
        1,
        len(canonical_compressed),
        len(canonical),
        1,
    )
    destination = package.with_name(f"{package.name}.canonical")
    try:
        with destination.open("xb") as output_file:
            _ = output_file.write(canonical_header)
            _ = output_file.write(canonical_compressed)
            _ = output_file.write(hashlib.sha1(canonical_compressed).digest())
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


def _copy_file(source: Path, destination: Path, *, mode: int) -> None:
    information = source.lstat()
    if source.is_symlink() or not source.is_file() or information.st_nlink != 1:
        raise RuntimeError(f"portable package input is unsafe: {source}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        shutil.copyfileobj(input_file, output_file, length=1_048_576)
        output_file.flush()
        os.fsync(output_file.fileno())
    os.chmod(destination, mode)


def _copy_tree(source: Path, destination: Path) -> None:
    if source.is_symlink() or not source.is_dir():
        raise RuntimeError(f"portable package directory input is unsafe: {source}")
    destination.mkdir(mode=0o700)
    for child in sorted(source.iterdir()):
        target = destination / child.name
        if child.is_dir() and not child.is_symlink():
            _copy_tree(child, target)
        else:
            mode = 0o500 if os.access(child, os.X_OK) else 0o400
            _copy_file(child, target, mode=mode)


def _payload_path(root: Path, absolute: Path) -> Path:
    if not absolute.is_absolute():
        raise RuntimeError("portable package payload path must be absolute")
    return root.joinpath(*absolute.parts[1:])


def _validate_signing_key(path: Path, *, root: Path) -> None:
    information = path.lstat()
    public_only = path.suffix == ".pub"
    mode = stat.S_IMODE(information.st_mode)
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or information.st_nlink != 1
        or information.st_uid != os.getuid()
        or (mode & 0o022 if public_only else mode & 0o077)
    ):
        raise RuntimeError("the SSH release signing key has unsafe metadata")
    expected = canonical_release_public_key(
        (root / "docs/release/remap-release-signing-key.pub").read_text(
            encoding="utf-8"
        )
    )
    if public_only:
        observed = canonical_release_public_key(path.read_text(encoding="utf-8"))
    else:
        observed = canonical_release_public_key(
            _capture(("/usr/bin/ssh-keygen", "-y", "-f", str(path)), root=root)
        )
    if observed != expected:
        raise RuntimeError(
            "the SSH release signing key does not match Remap's pinned public key"
        )


def canonical_release_public_key(value: str) -> str:
    fields = value.strip().split()
    if len(fields) not in {2, 3} or fields[0] != "ssh-ed25519":
        raise RuntimeError(
            "the Remap release public key is not one canonical Ed25519 key"
        )
    return " ".join(fields[:2])


def _architecture() -> str:
    value = platform.machine()
    if value not in {"arm64", "x86_64"}:
        raise RuntimeError(f"unsupported macOS release architecture: {value}")
    return value


def validate_version(value: str) -> None:
    parts = value.split(".")
    if len(parts) != 3 or not all(
        part.isdigit() and str(int(part)) == part for part in parts
    ):
        raise RuntimeError("the portable package version must be canonical SemVer")


def canonical_release_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as input_file:
        for chunk in iter(lambda: input_file.read(1_048_576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _capture(arguments: tuple[str, ...], *, root: Path) -> str:
    result = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result.stdout.strip()


def _run(
    arguments: tuple[str, ...],
    *,
    root: Path,
    environment: dict[str, str] | None = None,
) -> None:
    _ = subprocess.run(
        arguments,
        cwd=root,
        env=environment,
        check=True,
        timeout=1_200,
    )


def _run_pkgbuild(
    arguments: tuple[str, ...],
    *,
    root: Path,
    environment: dict[str, str],
) -> None:
    """Run Apple's package builder and classify its protected-xattr diagnostic."""
    result = subprocess.run(
        arguments,
        cwd=root,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=1_200,
    )
    diagnostics = [line for line in result.stderr.splitlines() if line]
    provenance_diagnostics = [
        line for line in diagnostics if line == "write: Permission denied"
    ]
    unexpected = [line for line in diagnostics if line != "write: Permission denied"]
    if (
        result.returncode != 0
        or unexpected
        or len(provenance_diagnostics) > 4
        or "Wrote package to" not in result.stdout
    ):
        detail = "\n".join((*unexpected, result.stdout)).strip()
        raise RuntimeError(f"Apple pkgbuild failed its exact output contract: {detail}")
