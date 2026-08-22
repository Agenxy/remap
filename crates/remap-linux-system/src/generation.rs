use std::io;
use std::path::Path;

use nix::unistd::{Group, User};
use remap_linux::{
    ResolverLinkManager, ResolverSupervisorIdentity, ResolverSupervisorLink, ServiceIdentity,
    SocketContract, SystemdUnitSet,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use xattr::FileExt;

use crate::install_model::{
    Artifact, DirectoryIdentity, DirectoryProvenance, Generation, PublicDirectory,
};
use crate::installer::{InstallRequest, invalid_data, platform_error};
use crate::source_io::{installed_xattrs_safe, read_asset, read_source};

const STATE_DIRECTORY: &str = "/var/lib/remap-system";
const DATA_DIRECTORY: &str = "/var/lib/remap";
const REMAPD_UNIT: &str = "remapd.service";
const RESOLVER_UNIT: &str = "remap-resolver.service";
const SOURCE_MANIFEST_DOMAIN: &[u8] = b"remap.linux-source-manifest/v1\0";
const MANPAGES: [&str; 22] = [
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
];
const PRODUCT_DOCUMENT_DIRECTORY: &str = "/usr/share/doc/remap";
pub(crate) const PUBLIC_DIRECTORY_PATHS: [&str; 10] = [
    "/usr/share/bash-completion",
    "/usr/share/bash-completion/completions",
    "/usr/share/doc",
    PRODUCT_DOCUMENT_DIRECTORY,
    "/usr/share/fish",
    "/usr/share/fish/vendor_completions.d",
    "/usr/share/man",
    "/usr/share/man/man1",
    "/usr/share/zsh",
    "/usr/share/zsh/site-functions",
];

#[derive(Debug)]
pub(crate) struct PreparedArtifact {
    pub(crate) relative_path: String,
    pub(crate) mode: u32,
    pub(crate) bytes: Vec<u8>,
}

#[derive(Serialize)]
struct GenerationManifest<'a> {
    schema: &'static str,
    product_version: &'a str,
    account: &'a str,
    group: &'a str,
    owner_uid: u32,
    daemon_uid: u32,
    link: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    interface_name: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resolver_manager: Option<ResolverLinkManager>,
    #[serde(skip_serializing_if = "crate::install_model::is_legacy_resolver_rebase_capability")]
    resolver_rebase_capability: u16,
    artifacts: &'a [Artifact],
    public_directories: Vec<ManifestPublicDirectory<'a>>,
}

#[derive(Serialize)]
struct ManifestPublicDirectory<'a> {
    path: &'a str,
    provenance: DirectoryProvenance,
}

pub(crate) fn prepare(
    request: &InstallRequest,
    previous: Option<&Generation>,
    resolver_manager: ResolverLinkManager,
    interface_name: &str,
) -> io::Result<(Generation, Vec<PreparedArtifact>)> {
    let user = User::from_name(&request.account)
        .map_err(account_error)?
        .ok_or_else(account_missing)?;
    let group = Group::from_name(&request.group)
        .map_err(account_error)?
        .ok_or_else(account_missing)?;
    if user.uid.is_root() || user.uid.as_raw() == 0 || group.gid.as_raw() == 0 {
        return Err(account_missing());
    }
    let remap = read_source(&request.remap_source, request.owner_uid)?;
    let remapd = read_source(&request.remapd_source, request.owner_uid)?;
    let system = read_source(&request.system_source, request.owner_uid)?;
    let mut prepared = vec![
        artifact("remap", 0o755, remap),
        artifact("remapd", 0o755, remapd),
        artifact("remap-linux-system", 0o755, system),
    ];
    append_assets(&mut prepared, &request.assets_source, request.owner_uid)?;
    prepared.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    verify_source_manifest(&prepared, request.source_manifest_sha256)?;
    let daemon = ServiceIdentity::new(
        request.account.clone(),
        request.group.clone(),
        "/usr/libexec/remap/current/remapd",
    )
    .map_err(platform_error)?;
    let supervisor = ResolverSupervisorIdentity::new(
        "/usr/libexec/remap/current/remap-linux-system",
        ResolverSupervisorLink::new(request.link, interface_name, resolver_manager)
            .map_err(platform_error)?,
        request.owner_uid,
        user.uid.as_raw(),
        STATE_DIRECTORY,
        format!("{DATA_DIRECTORY}/system.sock"),
    )
    .map_err(platform_error)?;
    let units =
        SystemdUnitSet::generate_installable(&daemon, &supervisor, &SocketContract::remap())
            .map_err(platform_error)?;
    prepared.extend([
        artifact(
            &format!("units/{REMAPD_UNIT}"),
            0o644,
            units.service().as_bytes().to_vec(),
        ),
        artifact(
            &format!("units/{RESOLVER_UNIT}"),
            0o644,
            units
                .resolver_service()
                .ok_or_else(|| invalid_data("resolver unit generation failed"))?
                .as_bytes()
                .to_vec(),
        ),
    ]);
    for (name, contents) in units.sockets() {
        prepared.push(artifact(
            &format!("units/{name}"),
            0o644,
            contents.as_bytes().to_vec(),
        ));
    }
    prepared.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    let artifacts = prepared.iter().map(to_artifact).collect::<Vec<_>>();
    let product_version = env!("CARGO_PKG_VERSION").to_owned();
    let mut generation = Generation {
        id: Uuid::nil(),
        manifest_digest: [0; 32],
        product_version,
        account: request.account.clone(),
        group: request.group.clone(),
        owner_uid: request.owner_uid,
        daemon_uid: user.uid.as_raw(),
        link: request.link.get(),
        interface_name: Some(interface_name.to_owned()),
        resolver_manager: Some(resolver_manager),
        resolver_rebase_capability: crate::install_model::RESOLVER_REBASE_CAPABILITY,
        artifacts,
        public_directories: inspect_public_directories(previous)?,
    };
    seal_identity(&mut generation)?;
    Ok((generation, prepared))
}

fn source_manifest_sha256(prepared: &[PreparedArtifact]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_MANIFEST_DOMAIN);
    hasher.update((prepared.len() as u64).to_le_bytes());
    for artifact in prepared {
        hasher.update((artifact.relative_path.len() as u64).to_le_bytes());
        hasher.update(artifact.relative_path.as_bytes());
        hasher.update(artifact.mode.to_le_bytes());
        hasher.update((artifact.bytes.len() as u64).to_le_bytes());
        hasher.update(&artifact.bytes);
    }
    hasher.finalize().into()
}

fn verify_source_manifest(prepared: &[PreparedArtifact], expected: [u8; 32]) -> io::Result<()> {
    let sorted = prepared
        .windows(2)
        .all(|pair| pair[0].relative_path < pair[1].relative_path);
    if sorted && source_manifest_sha256(prepared) == expected {
        Ok(())
    } else {
        Err(invalid_data(
            "the Linux generation sources differ from the reviewed source manifest",
        ))
    }
}

fn manifest_digest(generation: &Generation) -> io::Result<[u8; 32]> {
    let encoded = encoded_manifest(generation)?;
    Ok(crate::digest::sha256(&encoded))
}

fn legacy_manifest_digest(generation: &Generation) -> io::Result<[u8; 32]> {
    let encoded = encoded_manifest(generation)?;
    Ok(*blake3::hash(&encoded).as_bytes())
}

fn encoded_manifest(generation: &Generation) -> io::Result<Vec<u8>> {
    let manifest = GenerationManifest {
        schema: "remap.linux-generation/v1",
        product_version: &generation.product_version,
        account: &generation.account,
        group: &generation.group,
        owner_uid: generation.owner_uid,
        daemon_uid: generation.daemon_uid,
        link: generation.link,
        interface_name: generation.interface_name.as_deref(),
        resolver_manager: generation.resolver_manager,
        resolver_rebase_capability: generation.resolver_rebase_capability,
        artifacts: &generation.artifacts,
        public_directories: generation
            .public_directories
            .iter()
            .map(|directory| ManifestPublicDirectory {
                path: &directory.path,
                provenance: directory.provenance,
            })
            .collect(),
    };
    serde_json::to_vec(&manifest)
        .map_err(|_error| invalid_data("the generation manifest could not be encoded"))
}

fn manifest_uuid(digest: [u8; 32]) -> Uuid {
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

pub(crate) fn validate_identity(generation: &Generation) -> io::Result<()> {
    let digest = manifest_digest(generation)?;
    if digest != generation.manifest_digest || manifest_uuid(digest) != generation.id {
        return Err(invalid_data("the generation manifest identity is invalid"));
    }
    Ok(())
}

pub(crate) fn validate_legacy_identity(generation: &Generation) -> io::Result<()> {
    let digest = legacy_manifest_digest(generation)?;
    if digest != generation.manifest_digest || manifest_uuid(digest) != generation.id {
        return Err(invalid_data(
            "the legacy generation manifest identity is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn seal_legacy_identity(generation: &mut Generation) -> io::Result<()> {
    let digest = legacy_manifest_digest(generation)?;
    generation.id = manifest_uuid(digest);
    generation.manifest_digest = digest;
    Ok(())
}

pub(crate) fn seal_identity(generation: &mut Generation) -> io::Result<()> {
    let digest = manifest_digest(generation)?;
    generation.id = manifest_uuid(digest);
    generation.manifest_digest = digest;
    Ok(())
}

fn inspect_public_directories(previous: Option<&Generation>) -> io::Result<Vec<PublicDirectory>> {
    PUBLIC_DIRECTORY_PATHS
        .into_iter()
        .map(|path| {
            let prior_identity = previous
                .and_then(|generation| {
                    generation
                        .public_directories
                        .iter()
                        .find(|directory| directory.path == path)
                })
                .filter(|directory| directory.provenance == DirectoryProvenance::CreatedByRemap)
                .and_then(|directory| directory.identity);
            let (provenance, identity) = match std::fs::symlink_metadata(path) {
                Ok(metadata) => {
                    validate_public_directory_metadata(&metadata)?;
                    if prior_identity.is_none() {
                        validate_preexisting_public_directory_xattrs(Path::new(path))?;
                    }
                    if path == PRODUCT_DOCUMENT_DIRECTORY && previous.is_none() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "the Remap documentation path is occupied",
                        ));
                    }
                    if let Some(expected) = prior_identity {
                        let observed = metadata_identity(path).map_err(|_error| {
                            io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "a Remap-created public directory lost its ownership marker",
                            )
                        })?;
                        if expected != observed {
                            return Err(io::Error::new(
                                io::ErrorKind::AlreadyExists,
                                "a Remap-created public directory changed identity",
                            ));
                        }
                        (DirectoryProvenance::CreatedByRemap, Some(observed))
                    } else {
                        (DirectoryProvenance::Preexisting, None)
                    }
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound && prior_identity.is_none() =>
                {
                    (DirectoryProvenance::CreatedByRemap, None)
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        "a Remap-created public directory changed ownership",
                    ));
                }
                Err(error) => return Err(error),
            };
            Ok(PublicDirectory {
                path: path.to_owned(),
                provenance,
                identity,
            })
        })
        .collect()
}

fn validate_preexisting_public_directory_xattrs(path: &Path) -> io::Result<()> {
    let directory = std::fs::File::open(path)?;
    if installed_xattrs_safe(&directory)? {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a standard Linux publication directory has unsafe extended attributes",
        ))
    }
}

fn validate_public_directory_metadata(metadata: &std::fs::Metadata) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != 0o755
    {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "a standard Linux publication directory is unsafe",
        ));
    }
    Ok(())
}

pub(crate) fn validate_public_directories(directories: &[PublicDirectory]) -> io::Result<()> {
    if directories.len() != PUBLIC_DIRECTORY_PATHS.len()
        || directories
            .iter()
            .zip(PUBLIC_DIRECTORY_PATHS)
            .any(|(directory, expected)| directory.path != expected)
    {
        return Err(invalid_data(
            "the public directory provenance manifest is invalid",
        ));
    }
    if directories.iter().any(|directory| {
        (directory.provenance == DirectoryProvenance::Preexisting && directory.identity.is_some())
            || directory.identity.is_some_and(|identity| {
                identity.inode == 0
                    || identity.birth_seconds <= 0
                    || identity.birth_nanoseconds >= 1_000_000_000
                    || identity.ownership_nonce == [0; 16]
            })
    }) {
        return Err(invalid_data(
            "the public directory identity manifest is invalid",
        ));
    }
    Ok(())
}

fn metadata_identity(path: &str) -> io::Result<DirectoryIdentity> {
    let requested = rustix::fs::StatxFlags::INO | rustix::fs::StatxFlags::BTIME;
    let metadata = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        requested,
    )?;
    let available = rustix::fs::StatxFlags::from_bits_retain(metadata.stx_mask);
    if !available.contains(requested) {
        return Err(invalid_data(
            "the public directory filesystem does not expose durable creation identity",
        ));
    }
    let directory = std::fs::File::open(path)?;
    let ownership_nonce = directory
        .get_xattr("user.remap.owner")?
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_data("the public directory ownership marker is invalid"))?;
    Ok(DirectoryIdentity {
        inode: metadata.stx_ino,
        birth_seconds: metadata.stx_btime.tv_sec,
        birth_nanoseconds: metadata.stx_btime.tv_nsec,
        ownership_nonce,
    })
}

fn to_artifact(prepared: &PreparedArtifact) -> Artifact {
    Artifact {
        relative_path: prepared.relative_path.clone(),
        mode: prepared.mode,
        byte_length: prepared.bytes.len() as u64,
        digest: crate::digest::sha256(&prepared.bytes),
    }
}

fn append_assets(
    prepared: &mut Vec<PreparedArtifact>,
    source: &Path,
    owner_uid: u32,
) -> io::Result<()> {
    for name in MANPAGES {
        let bytes = read_asset(&source.join("manpages").join(name), owner_uid)?;
        if !bytes.windows(4).any(|window| window == b".TH ") {
            return Err(invalid_data("a generated Linux manpage is malformed"));
        }
        prepared.push(artifact(&format!("share/man/man1/{name}"), 0o644, bytes));
    }
    for shell in ["bash", "fish", "zsh"] {
        let bytes = read_asset(&source.join(format!("remap.{shell}")), owner_uid)?;
        prepared.push(artifact(
            &format!("share/completions/remap.{shell}"),
            0o644,
            bytes,
        ));
    }
    append_policy_asset(
        prepared,
        source,
        owner_uid,
        "LICENSE",
        include_bytes!("../LICENSE"),
    )?;
    append_policy_asset(
        prepared,
        source,
        owner_uid,
        "NOTICE",
        include_bytes!("../NOTICE"),
    )
}

fn append_policy_asset(
    prepared: &mut Vec<PreparedArtifact>,
    source: &Path,
    owner_uid: u32,
    name: &str,
    expected: &[u8],
) -> io::Result<()> {
    let bytes = read_asset(&source.join(name), owner_uid)?;
    if bytes != expected {
        return Err(invalid_data(
            "a Linux policy document differs from the canonical project text",
        ));
    }
    prepared.push(artifact(name, 0o644, bytes));
    Ok(())
}

fn artifact(relative_path: &str, mode: u32, bytes: Vec<u8>) -> PreparedArtifact {
    PreparedArtifact {
        relative_path: relative_path.to_owned(),
        mode,
        bytes,
    }
}

fn account_error(_error: nix::Error) -> io::Error {
    account_missing()
}

fn account_missing() -> io::Error {
    invalid_data("the declared non-root daemon account or group is unavailable")
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{
        PreparedArtifact, manifest_uuid, seal_identity, source_manifest_sha256, validate_identity,
        validate_preexisting_public_directory_xattrs, verify_source_manifest,
    };
    use crate::install_model::{Artifact, DirectoryProvenance, Generation, PublicDirectory};
    use uuid::Uuid;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct SourceManifestFixture {
        schema: String,
        sources: Vec<SourceFixture>,
        sha256: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct SourceFixture {
        path: String,
        mode: u32,
        content_hex: String,
    }

    #[test]
    fn manifest_uuid_is_stable_and_rfc_variant() {
        let digest = [0xa5; 32];
        let first = manifest_uuid(digest);
        assert_eq!(first, manifest_uuid(digest));
        assert_eq!(first.as_bytes()[6] >> 4, 8);
        assert_eq!(first.as_bytes()[8] >> 6, 2);
    }

    #[test]
    fn source_manifest_matches_the_language_neutral_sha256_fixture() -> std::io::Result<()> {
        let fixture: SourceManifestFixture = serde_json::from_str(include_str!(
            "../tests/fixtures/linux-source-manifest-v1.json"
        ))
        .map_err(std::io::Error::other)?;
        assert_eq!(fixture.schema, "remap.linux-source-manifest-fixture/v1");
        let sources = fixture
            .sources
            .into_iter()
            .map(|source| {
                Ok(PreparedArtifact {
                    relative_path: source.path,
                    mode: source.mode,
                    bytes: decode_hex(&source.content_hex)?,
                })
            })
            .collect::<std::io::Result<Vec<_>>>()?;
        assert_eq!(
            source_manifest_sha256(&sources),
            crate::parse_sha256(&fixture.sha256)?
        );
        Ok(())
    }

    #[test]
    fn source_manifest_rejects_each_substitutable_source_class() {
        let sources = [
            ("remap", 0o755),
            ("remapd", 0o755),
            ("remap-linux-system", 0o755),
            ("share/man/man1/remap.1", 0o644),
        ];
        let mut prepared = sources
            .iter()
            .map(|(path, mode)| PreparedArtifact {
                relative_path: (*path).to_owned(),
                mode: *mode,
                bytes: format!("reviewed-{path}").into_bytes(),
            })
            .collect::<Vec<_>>();
        prepared.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        let expected = source_manifest_sha256(&prepared);
        assert!(verify_source_manifest(&prepared, expected).is_ok());
        for index in 0..prepared.len() {
            let mut substituted = prepared
                .iter()
                .map(|artifact| PreparedArtifact {
                    relative_path: artifact.relative_path.clone(),
                    mode: artifact.mode,
                    bytes: artifact.bytes.clone(),
                })
                .collect::<Vec<_>>();
            substituted[index].bytes.push(b'!');
            assert!(verify_source_manifest(&substituted, expected).is_err());
        }
    }

    fn decode_hex(value: &str) -> std::io::Result<Vec<u8>> {
        if !value.len().is_multiple_of(2) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the source manifest fixture contains invalid hexadecimal bytes",
            ));
        }
        value
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let encoded = std::str::from_utf8(pair).map_err(std::io::Error::other)?;
                u8::from_str_radix(encoded, 16).map_err(std::io::Error::other)
            })
            .collect()
    }

    #[test]
    fn sealed_generation_identity_detects_manifest_drift() -> std::io::Result<()> {
        let mut generation = Generation {
            id: Uuid::nil(),
            manifest_digest: [0; 32],
            product_version: "0.1.1".to_owned(),
            account: "remap".to_owned(),
            group: "remap".to_owned(),
            owner_uid: 1000,
            daemon_uid: 1001,
            link: 2,
            interface_name: Some("eth0".to_owned()),
            resolver_manager: Some(remap_linux::ResolverLinkManager::SystemdNetworkd),
            resolver_rebase_capability: crate::install_model::RESOLVER_REBASE_CAPABILITY,
            artifacts: vec![Artifact {
                relative_path: "remap".to_owned(),
                mode: 0o755,
                byte_length: 4,
                digest: [7; 32],
            }],
            public_directories: super::PUBLIC_DIRECTORY_PATHS
                .iter()
                .map(|path| PublicDirectory {
                    path: (*path).to_owned(),
                    provenance: DirectoryProvenance::Preexisting,
                    identity: None,
                })
                .collect(),
        };
        seal_identity(&mut generation)?;
        validate_identity(&generation)?;
        generation.link = 3;
        assert!(validate_identity(&generation).is_err());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn preexisting_publication_directory_rejects_foreign_user_xattrs() -> std::io::Result<()> {
        let directory = tempfile::tempdir()?;
        validate_preexisting_public_directory_xattrs(directory.path())?;

        xattr::set(directory.path(), "user.remap-test", b"foreign")?;
        let error = match validate_preexisting_public_directory_xattrs(directory.path()) {
            Ok(()) => return Err(std::io::Error::other("the foreign xattr was accepted")),
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        Ok(())
    }
}
