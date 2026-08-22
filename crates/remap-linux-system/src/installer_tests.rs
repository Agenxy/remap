use std::cell::Cell;
use std::os::unix::fs::PermissionsExt;

use crate::generation::{PUBLIC_DIRECTORY_PATHS, PreparedArtifact, seal_identity};
use crate::install_model::{
    Artifact, DirectoryProvenance, Generation, InstallPhase, InstallRecord, PublicDirectory,
};

use crate::generation_storage::{
    StageMoment, remove_empty_staging_roots, remove_generation_partial_at, stage_generation_at,
};

fn fixture(id_salt: u8) -> std::io::Result<(Generation, Vec<PreparedArtifact>)> {
    let prepared = (0_u8..35)
        .map(|index| PreparedArtifact {
            relative_path: format!("units/artifact-{index}"),
            mode: 0o644,
            bytes: vec![id_salt.wrapping_add(index); 8],
        })
        .collect::<Vec<_>>();
    let mut generation = Generation {
        id: uuid::Uuid::nil(),
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
        artifacts: prepared
            .iter()
            .map(|artifact| Artifact {
                relative_path: artifact.relative_path.clone(),
                mode: artifact.mode,
                byte_length: artifact.bytes.len() as u64,
                digest: crate::digest::sha256(&artifact.bytes),
            })
            .collect(),
        public_directories: PUBLIC_DIRECTORY_PATHS
            .iter()
            .map(|path| PublicDirectory {
                path: (*path).to_owned(),
                provenance: DirectoryProvenance::Preexisting,
                identity: None,
            })
            .collect(),
    };
    seal_identity(&mut generation)?;
    Ok((generation, prepared))
}

fn generation_root(parent: &tempfile::TempDir) -> std::path::PathBuf {
    parent.path().join("remap").join("generations")
}

#[test]
fn every_stage_boundary_recovers_first_install_and_update() -> std::io::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let (generation, artifacts) = fixture(7)?;
    let (previous_generation, _previous_artifacts) = fixture(3)?;
    let previous = InstallRecord {
        phase: InstallPhase::Active,
        current: previous_generation,
        previous: None,
        previous_previous: None,
        pending_resolver_plan: None,
    };
    for prior in [None, Some(&previous)] {
        let measure = tempfile::tempdir()?;
        std::fs::set_permissions(measure.path(), std::fs::Permissions::from_mode(0o700))?;
        let measure_root = generation_root(&measure);
        if prior.is_some() {
            create_existing_roots(&measure_root)?;
        }
        let calls = Cell::new(0_usize);
        stage_generation_at(
            &generation,
            &artifacts,
            &measure_root,
            prior.is_none(),
            &mut |_moment| {
                calls.set(calls.get() + 1);
                Ok(())
            },
        )?;
        remove_generation_partial_at(&generation, &measure_root)?;
        remove_empty_staging_roots(&measure_root)?;
        for fail_at in 0..calls.get() {
            let parent = tempfile::tempdir()?;
            std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))?;
            let root = generation_root(&parent);
            if prior.is_some() {
                create_existing_roots(&root)?;
            }
            let durable = InstallRecord::staging(generation.clone(), prior);
            let encoded = crate::install_model::encode(&durable)?;
            let restarted = crate::install_model::decode(&encoded)?;
            let index = Cell::new(0_usize);
            let result = stage_generation_at(
                &generation,
                &artifacts,
                &root,
                prior.is_none(),
                &mut |_moment: StageMoment| {
                    let current = index.get();
                    index.set(current + 1);
                    if current == fail_at {
                        Err(std::io::Error::other("injected stage crash"))
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(result.is_err());
            assert_eq!(restarted.phase, InstallPhase::Staging);
            assert_eq!(restarted.rollback_record(), prior.cloned());
            remove_generation_partial_at(&generation, &root)?;
            if prior.is_none() {
                remove_empty_staging_roots(&root)?;
                assert!(!parent.path().join("remap").exists());
            } else {
                assert!(root.exists());
                remove_empty_staging_roots(&root)?;
            }
        }
    }
    Ok(())
}

fn create_existing_roots(root: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(root)?;
    std::fs::set_permissions(
        root.parent()
            .ok_or_else(|| std::io::Error::other("fixture generation root has no parent"))?,
        std::fs::Permissions::from_mode(0o755),
    )?;
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o755))
}

#[test]
fn partial_cleanup_refuses_foreign_or_substituted_nodes() -> std::io::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let (generation, artifacts) = fixture(11)?;
    let parent = tempfile::tempdir()?;
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = generation_root(&parent);
    stage_generation_at(&generation, &artifacts, &root, true, &mut |_moment| Ok(()))?;
    let directory = root.join(generation.id.to_string());
    std::fs::write(directory.join("foreign"), b"foreign")?;
    assert!(remove_generation_partial_at(&generation, &root).is_err());
    assert!(directory.join("foreign").exists());

    std::fs::remove_file(directory.join("foreign"))?;
    let artifact = directory.join(&generation.artifacts[0].relative_path);
    let length = usize::try_from(generation.artifacts[0].byte_length)
        .map_err(|_error| std::io::Error::other("fixture length does not fit usize"))?;
    std::fs::write(&artifact, vec![0xff; length])?;
    std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o644))?;
    assert!(remove_generation_partial_at(&generation, &root).is_err());
    assert!(artifact.exists());
    Ok(())
}

#[test]
fn partial_cleanup_refuses_added_extended_attributes() -> std::io::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let (generation, artifacts) = fixture(17)?;
    let parent = tempfile::tempdir()?;
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = generation_root(&parent);
    stage_generation_at(&generation, &artifacts, &root, true, &mut |_moment| Ok(()))?;
    let artifact = root
        .join(generation.id.to_string())
        .join(&generation.artifacts[0].relative_path);
    xattr::set(&artifact, "user.remap-test", b"foreign")?;
    assert!(remove_generation_partial_at(&generation, &root).is_err());
    assert!(artifact.exists());
    xattr::remove(&artifact, "user.remap-test")?;
    remove_generation_partial_at(&generation, &root)?;
    remove_empty_staging_roots(&root)
}

#[test]
fn pruning_replay_accepts_a_manifest_bound_partial_generation() -> std::io::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        return Ok(());
    }
    let (generation, artifacts) = fixture(23)?;
    let parent = tempfile::tempdir()?;
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700))?;
    let root = generation_root(&parent);
    stage_generation_at(&generation, &artifacts, &root, true, &mut |_moment| Ok(()))?;
    let generation_directory = root.join(generation.id.to_string());
    let removed = generation_directory.join(&generation.artifacts[0].relative_path);
    std::fs::remove_file(&removed)?;
    crate::installer::sync_directory(
        removed
            .parent()
            .ok_or_else(|| std::io::Error::other("fixture artifact has no parent"))?,
    )?;

    remove_generation_partial_at(&generation, &root)?;
    assert!(!generation_directory.exists());
    remove_empty_staging_roots(&root)
}
