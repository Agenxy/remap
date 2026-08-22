//! Root-only native filesystem contract tests for Linux CI and package hosts.

#![cfg(target_os = "linux")]

use std::net::{IpAddr, Ipv4Addr};
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use nix::unistd::Uid;
use remap_linux::{
    ActivationRecord, ActivationStore, DnsServer, LinkDomain, LinkIndex, LinkState, RecordMetadata,
    RootRecordStore,
};
use uuid::Uuid;

#[test]
fn root_store_round_trips_and_durably_removes_one_record() -> Result<(), Box<dyn std::error::Error>>
{
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    let mut store = RootRecordStore::open(directory.path())?;
    let record = record()?;
    store.save(&record)?;
    assert_eq!(store.load()?, Some(record.clone()));
    store.remove(record.metadata())?;
    assert_eq!(store.load()?, None);
    Ok(())
}

#[test]
fn root_store_rejects_a_symlinked_directory_component() -> Result<(), Box<dyn std::error::Error>> {
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let parent = tempfile::tempdir()?;
    let real = parent.path().join("real");
    std::fs::create_dir(&real)?;
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700))?;
    let linked = parent.path().join("linked");
    symlink(&real, &linked)?;
    assert!(RootRecordStore::open(&linked).is_err());
    Ok(())
}

#[test]
fn root_store_rejects_directory_extended_attributes() -> Result<(), Box<dyn std::error::Error>> {
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
    xattr::set(directory.path(), "user.remap-test", b"foreign")?;
    assert!(RootRecordStore::open(directory.path()).is_err());
    Ok(())
}

#[test]
fn separate_resolver_lock_inode_survives_three_contenders() -> Result<(), Box<dyn std::error::Error>>
{
    if !Uid::effective().is_root() {
        return Ok(());
    }
    let record_directory = tempfile::tempdir()?;
    let lock_directory = tempfile::tempdir()?;
    for directory in [record_directory.path(), lock_directory.path()] {
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    let first =
        RootRecordStore::open_with_lock_directory(record_directory.path(), lock_directory.path())?;
    let path = lock_directory.path().join(".resolver-activation.lock");
    let inode = std::fs::metadata(&path)?.ino();
    assert!(
        RootRecordStore::open_with_lock_directory(record_directory.path(), lock_directory.path())
            .is_err()
    );
    drop(first);

    let third =
        RootRecordStore::open_with_lock_directory(record_directory.path(), lock_directory.path())?;
    assert_eq!(std::fs::metadata(&path)?.ino(), inode);
    assert!(
        RootRecordStore::open_with_lock_directory(record_directory.path(), lock_directory.path())
            .is_err()
    );
    drop(third);
    assert_eq!(std::fs::metadata(path)?.ino(), inode);
    Ok(())
}

fn record() -> Result<ActivationRecord, Box<dyn std::error::Error>> {
    let link = LinkIndex::new(7)?;
    let before = LinkState::new(
        link,
        vec![DnsServer::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)),
            53,
            "",
        )?],
        vec![LinkDomain::new("example", false)?],
        false,
    )?;
    let owned = LinkState::remap_loopback(link)?;
    let metadata = RecordMetadata::new(Uuid::from_u128(0x1234), 1, 1000, 1)?;
    Ok(ActivationRecord::prepare(metadata, &[before], owned)?)
}
