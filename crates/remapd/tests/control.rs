//! Live local-control proofs against a real Unix listener and registry thread.

use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::process::Stdio;
use std::time::Duration;

use nix::sys::signal::{Signal, kill};
use nix::unistd::Pid;
use remap_protocol::{
    Change, Command, CommandResult, ControlClient, ControlPaths, HostPolicy, Surface,
};
use remapd::DaemonConfig;

const OP_ONE: &str = "f2442607-455d-4dff-bad9-2ddce6be04dd";

#[tokio::test]
async fn sigterm_drains_and_removes_the_control_socket() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_remapd"))
        .arg("--data-dir")
        .arg(paths.data_dir())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    wait_for_socket(paths.socket()).await?;
    let process_id = child
        .id()
        .ok_or_else(|| std::io::Error::other("spawned daemon had no process identifier"))?;
    kill(Pid::from_raw(i32::try_from(process_id)?), Signal::SIGTERM)?;
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait()).await??;
    assert!(status.success());
    assert!(!paths.socket().exists());
    Ok(())
}

#[tokio::test]
async fn two_surfaces_observe_one_live_authority() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon_paths = paths.clone();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(daemon_paths), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;

    let mcp = ControlClient::new(paths.socket(), Surface::Mcp, "0.1.0");
    let cli = ControlClient::new(paths.socket(), Surface::Cli, "0.1.0");
    let status = mcp.execute(Command::Status).await?;
    let CommandResult::Status(status) = status else {
        return Err("status returned the wrong result kind".into());
    };
    assert_eq!(status.revision, 0);

    cli.execute(Command::Apply {
        expected_revision: status.revision,
        operation_id: OP_ONE.to_owned(),
        changes: vec![Change::Set {
            pattern: "atlas".to_owned(),
            target: "10.0.0.8".to_owned(),
            host_policy: HostPolicy::PreserveClient,
            enabled: None,
        }],
    })
    .await?;
    let resolved = mcp
        .execute(Command::Resolve {
            name: "atlas".to_owned(),
        })
        .await?;
    let CommandResult::Resolution(resolution) = resolved else {
        return Err("resolve returned the wrong result kind".into());
    };
    assert_eq!(resolution.revision, 1);
    assert!(resolution.mapping.is_some());

    let directory_mode = std::fs::metadata(paths.data_dir())?.permissions().mode() & 0o777;
    let socket_mode = std::fs::metadata(paths.socket())?.permissions().mode() & 0o777;
    assert_eq!(directory_mode, 0o700);
    assert_eq!(socket_mode, 0o600);
    assert_private_files(paths.data_dir())?;

    let _result = stop_sender.send(());
    daemon.await??;
    assert!(!paths.socket().exists());
    Ok(())
}

#[tokio::test]
async fn shutdown_remains_responsive_when_connection_capacity_is_full()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let mut config = DaemonConfig::new(paths.clone());
    config.connection_limit = 2;
    config.read_timeout = Duration::from_secs(30);
    config.shutdown_grace = Duration::from_secs(1);
    let daemon = tokio::spawn(async move {
        remapd::serve_until(config, async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;

    let _first = tokio::net::UnixStream::connect(paths.socket()).await?;
    let _second = tokio::net::UnixStream::connect(paths.socket()).await?;
    let _overflow = tokio::net::UnixStream::connect(paths.socket()).await?;
    tokio::time::sleep(Duration::from_millis(25)).await;

    let _sent = stop_sender.send(());
    tokio::time::timeout(Duration::from_secs(2), daemon).await???;
    assert!(!paths.socket().exists());
    Ok(())
}

#[tokio::test]
async fn authority_lock_survives_a_removed_socket_path() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let first_paths = paths.clone();
    let first = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(first_paths), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    std::fs::remove_file(paths.socket())?;

    let error = remapd::serve_until(DaemonConfig::new(paths.clone()), async {})
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("a second authority acquired the data directory"))?;
    assert_eq!(error.code, "E_DAEMON_ALREADY_RUNNING");

    let _sent = stop_sender.send(());
    first.await??;
    Ok(())
}

#[tokio::test]
async fn shutdown_interrupts_idle_revision_waits_before_joining_the_writer()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon_paths = paths.clone();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(DaemonConfig::new(daemon_paths), async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let client = ControlClient::new(paths.socket(), Surface::Probe, "0.1.0");
    let waiting = tokio::spawn(async move {
        client
            .execute(Command::WaitForRevision {
                after: 0,
                timeout_ms: remap_protocol::MAX_REVISION_WAIT_MS,
            })
            .await
    });
    tokio::time::sleep(Duration::from_millis(25)).await;

    let _sent = stop_sender.send(());
    tokio::time::timeout(Duration::from_secs(2), daemon).await???;
    assert!(waiting.await?.is_err());
    Ok(())
}

#[tokio::test]
async fn overlong_socket_paths_fail_with_a_permanent_diagnostic()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("x".repeat(180)));
    let error = remapd::serve_until(DaemonConfig::new(paths), async {})
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("an overlong Unix socket path was accepted"))?;
    assert_eq!(error.code, "E_CONTROL_SOCKET_PATH");
    assert!(!error.retryable);
    Ok(())
}

fn assert_private_files(directory: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let metadata = entry.metadata()?;
        if metadata.file_type().is_file() {
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        } else if !metadata.file_type().is_socket() {
            return Err(format!(
                "unexpected data-directory entry: {}",
                entry.path().display()
            )
            .into());
        }
    }
    Ok(())
}

async fn wait_for_socket(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Err("daemon socket did not appear within one second".into())
}
