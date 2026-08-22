//! Opt-in end-to-end Linux proof for remapd's systemd activation path.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
use std::time::Duration;

use nix::fcntl::{FcntlArg, fcntl};
use nix::sys::signal::{Signal, kill};
use nix::unistd::{Pid, Uid};
use remap_protocol::ControlPaths;

#[test]
#[ignore = "requires available Linux loopback ports 53 and 80"]
fn remapd_serves_from_systemd_descriptors_without_root() -> Result<(), Box<dyn std::error::Error>> {
    assert!(!Uid::effective().is_root());
    let directory = tempfile::tempdir()?;
    let data_directory = directory.path().join("data");
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))?;
    let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 53))?;
    let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 80))?;
    let descriptors = [
        duplicate_high(&udp)?,
        duplicate_high(&dns_tcp)?,
        duplicate_high(&http)?,
    ];
    let mut child = spawn_wrapper(&descriptors, &data_directory)?;
    let control = ControlPaths::under(&data_directory);
    wait_for_ready(&mut child, control.socket())?;
    assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, 80)).is_err());
    kill(Pid::from_raw(i32::try_from(child.id())?), Signal::SIGTERM)?;
    assert!(child.wait()?.success());
    assert!(!control.socket().exists());
    Ok(())
}

#[test]
fn systemd_exec_child() -> Result<(), Box<dyn std::error::Error>> {
    let Some(data_directory) = std::env::var_os("REMAP_SYSTEMD_TEST_DATA") else {
        return Ok(());
    };
    // SAFETY: the parent runs only this exact test in a fresh process before
    // exec, so no concurrent thread reads or mutates the environment.
    unsafe {
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
    }
    let error = Command::new(env!("CARGO_BIN_EXE_remapd"))
        .args([
            "--data-dir",
            &data_directory.to_string_lossy(),
            "--dns-listen",
            "127.0.0.1:53",
            "--dns-upstream",
            "192.0.2.53:53",
            "--http-listen",
            "127.0.0.1:80",
            "--systemd-sockets",
        ])
        .exec();
    Err(error.into())
}

fn spawn_wrapper(
    descriptors: &[OwnedFd; 3],
    data_directory: &Path,
) -> Result<Child, Box<dyn std::error::Error>> {
    let raw = [
        descriptors[0].as_raw_fd(),
        descriptors[1].as_raw_fd(),
        descriptors[2].as_raw_fd(),
    ];
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["--exact", "systemd_exec_child", "--nocapture"])
        .env("LISTEN_FDS", "3")
        .env("LISTEN_FDNAMES", "dns-udp:dns-tcp:http")
        .env("REMAP_SYSTEMD_TEST_DATA", data_directory);
    // SAFETY: only async-signal-safe dup2 calls occur after fork. Sources are
    // private descriptors numbered at least 10, so target assignment cannot
    // invalidate a later source and each target has one owner in the child.
    unsafe {
        command.pre_exec(move || {
            for (source, target) in raw.into_iter().zip(3..=5) {
                if nix::libc::dup2(source, target) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(command.spawn()?)
}

fn duplicate_high<Fd: std::os::fd::AsFd>(descriptor: Fd) -> nix::Result<OwnedFd> {
    let raw = fcntl(descriptor, FcntlArg::F_DUPFD_CLOEXEC(10))?;
    // SAFETY: F_DUPFD_CLOEXEC returned one new descriptor with no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn wait_for_ready(child: &mut Child, socket: &Path) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        if socket.exists() {
            return Ok(());
        }
        if let Some(status) = child.try_wait()? {
            return Err(std::io::Error::other(format!(
                "systemd-activated remapd exited before readiness: {status}"
            ))
            .into());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let _terminated = kill(Pid::from_raw(i32::try_from(child.id())?), Signal::SIGTERM);
    let _status = child.wait();
    Err(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "systemd-activated remapd did not publish its control socket",
    )
    .into())
}
