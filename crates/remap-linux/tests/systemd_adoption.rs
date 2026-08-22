//! Opt-in live descriptor-adoption proof for a Linux systemd-shaped host.

#![cfg(target_os = "linux")]
#![allow(unsafe_code)]

use std::fs::File;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::Command;

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use remap_linux::{adopt_systemd_sockets, reject_unrequested_activation};

#[test]
fn ordinary_launch_rejects_and_closes_inherited_descriptors()
-> Result<(), Box<dyn std::error::Error>> {
    let null = File::open("/dev/null")?;
    let descriptors = [
        duplicate_high(&null)?,
        duplicate_high(&null)?,
        duplicate_high(&null)?,
    ];
    let rejected = run_child(&descriptors, "dns-udp:dns-tcp:http", "ordinary")?;
    assert!(rejected.success());
    Ok(())
}

#[test]
#[ignore = "requires available Linux loopback ports 53 and 80"]
fn adopts_exact_descriptors_and_rejects_name_substitution() -> Result<(), Box<dyn std::error::Error>>
{
    let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 53))?;
    let dns_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 53))?;
    let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 80))?;
    let descriptors = [
        duplicate_high(&udp)?,
        duplicate_high(&dns_tcp)?,
        duplicate_high(&http)?,
    ];
    let accepted = run_child(&descriptors, "dns-udp:dns-tcp:http", "accept")?;
    assert!(accepted.success());
    let rejected = run_child(&descriptors, "dns-udp:http:dns-tcp", "reject")?;
    assert!(rejected.success());
    Ok(())
}

#[test]
fn adoption_child() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(mode) = std::env::var("REMAP_ADOPTION_TEST_MODE") else {
        return Ok(());
    };
    // SAFETY: the parent selects this single exact test in a fresh process;
    // no other test or runtime thread reads or writes the environment.
    unsafe {
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
    }
    if mode == "ordinary" {
        assert!(reject_unrequested_activation().is_err());
        assert_activation_environment_absent();
        for descriptor in 3..=5 {
            assert_eq!(
                unsafe { nix::libc::fcntl(descriptor, nix::libc::F_GETFD) },
                -1
            );
            assert_eq!(nix::errno::Errno::last(), nix::errno::Errno::EBADF);
        }
        return Ok(());
    }
    let adoption = adopt_systemd_sockets();
    if mode == "reject" {
        assert!(adoption.is_err());
        return Ok(());
    }
    let sockets = adoption?;
    let (udp, dns_tcp, http) = sockets.into_parts();
    assert_eq!(
        udp.local_addr()?,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53))
    );
    assert_eq!(
        dns_tcp.local_addr()?,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 53))
    );
    assert_eq!(
        http.local_addr()?,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 80))
    );
    verify_flags(&udp)?;
    verify_flags(&dns_tcp)?;
    verify_flags(&http)?;
    assert_activation_environment_absent();
    Ok(())
}

fn assert_activation_environment_absent() {
    assert!(std::env::var_os("LISTEN_PID").is_none());
    assert!(std::env::var_os("LISTEN_FDS").is_none());
    assert!(std::env::var_os("LISTEN_FDNAMES").is_none());
}

fn run_child(
    descriptors: &[OwnedFd; 3],
    names: &str,
    mode: &str,
) -> Result<std::process::ExitStatus, Box<dyn std::error::Error>> {
    let executable = std::env::current_exe()?;
    let raw = [
        descriptors[0].as_raw_fd(),
        descriptors[1].as_raw_fd(),
        descriptors[2].as_raw_fd(),
    ];
    let mut command = Command::new(executable);
    command
        .args(["--exact", "adoption_child", "--nocapture"])
        .env("LISTEN_FDS", "3")
        .env("LISTEN_FDNAMES", names)
        .env("REMAP_ADOPTION_TEST_MODE", mode);
    // SAFETY: the closure uses only async-signal-safe dup2 calls. Sources are
    // private duplicates numbered at least 10, so assigning 3, 4, and 5 cannot
    // invalidate a later source. Each target becomes the child's sole owner.
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
    Ok(command.status()?)
}

fn duplicate_high<Fd: std::os::fd::AsFd>(descriptor: Fd) -> nix::Result<OwnedFd> {
    let raw = fcntl(descriptor, FcntlArg::F_DUPFD_CLOEXEC(10))?;
    // SAFETY: F_DUPFD_CLOEXEC returned one new descriptor with no other owner.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn verify_flags<Fd: std::os::fd::AsFd>(descriptor: Fd) -> nix::Result<()> {
    let descriptor_flags = FdFlag::from_bits_truncate(fcntl(&descriptor, FcntlArg::F_GETFD)?);
    let status_flags = OFlag::from_bits_truncate(fcntl(&descriptor, FcntlArg::F_GETFL)?);
    assert!(descriptor_flags.contains(FdFlag::FD_CLOEXEC));
    assert!(status_flags.contains(OFlag::O_NONBLOCK));
    Ok(())
}
