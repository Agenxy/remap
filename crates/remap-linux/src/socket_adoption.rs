#![allow(unsafe_code)]

use std::collections::BTreeMap;
use std::net::{SocketAddr, TcpListener, UdpSocket};
use std::os::fd::{FromRawFd, OwnedFd};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::sys::socket::{SockType, getsockopt, setsockopt, sockopt};
use nix::unistd::Uid;

use crate::{
    ActivationEnvironment, DescriptorKind, DescriptorSpec, LinuxError, LinuxErrorKind, LinuxResult,
    SocketContract,
};

const ENVIRONMENT_KEYS: [&str; 3] = ["LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"];
const MAX_CLOSE_COUNT: u32 = 16;

/// Exact DNS and HTTP sockets safely owned after systemd activation.
#[derive(Debug)]
pub struct AdoptedSystemdSockets {
    dns_udp: UdpSocket,
    dns_tcp: TcpListener,
    http: TcpListener,
}

impl AdoptedSystemdSockets {
    /// Transfers the validated native sockets to the portable runtime adapter.
    #[must_use]
    pub fn into_parts(self) -> (UdpSocket, TcpListener, TcpListener) {
        (self.dns_udp, self.dns_tcp, self.http)
    }
}

/// Adopts systemd's exact named descriptor set before runtime threads exist.
///
/// The environment is erased on every parsed path. Any mismatch drops every
/// descriptor already adopted and closes the declared range before returning.
///
/// # Errors
///
/// Returns an invalid-service-contract error for root execution, incomplete or
/// substituted descriptors, wrong socket type/address/port/listening state, or
/// failure to enforce nonblocking, close-on-exec, and UDP address-exclusivity
/// policy.
pub fn adopt_systemd_sockets() -> LinuxResult<AdoptedSystemdSockets> {
    let values = read_environment()?;
    if Uid::effective().is_root() {
        close_declared(&values[0], &values[1]);
        scrub_environment();
        return Err(contract_error(
            "the systemd service must run as its declared non-root account",
        ));
    }
    let contract = SocketContract::remap();
    let environment = ActivationEnvironment::parse(
        std::process::id(),
        &values[0],
        &values[1],
        &values[2],
        &contract,
    );
    let environment = match environment {
        Ok(environment) => environment,
        Err(error) => {
            close_declared(&values[0], &values[1]);
            scrub_environment();
            return Err(error);
        }
    };
    let descriptors = adopt_descriptors(&environment, &contract);
    scrub_environment();
    let mut descriptors = descriptors?;
    let dns_udp = UdpSocket::from(take_descriptor(&mut descriptors, "dns-udp")?);
    let dns_tcp = TcpListener::from(take_descriptor(&mut descriptors, "dns-tcp")?);
    let http = TcpListener::from(take_descriptor(&mut descriptors, "http")?);
    if !descriptors.is_empty() {
        return Err(contract_error("systemd supplied an undeclared descriptor"));
    }
    Ok(AdoptedSystemdSockets {
        dns_udp,
        dns_tcp,
        http,
    })
}

/// Rejects and scrubs systemd descriptors from an ordinary daemon launch.
///
/// # Errors
///
/// Returns an invalid-service-contract error whenever any activation variable
/// is present without explicit adoption mode.
pub fn reject_unrequested_activation() -> LinuxResult<()> {
    let values = ENVIRONMENT_KEYS.map(std::env::var_os);
    if values.iter().all(Option::is_none) {
        return Ok(());
    }
    let pid = values[0].as_ref().and_then(|value| value.to_str());
    let count = values[1].as_ref().and_then(|value| value.to_str());
    if let (Some(pid), Some(count)) = (pid, count) {
        close_declared(pid, count);
    }
    scrub_environment();
    Err(contract_error(
        "socket descriptors require explicit systemd activation mode",
    ))
}

fn read_environment() -> LinuxResult<[String; 3]> {
    let [pid, count, names] = ENVIRONMENT_KEYS.map(std::env::var);
    match (pid, count, names) {
        (Ok(pid), Ok(count), Ok(names)) => Ok([pid, count, names]),
        (pid, count, _names) => {
            if let (Ok(pid), Ok(count)) = (pid, count) {
                close_declared(&pid, &count);
            }
            scrub_environment();
            Err(contract_error(
                "systemd did not supply the complete activation environment",
            ))
        }
    }
}

fn adopt_descriptors(
    environment: &ActivationEnvironment,
    contract: &SocketContract,
) -> LinuxResult<BTreeMap<&'static str, OwnedFd>> {
    for spec in contract.descriptors() {
        let number = descriptor_number(environment, spec.name())?;
        if !descriptor_is_open(number) {
            close_environment_descriptors(environment, contract);
            return Err(contract_error("systemd supplied a closed descriptor"));
        }
    }
    let mut adopted = BTreeMap::new();
    for spec in contract.descriptors() {
        let number = descriptor_number(environment, spec.name())?;
        // SAFETY: every descriptor was verified open immediately above,
        // systemd transferred this exact contiguous set to this process,
        // bootstrap is single-threaded, and each number is adopted once.
        let descriptor = unsafe { OwnedFd::from_raw_fd(number.cast_signed()) };
        if adopted.insert(spec.name(), descriptor).is_some() {
            return Err(contract_error("systemd duplicated a descriptor name"));
        }
    }
    for spec in contract.descriptors() {
        let descriptor = adopted
            .get(spec.name())
            .ok_or_else(|| contract_error("systemd omitted a declared descriptor"))?;
        configure_descriptor(descriptor, spec.kind())?;
        validate_descriptor(descriptor, *spec)?;
    }
    Ok(adopted)
}

fn descriptor_number(environment: &ActivationEnvironment, name: &str) -> LinuxResult<u32> {
    environment
        .descriptor_number(name)
        .ok_or_else(|| contract_error("systemd omitted a declared descriptor"))
}

fn configure_descriptor(descriptor: &OwnedFd, kind: DescriptorKind) -> LinuxResult<()> {
    if kind == DescriptorKind::Datagram {
        setsockopt(descriptor, sockopt::ReuseAddr, &false).map_err(|_error| {
            contract_error("an activated socket could not enforce exclusive address ownership")
        })?;
    }
    let descriptor_flags = fcntl(descriptor, FcntlArg::F_GETFD)
        .map_err(|_error| contract_error("an activated descriptor could not be inspected"))?;
    let mut descriptor_flags = FdFlag::from_bits_truncate(descriptor_flags);
    descriptor_flags.insert(FdFlag::FD_CLOEXEC);
    fcntl(descriptor, FcntlArg::F_SETFD(descriptor_flags))
        .map_err(|_error| contract_error("an activated descriptor could not be secured"))?;
    let status_flags = fcntl(descriptor, FcntlArg::F_GETFL)
        .map_err(|_error| contract_error("an activated socket could not be inspected"))?;
    let mut status_flags = OFlag::from_bits_truncate(status_flags);
    status_flags.insert(OFlag::O_NONBLOCK);
    fcntl(descriptor, FcntlArg::F_SETFL(status_flags))
        .map_err(|_error| contract_error("an activated socket could not be secured"))?;
    verify_flags(descriptor, kind)
}

fn verify_flags(descriptor: &OwnedFd, kind: DescriptorKind) -> LinuxResult<()> {
    let descriptor_flags = fcntl(descriptor, FcntlArg::F_GETFD)
        .map(FdFlag::from_bits_truncate)
        .map_err(|_error| contract_error("an activated descriptor could not be verified"))?;
    let status_flags = fcntl(descriptor, FcntlArg::F_GETFL)
        .map(OFlag::from_bits_truncate)
        .map_err(|_error| contract_error("an activated socket could not be verified"))?;
    let address_reuse = getsockopt(descriptor, sockopt::ReuseAddr).map_err(|_error| {
        contract_error("an activated socket address-ownership policy could not be verified")
    })?;
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC)
        || !status_flags.contains(OFlag::O_NONBLOCK)
        || (kind == DescriptorKind::Datagram && address_reuse)
    {
        return Err(contract_error(
            "an activated socket did not retain its required descriptor flags",
        ));
    }
    Ok(())
}

fn validate_descriptor(descriptor: &OwnedFd, specification: DescriptorSpec) -> LinuxResult<()> {
    let socket_type = getsockopt(descriptor, sockopt::SockType)
        .map_err(|_error| contract_error("an activated descriptor is not a socket"))?;
    let accepting = getsockopt(descriptor, sockopt::AcceptConn)
        .map_err(|_error| contract_error("an activated socket state is unavailable"))?;
    let valid_type = matches!(
        (specification.kind(), socket_type, accepting),
        (DescriptorKind::Datagram, SockType::Datagram, false)
            | (DescriptorKind::Stream, SockType::Stream, true)
    );
    if !valid_type {
        return Err(contract_error(
            "an activated socket has the wrong transport or listening state",
        ));
    }
    let expected = specification
        .address()
        .parse::<SocketAddr>()
        .map_err(|_error| contract_error("the compiled socket contract is invalid"))?;
    let duplicate = descriptor
        .try_clone()
        .map_err(|_error| contract_error("an activated socket could not be duplicated"))?;
    let observed = match specification.kind() {
        DescriptorKind::Datagram => UdpSocket::from(duplicate).local_addr(),
        DescriptorKind::Stream => TcpListener::from(duplicate).local_addr(),
    }
    .map_err(|_error| contract_error("an activated socket address is invalid"))?;
    if observed != expected {
        return Err(contract_error(
            "an activated socket does not match its declared loopback address and port",
        ));
    }
    Ok(())
}

fn take_descriptor(
    descriptors: &mut BTreeMap<&'static str, OwnedFd>,
    name: &'static str,
) -> LinuxResult<OwnedFd> {
    descriptors
        .remove(name)
        .ok_or_else(|| contract_error("systemd omitted a required descriptor"))
}

fn close_environment_descriptors(environment: &ActivationEnvironment, contract: &SocketContract) {
    for spec in contract.descriptors() {
        if let Some(number) = environment.descriptor_number(spec.name()) {
            let _closed = nix::unistd::close(number.cast_signed());
        }
    }
}

fn close_declared(listen_pid: &str, listen_fds: &str) {
    let Ok(owner) = listen_pid.parse::<u32>() else {
        return;
    };
    let Ok(count) = listen_fds.parse::<u32>() else {
        return;
    };
    if owner != std::process::id() || count > MAX_CLOSE_COUNT {
        return;
    }
    for number in 3..3_u32.saturating_add(count) {
        let _closed = nix::unistd::close(number.cast_signed());
    }
}

fn descriptor_is_open(number: u32) -> bool {
    // SAFETY: fcntl(F_GETFD) only inspects the supplied integer and does not
    // borrow memory. The caller bounds systemd's descriptor count first.
    unsafe { nix::libc::fcntl(number.cast_signed(), nix::libc::F_GETFD) >= 0 }
}

fn scrub_environment() {
    // SAFETY: bootstrap runs before construction of the async runtime or any
    // worker thread, so no concurrent environment reader or writer exists.
    unsafe {
        for key in ENVIRONMENT_KEYS {
            std::env::remove_var(key);
        }
    }
}

const fn contract_error(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::InvalidServiceContract, message)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{
        AddressFamily, SockFlag, SockType, SockaddrIn, bind, getsockname, setsockopt, socket,
        sockopt,
    };

    use super::{DescriptorKind, configure_descriptor};

    #[test]
    fn adoption_clears_udp_address_reuse_before_a_second_bind()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = reusable_udp_socket()?;
        bind(
            first.as_raw_fd(),
            &SockaddrIn::from(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
        )?;
        let address = getsockname::<SockaddrIn>(first.as_raw_fd())?;
        configure_descriptor(&first, DescriptorKind::Datagram)?;

        let second = reusable_udp_socket()?;
        let error = match bind(second.as_raw_fd(), &address) {
            Ok(()) => {
                return Err(std::io::Error::other(
                    "exclusive adoption accepted a second reuse-address bind",
                )
                .into());
            }
            Err(error) => error,
        };
        assert_eq!(error, nix::errno::Errno::EADDRINUSE);
        Ok(())
    }

    #[test]
    fn adoption_retains_tcp_address_reuse_for_restart() -> Result<(), Box<dyn std::error::Error>> {
        let descriptor = socket(
            AddressFamily::Inet,
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;
        setsockopt(&descriptor, sockopt::ReuseAddr, &true)?;

        configure_descriptor(&descriptor, DescriptorKind::Stream)?;

        assert!(nix::sys::socket::getsockopt(
            &descriptor,
            sockopt::ReuseAddr
        )?);
        Ok(())
    }

    fn reusable_udp_socket() -> nix::Result<std::os::fd::OwnedFd> {
        let descriptor = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC,
            None,
        )?;
        setsockopt(&descriptor, sockopt::ReuseAddr, &true)?;
        Ok(descriptor)
    }
}
