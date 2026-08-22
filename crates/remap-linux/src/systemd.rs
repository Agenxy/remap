use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::{LinkIndex, LinuxError, LinuxErrorKind, LinuxResult};

const FIRST_ACTIVATED_DESCRIPTOR: u32 = 3;
const MAX_ENVIRONMENT_BYTES: usize = 512;

/// Transport type expected for one activated descriptor.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum DescriptorKind {
    /// Connectionless DNS listener.
    Datagram,
    /// Connection-oriented DNS or HTTP listener.
    Stream,
}

/// One named, loopback-only descriptor supplied by systemd.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DescriptorSpec {
    name: &'static str,
    kind: DescriptorKind,
    address: &'static str,
}

impl DescriptorSpec {
    /// Returns the stable `LISTEN_FDNAMES` identity.
    #[must_use]
    pub const fn name(self) -> &'static str {
        self.name
    }

    /// Returns the required socket kind.
    #[must_use]
    pub const fn kind(self) -> DescriptorKind {
        self.kind
    }

    /// Returns the loopback-only socket address.
    #[must_use]
    pub const fn address(self) -> &'static str {
        self.address
    }
}

/// Exact host-wide socket-activation contract for the first Linux slice.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SocketContract {
    descriptors: [DescriptorSpec; 3],
}

impl SocketContract {
    /// Builds the fixed DNS and cleartext HTTP descriptor contract.
    #[must_use]
    pub const fn remap() -> Self {
        Self {
            descriptors: [
                DescriptorSpec {
                    name: "dns-udp",
                    kind: DescriptorKind::Datagram,
                    address: "127.0.0.1:53",
                },
                DescriptorSpec {
                    name: "dns-tcp",
                    kind: DescriptorKind::Stream,
                    address: "127.0.0.1:53",
                },
                DescriptorSpec {
                    name: "http",
                    kind: DescriptorKind::Stream,
                    address: "127.0.0.1:80",
                },
            ],
        }
    }

    /// Returns every descriptor in the declared unit order.
    #[must_use]
    pub const fn descriptors(&self) -> &[DescriptorSpec; 3] {
        &self.descriptors
    }
}

impl Default for SocketContract {
    fn default() -> Self {
        Self::remap()
    }
}

/// Validated systemd socket-activation environment without taking FD ownership.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ActivationEnvironment {
    descriptors: BTreeMap<&'static str, u32>,
}

impl ActivationEnvironment {
    /// Validates `LISTEN_PID`, `LISTEN_FDS`, and `LISTEN_FDNAMES` as one set.
    ///
    /// Callers must remove all three variables immediately after this check,
    /// then adopt and independently validate each socket's type and address.
    ///
    /// # Errors
    ///
    /// Returns an invalid-contract error for the wrong process, count, or names.
    pub fn parse(
        current_pid: u32,
        listen_pid: &str,
        listen_fds: &str,
        listen_fdnames: &str,
        contract: &SocketContract,
    ) -> LinuxResult<Self> {
        if listen_pid.len() + listen_fds.len() + listen_fdnames.len() > MAX_ENVIRONMENT_BYTES {
            return Err(contract_error(
                "the socket-activation environment exceeds its bound",
            ));
        }
        let owner_pid = parse_decimal(listen_pid)?;
        let descriptor_count = parse_decimal(listen_fds)?;
        if owner_pid != current_pid || descriptor_count as usize != contract.descriptors.len() {
            return Err(contract_error(
                "systemd did not provide the exact descriptor count to this process",
            ));
        }
        let names = listen_fdnames.split(':').collect::<Vec<_>>();
        if names.len() != contract.descriptors.len() {
            return Err(contract_error(
                "systemd did not name every Remap descriptor",
            ));
        }
        let mut descriptors = BTreeMap::new();
        for (offset, supplied_name) in names.into_iter().enumerate() {
            let Some(expected) = contract
                .descriptors
                .iter()
                .find(|descriptor| descriptor.name == supplied_name)
            else {
                return Err(contract_error(
                    "systemd supplied an unknown Remap descriptor",
                ));
            };
            let descriptor_number = FIRST_ACTIVATED_DESCRIPTOR
                .checked_add(u32::try_from(offset).map_err(|_error| contract_overflow())?)
                .ok_or_else(contract_overflow)?;
            if descriptors
                .insert(expected.name, descriptor_number)
                .is_some()
            {
                return Err(contract_error(
                    "systemd supplied a duplicate Remap descriptor",
                ));
            }
        }
        Ok(Self { descriptors })
    }

    /// Returns the inherited descriptor number associated with a stable name.
    #[must_use]
    pub fn descriptor_number(&self, name: &str) -> Option<u32> {
        self.descriptors.get(name).copied()
    }
}

/// Non-root daemon identity embedded in generated systemd units.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ServiceIdentity {
    account: String,
    group: String,
    executable: PathBuf,
}

/// Root supervisor identity embedded in installable systemd units.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolverSupervisorIdentity {
    executable: PathBuf,
    link: LinkIndex,
    interface_name: String,
    manager: crate::ResolverLinkManager,
    owner_uid: u32,
    daemon_uid: u32,
    record_directory: PathBuf,
    system_socket: PathBuf,
}

/// Exact manager-bound link identity embedded in the resolver supervisor unit.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolverSupervisorLink {
    link: LinkIndex,
    interface_name: String,
    manager: crate::ResolverLinkManager,
}

impl ResolverSupervisorLink {
    /// Creates one bounded command-line-safe native link identity.
    ///
    /// # Errors
    ///
    /// Returns an invalid-contract error for an ambiguous interface name.
    pub fn new(
        link: LinkIndex,
        interface_name: impl Into<String>,
        manager: crate::ResolverLinkManager,
    ) -> LinuxResult<Self> {
        let interface_name = interface_name.into();
        if interface_name.is_empty()
            || interface_name.len() > 15
            || !interface_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        {
            return Err(contract_error(
                "the resolver supervisor link identity is unsafe or ambiguous",
            ));
        }
        Ok(Self {
            link,
            interface_name,
            manager,
        })
    }
}

impl ResolverSupervisorIdentity {
    /// Validates one explicit resolver scope and private local channel.
    ///
    /// # Errors
    ///
    /// Returns an invalid-contract error for root users or unsafe paths.
    pub fn new(
        executable: impl Into<PathBuf>,
        link: ResolverSupervisorLink,
        owner_uid: u32,
        daemon_uid: u32,
        record_directory: impl Into<PathBuf>,
        system_socket: impl Into<PathBuf>,
    ) -> LinuxResult<Self> {
        let executable = executable.into();
        let record_directory = record_directory.into();
        let system_socket = system_socket.into();
        if owner_uid == 0
            || daemon_uid == 0
            || !valid_executable(&executable)
            || !valid_executable(&record_directory)
            || !valid_executable(&system_socket)
        {
            return Err(contract_error(
                "the resolver supervisor identity is unsafe or ambiguous",
            ));
        }
        Ok(Self {
            executable,
            link: link.link,
            interface_name: link.interface_name,
            manager: link.manager,
            owner_uid,
            daemon_uid,
            record_directory,
            system_socket,
        })
    }
}

impl ServiceIdentity {
    /// Validates an unambiguous account, group, and absolute executable path.
    ///
    /// # Errors
    ///
    /// Returns an invalid-contract error for root, unsafe names, or unsafe paths.
    pub fn new(
        account: impl Into<String>,
        group: impl Into<String>,
        executable: impl Into<PathBuf>,
    ) -> LinuxResult<Self> {
        let account = account.into();
        let group = group.into();
        let executable = executable.into();
        if !valid_identity(&account) || !valid_identity(&group) || !valid_executable(&executable) {
            return Err(contract_error(
                "the systemd service identity is unsafe or ambiguous",
            ));
        }
        Ok(Self {
            account,
            group,
            executable,
        })
    }
}

/// Deterministically generated hardened service and socket unit contents.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SystemdUnitSet {
    service: String,
    resolver_service: Option<String>,
    sockets: BTreeMap<String, String>,
}

impl SystemdUnitSet {
    /// Generates units matching the descriptor adoption contract.
    ///
    /// This function does not write, enable, or start units. The daemon must
    /// implement `--systemd-sockets` before a package may install this output.
    ///
    /// # Errors
    ///
    /// Returns an invalid-contract error if generated unit identities collide.
    pub fn generate(identity: &ServiceIdentity, contract: &SocketContract) -> LinuxResult<Self> {
        let mut socket_names = Vec::with_capacity(contract.descriptors.len());
        let mut sockets = BTreeMap::new();
        for descriptor in contract.descriptors {
            let unit_name = format!("remapd-{}.socket", descriptor.name);
            let unit = render_socket(descriptor, None);
            socket_names.push(unit_name.clone());
            if sockets.insert(unit_name, unit).is_some() {
                return Err(contract_error(
                    "the systemd socket unit names are not unique",
                ));
            }
        }
        let service = render_service(identity, &socket_names, None);
        Ok(Self {
            service,
            resolver_service: None,
            sockets,
        })
    }

    /// Generates the daemon, resolver supervisor, and socket unit set.
    ///
    /// # Errors
    ///
    /// Returns an invalid-contract error if any generated identity collides.
    pub fn generate_installable(
        identity: &ServiceIdentity,
        supervisor: &ResolverSupervisorIdentity,
        contract: &SocketContract,
    ) -> LinuxResult<Self> {
        let mut units = Self::generate(identity, contract)?;
        let socket_names = units.sockets.keys().cloned().collect::<Vec<_>>();
        units.service = render_service(
            identity,
            &socket_names,
            Some(supervisor.executable.as_path()),
        );
        units.sockets.clear();
        for descriptor in contract.descriptors {
            let name = format!("remapd-{}.socket", descriptor.name);
            units.sockets.insert(
                name,
                render_socket(descriptor, Some(supervisor.executable.as_path())),
            );
        }
        units.resolver_service = Some(render_resolver_service(supervisor));
        Ok(units)
    }

    /// Returns `remapd.service` content.
    #[must_use]
    pub fn service(&self) -> &str {
        &self.service
    }

    /// Returns `remap-resolver.service` content when installable generation was requested.
    #[must_use]
    pub fn resolver_service(&self) -> Option<&str> {
        self.resolver_service.as_deref()
    }

    /// Returns socket unit content keyed by unit filename.
    #[must_use]
    pub const fn sockets(&self) -> &BTreeMap<String, String> {
        &self.sockets
    }
}

fn render_resolver_service(identity: &ResolverSupervisorIdentity) -> String {
    format!(
        "[Unit]\nDescription=Remap reversible resolver supervisor\nDocumentation=https://github.com/agenxy/remap\nRequires=remapd.service systemd-resolved.service\nWants=network-online.target\nAfter=network-online.target remapd.service systemd-resolved.service\nPartOf=remapd.service\n\n[Service]\nType=simple\nUser=root\nGroup=root\nExecCondition={} authorize-runtime\nExecStart={} serve --link {} --interface-name {} --manager {} --owner-uid {} --daemon-uid {} --record-dir {} --system-socket {}\nRestart=on-failure\nRestartSec=1s\nStateDirectory=remap-system\nStateDirectoryMode=0700\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_NET_ADMIN\nAmbientCapabilities=CAP_DAC_OVERRIDE CAP_NET_ADMIN\nPrivateDevices=yes\nPrivateTmp=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectHome=yes\nProtectHostname=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nProtectKernelTunables=yes\nProtectSystem=strict\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nRestrictAddressFamilies=AF_UNIX\nRestrictNamespaces=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\n\n[Install]\nWantedBy=multi-user.target\n",
        identity.executable.display(),
        identity.executable.display(),
        identity.link.get(),
        identity.interface_name,
        resolver_manager_name(identity.manager),
        identity.owner_uid,
        identity.daemon_uid,
        identity.record_directory.display(),
        identity.system_socket.display(),
    )
}

const fn resolver_manager_name(manager: crate::ResolverLinkManager) -> &'static str {
    match manager {
        crate::ResolverLinkManager::SystemdResolved => "systemd-resolved",
        crate::ResolverLinkManager::SystemdNetworkd => "systemd-networkd",
        crate::ResolverLinkManager::NetworkManager => "network-manager",
    }
}

fn render_service(
    identity: &ServiceIdentity,
    socket_names: &[String],
    authorizer: Option<&Path>,
) -> String {
    let sockets = socket_names.join(" ");
    let authorization = authorizer.map_or_else(String::new, |executable| {
        format!(
            "ExecCondition=+{} authorize-runtime\n",
            executable.display()
        )
    });
    format!(
        "[Unit]\nDescription=Remap local name and service router\nDocumentation=https://github.com/agenxy/remap\nRequires={sockets}\nAfter=network.target {sockets}\n\n[Service]\nType=simple\nUser={}\nGroup={}\n{authorization}ExecStart={} --systemd-sockets --data-dir /var/lib/remap --dns-listen 127.0.0.1:53 --http-listen 127.0.0.1:80\nSockets={sockets}\nRuntimeDirectory=remap\nRuntimeDirectoryMode=0700\nStateDirectory=remap\nStateDirectoryMode=0700\nUMask=0077\nNoNewPrivileges=yes\nCapabilityBoundingSet=\nAmbientCapabilities=\nPrivateDevices=yes\nPrivateTmp=yes\nProtectClock=yes\nProtectControlGroups=yes\nProtectHome=yes\nProtectHostname=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nProtectKernelTunables=yes\nProtectSystem=strict\nLockPersonality=yes\nMemoryDenyWriteExecute=yes\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6\nRestrictNamespaces=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\n\n[Install]\nWantedBy=multi-user.target\n",
        identity.account,
        identity.group,
        identity.executable.display()
    )
}

fn render_socket(descriptor: DescriptorSpec, authorizer: Option<&Path>) -> String {
    let directive = match descriptor.kind {
        DescriptorKind::Datagram => "ListenDatagram",
        DescriptorKind::Stream => "ListenStream",
    };
    let authorization = authorizer.map_or_else(String::new, |executable| {
        format!("ExecStartPre={} authorize-runtime\n", executable.display())
    });
    // Descriptor adoption establishes and verifies CLOEXEC and nonblocking flags.
    // They are process-side properties, not portable systemd.socket directives.
    format!(
        "[Unit]\nDescription=Remap {} socket\n\n[Socket]\n{authorization}{directive}={}\nFileDescriptorName={}\nService=remapd.service\nFreeBind=no\n\n[Install]\nWantedBy=sockets.target\n",
        descriptor.name, descriptor.address, descriptor.name
    )
}

fn parse_decimal(value: &str) -> LinuxResult<u32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(contract_error(
            "the socket-activation count or process ID is invalid",
        ));
    }
    value
        .parse::<u32>()
        .map_err(|_error| contract_error("the socket-activation integer is out of range"))
}

fn valid_identity(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first.is_ascii_lowercase() || first == b'_')
        && value.len() <= 32
        && bytes
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
        && value != "root"
}

fn valid_executable(path: &Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|value| !value.is_empty() && value.bytes().all(is_safe_path_byte))
}

const fn is_safe_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
}

const fn contract_error(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::InvalidServiceContract, message)
}

const fn contract_overflow() -> LinuxError {
    contract_error("the inherited descriptor number is out of range")
}
