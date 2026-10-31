// SPDX-License-Identifier: GPL-3.0-or-later
//! The one native resolver transaction the supervisor owns: systemd-resolved
//! (directly or through systemd-networkd) or `NetworkManager`.

use std::io;

use remap_linux::{
    ActivationRecord, LinkIndex, LinkState, NetworkManagerStartupObservation,
    NetworkManagerTransaction, RecordMetadata, ResolverStartupObservation, ResolverTransaction,
    RootRecordStore, SystemdResolved,
};

use crate::resolver_worker::platform_error;
use crate::supervisor::SupervisorConfig;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum NativeStartupObservation {
    Systemd(ResolverStartupObservation),
    NetworkManager(NetworkManagerStartupObservation),
}

impl NativeStartupObservation {
    /// The resolved view of the link, whichever manager owns it.
    pub(crate) const fn resolved_state(&self) -> &LinkState {
        match self {
            Self::Systemd(observed) => observed.state(),
            Self::NetworkManager(observed) => observed.resolved(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum NativeResolverTransaction {
    Systemd {
        transaction: ResolverTransaction<SystemdResolved, RootRecordStore>,
        migrate_legacy_manager: bool,
    },
    NetworkManager(NetworkManagerTransaction<RootRecordStore>),
}

impl NativeResolverTransaction {
    pub(crate) fn connect(config: &SupervisorConfig) -> io::Result<Self> {
        let lock_directory = crate::authority::resolver_lock_directory()?;
        let store =
            RootRecordStore::open_with_lock_directory(&config.record_directory, &lock_directory)
                .map_err(platform_error)?;
        Self::connect_with_store(config, store)
    }

    pub(crate) fn connect_with_store(
        config: &SupervisorConfig,
        store: RootRecordStore,
    ) -> io::Result<Self> {
        if let (Some(manager), Some(interface_name)) =
            (config.manager, config.interface_name.as_deref())
            && !SystemdResolved::expected_manager_ready(config.link, interface_name, manager)
                .map_err(platform_error)?
        {
            return Err(platform_error(remap_linux::LinuxError::new(
                remap_linux::LinuxErrorKind::ResolverUnavailable,
                "the selected native resolver manager is temporarily unavailable",
            )));
        }
        let inspection = SystemdResolved::inspect(config.link).map_err(platform_error)?;
        if config
            .manager
            .is_some_and(|expected| expected != inspection.manager())
            || config
                .interface_name
                .as_deref()
                .is_some_and(|expected| expected != inspection.interface_name())
        {
            return Err(conflict(
                "the selected resolver link changed its approved native identity",
            ));
        }
        match SystemdResolved::connect(config.link) {
            Ok(backend)
                if config
                    .manager
                    .is_none_or(|expected| expected == backend.manager())
                    && config
                        .interface_name
                        .as_deref()
                        .is_none_or(|expected| expected == backend.interface_name()) =>
            {
                Ok(Self::Systemd {
                    transaction: ResolverTransaction::new(backend, store),
                    migrate_legacy_manager: config.manager.is_some()
                        && config.interface_name.is_some(),
                })
            }
            Ok(_backend) => Err(conflict(
                "the selected resolver link changed its approved native manager",
            )),
            Err(error)
                if error.kind() == remap_linux::LinuxErrorKind::UnsupportedResolverManager =>
            {
                if config.manager.is_some_and(|manager| {
                    manager != remap_linux::ResolverLinkManager::NetworkManager
                }) {
                    return Err(conflict(
                        "the selected resolver link changed its approved native manager",
                    ));
                }
                let transaction = match config.interface_name.as_deref() {
                    Some(expected) => {
                        NetworkManagerTransaction::connect_expected(config.link, expected, store)
                    }
                    None => NetworkManagerTransaction::connect(config.link, store),
                }
                .map_err(platform_error)?;
                Ok(Self::NetworkManager(transaction))
            }
            Err(error) => Err(platform_error(error)),
        }
    }

    pub(crate) fn activate_observed(
        &mut self,
        metadata: RecordMetadata,
        owned: LinkState,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<ActivationRecord> {
        match (self, observed) {
            (Self::Systemd { transaction, .. }, NativeStartupObservation::Systemd(observed)) => {
                transaction.activate_observed(metadata, owned, observed)
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.activate_observed(metadata, owned, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    pub(crate) fn recover(&mut self) -> remap_linux::LinuxResult<Option<ActivationRecord>> {
        match self {
            Self::Systemd { transaction, .. } => transaction.recover(),
            Self::NetworkManager(transaction) => transaction.recover(),
        }
    }

    pub(crate) fn abort_activation(&mut self) -> remap_linux::LinuxResult<()> {
        match self {
            Self::Systemd { transaction, .. } => transaction.abort_activation(),
            Self::NetworkManager(transaction) => transaction.abort_activation(),
        }
    }

    pub(crate) fn deactivate_observed(
        &mut self,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<()> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.deactivate_observed(observed)
                } else {
                    transaction.deactivate_observed_preserving_legacy_manager(observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.deactivate_observed(observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    pub(crate) fn rebase_observed(
        &mut self,
        generation: u64,
        created: u64,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<ActivationRecord> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.rebase_observed(generation, created, observed)
                } else {
                    transaction
                        .rebase_observed_preserving_legacy_manager(generation, created, observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.rebase_observed(generation, created, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    pub(crate) fn startup_observation(
        &mut self,
        link: LinkIndex,
    ) -> remap_linux::LinuxResult<Option<NativeStartupObservation>> {
        match self {
            Self::Systemd { transaction, .. } => transaction
                .startup_observation(link)
                .map(|state| state.map(NativeStartupObservation::Systemd)),
            Self::NetworkManager(transaction) => transaction
                .startup_observation()
                .map(|state| state.map(NativeStartupObservation::NetworkManager)),
        }
    }

    pub(crate) fn observation_requires_rebase(
        &mut self,
        record: &ActivationRecord,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<bool> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.observation_requires_rebase(record, observed)
                } else {
                    transaction
                        .observation_requires_rebase_preserving_legacy_manager(record, observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.observation_requires_rebase(record, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(remap_linux::LinuxError::new(
                    remap_linux::LinuxErrorKind::OwnershipConflict,
                    "the native resolver manager changed after stabilization",
                ))
            }
        }
    }

    pub(crate) fn load(&mut self) -> remap_linux::LinuxResult<Option<ActivationRecord>> {
        match self {
            Self::Systemd { transaction, .. } => transaction.load_record(),
            Self::NetworkManager(transaction) => transaction.load(),
        }
    }

    pub(crate) fn into_store(self) -> RootRecordStore {
        match self {
            Self::Systemd { transaction, .. } => transaction.into_parts().1,
            Self::NetworkManager(transaction) => transaction.into_store(),
        }
    }

    pub(crate) fn bypass_observed(
        &mut self,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<ActivationRecord> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.bypass_observed(observed)
                } else {
                    transaction.bypass_observed_preserving_legacy_manager(observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.bypass_observed(observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(manager_changed())
            }
        }
    }

    pub(crate) fn rearm_observed(
        &mut self,
        generation: u64,
        created: u64,
        observed: &NativeStartupObservation,
    ) -> remap_linux::LinuxResult<ActivationRecord> {
        match (self, observed) {
            (
                Self::Systemd {
                    transaction,
                    migrate_legacy_manager,
                },
                NativeStartupObservation::Systemd(observed),
            ) => {
                if *migrate_legacy_manager {
                    transaction.rearm_observed(generation, created, observed)
                } else {
                    transaction
                        .rearm_observed_preserving_legacy_manager(generation, created, observed)
                }
            }
            (
                Self::NetworkManager(transaction),
                NativeStartupObservation::NetworkManager(observed),
            ) => transaction.rearm_observed(generation, created, observed),
            (Self::Systemd { .. }, NativeStartupObservation::NetworkManager(_))
            | (Self::NetworkManager(_), NativeStartupObservation::Systemd(_)) => {
                Err(manager_changed())
            }
        }
    }

    pub(crate) fn release_bypassed(&mut self) -> remap_linux::LinuxResult<()> {
        match self {
            Self::Systemd { transaction, .. } => transaction.release_bypassed(),
            Self::NetworkManager(transaction) => transaction.release_bypassed(),
        }
    }
}

const fn manager_changed() -> remap_linux::LinuxError {
    remap_linux::LinuxError::new(
        remap_linux::LinuxErrorKind::OwnershipConflict,
        "the native resolver manager changed after stabilization",
    )
}

fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}
