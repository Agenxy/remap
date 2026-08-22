use remap_linux::{
    ResolverBackendKind, ResolverEnvironment, ResolverLinkManager, ResolverLinkSelectionState,
    ResolverSupport,
};

use crate::install_model::{InstallPhase, RollbackStep, UninstallStep};

pub(crate) fn selection_state(state: ResolverLinkSelectionState) -> String {
    match state {
        ResolverLinkSelectionState::SupportedPrimary => "supported_primary",
        ResolverLinkSelectionState::SupportedSecondary => "supported_secondary",
        ResolverLinkSelectionState::Inactive => "inactive",
        ResolverLinkSelectionState::Unsupported => "unsupported",
    }
    .to_owned()
}

pub(crate) const fn environment(environment: ResolverEnvironment) -> &'static str {
    match (environment.backend(), environment.support()) {
        (ResolverBackendKind::SystemdResolved, ResolverSupport::Supported) => {
            "systemd_resolved_supported"
        }
        (ResolverBackendKind::NetworkManager, _) => "network_manager_without_resolved",
        (ResolverBackendKind::ResolvConf, _) => "resolv_conf_unknown_owner",
        (ResolverBackendKind::SystemdResolved, _) => "systemd_resolved_unavailable",
        (ResolverBackendKind::Unknown, _) => "resolver_manager_unknown",
    }
}

pub(crate) fn manager(manager: ResolverLinkManager) -> String {
    match manager {
        ResolverLinkManager::SystemdResolved => "systemd_resolved",
        ResolverLinkManager::SystemdNetworkd => "systemd_networkd",
        ResolverLinkManager::NetworkManager => "network_manager",
    }
    .to_owned()
}

pub(crate) const fn phase(phase: InstallPhase) -> &'static str {
    match phase {
        InstallPhase::Staging => "staging",
        InstallPhase::Staged => "staged",
        InstallPhase::Published => "published",
        InstallPhase::RollingBack(_) => "rolling_back",
        InstallPhase::Pruning => "pruning",
        InstallPhase::Active => "active",
        InstallPhase::Uninstalling(_) => "uninstalling",
    }
}

pub(crate) const fn uninstall_step(step: UninstallStep) -> &'static str {
    match step {
        UninstallStep::RestoreResolver => "restore_resolver",
        UninstallStep::StopServices => "stop_services",
        UninstallStep::RemoveUnitLinks => "remove_unit_links",
        UninstallStep::RemovePublicPaths => "remove_public_paths",
        UninstallStep::RemoveCurrent => "remove_current",
        UninstallStep::ReloadManager => "reload_manager",
        UninstallStep::RemoveCurrentGeneration => "remove_current_generation",
        UninstallStep::RemovePreviousGeneration => "remove_previous_generation",
        UninstallStep::RemoveGenerationRoots => "remove_generation_roots",
        UninstallStep::Finalize => "finalize",
    }
}

pub(crate) const fn rollback_step(step: RollbackStep) -> &'static str {
    match step {
        RollbackStep::StopServices => "stop_services",
        RollbackStep::RestoreResolver => "restore_resolver",
        RollbackStep::RestoreCurrent => "restore_current",
        RollbackStep::RemoveUnitLinks => "remove_unit_links",
        RollbackStep::RemovePublicPaths => "remove_public_paths",
        RollbackStep::ReloadManager => "reload_manager",
        RollbackStep::StartPrevious => "start_previous",
        RollbackStep::RemoveFailedGeneration => "remove_failed_generation",
        RollbackStep::RemoveGenerationRoots => "remove_generation_roots",
        RollbackStep::Finalize => "finalize",
    }
}
