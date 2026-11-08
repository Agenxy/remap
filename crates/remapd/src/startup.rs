// SPDX-License-Identifier: GPL-3.0-or-later
//! What `remapd` says as it starts.

use crate::DaemonConfig;

impl DaemonConfig {
    /// The line printed as the daemon starts, true of whoever started it.
    ///
    /// Control-C stops only a daemon in a terminal. Under launchd or systemd
    /// the line reaches a log, if anywhere, and the service manager stops it.
    #[must_use]
    pub const fn startup_notice(&self, interactive: bool) -> &'static str {
        if self.launchd_sockets {
            "Remap daemon starting under launchd."
        } else if self.systemd_sockets {
            "Remap daemon starting under systemd."
        } else if interactive {
            "Remap daemon starting; press Control-C to stop."
        } else {
            "Remap daemon starting."
        }
    }
}

#[cfg(test)]
mod tests {
    use remap_protocol::ControlPaths;

    use crate::DaemonConfig;

    fn config() -> DaemonConfig {
        DaemonConfig::new(ControlPaths::under("/private/remap-startup-test"))
    }

    #[test]
    fn only_a_daemon_in_a_terminal_is_told_about_control_c() {
        assert!(config().startup_notice(true).contains("Control-C"));
        assert!(!config().startup_notice(false).contains("Control-C"));
    }

    #[test]
    fn a_managed_daemon_names_its_service_manager() {
        let mut launchd = config();
        launchd.launchd_sockets = true;
        let mut systemd = config();
        systemd.systemd_sockets = true;
        for interactive in [true, false] {
            assert_eq!(
                launchd.startup_notice(interactive),
                "Remap daemon starting under launchd."
            );
            assert_eq!(
                systemd.startup_notice(interactive),
                "Remap daemon starting under systemd."
            );
        }
    }
}
