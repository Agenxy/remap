// SPDX-License-Identifier: GPL-3.0-or-later
//! Authenticated local-control server and single-writer daemon runtime.

mod engine;
mod launchd;
mod network_bootstrap;
mod peer;
mod privilege;
mod reachability;
mod server;
mod startup;
mod system_control;
mod systemd;

pub use engine::Engine;
pub use server::{DaemonBootstrap, DaemonConfig, RunAsUser, bootstrap, run, serve_until};
