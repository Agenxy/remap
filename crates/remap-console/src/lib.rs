// SPDX-License-Identifier: GPL-3.0-or-later
//! Full-screen terminal interface for Remap (ADR-0041).
//!
//! [`run`] is the entry point the `remap console` command calls. The rest of
//! the public surface is the console's pure core, public so it can be driven
//! without a terminal: [`model::Model`] holds the state,
//! [`update::update`] turns an [`update::Event`] into daemon
//! [`update::Effect`]s, [`view::view`] draws the model, and
//! [`authority::execute`] runs an effect against an [`authority::Authority`].

pub mod authority;
mod browse;
mod form;
mod input;
mod layout;
pub mod model;
mod overlay;
mod resolve;
mod terminal;
#[cfg(test)]
mod tests;
mod text;
pub mod update;
pub mod view;
mod worker;
mod write;

use std::io::IsTerminal;

use remap_protocol::{ControlClient, Diagnostic};

/// Stable code returned when the console is not attached to a terminal.
pub const NEEDS_TERMINAL: &str = "console-needs-terminal";

/// Runs the console until the owner quits. Refuses unless stdin and stdout are terminals.
///
/// # Errors
///
/// Returns `console-needs-terminal` when standard input or output is not a
/// terminal, `console-terminal-io` when the terminal cannot be driven, and
/// `console-internal-error` when the console stopped after an internal fault.
/// Daemon failures never end the console; it shows them and keeps retrying.
pub async fn run(client: ControlClient) -> Result<(), Diagnostic> {
    require_terminals(
        std::io::stdin().is_terminal(),
        std::io::stdout().is_terminal(),
    )?;
    terminal::run(client).await
}

/// Refuses unless both standard streams are terminals.
pub(crate) fn require_terminals(stdin: bool, stdout: bool) -> Result<(), Diagnostic> {
    let missing = match (stdin, stdout) {
        (true, true) => return Ok(()),
        (false, true) => "standard input",
        (true, false) => "standard output",
        (false, false) => "standard input and output",
    };
    Err(Diagnostic::new(
        NEEDS_TERMINAL,
        format!("remap console needs a terminal, and {missing} is not one"),
        Some(
            "run it in an interactive terminal; for scripts and pipes use 'remap list' and 'remap status'"
                .to_owned(),
        ),
        false,
    )
    .with_context("not_a_terminal", missing))
}
