// SPDX-License-Identifier: GPL-3.0-or-later
//! The interactive interfaces: `remap console` and `remap web` (ADR-0041).

use clap::{Arg, Command};

use super::Action;
use crate::diagnostic::Diagnostic;

const PORT: &str = "port";
const NAME: &str = "name";

pub(super) const JSON_REFUSAL: &str =
    "--json cannot be combined with 'console' or 'web' because they are interactive";

const CONSOLE_GUIDANCE: &str = concat!(
    "Keys:\n",
    "  ↑ ↓ j k      move          /   filter        a   show disabled\n",
    "  n            new mapping   e   edit          space  turn on or off\n",
    "  d            remove        r   resolve a name  g  refresh\n",
    "  ?            all keys      q   quit\n\n",
    "Every change is previewed first and applied only after you confirm it, against\n",
    "the revision you reviewed. If the registry changed elsewhere in the meantime,\n",
    "the console shows the new state and asks again.\n\n",
    "For scripts, use 'remap list' and 'remap status' instead.",
);

const WEB_GUIDANCE: &str = concat!(
    "Examples:\n",
    "  remap web\n",
    "  remap web --port 7341\n",
    "  remap set remap.lab http://127.0.0.1:7341/ --host-header use-upstream\n",
    "  remap web --port 7341 --name remap.lab\n\n",
    "The interface listens on 127.0.0.1 only, for as long as this command runs.\n",
    "It prints one address that carries a secret token after '#'. Anyone who has\n",
    "that address can change your mappings until you stop the command, so do not\n",
    "share it. Each run makes a new token.\n\n",
    "--port keeps the same port across runs, so you can give the interface a name\n",
    "with Remap. Pass that name with --name so the interface accepts requests for\n",
    "it; it refuses any other name, which stops DNS rebinding.",
);

/// Options for `remap web`, passed through to the `remap-web` crate.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct WebAction {
    /// The loopback port, or 0 for one the system chooses.
    pub(crate) port: u16,
    /// One more name the interface answers to, besides 127.0.0.1 and localhost.
    pub(crate) name: Option<String>,
}

pub(super) fn console_command() -> Command {
    Command::new("console")
        .about("Opens a full-screen terminal interface for your mappings")
        .long_about(
            "Shows status and every mapping, follows changes as they happen, and lets\n\
             you add, edit, turn on or off, remove, and resolve names from the keyboard.\n\
             Needs an interactive terminal.",
        )
        .after_help(CONSOLE_GUIDANCE)
}

pub(super) fn web_command() -> Command {
    Command::new("web")
        .about("Serves a browser interface on this computer until you stop it")
        .long_about(
            "Serves the same views and changes as 'remap console' in a browser, on\n\
             127.0.0.1 only. Prints the address to open; press Ctrl-C to stop.",
        )
        .arg(
            Arg::new(PORT)
                .long(PORT)
                .value_name("PORT")
                .value_parser(clap::value_parser!(u16).range(1..))
                .help("Listen on this loopback port instead of one the system chooses"),
        )
        .arg(
            Arg::new(NAME)
                .long(NAME)
                .value_name("HOSTNAME")
                .help("Also accept requests for this name, such as one you mapped to the port"),
        )
        .after_help(WEB_GUIDANCE)
}

pub(super) fn parse(name: &str, command: &clap::ArgMatches) -> Result<Action, Diagnostic> {
    match name {
        "console" => Ok(Action::Console),
        "web" => Ok(Action::Web(WebAction {
            port: command.get_one::<u16>(PORT).copied().unwrap_or(0),
            name: command.get_one::<String>(NAME).cloned(),
        })),
        _ => Err(Diagnostic::internal("unknown interface command")),
    }
}
