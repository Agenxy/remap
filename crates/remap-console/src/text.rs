// SPDX-License-Identifier: GPL-3.0-or-later
//! The console's words, shared by the view and the status line. They follow
//! the MCP panel: target kind, host policy, landing, address, advisory.

use remap_protocol::{ApplyResult, Diagnostic, MappingView, RegistryStatus};

use crate::model::{Connection, Model};

/// The daemon's code for a socket nobody answers.
const DAEMON_UNAVAILABLE: &str = "E_DAEMON_UNAVAILABLE";

pub(crate) const fn state_word(enabled: bool) -> &'static str {
    if enabled { "on" } else { "off" }
}

/// One sentence: capitalised, ending in a full stop.
pub(crate) fn sentence(text: &str) -> String {
    let text = text.trim();
    let mut characters = text.chars();
    let Some(first) = characters.next() else {
        return String::new();
    };
    let mut sentence: String = first.to_uppercase().chain(characters).collect();
    if !sentence.ends_with(['.', '!', '?']) {
        sentence.push('.');
    }
    sentence
}

/// A diagnostic as the owner reads it: what failed, then what to do.
pub(crate) fn diagnostic(diagnostic: &Diagnostic) -> String {
    let message = sentence(&diagnostic.message);
    match &diagnostic.hint {
        Some(hint) => format!("{message} {}", sentence(hint)),
        None => message,
    }
}

/// A mapping on one line, as the confirm dialog shows before and after.
pub(crate) fn mapping_summary(mapping: &MappingView) -> String {
    let mut summary = format!(
        "{} ({}, {}, {}",
        mapping.target,
        mapping.target_kind,
        mapping.host_policy.as_str(),
        state_word(mapping.enabled)
    );
    if let Some(landing) = &mapping.landing {
        summary.push_str(", landing ");
        summary.push_str(landing);
    }
    if let Some(address) = &mapping.peer_address {
        summary.push_str(", address ");
        summary.push_str(address);
    }
    summary.push(')');
    summary
}

/// The status line after a committed write.
pub(crate) fn receipt(title: &str, receipt: &ApplyResult) -> String {
    let mut line = if receipt.changed {
        format!(
            "Applied {title}: changed, now revision {} (was {}).",
            receipt.revision, receipt.previous_revision
        )
    } else {
        format!(
            "Applied {title}: unchanged, still revision {}.",
            receipt.revision
        )
    };
    for warning in &receipt.warnings {
        line.push_str(" Advisory: ");
        line.push_str(warning);
    }
    line
}

fn count(value: u64, one: &str, many: &str) -> String {
    format!("{value} {}", if value == 1 { one } else { many })
}

/// The header, as long as `width` allows.
pub(crate) fn header(status: Option<&RegistryStatus>, width: u16) -> String {
    let Some(status) = status else {
        return fit(
            &["Remap console  waiting for the daemon", "Remap  waiting"],
            width,
        );
    };
    let revision = format!("revision {}", status.revision);
    let counts = format!(
        "{}, {} on",
        count(status.mapping_count, "mapping", "mappings"),
        status.enabled_count
    );
    let daemon = format!("daemon {}", status.daemon_version);
    fit(
        &[
            format!("Remap console  {revision}  {counts}  {daemon}").as_str(),
            format!("Remap  {revision}  {counts}  {daemon}").as_str(),
            format!("{revision}  {counts}").as_str(),
            format!("rev {}  {counts}", status.revision).as_str(),
        ],
        width,
    )
}

/// The first candidate that fits, else the last one cut to fit.
fn fit(candidates: &[&str], width: u16) -> String {
    let width = usize::from(width);
    candidates
        .iter()
        .find(|candidate| candidate.chars().count() <= width)
        .map_or_else(
            || truncate(candidates.last().copied().unwrap_or_default(), width),
            |candidate| (*candidate).to_owned(),
        )
}

/// Cuts text to `width` characters, marking the cut.
pub(crate) fn truncate(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    if width == 0 {
        return String::new();
    }
    let mut cut: String = text.chars().take(width - 1).collect();
    cut.push('…');
    cut
}

/// Every problem the daemon reports, in words, one entry each.
pub(crate) fn problems(model: &Model) -> Vec<String> {
    let mut problems = Vec::new();
    if let Connection::Unreachable(failure) = &model.connection {
        let label = match failure.code.as_str() {
            DAEMON_UNAVAILABLE => "Daemon unreachable",
            crate::authority::REGISTRY_BUSY => "Registry busy",
            _ => "Daemon not answering",
        };
        problems.push(format!(
            "{label}: {} Retrying in the background.",
            diagnostic(failure)
        ));
    }
    if let Some(status) = &model.status {
        status_problems(status, &mut problems);
    }
    problems
}

fn status_problems(status: &RegistryStatus, problems: &mut Vec<String>) {
    if let Some(maintenance) = &status.maintenance {
        problems.push(format!(
            "Maintenance: {} New changes are blocked.{}",
            sentence(&maintenance.message),
            maintenance
                .hint
                .as_deref()
                .map_or_else(String::new, |hint| format!(" {}", sentence(hint)))
        ));
    }
    if let Some(upstream) = &status.dns_upstream {
        problems.push(format!(
            "Upstream DNS not answering: {}",
            diagnostic(upstream)
        ));
    }
    if let Some(off) = &status.dns_turned_off {
        problems.push(format!(
            "DNS turned off by the owner at {} (`{}`). Turn it on with `{}`.",
            off.turned_off_at, off.command, off.turn_on
        ));
    }
    if let Some(listeners) = &status.peer_machine_listeners
        && listeners.not_listening > 0
    {
        let mut line = format!(
            "Peer listeners: {} not listening, {} listening.",
            listeners.not_listening, listeners.listening
        );
        for failure in listeners.failures.iter().take(2) {
            let failure = format!(
                " {} {} on {}:{}: {}.",
                failure.pattern,
                failure.service,
                failure.address,
                failure.port,
                failure.detail.trim_end_matches('.')
            );
            line.push_str(&failure);
        }
        let shown = u64::try_from(listeners.failures.len().min(2)).unwrap_or(u64::MAX);
        if listeners.not_listening > shown {
            let more = format!(" {} more.", listeners.not_listening - shown);
            line.push_str(&more);
        }
        problems.push(line);
    }
}

/// Word-wraps text to `width` columns. Text that fits is kept exactly;
/// longer text keeps its indent, and words longer than a line are split.
pub(crate) fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    if text.chars().count() <= width {
        return vec![text.to_owned()];
    }
    let indent: String = text.chars().take_while(|c| *c == ' ').collect();
    let indent = if indent.len() * 2 < width {
        indent
    } else {
        String::new()
    };
    let room = width - indent.len();
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in text.split_whitespace() {
        let mut word: Vec<char> = word.chars().collect();
        let used = line.chars().count();
        if used > 0 && used + 1 + word.len() > room {
            lines.push(std::mem::take(&mut line));
        }
        while word.len() > room {
            if !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            lines.push(word.drain(..room).collect());
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.extend(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
        .into_iter()
        .map(|line| format!("{indent}{line}"))
        .collect()
}
