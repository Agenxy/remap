// SPDX-License-Identifier: GPL-3.0-or-later
//! Peer targets whose peer or service is read from the name a client asked
//! for (ADR-0032). The owner writes the template; the name only fills it.

use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{NamePattern, PeerServiceError, RemapName};

/// The most name labels a template may read: one for each peer-target field.
pub const MAX_TEMPLATE_CAPTURES: usize = 2;

/// Returns the capture a whole field names, `{1}` or `{2}`, or `None` for a
/// literal field.
///
/// # Errors
///
/// Refuses a field that starts with `{` but is not exactly a placeholder
/// within [`MAX_TEMPLATE_CAPTURES`], so a brace is never read as a literal.
pub(crate) fn placeholder(field: &str) -> Result<Option<usize>, PeerServiceError> {
    if !field.starts_with('{') {
        return Ok(None);
    }
    field
        .strip_prefix('{')
        .and_then(|rest| rest.strip_suffix('}'))
        .and_then(|digits| digits.parse::<usize>().ok())
        .filter(|index| (1..=MAX_TEMPLATE_CAPTURES).contains(index))
        .filter(|index| field == format!("{{{index}}}"))
        .map(Some)
        .ok_or_else(|| PeerServiceError::InvalidTemplate(field.to_owned()))
}

/// Returns how many labels the fields' placeholders read, `None` when every
/// field is literal.
///
/// # Errors
///
/// Refuses placeholders that skip a capture, such as `{2}` without `{1}`:
/// every label a template reads must be used.
pub(crate) fn arity(fields: [&str; 2]) -> Result<Option<usize>, PeerServiceError> {
    let mut used = [false; MAX_TEMPLATE_CAPTURES];
    for field in fields {
        if let Some(index) = placeholder(field)? {
            used[index - 1] = true;
        }
    }
    let count = used.iter().take_while(|used| **used).count();
    if used[count..].iter().any(|used| *used) {
        return Err(PeerServiceError::InvalidTemplate(format!(
            "{}/{}",
            fields[0], fields[1]
        )));
    }
    Ok((count > 0).then_some(count))
}

/// Substitutes one field, where `captures[0]` is the label nearest the suffix.
pub(crate) fn fill(field: &str, captures: &[&str]) -> String {
    match placeholder(field) {
        Ok(Some(index)) => captures
            .get(index - 1)
            .map_or_else(String::new, |label| (*label).to_owned()),
        _ => field.to_owned(),
    }
}

/// Returns the labels a wildcard pattern leaves before its suffix, nearest
/// the suffix first, or `None` when the pattern is exact or does not match.
#[must_use]
pub fn captured_labels<'a>(pattern: &NamePattern, name: &'a RemapName) -> Option<Vec<&'a str>> {
    let NamePattern::Wildcard(suffix) = pattern else {
        return None;
    };
    let prefix = name
        .as_str()
        .strip_suffix(suffix.as_str())?
        .strip_suffix('.')?;
    Some(prefix.rsplit('.').collect())
}

/// Why a name a templated mapping matched cannot fill its template.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TemplateNameError {
    /// The name has a different number of labels before the suffix than the
    /// template reads.
    LabelCount {
        /// Labels the template reads.
        expected: usize,
        /// Labels the name has before the suffix.
        found: usize,
    },
    /// A label is not valid in the field it fills.
    Field(PeerServiceError),
}

impl Display for TemplateNameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabelCount { expected, found } => write!(
                formatter,
                "this mapping's target reads {expected} label(s) before its suffix, and the name has {found}"
            ),
            Self::Field(error) => write!(
                formatter,
                "the name cannot fill this mapping's target: {error}"
            ),
        }
    }
}

impl Error for TemplateNameError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::LabelCount { .. } => None,
            Self::Field(error) => Some(error),
        }
    }
}
