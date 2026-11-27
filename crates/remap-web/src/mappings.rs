// SPDX-License-Identifier: GPL-3.0-or-later
//! The full mapping list, read page by page at one revision.

use std::future::Future;

use remap_protocol::{
    Command, CommandResult, ControlClient, Diagnostic, ListResult, MAX_MAPPING_COUNT,
    MAX_MAPPING_PAGE_SIZE,
};

use crate::status;

/// How many times a list that moved under the reader is read again.
pub(crate) const MAX_LIST_ATTEMPTS: usize = 4;

/// Pages needed for the registry's mapping ceiling, plus the empty last one.
const MAX_PAGES: usize = MAX_MAPPING_COUNT.div_ceil(MAX_MAPPING_PAGE_SIZE as usize) + 1;

/// Reads every mapping, including disabled ones, at a single revision.
///
/// The registry may change between pages. When a page reports a revision
/// other than the first page's, the whole read restarts, a bounded number of
/// times, so the result never mixes two revisions.
pub(crate) async fn read_all(client: &ControlClient) -> Result<ListResult, Diagnostic> {
    read_all_with(|after| page(client, after)).await
}

/// [`read_all`] over any page source, so the restart rule is testable.
async fn read_all_with<F, Fut>(mut fetch: F) -> Result<ListResult, Diagnostic>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<ListResult, Diagnostic>>,
{
    for _attempt in 0..MAX_LIST_ATTEMPTS {
        if let Some(list) = read_once(&mut fetch).await? {
            return Ok(list);
        }
    }
    Err(Diagnostic::new(
        "web-mappings-unstable",
        format!("the registry changed during each of {MAX_LIST_ATTEMPTS} attempts to read it"),
        Some("retry; the list is read again once changes settle".to_owned()),
        true,
    ))
}

/// One pass over every page; `None` when the revision moved mid-read.
async fn read_once<F, Fut>(fetch: &mut F) -> Result<Option<ListResult>, Diagnostic>
where
    F: FnMut(Option<String>) -> Fut,
    Fut: Future<Output = Result<ListResult, Diagnostic>>,
{
    let mut after = None;
    let mut revision = None;
    let mut mappings = Vec::new();
    for _page in 0..MAX_PAGES {
        let page = fetch(after.take()).await?;
        if *revision.get_or_insert(page.revision) != page.revision {
            return Ok(None);
        }
        mappings.extend(page.mappings);
        if mappings.len() > MAX_MAPPING_COUNT {
            break;
        }
        let Some(cursor) = page.next_cursor else {
            return Ok(Some(ListResult {
                revision: page.revision,
                mappings,
                next_cursor: None,
            }));
        };
        after = Some(cursor);
    }
    Err(Diagnostic::protocol(format!(
        "the daemon listed more than {MAX_MAPPING_COUNT} mappings"
    )))
}

async fn page(client: &ControlClient, after: Option<String>) -> Result<ListResult, Diagnostic> {
    let command = Command::List {
        after,
        limit: MAX_MAPPING_PAGE_SIZE,
        include_disabled: true,
    };
    match client.execute(command).await? {
        CommandResult::List(page) => Ok(page),
        _ => Err(status::unexpected_result()),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::future::ready;

    use remap_protocol::{Diagnostic, HostPolicy, ListResult, MappingView};

    use super::{MAX_LIST_ATTEMPTS, read_all_with};

    fn mapping(pattern: &str) -> MappingView {
        MappingView {
            landing: None,
            pattern: pattern.to_owned(),
            target: "127.0.0.1".to_owned(),
            target_kind: "ip".to_owned(),
            host_policy: HostPolicy::PreserveClient,
            enabled: true,
            updated_revision: 1,
            peer_address: None,
        }
    }

    fn page(revision: u64, pattern: &str, next: Option<&str>) -> ListResult {
        ListResult {
            revision,
            mappings: vec![mapping(pattern)],
            next_cursor: next.map(str::to_owned),
        }
    }

    /// Answers scripted pages in order and records each cursor asked for.
    struct Script {
        pages: RefCell<VecDeque<ListResult>>,
        cursors: RefCell<Vec<Option<String>>>,
    }

    impl Script {
        fn new(pages: Vec<ListResult>) -> Self {
            Self {
                pages: RefCell::new(pages.into()),
                cursors: RefCell::new(Vec::new()),
            }
        }

        fn fetch(
            &self,
            after: Option<String>,
        ) -> std::future::Ready<Result<ListResult, Diagnostic>> {
            self.cursors.borrow_mut().push(after);
            ready(
                self.pages
                    .borrow_mut()
                    .pop_front()
                    .ok_or_else(|| Diagnostic::protocol("script exhausted")),
            )
        }
    }

    #[tokio::test]
    async fn joins_every_page_in_order() -> Result<(), Diagnostic> {
        let script = Script::new(vec![
            page(3, "a.test", Some("a.test")),
            page(3, "b.test", Some("b.test")),
            page(3, "c.test", None),
        ]);
        let list = read_all_with(|after| script.fetch(after)).await?;
        assert_eq!(list.revision, 3);
        assert_eq!(list.next_cursor, None);
        let patterns = list
            .mappings
            .iter()
            .map(|m| m.pattern.as_str())
            .collect::<Vec<_>>();
        assert_eq!(patterns, ["a.test", "b.test", "c.test"]);
        assert_eq!(
            *script.cursors.borrow(),
            [None, Some("a.test".to_owned()), Some("b.test".to_owned())]
        );
        Ok(())
    }

    #[tokio::test]
    async fn restarts_from_the_first_page_when_the_revision_moves() -> Result<(), Diagnostic> {
        let script = Script::new(vec![
            page(3, "a.test", Some("a.test")),
            page(4, "b.test", None),
            page(4, "a.test", Some("a.test")),
            page(4, "b.test", None),
        ]);
        let list = read_all_with(|after| script.fetch(after)).await?;
        assert_eq!(list.revision, 4);
        assert_eq!(list.mappings.len(), 2);
        assert_eq!(script.cursors.borrow()[2], None);
        Ok(())
    }

    #[tokio::test]
    async fn gives_up_after_a_bounded_number_of_restarts() {
        let mut pages = Vec::new();
        for attempt in 0..MAX_LIST_ATTEMPTS as u64 {
            pages.push(page(attempt * 2, "a.test", Some("a.test")));
            pages.push(page(attempt * 2 + 1, "b.test", None));
        }
        let script = Script::new(pages);
        let refusal = read_all_with(|after| script.fetch(after)).await.err();
        assert_eq!(
            refusal.as_ref().map(|diagnostic| diagnostic.code.as_str()),
            Some("web-mappings-unstable")
        );
        assert!(refusal.is_some_and(|diagnostic| diagnostic.retryable));
        assert!(script.pages.borrow().is_empty());
    }

    #[tokio::test]
    async fn passes_a_daemon_failure_through() {
        let script = Script::new(Vec::new());
        let refusal = read_all_with(|after| script.fetch(after)).await.err();
        assert_eq!(
            refusal.map(|diagnostic| diagnostic.code),
            Some("E_CONTROL_PROTOCOL".to_owned())
        );
    }
}
