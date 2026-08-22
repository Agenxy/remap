use crate::LinkState;

/// One fail-closed result from reconciling native resolver link candidates.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LinkLifecycleEvent {
    /// No eligible link has appeared and there is no prior selection.
    NoSelection,
    /// Exactly one initial link became eligible for explicit activation.
    Selected(LinkState),
    /// The selected link and its complete state are unchanged.
    Stable,
    /// The same selected link changed resolver state.
    Changed {
        /// State before the native lifecycle notification.
        previous: LinkState,
        /// Complete replacement state after the notification.
        current: LinkState,
    },
    /// The previously selected link disappeared.
    Removed {
        /// Last complete state retained for recovery decisions.
        previous: LinkState,
    },
    /// More than one scope exists and no mutation may be inferred.
    Ambiguous {
        /// Previously selected state retained without replacement.
        previous: Option<LinkState>,
        /// Bounded number of candidates supplied by the native observer.
        candidate_count: usize,
    },
}

/// Stateful policy layer for native link and resolver-manager notifications.
#[derive(Debug, Clone, Default)]
pub struct LinkScopeMonitor {
    selected: Option<LinkState>,
}

impl LinkScopeMonitor {
    /// Creates a monitor with no inferred link ownership.
    #[must_use]
    pub const fn new() -> Self {
        Self { selected: None }
    }

    /// Reconciles a complete bounded candidate set from a native observer.
    ///
    /// Multiple candidates never replace the retained selection. A removed
    /// selection remains in the returned event so recovery can compare rather
    /// than inventing a new scope.
    #[must_use]
    pub fn reconcile(&mut self, candidates: &[LinkState]) -> LinkLifecycleEvent {
        match candidates {
            [] => self.removed(),
            [current] => self.single(current),
            _ => LinkLifecycleEvent::Ambiguous {
                previous: self.selected.clone(),
                candidate_count: candidates.len(),
            },
        }
    }

    /// Returns the currently retained exact selection.
    #[must_use]
    pub const fn selected(&self) -> Option<&LinkState> {
        self.selected.as_ref()
    }

    fn removed(&mut self) -> LinkLifecycleEvent {
        self.selected
            .take()
            .map_or(LinkLifecycleEvent::NoSelection, |previous| {
                LinkLifecycleEvent::Removed { previous }
            })
    }

    fn single(&mut self, current: &LinkState) -> LinkLifecycleEvent {
        let Some(previous) = self.selected.as_ref() else {
            self.selected = Some(current.clone());
            return LinkLifecycleEvent::Selected(current.clone());
        };
        if previous == current {
            return LinkLifecycleEvent::Stable;
        }
        if previous.link() != current.link() {
            return LinkLifecycleEvent::Ambiguous {
                previous: Some(previous.clone()),
                candidate_count: 1,
            };
        }
        let previous = previous.clone();
        self.selected = Some(current.clone());
        LinkLifecycleEvent::Changed {
            previous,
            current: current.clone(),
        }
    }
}
