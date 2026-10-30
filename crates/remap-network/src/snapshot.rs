// SPDX-License-Identifier: GPL-3.0-or-later
use std::sync::Arc;

use arc_swap::ArcSwap;
use remap_core::RegistrySnapshot;
use tokio::sync::watch;

/// Lock-free publication point for complete immutable registry revisions.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    current: Arc<ArcSwap<RegistrySnapshot>>,
    published: Arc<watch::Sender<u64>>,
}

impl SnapshotStore {
    /// Creates a store containing revision zero and no mappings.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(RegistrySnapshot::empty())),
            published: Arc::new(watch::Sender::new(0)),
        }
    }

    /// Returns one stable revision for the lifetime of the returned `Arc`.
    #[must_use]
    pub fn load(&self) -> Arc<RegistrySnapshot> {
        self.current.load_full()
    }

    /// Atomically publishes a complete snapshot if it is not older than current.
    ///
    /// Returns `false` without changing state when a stale snapshot arrives.
    #[must_use]
    pub fn publish(&self, snapshot: RegistrySnapshot) -> bool {
        if snapshot.revision() < self.current.load().revision() {
            return false;
        }
        let revision = snapshot.revision();
        self.current.store(Arc::new(snapshot));
        self.published.send_replace(revision);
        true
    }

    /// Watches the revision of each published snapshot, for a reader that
    /// must act when the mappings change rather than when it is asked.
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.published.subscribe()
    }
}

impl Default for SnapshotStore {
    fn default() -> Self {
        Self::empty()
    }
}

#[cfg(test)]
mod tests {
    use remap_core::RegistrySnapshot;

    use super::SnapshotStore;

    #[test]
    fn rejects_stale_publication_without_disturbing_readers() {
        let store = SnapshotStore::empty();
        let first = RegistrySnapshot::new(7, Vec::new());
        assert!(first.is_ok());
        if let Ok(snapshot) = first {
            assert!(store.publish(snapshot));
        }
        let stale = RegistrySnapshot::new(6, Vec::new());
        assert!(stale.is_ok());
        if let Ok(snapshot) = stale {
            assert!(!store.publish(snapshot));
        }
        assert_eq!(store.load().revision(), 7);
    }
}
