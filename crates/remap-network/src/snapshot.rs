use std::sync::Arc;

use arc_swap::ArcSwap;
use remap_core::RegistrySnapshot;

/// Lock-free publication point for complete immutable registry revisions.
#[derive(Debug, Clone)]
pub struct SnapshotStore {
    current: Arc<ArcSwap<RegistrySnapshot>>,
}

impl SnapshotStore {
    /// Creates a store containing revision zero and no mappings.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            current: Arc::new(ArcSwap::from_pointee(RegistrySnapshot::empty())),
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
        self.current.store(Arc::new(snapshot));
        true
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
