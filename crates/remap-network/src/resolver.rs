use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwapOption;
use tokio_util::sync::CancellationToken;

use crate::NetworkError;

/// Lock-free reader and serialized publisher for ordered DNS resolver plans.
#[derive(Debug, Clone)]
pub struct ResolverPlanStore {
    active: Arc<ArcSwapOption<ResolverPlan>>,
    publisher: Arc<Mutex<PublisherState>>,
}

#[derive(Debug)]
struct PublisherState {
    latest_generation: u64,
}

#[derive(Debug)]
pub(crate) struct ResolverPlan {
    generation: u64,
    upstreams: Arc<[SocketAddr]>,
    cancellation: CancellationToken,
}

impl ResolverPlanStore {
    /// Creates a store with no forwarding plan for native-supervisor startup.
    ///
    /// An empty plan is never admitted. Unmapped DNS fails closed until the
    /// authenticated privileged supervisor publishes generation one or newer.
    #[must_use]
    pub fn dormant() -> Self {
        Self {
            active: Arc::new(ArcSwapOption::empty()),
            publisher: Arc::new(Mutex::new(PublisherState {
                latest_generation: 0,
            })),
        }
    }

    /// Creates generation one from an ordered, bounded upstream set.
    ///
    /// # Errors
    ///
    /// Returns a configuration failure for unsafe or empty endpoints.
    pub fn initial(upstreams: Vec<SocketAddr>) -> Result<Self, NetworkError> {
        let plan = Arc::new(ResolverPlan::new(1, upstreams)?);
        Ok(Self {
            active: Arc::new(ArcSwapOption::from(Some(plan))),
            publisher: Arc::new(Mutex::new(PublisherState {
                latest_generation: 1,
            })),
        })
    }

    /// Atomically publishes a strictly newer ordered resolver generation.
    ///
    /// Existing readers keep an immutable generation, but its cancellation
    /// signal is raised before publication returns.
    ///
    /// # Errors
    ///
    /// Returns a configuration failure for stale generations, unsafe
    /// endpoints, or a poisoned publisher lock.
    pub fn publish(&self, generation: u64, upstreams: Vec<SocketAddr>) -> Result<(), NetworkError> {
        let plan = Arc::new(ResolverPlan::new(generation, upstreams)?);
        let mut publisher = self.publisher.lock().map_err(|_| {
            NetworkError::Configuration("the resolver publisher lock is unavailable")
        })?;
        if generation <= publisher.latest_generation {
            return Err(NetworkError::Configuration(
                "resolver generations must increase monotonically",
            ));
        }
        publisher.latest_generation = generation;
        if let Some(previous) = self.active.swap(Some(plan)) {
            previous.cancellation.cancel();
        }
        Ok(())
    }

    /// Invalidates one exact active generation without admitting stale races.
    ///
    /// # Errors
    ///
    /// Returns a configuration failure when the publisher lock is poisoned.
    pub fn invalidate(&self, generation: u64) -> Result<bool, NetworkError> {
        let _publisher = self.publisher.lock().map_err(|_| {
            NetworkError::Configuration("the resolver publisher lock is unavailable")
        })?;
        let Some(active) = self.active.load_full() else {
            return Ok(false);
        };
        if active.generation != generation {
            return Ok(false);
        }
        let removed = self.active.swap(None);
        if let Some(plan) = removed {
            plan.cancellation.cancel();
        }
        Ok(true)
    }

    /// Returns the currently admitted generation, if forwarding is active.
    #[must_use]
    pub fn active_generation(&self) -> Option<u64> {
        self.active.load().as_ref().map(|plan| plan.generation)
    }

    pub(crate) fn capture(&self) -> Option<Arc<ResolverPlan>> {
        self.active.load_full()
    }
}

impl ResolverPlan {
    fn new(generation: u64, upstreams: Vec<SocketAddr>) -> Result<Self, NetworkError> {
        if generation == 0 {
            return Err(NetworkError::Configuration(
                "resolver generation zero is reserved",
            ));
        }
        if upstreams.is_empty() || upstreams.len() > 4 {
            return Err(NetworkError::Configuration(
                "configure between one and four DNS upstreams",
            ));
        }
        if upstreams.iter().any(|upstream| {
            upstream.port() == 0 || upstream.ip().is_unspecified() || upstream.ip().is_multicast()
        }) {
            return Err(NetworkError::Configuration(
                "DNS upstreams must be specified unicast endpoints",
            ));
        }
        Ok(Self {
            generation,
            upstreams: upstreams.into(),
            cancellation: CancellationToken::new(),
        })
    }

    pub(crate) fn upstreams(&self) -> &[SocketAddr] {
        &self.upstreams
    }

    pub(crate) fn cancellation(&self) -> &CancellationToken {
        &self.cancellation
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};

    use super::ResolverPlanStore;

    fn endpoint(octet: u8) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, octet), 53))
    }

    #[test]
    fn dormant_store_accepts_only_a_valid_first_generation() -> Result<(), Box<dyn Error>> {
        let store = ResolverPlanStore::dormant();
        assert_eq!(store.active_generation(), None);
        assert!(store.publish(0, vec![endpoint(1)]).is_err());
        assert!(store.publish(1, Vec::new()).is_err());
        assert_eq!(store.active_generation(), None);
        store.publish(1, vec![endpoint(1)])?;
        assert_eq!(store.active_generation(), Some(1));
        assert!(store.publish(1, vec![endpoint(2)]).is_err());
        Ok(())
    }

    #[test]
    fn publication_preserves_order_and_cancels_the_previous_generation()
    -> Result<(), Box<dyn Error>> {
        let store = ResolverPlanStore::initial(vec![endpoint(2), endpoint(1)])?;
        let previous = store
            .capture()
            .ok_or_else(|| io::Error::other("initial plan disappeared"))?;
        store.publish(2, vec![endpoint(4), endpoint(3)])?;
        let current = store
            .capture()
            .ok_or_else(|| io::Error::other("published plan disappeared"))?;
        assert_eq!(current.upstreams(), [endpoint(4), endpoint(3)]);
        assert!(previous.cancellation().is_cancelled());
        assert_eq!(store.active_generation(), Some(2));
        Ok(())
    }

    #[test]
    fn stale_publication_and_invalidation_cannot_remove_a_newer_plan() -> Result<(), Box<dyn Error>>
    {
        let store = ResolverPlanStore::initial(vec![endpoint(1)])?;
        store.publish(4, vec![endpoint(4)])?;
        assert!(store.publish(3, vec![endpoint(3)]).is_err());
        assert!(!store.invalidate(1)?);
        assert_eq!(store.active_generation(), Some(4));
        assert!(store.invalidate(4)?);
        assert_eq!(store.active_generation(), None);
        Ok(())
    }

    #[test]
    fn unsafe_upstreams_are_rejected_before_publication() -> Result<(), Box<dyn Error>> {
        let store = ResolverPlanStore::initial(vec![endpoint(1)])?;
        let unspecified = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 53));
        assert!(store.publish(2, vec![unspecified]).is_err());
        assert_eq!(store.active_generation(), Some(1));
        Ok(())
    }
}
