pub(crate) const REQUIRED_STABLE_OBSERVATIONS: u8 = 3;

pub(crate) fn deadline_reached(now: tokio::time::Instant, deadline: tokio::time::Instant) -> bool {
    now >= deadline
}

pub(crate) fn seeded<T>(initial: T) -> ObservationStability<T>
where
    T: Eq,
{
    let mut stability = ObservationStability::default();
    let initial_stable = stability.observe(initial);
    debug_assert!(!initial_stable);
    stability
}

#[derive(Debug)]
pub(crate) struct ObservationStability<T> {
    candidate: Option<T>,
    count: u8,
}

impl<T> Default for ObservationStability<T> {
    fn default() -> Self {
        Self {
            candidate: None,
            count: 0,
        }
    }
}

impl<T> ObservationStability<T>
where
    T: Eq,
{
    pub(crate) fn observe(&mut self, observation: T) -> bool {
        if self.candidate.as_ref() == Some(&observation) {
            self.count = self.count.saturating_add(1);
        } else {
            self.candidate = Some(observation);
            self.count = 1;
        }
        self.count >= REQUIRED_STABLE_OBSERVATIONS
    }

    pub(crate) fn reset(&mut self) {
        self.candidate = None;
        self.count = 0;
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum SteadyObservation<T> {
    Cancelled,
    Pending,
    Stable(T),
}

pub(crate) fn evaluate_steady_observation<T>(
    stability: &mut ObservationStability<T>,
    observation: Option<T>,
    requires_rebase: bool,
) -> SteadyObservation<T>
where
    T: Clone + Eq,
{
    let Some(observation) = observation else {
        stability.reset();
        return SteadyObservation::Pending;
    };
    if !requires_rebase {
        return SteadyObservation::Cancelled;
    }
    if stability.observe(observation.clone()) {
        SteadyObservation::Stable(observation)
    } else {
        SteadyObservation::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ObservationStability, REQUIRED_STABLE_OBSERVATIONS, SteadyObservation,
        evaluate_steady_observation,
    };

    #[test]
    fn steady_sequences_cancel_disappearing_drift_and_reset_changed_candidates() {
        let mut missing = ObservationStability::default();
        assert_eq!(
            evaluate_steady_observation(&mut missing, None::<u8>, false),
            SteadyObservation::Pending
        );

        let mut owned = ObservationStability::default();
        assert_eq!(
            evaluate_steady_observation(&mut owned, Some(1_u8), false),
            SteadyObservation::Cancelled
        );

        let mut changed = ObservationStability::default();
        assert_eq!(
            evaluate_steady_observation(&mut changed, Some(1_u8), true),
            SteadyObservation::Pending
        );
        assert_eq!(
            evaluate_steady_observation(&mut changed, Some(2_u8), true),
            SteadyObservation::Pending
        );
        assert_eq!(
            evaluate_steady_observation(&mut changed, Some(2_u8), true),
            SteadyObservation::Pending
        );
        assert_eq!(
            evaluate_steady_observation(&mut changed, Some(2_u8), true),
            SteadyObservation::Stable(2)
        );
        assert_eq!(REQUIRED_STABLE_OBSERVATIONS, 3);
    }
}
