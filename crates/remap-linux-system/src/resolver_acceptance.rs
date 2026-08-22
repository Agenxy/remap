use std::io;
use std::path::{Path, PathBuf};

use uuid::Uuid;

use crate::channel::SystemChannel;
use crate::install_model::ResolverPlanIdentity;
use crate::installer::{STATE_DIRECTORY, conflict, invalid_data, platform_error};

const DATA_DIRECTORY: &str = "/var/lib/remap";
pub(crate) const RESOLVER_PLAN_PUBLICATION_TIMEOUT: &str =
    "the resolver supervisor did not publish a private upstream plan";

pub(crate) async fn wait_for_health(daemon_uid: u32) -> io::Result<()> {
    let channel = SystemChannel::new(
        PathBuf::from(format!("{DATA_DIRECTORY}/system.sock")),
        daemon_uid,
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        let expected = remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
            .map_err(platform_error)?
            .filter(|record| record.phase() == remap_linux::ActivationPhase::Active)
            .map(|record| {
                (
                    record.metadata().activation_id(),
                    record.metadata().generation(),
                )
            });
        if let (Some(expected), Ok(result)) = (
            expected,
            channel
                .exchange(remap_protocol::SystemCommand::ResolverHealth)
                .await,
        ) && health_matches(expected, &result)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                RESOLVER_PLAN_PUBLICATION_TIMEOUT,
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub(crate) async fn wait_for_daemon(daemon_uid: u32) -> io::Result<()> {
    let channel = SystemChannel::new(
        PathBuf::from(format!("{DATA_DIRECTORY}/system.sock")),
        daemon_uid,
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
    loop {
        if channel
            .exchange(remap_protocol::SystemCommand::ResolverHealth)
            .await
            .is_ok()
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the private daemon control channel did not become ready",
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

pub(crate) async fn current_plan_identity(
    daemon_uid: u32,
) -> io::Result<Option<ResolverPlanIdentity>> {
    let channel = SystemChannel::new(
        PathBuf::from(format!("{DATA_DIRECTORY}/system.sock")),
        daemon_uid,
    );
    let result = channel
        .exchange(remap_protocol::SystemCommand::ResolverHealth)
        .await?;
    match (result.activation_id, result.active_generation) {
        (Some(activation_id), Some(generation)) => Ok(Some(ResolverPlanIdentity {
            activation_id,
            generation,
        })),
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(invalid_data(
            "the daemon reported a partial resolver plan identity",
        )),
    }
}

pub(crate) async fn invalidate_plan_identity(
    daemon_uid: u32,
    identity: ResolverPlanIdentity,
) -> io::Result<()> {
    let channel = SystemChannel::new(
        PathBuf::from(format!("{DATA_DIRECTORY}/system.sock")),
        daemon_uid,
    );
    let result = channel
        .exchange(remap_protocol::SystemCommand::InvalidateResolverPlan {
            activation_id: identity.activation_id,
            generation: identity.generation,
        })
        .await?;
    if result.activation_id.is_none() && result.active_generation.is_none() {
        Ok(())
    } else {
        Err(conflict(
            "the daemon did not invalidate the previous resolver plan",
        ))
    }
}

pub(crate) fn require_activation_digest(expected: Option<[u8; 32]>) -> io::Result<()> {
    let observed = remap_linux::RootRecordStore::inspect(Path::new(STATE_DIRECTORY))
        .map_err(platform_error)?
        .as_ref()
        .map(activation_digest)
        .transpose()?;
    if observed == expected {
        Ok(())
    } else {
        Err(conflict(
            "the resolver activation changed after lifecycle authorization",
        ))
    }
}

fn health_matches(expected: (Uuid, u64), result: &remap_protocol::SystemResult) -> bool {
    result.activation_id == Some(expected.0) && result.active_generation == Some(expected.1)
}

pub(crate) fn activation_digest(record: &remap_linux::ActivationRecord) -> io::Result<[u8; 32]> {
    let encoded = serde_json::to_vec(record)
        .map_err(|_error| invalid_data("the resolver activation record could not be encoded"))?;
    Ok(crate::digest::sha256(&encoded))
}

#[cfg(test)]
mod tests {
    use super::health_matches;

    #[test]
    fn health_acceptance_rejects_stale_or_partial_identity() {
        let activation = uuid::Uuid::from_u128(7);
        let exact = remap_protocol::SystemResult {
            activation_id: Some(activation),
            active_generation: Some(11),
        };
        assert!(health_matches((activation, 11), &exact));
        assert!(!health_matches((activation, 12), &exact));
        assert!(!health_matches((uuid::Uuid::from_u128(8), 11), &exact));
        assert!(!health_matches(
            (activation, 11),
            &remap_protocol::SystemResult {
                activation_id: None,
                active_generation: Some(11),
            },
        ));
    }
}
