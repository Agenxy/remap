use std::collections::BTreeSet;
use std::io;
use std::time::{Duration, Instant};

use zbus::blocking::Connection;
use zbus::zvariant::OwnedObjectPath;

const JOB_MODE: &str = "replace";
const START_STATE_TIMEOUT: Duration = Duration::from_secs(15);
const STOP_STATE_TIMEOUT: Duration = remap_protocol::NATIVE_DAEMON_TERMINATION_GRACE;
const QUIESCE_GRACE: Duration = remap_protocol::NATIVE_DAEMON_TERMINATION_GRACE;
const STATE_POLL: Duration = Duration::from_millis(25);
const JOB_PATH_PREFIX: &str = "/org/freedesktop/systemd1/job/";
#[derive(Debug)]
pub(crate) struct SystemdManager {
    connection: Connection,
}

impl SystemdManager {
    pub(crate) fn connect() -> io::Result<Self> {
        Ok(Self {
            connection: Connection::system().map_err(manager_error)?,
        })
    }

    pub(crate) fn reload(&self) -> io::Result<()> {
        self.proxy()?.reload().map_err(manager_error)
    }

    pub(crate) fn start(&self, unit: &str) -> io::Result<()> {
        self.start_transaction(unit, &[])
    }

    pub(crate) fn start_transaction(&self, unit: &str, dependencies: &[&str]) -> io::Result<()> {
        self.prepare_start_transaction(unit, dependencies)?;
        self.start_prepared_transaction(unit, dependencies)
    }

    pub(crate) fn prepare_start_transaction(
        &self,
        unit: &str,
        dependencies: &[&str],
    ) -> io::Result<()> {
        for dependency in dependencies {
            self.prepare_start(dependency)?;
        }
        self.prepare_start(unit)
    }

    pub(crate) fn start_prepared_transaction(
        &self,
        unit: &str,
        dependencies: &[&str],
    ) -> io::Result<()> {
        self.start_prepared_transaction_with_handoff(unit, dependencies, || Ok(()))
    }

    pub(crate) fn start_prepared_transaction_with_handoff<F>(
        &self,
        unit: &str,
        dependencies: &[&str],
        mut failure_handoff: F,
    ) -> io::Result<()>
    where
        F: FnMut() -> io::Result<()>,
    {
        let proxy = self.proxy()?;
        let root_path = match proxy.start_unit(unit, JOB_MODE) {
            Ok(path) => path,
            Err(error) => {
                self.finish_failed_start(&proxy, unit, dependencies, &mut failure_handoff);
                return Err(manager_error(error));
            }
        };
        let result = JobIdentity::new(root_path).and_then(|root| {
            let jobs = self.capture_transaction(&proxy, root, dependencies)?;
            if !Self::wait_for_transaction(&proxy, &jobs, START_STATE_TIMEOUT)? {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the native systemd start transaction did not settle",
                ));
            }
            self.require_transaction_active(unit, dependencies)
        });
        if let Err(error) = result {
            self.finish_failed_start(&proxy, unit, dependencies, &mut failure_handoff);
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn stop(&self, unit: &str) -> io::Result<()> {
        let initial = stop_action(&self.observed_state(unit)?);
        if initial != StopAction::Request {
            return self.finalize_stop_action(unit, initial);
        }
        let stopped = self
            .proxy()?
            .stop_unit(unit, JOB_MODE)
            .map_err(manager_error);
        if let Err(error) = stopped {
            let action = stop_action(&self.observed_state(unit)?);
            if action == StopAction::Request {
                return Err(error);
            }
            return self.finalize_stop_action(unit, action);
        }
        let action = self.wait_for_stop_action(unit, STOP_STATE_TIMEOUT)?;
        self.finalize_stop_action(unit, action)
    }

    pub(crate) fn quiesce_process(&self, unit: &str) -> io::Result<()> {
        let proxy = self.proxy()?;
        let mut termination_sent = false;
        let mut escalation = Instant::now() + QUIESCE_GRACE;
        loop {
            let action = stop_action(&self.observed_state(unit)?);
            let job = self.unit_job(unit)?;
            if action == StopAction::Settled && job.is_none() {
                return Ok(());
            }
            if let Some((id, _path)) = job {
                let _result = proxy.cancel_job(id);
            }
            match action {
                StopAction::Settled => termination_sent = false,
                StopAction::ResetFailed => self.reset_failed(unit)?,
                StopAction::Request if !termination_sent => {
                    proxy
                        .kill_unit(unit, "all", nix::libc::SIGTERM)
                        .map_err(manager_error)?;
                    termination_sent = true;
                    escalation = Instant::now() + QUIESCE_GRACE;
                }
                StopAction::Request if Instant::now() >= escalation => {
                    proxy
                        .kill_unit(unit, "all", nix::libc::SIGKILL)
                        .map_err(manager_error)?;
                    escalation = Instant::now() + STOP_STATE_TIMEOUT;
                }
                StopAction::Request => {}
            }
            std::thread::sleep(STATE_POLL);
        }
    }

    pub(crate) fn observed_state(&self, unit: &str) -> io::Result<String> {
        match self.proxy()?.get_unit(unit) {
            Ok(path) => SystemdUnitProxy::builder(&self.connection)
                .path(path)
                .map_err(manager_error)?
                .build()
                .map_err(manager_error)?
                .active_state()
                .map_err(manager_error),
            Err(zbus::Error::MethodError(name, _detail, _reply))
                if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit" =>
            {
                Ok("not_found".to_owned())
            }
            Err(error) => Err(manager_error(error)),
        }
    }

    pub(crate) fn quiesce_failed_start(&self, unit: &str) {
        loop {
            if let Ok(proxy) = self.proxy() {
                self.quiesce_start_transaction(&proxy, unit, &[]);
                return;
            }
            std::thread::sleep(STATE_POLL);
        }
    }

    pub(crate) fn require_settled_active(&self, unit: &str) -> io::Result<()> {
        self.require_transaction_active(unit, &[])
    }

    fn wait_for_transaction(
        proxy: &SystemdManagerApiProxy<'_>,
        jobs: &[JobIdentity],
        timeout: Duration,
    ) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        loop {
            if !jobs
                .iter()
                .map(|job| job_pending(proxy, job))
                .collect::<io::Result<Vec<_>>>()?
                .into_iter()
                .any(|pending| pending)
            {
                return Ok(true);
            }
            if Instant::now() >= deadline {
                return Ok(false);
            }
            std::thread::sleep(STATE_POLL);
        }
    }

    fn capture_transaction(
        &self,
        proxy: &SystemdManagerApiProxy<'_>,
        root: JobIdentity,
        dependencies: &[&str],
    ) -> io::Result<Vec<JobIdentity>> {
        let root_id = root.id;
        let mut identities = vec![root];
        let mut ids = BTreeSet::from([root_id]);
        for dependency in dependencies {
            if let Some((id, path)) = self.unit_job(dependency)?
                && ids.insert(id)
            {
                identities.push(JobIdentity { id, path });
            }
        }
        if !job_pending(proxy, &identities[0])? {
            identities.retain(|identity| identity.id != root_id);
        }
        Ok(identities)
    }

    fn quiesce_start_transaction(
        &self,
        proxy: &SystemdManagerApiProxy<'_>,
        unit: &str,
        dependencies: &[&str],
    ) {
        self.cancel_current_start_jobs(proxy, unit, dependencies);
        self.request_transaction_stop(proxy, unit, dependencies, false);
        let mut escalation = Instant::now() + STOP_STATE_TIMEOUT;
        loop {
            if self.transaction_is_quiesced(unit, dependencies) {
                return;
            }
            if Instant::now() >= escalation {
                self.request_transaction_stop(proxy, unit, dependencies, true);
                escalation = Instant::now() + STOP_STATE_TIMEOUT;
            }
            std::thread::sleep(STATE_POLL);
        }
    }

    fn finish_failed_start<F>(
        &self,
        proxy: &SystemdManagerApiProxy<'_>,
        unit: &str,
        dependencies: &[&str],
        failure_handoff: &mut F,
    ) where
        F: FnMut() -> io::Result<()>,
    {
        self.quiesce_start_transaction(proxy, unit, &[]);
        for dependency in dependencies {
            self.settle_failed_dependency(proxy, dependency);
        }
        while failure_handoff().is_err() {
            std::thread::sleep(STATE_POLL);
        }
    }

    fn settle_failed_dependency(&self, proxy: &SystemdManagerApiProxy<'_>, unit: &str) {
        let deadline = Instant::now() + STOP_STATE_TIMEOUT;
        loop {
            let state = self.observed_state(unit);
            let job = self.unit_job(unit);
            let no_job = matches!(job, Ok(None));
            if matches!(state.as_deref(), Ok("active")) && no_job {
                return;
            }
            if no_job || Instant::now() >= deadline {
                self.quiesce_start_transaction(proxy, unit, &[]);
                return;
            }
            std::thread::sleep(STATE_POLL);
        }
    }

    fn cancel_current_start_jobs(
        &self,
        proxy: &SystemdManagerApiProxy<'_>,
        unit: &str,
        dependencies: &[&str],
    ) {
        for required in dependencies.iter().copied().chain(std::iter::once(unit)) {
            let Ok(Some((id, _path))) = self.unit_job(required) else {
                continue;
            };
            let _result = proxy.cancel_job(id);
        }
    }

    fn request_transaction_stop(
        &self,
        proxy: &SystemdManagerApiProxy<'_>,
        unit: &str,
        dependencies: &[&str],
        force: bool,
    ) {
        for required in std::iter::once(unit).chain(dependencies.iter().copied()) {
            if force {
                let _result = proxy.kill_unit(required, "all", nix::libc::SIGKILL);
            }
            let _result = proxy.stop_unit(required, JOB_MODE);
            if matches!(self.observed_state(required).as_deref(), Ok("failed")) {
                let _result = proxy.reset_failed_unit(required);
            }
        }
    }

    fn transaction_is_quiesced(&self, unit: &str, dependencies: &[&str]) -> bool {
        dependencies
            .iter()
            .copied()
            .chain(std::iter::once(unit))
            .all(|required| {
                matches!(
                    self.observed_state(required).as_deref(),
                    Ok("inactive" | "not_found")
                ) && self.unit_job(required).is_ok_and(|job| job.is_none())
            })
    }

    fn unit_job(&self, unit: &str) -> io::Result<Option<(u32, OwnedObjectPath)>> {
        let path = match self.proxy()?.get_unit(unit) {
            Ok(path) => path,
            Err(error) if is_no_such_unit(&error) => return Ok(None),
            Err(error) => return Err(manager_error(error)),
        };
        let (id, job_path) = SystemdUnitProxy::builder(&self.connection)
            .path(path)
            .map_err(manager_error)?
            .build()
            .map_err(manager_error)?
            .job()
            .map_err(manager_error)?;
        if id == 0 {
            return Ok(None);
        }
        if parse_job_path(&job_path)? != id {
            return Err(manager_error(io::Error::other(
                "the native systemd unit reported a mismatched job identity",
            )));
        }
        Ok(Some((id, job_path)))
    }

    fn prepare_start(&self, unit: &str) -> io::Result<()> {
        match start_action(&self.observed_state(unit)?) {
            StartAction::Ready => Ok(()),
            StartAction::ResetInactive => self.reset_inactive_start_limit(unit),
            StartAction::ResetFailed => self.reset_failed(unit),
            StartAction::Missing => Err(io::Error::new(
                io::ErrorKind::NotFound,
                "a required native systemd unit is not loaded",
            )),
            StartAction::Transitional => Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a required native systemd unit already has a transitional state",
            )),
        }
    }

    fn reset_inactive_start_limit(&self, unit: &str) -> io::Result<()> {
        self.proxy()?
            .reset_failed_unit(unit)
            .map_err(manager_error)?;
        if self.observed_state(unit)? == "inactive" && self.unit_job(unit)?.is_none() {
            Ok(())
        } else {
            Err(unit_reactivated_error())
        }
    }

    fn require_transaction_active(&self, unit: &str, dependencies: &[&str]) -> io::Result<()> {
        for required in dependencies.iter().copied().chain(std::iter::once(unit)) {
            if self.observed_state(required)? != "active" || self.unit_job(required)?.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the native systemd start transaction completed without activating every required unit",
                ));
            }
        }
        Ok(())
    }

    fn wait_for_stop_action(&self, unit: &str, timeout: Duration) -> io::Result<StopAction> {
        let deadline = Instant::now() + timeout;
        loop {
            let action = stop_action(&self.observed_state(unit)?);
            if action != StopAction::Request || Instant::now() >= deadline {
                return Ok(action);
            }
            std::thread::sleep(STATE_POLL);
        }
    }

    fn finalize_stop_action(&self, unit: &str, _observed: StopAction) -> io::Result<()> {
        match stop_action(&self.observed_state(unit)?) {
            StopAction::Settled => Ok(()),
            StopAction::ResetFailed => self.reset_failed(unit),
            StopAction::Request => Err(unit_reactivated_error()),
        }
    }

    fn reset_failed(&self, unit: &str) -> io::Result<()> {
        match stop_action(&self.observed_state(unit)?) {
            StopAction::Settled => return Ok(()),
            StopAction::ResetFailed => {}
            StopAction::Request => return Err(unit_reactivated_error()),
        }
        let reset = self.proxy()?.reset_failed_unit(unit).map_err(manager_error);
        if let Err(error) = reset
            && stop_action(&self.observed_state(unit)?) != StopAction::Settled
        {
            return Err(error);
        }
        if stop_action(&self.observed_state(unit)?) == StopAction::Settled {
            Ok(())
        } else {
            Err(unit_reactivated_error())
        }
    }

    fn proxy(&self) -> io::Result<SystemdManagerApiProxy<'_>> {
        SystemdManagerApiProxy::new(&self.connection).map_err(manager_error)
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Manager",
    default_service = "org.freedesktop.systemd1",
    default_path = "/org/freedesktop/systemd1",
    gen_async = false
)]
trait SystemdManagerApi {
    #[zbus(name = "Reload")]
    fn reload(&self) -> zbus::Result<()>;

    #[zbus(name = "StartUnit")]
    fn start_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "StopUnit")]
    fn stop_unit(&self, name: &str, mode: &str) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "GetJob")]
    fn get_job(&self, id: u32) -> zbus::Result<OwnedObjectPath>;

    #[zbus(name = "CancelJob")]
    fn cancel_job(&self, id: u32) -> zbus::Result<()>;

    #[zbus(name = "KillUnit")]
    fn kill_unit(&self, name: &str, whom: &str, signal: i32) -> zbus::Result<()>;

    #[zbus(name = "ResetFailedUnit")]
    fn reset_failed_unit(&self, name: &str) -> zbus::Result<()>;

    #[zbus(name = "GetUnit")]
    fn get_unit(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
}

#[zbus::proxy(
    interface = "org.freedesktop.systemd1.Unit",
    default_service = "org.freedesktop.systemd1",
    gen_async = false
)]
trait SystemdUnit {
    #[zbus(property, name = "ActiveState")]
    fn active_state(&self) -> zbus::Result<String>;

    #[zbus(property, name = "Job")]
    fn job(&self) -> zbus::Result<(u32, OwnedObjectPath)>;
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct JobIdentity {
    id: u32,
    path: OwnedObjectPath,
}

impl JobIdentity {
    fn new(path: OwnedObjectPath) -> io::Result<Self> {
        Ok(Self {
            id: parse_job_path(&path)?,
            path,
        })
    }
}

fn job_pending(proxy: &SystemdManagerApiProxy<'_>, expected: &JobIdentity) -> io::Result<bool> {
    match proxy.get_job(expected.id) {
        Ok(observed) if observed == expected.path => Ok(true),
        Ok(_substitution) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the native systemd job identity changed",
        )),
        Err(error) if is_no_such_job(&error) => Ok(false),
        Err(error) => Err(manager_error(error)),
    }
}

fn parse_job_path(path: &OwnedObjectPath) -> io::Result<u32> {
    let value = path
        .as_str()
        .strip_prefix(JOB_PATH_PREFIX)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid systemd job path"))?;
    let id = value
        .parse::<u32>()
        .map_err(|_error| io::Error::new(io::ErrorKind::InvalidData, "invalid systemd job id"))?;
    if id == 0 || value != id.to_string() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "non-canonical systemd job identity",
        ));
    }
    Ok(id)
}

fn is_no_such_job(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _detail, _reply)
        if name.as_str() == "org.freedesktop.systemd1.NoSuchJob")
}

fn is_no_such_unit(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _detail, _reply)
        if name.as_str() == "org.freedesktop.systemd1.NoSuchUnit")
}

fn manager_error(_error: impl std::error::Error) -> io::Error {
    io::Error::other("the native systemd manager operation failed")
}

fn unit_reactivated_error() -> io::Error {
    io::Error::other("a systemd unit reactivated while it was being stopped")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StartAction {
    Ready,
    ResetInactive,
    ResetFailed,
    Missing,
    Transitional,
}

fn start_action(state: &str) -> StartAction {
    match state {
        "active" => StartAction::Ready,
        "inactive" => StartAction::ResetInactive,
        "failed" => StartAction::ResetFailed,
        "not_found" => StartAction::Missing,
        _ => StartAction::Transitional,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopAction {
    Settled,
    ResetFailed,
    Request,
}

fn stop_action(state: &str) -> StopAction {
    match state {
        "inactive" | "not_found" => StopAction::Settled,
        "failed" => StopAction::ResetFailed,
        _ => StopAction::Request,
    }
}

#[cfg(test)]
mod tests {
    use zbus::zvariant::OwnedObjectPath;

    use super::{StartAction, StopAction, parse_job_path, start_action, stop_action};

    #[test]
    fn systemd_job_paths_require_one_canonical_nonzero_identity() -> std::io::Result<()> {
        let path = |value: &str| {
            OwnedObjectPath::try_from(value.to_owned()).map_err(std::io::Error::other)
        };
        assert_eq!(
            parse_job_path(&path("/org/freedesktop/systemd1/job/42")?)?,
            42
        );
        for invalid in [
            "/org/freedesktop/systemd1/job/0",
            "/org/freedesktop/systemd1/job/042",
            "/org/freedesktop/systemd1/job/4294967296",
            "/org/freedesktop/systemd1/unit/42",
        ] {
            assert!(parse_job_path(&path(invalid)?).is_err());
        }
        Ok(())
    }

    #[test]
    fn failed_units_require_reset_and_reactivation_is_never_settled() {
        assert_eq!(stop_action("inactive"), StopAction::Settled);
        assert_eq!(stop_action("not_found"), StopAction::Settled);
        assert_eq!(stop_action("failed"), StopAction::ResetFailed);
        assert_eq!(stop_action("active"), StopAction::Request);
        assert_eq!(stop_action("activating"), StopAction::Request);
        assert_eq!(stop_action("deactivating"), StopAction::Request);

        let failed_then_active = ["failed", "active"].map(stop_action);
        assert_eq!(
            failed_then_active,
            [StopAction::ResetFailed, StopAction::Request]
        );
        let inactive_then_active = ["inactive", "active"].map(stop_action);
        assert_eq!(
            inactive_then_active,
            [StopAction::Settled, StopAction::Request]
        );
    }

    #[test]
    fn inactive_units_reset_hidden_start_limit_before_start() {
        assert_eq!(start_action("active"), StartAction::Ready);
        assert_eq!(start_action("inactive"), StartAction::ResetInactive);
        assert_eq!(start_action("failed"), StartAction::ResetFailed);
        assert_eq!(start_action("not_found"), StartAction::Missing);
        assert_eq!(start_action("activating"), StartAction::Transitional);
    }
}
