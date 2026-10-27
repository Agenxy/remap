//! Preview and apply probe loopback HTTP targets and advise when nothing
//! listens there, without ever refusing the change (ADR-0028).

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::time::{Duration, Instant};

use remap_protocol::{
    Change, Command, CommandResult, ControlClient, ControlPaths, HostPolicy, Surface,
};
use remapd::DaemonConfig;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

type TestResult = Result<(), Box<dyn Error>>;

struct Daemon {
    client: ControlClient,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<(), remap_protocol::Diagnostic>>,
    _directory: tempfile::TempDir,
}

impl Daemon {
    async fn start() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path().join("data"));
        let (stop, stopped) = oneshot::channel();
        let config = DaemonConfig::new(paths.clone());
        let task = tokio::spawn(remapd::serve_until(config, async {
            let _done = stopped.await;
        }));
        wait_for_socket(paths.socket()).await?;
        Ok(Self {
            client: ControlClient::new(paths.socket(), Surface::Cli, "0.2.0"),
            stop,
            task,
            _directory: directory,
        })
    }

    async fn stop(self) -> TestResult {
        let _sent = self.stop.send(());
        self.task.await??;
        Ok(())
    }

    async fn preview(&self, changes: Vec<Change>) -> Result<Vec<String>, Box<dyn Error>> {
        match self.client.execute(Command::Preview { changes }).await? {
            CommandResult::Preview(preview) => Ok(preview.warnings),
            _ => Err("preview returned another result".into()),
        }
    }

    async fn target_of(&self, pattern: &str) -> Result<Option<String>, Box<dyn Error>> {
        match self
            .client
            .execute(Command::Get {
                pattern: pattern.to_owned(),
            })
            .await?
        {
            CommandResult::Mapping(mapping) => Ok(mapping.map(|mapping| mapping.target)),
            _ => Err("get returned another result".into()),
        }
    }
}

async fn wait_for_socket(path: &Path) -> TestResult {
    for _attempt in 0..200 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("daemon socket did not appear".into())
}

fn set(pattern: &str, target: &str) -> Change {
    Change::Set {
        pattern: pattern.to_owned(),
        target: target.to_owned(),
        host_policy: HostPolicy::UseUpstream,
        enabled: None,
        landing: None,
    }
}

async fn closed_port() -> Result<SocketAddr, Box<dyn Error>> {
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = reservation.local_addr()?;
    drop(reservation);
    Ok(address)
}

fn refusal_for<'a>(warnings: &'a [String], pattern: &str) -> Option<&'a String> {
    warnings
        .iter()
        .find(|warning| warning.starts_with(&format!("{pattern}: target refused connection")))
}

#[tokio::test]
async fn apply_advises_on_a_refused_target_and_still_commits() -> TestResult {
    let daemon = Daemon::start().await?;
    let dead = closed_port().await?;
    let target = format!("http://{dead}/");
    let result = daemon
        .client
        .execute(Command::Apply {
            expected_revision: 0,
            operation_id: "2f0b8d5e-4c1a-4c39-9a51-6f0e3e2b7a10".to_owned(),
            changes: vec![set("api.test", &target)],
        })
        .await?;
    let CommandResult::Apply(receipt) = result else {
        return Err("apply returned another result".into());
    };
    assert!(receipt.changed, "the owner's change was not committed");
    assert_eq!(receipt.revision, 1);
    let warning = refusal_for(&receipt.warnings, "api.test")
        .ok_or_else(|| format!("no refusal advice in {:?}", receipt.warnings))?;
    assert!(warning.contains("E_GATEWAY_UPSTREAM"), "{warning}");
    assert_eq!(daemon.target_of("api.test").await?, Some(target));
    daemon.stop().await
}

#[tokio::test]
async fn preview_advises_only_where_nothing_listens() -> TestResult {
    let daemon = Daemon::start().await?;
    let dead = closed_port().await?;
    let live = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let live_address = live.local_addr()?;
    let accepting = tokio::spawn(async move { while live.accept().await.is_ok() {} });
    let started = Instant::now();
    let warnings = daemon
        .preview(vec![
            set("dead.test", &format!("http://{dead}/")),
            set("live.test", &format!("http://{live_address}/")),
            // Neither of these is probed: one is another machine, the
            // other a Supgang peer. Probing the first would time out.
            set("lan.test", "http://192.0.2.10:8080/"),
            set("peer.test", "supgang://solis/dibs"),
        ])
        .await?;
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "a probe left loopback"
    );
    assert!(
        refusal_for(&warnings, "dead.test").is_some(),
        "{warnings:?}"
    );
    for quiet in ["live.test", "lan.test", "peer.test"] {
        assert!(
            !warnings
                .iter()
                .any(|warning| warning.starts_with(&format!("{quiet}:"))),
            "{quiet} was advised: {warnings:?}"
        );
    }
    assert_eq!(
        daemon.target_of("dead.test").await?,
        None,
        "preview committed"
    );
    accepting.abort();
    daemon.stop().await
}

#[tokio::test]
async fn preview_advice_clears_once_the_service_starts() -> TestResult {
    let daemon = Daemon::start().await?;
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = reservation.local_addr()?;
    drop(reservation);
    let change = || {
        vec![set(
            "later.test",
            &format!("http://localhost:{}/", address.port()),
        )]
    };
    let before = daemon.preview(change()).await?;
    assert!(refusal_for(&before, "later.test").is_some(), "{before:?}");
    let service = TcpListener::bind(address).await?;
    let accepting = tokio::spawn(async move { while service.accept().await.is_ok() {} });
    let after = daemon.preview(change()).await?;
    assert!(after.is_empty(), "{after:?}");
    accepting.abort();
    daemon.stop().await
}
