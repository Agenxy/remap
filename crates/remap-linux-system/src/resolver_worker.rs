use std::io;
use std::time::Duration;

use tokio::sync::{Semaphore, mpsc, oneshot};

use remap_linux::{ActivationRecord, LinkIndex};

use crate::supervisor::SupervisorConfig;
use crate::supervisor::{NativeResolverTransaction, NativeStartupObservation};

type NativeOperation<T> = Box<dyn FnOnce(&mut T) + Send + 'static>;
const NATIVE_READ_CALL_TIMEOUT: Duration = Duration::from_millis(150);

#[derive(Debug)]
pub(crate) enum BoundedCall<T> {
    Completed(T),
    TimedOut,
}

#[derive(Debug)]
pub(crate) enum SettledCall<T> {
    Completed(T),
    Stopped(T),
}

#[derive(Debug)]
pub(crate) enum EffectCall<T> {
    Completed(T),
    TimedOut,
    Stopped(T),
}

#[derive(Debug)]
#[must_use = "a dispatched native effect must be settled before returning"]
pub(crate) struct DispatchedCall<T> {
    receiver: oneshot::Receiver<T>,
}

impl<T> DispatchedCall<T> {
    pub(crate) async fn settle(self) -> io::Result<T> {
        self.receiver.await.map_err(|_error| worker_stopped())
    }
}

pub(crate) async fn startup_observation(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    link: LinkIndex,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<Option<NativeStartupObservation>> {
    match call_with_shutdown(
        transaction.call(NATIVE_READ_CALL_TIMEOUT, move |transaction| {
            transaction.startup_observation(link)
        }),
        shutdown,
    )
    .await?
    {
        BoundedCall::Completed(Ok(observed)) => Ok(observed),
        BoundedCall::Completed(Err(error))
            if error.kind() == remap_linux::LinuxErrorKind::ResolverUnavailable =>
        {
            Ok(None)
        }
        BoundedCall::Completed(Err(error)) => Err(io::Error::other(error)),
        BoundedCall::TimedOut => Ok(None),
    }
}

pub(crate) async fn rebase_comparison(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    record: &ActivationRecord,
    observed: &NativeStartupObservation,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<Option<bool>> {
    let record = record.clone();
    let observed = observed.clone();
    match call_with_shutdown(
        transaction.call(NATIVE_READ_CALL_TIMEOUT, move |transaction| {
            transaction.observation_requires_rebase(&record, &observed)
        }),
        shutdown,
    )
    .await?
    {
        BoundedCall::Completed(Ok(requires_rebase)) => Ok(Some(requires_rebase)),
        BoundedCall::Completed(Err(error))
            if error.kind() == remap_linux::LinuxErrorKind::UnstableObservation =>
        {
            Ok(None)
        }
        BoundedCall::Completed(Err(error)) => Err(io::Error::other(error)),
        BoundedCall::TimedOut => Ok(None),
    }
}

pub(crate) async fn load(
    transaction: &BoundedWorker<NativeResolverTransaction>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<Option<Option<ActivationRecord>>> {
    match call_with_shutdown(
        transaction.call(NATIVE_READ_CALL_TIMEOUT, NativeResolverTransaction::load),
        shutdown,
    )
    .await?
    {
        BoundedCall::Completed(result) => result.map(Some).map_err(io::Error::other),
        BoundedCall::TimedOut => Ok(None),
    }
}

pub(crate) fn platform_error_is_unavailable(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<remap_linux::LinuxError>())
        .is_some_and(|error| error.kind() == remap_linux::LinuxErrorKind::ResolverUnavailable)
}

pub(crate) fn platform_error(error: remap_linux::LinuxError) -> io::Error {
    io::Error::other(error)
}

pub(crate) fn startup_stopped() -> io::Error {
    io::Error::new(io::ErrorKind::Interrupted, "resolver startup was stopped")
}

pub(crate) async fn connect_when_ready(
    config: &SupervisorConfig,
    timeout: Duration,
    retry: Duration,
    timeout_message: &'static str,
) -> io::Result<NativeResolverTransaction> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match NativeResolverTransaction::connect(config) {
            Ok(transaction) => return Ok(transaction),
            Err(error) if platform_error_is_unavailable(&error) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, timeout_message));
                }
                tokio::time::sleep(retry).await;
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) async fn call_with_shutdown<T>(
    call: impl std::future::Future<Output = io::Result<BoundedCall<T>>>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<BoundedCall<T>> {
    tokio::select! {
        result = call => result,
        result = shutdown.changed() => {
            result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
            Err(io::Error::new(io::ErrorKind::Interrupted, "resolver supervision was stopped"))
        }
    }
}

pub(crate) async fn call_with_shutdown_settled<T>(
    call: impl std::future::Future<Output = io::Result<T>>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<SettledCall<T>> {
    tokio::pin!(call);
    tokio::select! {
        result = &mut call => {
            let result = result?;
            if *shutdown.borrow() {
                Ok(SettledCall::Stopped(result))
            } else {
                Ok(SettledCall::Completed(result))
            }
        }
        result = shutdown.changed() => {
            result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
            call.await.map(SettledCall::Stopped)
        }
    }
}

pub(crate) async fn call_effect_with_shutdown<T>(
    call: impl std::future::Future<Output = io::Result<T>>,
    timeout: Duration,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> io::Result<EffectCall<T>> {
    tokio::pin!(call);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);
    tokio::select! {
        biased;
        result = shutdown.changed() => {
            result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
            call.await.map(EffectCall::Stopped)
        }
        result = &mut call => {
            let result = result?;
            if *shutdown.borrow() {
                Ok(EffectCall::Stopped(result))
            } else {
                Ok(EffectCall::Completed(result))
            }
        }
        () = &mut deadline => Ok(EffectCall::TimedOut),
    }
}

pub(crate) fn shutdown_receiver() -> io::Result<tokio::sync::watch::Receiver<bool>> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (sender, receiver) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        tokio::select! {
            _signal = terminate.recv() => {}
            _result = tokio::signal::ctrl_c() => {}
        }
        let _result = sender.send(true);
    });
    Ok(receiver)
}

pub(crate) struct BoundedWorker<T> {
    sender: mpsc::Sender<NativeOperation<T>>,
    permit: std::sync::Arc<Semaphore>,
}

impl<T> BoundedWorker<T>
where
    T: Send + 'static,
{
    pub(crate) fn new(mut state: T) -> io::Result<Self> {
        let (sender, mut receiver) = mpsc::channel::<NativeOperation<T>>(1);
        std::thread::Builder::new()
            .name("remap-native-resolver".to_owned())
            .spawn(move || {
                while let Some(operation) = receiver.blocking_recv() {
                    operation(&mut state);
                }
            })
            .map_err(|_error| worker_stopped())?;
        Ok(Self {
            sender,
            permit: std::sync::Arc::new(Semaphore::new(1)),
        })
    }

    pub(crate) async fn call<R, F>(
        &self,
        timeout: Duration,
        operation: F,
    ) -> io::Result<BoundedCall<R>>
    where
        R: Send + 'static,
        F: FnOnce(&mut T) -> R + Send + 'static,
    {
        let deadline = tokio::time::Instant::now() + timeout;
        let permit =
            match tokio::time::timeout_at(deadline, self.permit.clone().acquire_owned()).await {
                Ok(Ok(permit)) => permit,
                Ok(Err(_error)) => return Err(worker_stopped()),
                Err(_elapsed) => return Ok(BoundedCall::TimedOut),
            };
        let (result_sender, result_receiver) = oneshot::channel();
        let command = Box::new(move |state: &mut T| {
            let _permit = permit;
            let _result = result_sender.send(operation(state));
        });
        self.sender
            .send(command)
            .await
            .map_err(|_error| worker_stopped())?;
        match tokio::time::timeout_at(deadline, result_receiver).await {
            Ok(Ok(result)) => Ok(BoundedCall::Completed(result)),
            Ok(Err(_error)) => Err(worker_stopped()),
            Err(_elapsed) => Ok(BoundedCall::TimedOut),
        }
    }

    pub(crate) async fn call_settled<R, F>(&self, operation: F) -> io::Result<R>
    where
        R: Send + 'static,
        F: FnOnce(&mut T) -> R + Send + 'static,
    {
        self.dispatch(operation).await?.settle().await
    }

    pub(crate) async fn dispatch<R, F>(&self, operation: F) -> io::Result<DispatchedCall<R>>
    where
        R: Send + 'static,
        F: FnOnce(&mut T) -> R + Send + 'static,
    {
        let permit = self
            .permit
            .clone()
            .acquire_owned()
            .await
            .map_err(|_error| worker_stopped())?;
        let (result_sender, result_receiver) = oneshot::channel();
        let command = Box::new(move |state: &mut T| {
            let _permit = permit;
            let _result = result_sender.send(operation(state));
        });
        self.sender
            .send(command)
            .await
            .map_err(|_error| worker_stopped())?;
        Ok(DispatchedCall {
            receiver: result_receiver,
        })
    }

    pub(crate) async fn dispatch_effect<R, F>(
        &self,
        operation: F,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> io::Result<DispatchedCall<R>>
    where
        R: Send + 'static,
        F: FnOnce(&mut T) -> R + Send + 'static,
    {
        if *shutdown.borrow() {
            return Err(supervision_stopped());
        }
        let permit = tokio::select! {
            biased;
            result = shutdown.changed() => {
                result.map_err(|_error| io::Error::other("the supervisor shutdown monitor stopped"))?;
                return Err(supervision_stopped());
            }
            result = self.permit.clone().acquire_owned() => {
                result.map_err(|_error| worker_stopped())?
            }
        };
        if *shutdown.borrow() {
            return Err(supervision_stopped());
        }
        let (result_sender, result_receiver) = oneshot::channel();
        let command = Box::new(move |state: &mut T| {
            let _permit = permit;
            let _result = result_sender.send(operation(state));
        });
        self.sender.try_send(command).map_err(|error| match error {
            mpsc::error::TrySendError::Closed(_command) => worker_stopped(),
            mpsc::error::TrySendError::Full(_command) => {
                io::Error::other("the bounded native resolver worker queue is unexpectedly full")
            }
        })?;
        Ok(DispatchedCall {
            receiver: result_receiver,
        })
    }
}

fn supervision_stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::Interrupted,
        "resolver supervision was stopped",
    )
}

fn worker_stopped() -> io::Error {
    io::Error::other("the bounded native resolver worker stopped unexpectedly")
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::{
        BoundedCall, BoundedWorker, EffectCall, SettledCall, call_effect_with_shutdown,
        call_with_shutdown_settled,
    };

    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_call_keeps_the_runtime_responsive_and_never_queues_another_command()
    -> std::io::Result<()> {
        let worker = BoundedWorker::new(0_u8)?;
        let started = Arc::new(AtomicUsize::new(0));
        let first_started = Arc::clone(&started);
        let first = worker.call(std::time::Duration::from_millis(10), move |_state| {
            first_started.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(80));
        });
        assert!(matches!(first.await?, BoundedCall::TimedOut));

        let timer = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            tokio::time::sleep(std::time::Duration::from_millis(1)),
        )
        .await;
        assert!(timer.is_ok());
        let second_started = Arc::clone(&started);
        let second = worker.call(std::time::Duration::from_millis(10), move |_state| {
            second_started.fetch_add(1, Ordering::SeqCst);
        });
        assert!(matches!(second.await?, BoundedCall::TimedOut));
        assert_eq!(started.load(Ordering::SeqCst), 1);
        tokio::time::sleep(std::time::Duration::from_millis(90)).await;
        let state = worker
            .call(std::time::Duration::from_millis(20), |state| *state)
            .await?;
        assert!(matches!(state, BoundedCall::Completed(0)));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn startup_shutdown_settles_an_effect_committed_before_the_held_reply()
    -> std::io::Result<()> {
        let worker = BoundedWorker::new(())?;
        let changed = Arc::new(AtomicUsize::new(0));
        let worker_changed = Arc::clone(&changed);
        let (shutdown_sender, mut shutdown) = tokio::sync::watch::channel(false);
        let started = std::time::Instant::now();
        let call = worker.call_settled(move |_state| {
            worker_changed.store(1, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(100));
            worker_changed.store(2, Ordering::SeqCst);
        });
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let _result = shutdown_sender.send(true);
        });
        let result = call_with_shutdown_settled(call, &mut shutdown).await?;
        assert!(matches!(result, SettledCall::Stopped(())));
        assert!(started.elapsed() < std::time::Duration::from_millis(150));
        assert_eq!(changed.load(Ordering::SeqCst), 2);
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert_eq!(changed.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn steady_shutdown_settles_a_dispatched_mutation_before_reporting_stop()
    -> std::io::Result<()> {
        let worker = BoundedWorker::new(())?;
        let changed = Arc::new(AtomicUsize::new(0));
        let worker_changed = Arc::clone(&changed);
        let (shutdown_sender, mut shutdown) = tokio::sync::watch::channel(false);
        let dispatched = worker
            .dispatch_effect(
                move |_state| {
                    worker_changed.store(1, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    worker_changed.store(2, Ordering::SeqCst);
                    42_u8
                },
                &mut shutdown,
            )
            .await?;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            let _result = shutdown_sender.send(true);
        });
        let result = call_effect_with_shutdown(
            dispatched.settle(),
            std::time::Duration::from_secs(1),
            &mut shutdown,
        )
        .await?;
        assert!(matches!(result, EffectCall::Stopped(42)));
        assert_eq!(changed.load(Ordering::SeqCst), 2);
        tokio::time::sleep(std::time::Duration::from_millis(120)).await;
        assert_eq!(changed.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn steady_shutdown_observed_before_dispatch_has_no_effect() -> std::io::Result<()> {
        let worker = BoundedWorker::new(())?;
        let changed = Arc::new(AtomicUsize::new(0));
        let worker_changed = Arc::clone(&changed);
        let (shutdown_sender, mut shutdown) = tokio::sync::watch::channel(false);
        shutdown_sender
            .send(true)
            .map_err(|_error| std::io::Error::other("shutdown receiver stopped"))?;
        let error = match worker
            .dispatch_effect(
                move |_state| worker_changed.store(1, Ordering::SeqCst),
                &mut shutdown,
            )
            .await
        {
            Ok(_dispatched) => {
                return Err(std::io::Error::other(
                    "shutdown unexpectedly dispatched a native effect",
                ));
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), std::io::ErrorKind::Interrupted);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(changed.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn timed_out_mutation_is_reported_as_unknown_while_the_single_worker_finishes_it()
    -> std::io::Result<()> {
        let worker = BoundedWorker::new(())?;
        let changed = Arc::new(AtomicUsize::new(0));
        let worker_changed = Arc::clone(&changed);
        let result = worker
            .call(std::time::Duration::from_millis(5), move |_state| {
                std::thread::sleep(std::time::Duration::from_millis(30));
                worker_changed.store(1, Ordering::SeqCst);
            })
            .await?;
        assert!(matches!(result, BoundedCall::TimedOut));
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        assert_eq!(changed.load(Ordering::SeqCst), 1);
        Ok(())
    }
}
