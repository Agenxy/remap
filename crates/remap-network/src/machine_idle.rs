// SPDX-License-Identifier: GPL-3.0-or-later
//! Copying a carried connection both ways until each side closes, or until
//! no byte has moved in either direction for the idle deadline (ADR-0033).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio::time::{Instant, sleep_until};

/// When a byte last moved, as milliseconds after the copy began.
struct Activity {
    began: Instant,
    last_ms: AtomicU64,
}

impl Activity {
    fn touch(&self) {
        let elapsed = u64::try_from(self.began.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_ms.store(elapsed, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.began + Duration::from_millis(self.last_ms.load(Ordering::Relaxed))
    }
}

/// One side of the copy, marking activity whenever bytes are read or written.
struct Watched<'a, T> {
    inner: &'a mut T,
    activity: Arc<Activity>,
}

impl<T: AsyncRead + Unpin> AsyncRead for Watched<'_, T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let polled = Pin::new(&mut *this.inner).poll_read(context, buffer);
        if matches!(polled, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            this.activity.touch();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Watched<'_, T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let polled = Pin::new(&mut *this.inner).poll_write(context, bytes);
        if matches!(polled, Poll::Ready(Ok(written)) if written > 0) {
            this.activity.touch();
        }
        polled
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut *self.get_mut().inner).poll_shutdown(context)
    }
}

/// Copies both ways until each side has closed, or until neither direction
/// has moved a byte for `idle`; either way both streams are then dropped by
/// the caller.
pub(crate) async fn carry_until_idle<A, B>(client: &mut A, upstream: &mut B, idle: Duration)
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = Arc::new(Activity {
        began: Instant::now(),
        last_ms: AtomicU64::new(0),
    });
    let mut left = Watched {
        inner: client,
        activity: Arc::clone(&activity),
    };
    let mut right = Watched {
        inner: upstream,
        activity: Arc::clone(&activity),
    };
    let copy = copy_bidirectional(&mut left, &mut right);
    tokio::pin!(copy);
    loop {
        tokio::select! {
            _copied = &mut copy => return,
            () = sleep_until(activity.last() + idle) => {
                if activity.last() + idle <= Instant::now() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
    use tokio::time::{Instant, sleep, timeout};

    use super::carry_until_idle;

    #[tokio::test]
    async fn traffic_keeps_the_copy_open_and_silence_ends_it()
    -> Result<(), Box<dyn std::error::Error>> {
        let idle = Duration::from_millis(150);
        let (mut client, mut near) = duplex(64);
        let (mut far, mut server) = duplex(64);
        let carried = tokio::spawn(async move {
            carry_until_idle(&mut near, &mut far, idle).await;
        });
        let began = Instant::now();
        for _round in 0..6 {
            client.write_all(b"ping").await?;
            let mut echoed = [0_u8; 4];
            timeout(Duration::from_secs(1), server.read_exact(&mut echoed)).await??;
            assert_eq!(&echoed, b"ping");
            sleep(Duration::from_millis(60)).await;
        }
        assert!(!carried.is_finished(), "traffic did not keep the copy open");
        assert!(began.elapsed() > idle);
        timeout(Duration::from_secs(2), carried).await??;
        let mut rest = Vec::new();
        timeout(Duration::from_secs(1), server.read_to_end(&mut rest)).await??;
        assert_eq!(rest, Vec::<u8>::new(), "the idle copy closed its side");
        Ok(())
    }
}
