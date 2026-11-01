// SPDX-License-Identifier: GPL-3.0-or-later
//! Receives the listening sockets the macOS root supervisor creates for
//! peer-machine names. They travel as `SCM_RIGHTS` with one system request
//! (ADR-0033 amendment). This is the only place `remapd` accepts a descriptor
//! from another process.
#![allow(unsafe_code)]

use std::io::{self, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::fcntl::{FcntlArg, FdFlag, fcntl};
use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
use remap_protocol::{MAX_LISTENERS_PER_EXCHANGE, MAX_SYSTEM_FRAME_BYTES};
use tokio::io::Interest;
use tokio::net::UnixStream;

/// One system frame and every descriptor that arrived with it.
pub(crate) struct ReceivedFrame {
    pub(crate) payload: Vec<u8>,
    pub(crate) descriptors: Vec<OwnedFd>,
}

/// Reads one length-prefixed system frame, keeping any descriptors sent with
/// it. A frame that carries more than one exchange's worth of descriptors, or
/// whose control data the kernel truncated, is refused; every descriptor
/// already received is closed when the error drops them.
pub(crate) async fn read_frame(stream: &UnixStream) -> io::Result<ReceivedFrame> {
    let mut descriptors = Vec::new();
    let mut header = [0_u8; 4];
    fill(stream, &mut header, &mut descriptors).await?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(invalid)?;
    if length > MAX_SYSTEM_FRAME_BYTES {
        return Err(invalid("a system frame exceeds its limit"));
    }
    let mut payload = vec![0_u8; length];
    fill(stream, &mut payload, &mut descriptors).await?;
    Ok(ReceivedFrame {
        payload,
        descriptors,
    })
}

async fn fill(
    stream: &UnixStream,
    buffer: &mut [u8],
    descriptors: &mut Vec<OwnedFd>,
) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = stream
            .async_io(Interest::READABLE, || {
                receive(stream.as_raw_fd(), &mut buffer[filled..], descriptors)
            })
            .await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += read;
    }
    Ok(())
}

fn receive(socket: RawFd, buffer: &mut [u8], descriptors: &mut Vec<OwnedFd>) -> io::Result<usize> {
    let mut iov = [IoSliceMut::new(buffer)];
    let mut space = nix::cmsg_space!([RawFd; MAX_LISTENERS_PER_EXCHANGE]);
    let message = recvmsg::<()>(socket, &mut iov, Some(&mut space), MsgFlags::empty())
        .map_err(io::Error::from)?;
    let truncated = message.flags.contains(MsgFlags::MSG_CTRUNC);
    for control in message.cmsgs().map_err(io::Error::from)? {
        if let ControlMessageOwned::ScmRights(received) = control {
            for raw in received {
                // SAFETY: SCM_RIGHTS installed this descriptor in this process
                // for this message alone. Nothing else knows its number, it has
                // not been closed, and OwnedFd becomes its sole closing owner.
                let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
                let _flags = fcntl(&descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))?;
                descriptors.push(descriptor);
            }
        }
    }
    if truncated || descriptors.len() > MAX_LISTENERS_PER_EXCHANGE {
        return Err(invalid(
            "a system frame carried more descriptors than one exchange allows",
        ));
    }
    Ok(message.bytes)
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::io::IoSlice;
    use std::os::fd::{AsFd, AsRawFd, OwnedFd};

    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use tokio::net::UnixStream;

    use super::read_frame;

    fn send(
        stream: &UnixStream,
        payload: &[u8],
        descriptors: &[OwnedFd],
    ) -> Result<(), Box<dyn Error>> {
        let mut frame = u32::try_from(payload.len())?.to_be_bytes().to_vec();
        frame.extend_from_slice(payload);
        let raw: Vec<_> = descriptors.iter().map(AsRawFd::as_raw_fd).collect();
        let rights = [ControlMessage::ScmRights(&raw)];
        let control: &[ControlMessage<'_>] = if raw.is_empty() { &[] } else { &rights };
        let sent = sendmsg::<()>(
            stream.as_fd().as_raw_fd(),
            &[IoSlice::new(&frame)],
            control,
            MsgFlags::empty(),
            None,
        )?;
        assert_eq!(sent, frame.len());
        Ok(())
    }

    fn pipe_ends() -> Result<Vec<OwnedFd>, Box<dyn Error>> {
        let (read, write) = nix::unistd::pipe()?;
        Ok(vec![read, write])
    }

    #[tokio::test]
    async fn a_frame_keeps_the_descriptors_sent_with_it() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = UnixStream::pair()?;
        let descriptors = pipe_ends()?;
        send(&sender, br#"{"kind":"probe"}"#, &descriptors)?;
        let frame = read_frame(&receiver).await?;
        assert_eq!(frame.payload, br#"{"kind":"probe"}"#);
        assert_eq!(frame.descriptors.len(), 2);
        // The received descriptors are new numbers for the same open files.
        for (received, original) in frame.descriptors.iter().zip(&descriptors) {
            assert_ne!(received.as_raw_fd(), original.as_raw_fd());
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_frame_without_descriptors_carries_none() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = UnixStream::pair()?;
        send(&sender, b"{}", &[])?;
        let frame = read_frame(&receiver).await?;
        assert!(frame.descriptors.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn more_descriptors_than_one_exchange_allows_are_refused() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = UnixStream::pair()?;
        let mut descriptors = Vec::new();
        for _pair in 0..33 {
            descriptors.extend(pipe_ends()?);
        }
        send(&sender, b"{}", &descriptors)?;
        assert!(read_frame(&receiver).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn an_oversized_frame_is_refused() -> Result<(), Box<dyn Error>> {
        let (sender, receiver) = UnixStream::pair()?;
        let header = u32::try_from(remap_protocol::MAX_SYSTEM_FRAME_BYTES + 1)?.to_be_bytes();
        sendmsg::<()>(
            sender.as_fd().as_raw_fd(),
            &[IoSlice::new(&header)],
            &[],
            MsgFlags::empty(),
            None,
        )?;
        assert!(read_frame(&receiver).await.is_err());
        Ok(())
    }
}
