use std::collections::VecDeque;
use std::io;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Waker};

use bytes::Bytes;
use concord_common::{Address, PacketBuf, PacketSession, Tasks};
use nowhere::UdpTunnel;
use tokio::sync::mpsc;

use crate::util::lock;

/// Datagrams a session holds before its reader takes them or its pump runs.
const QUEUE: usize = 64;

struct Inbox {
    packets: VecDeque<Bytes>,
    waker: Option<Waker>,
    closed: bool,
    error: Option<(io::ErrorKind, String)>,
}

/// UDP packets over one `UdpTunnel`, which is bound to a single destination.
/// A pump task owns the tunnel: it forwards queued sends and pushes received
/// packets into the inbox, dropping the oldest when the reader falls behind.
pub(crate) struct NowherePackets {
    out: mpsc::Sender<Bytes>,
    inbox: Arc<Mutex<Inbox>>,
    send_waker: Arc<Mutex<Option<Waker>>>,
    remote: Address,
    closed: AtomicBool,
    cancel: tokio_util::sync::CancellationToken,
}

impl NowherePackets {
    pub(crate) fn new(tunnel: UdpTunnel, remote: Address, tasks: &Tasks) -> Self {
        let (out, rx) = mpsc::channel(QUEUE);
        let inbox = Arc::new(Mutex::new(Inbox {
            packets: VecDeque::new(),
            waker: None,
            closed: false,
            error: None,
        }));
        let send_waker = Arc::new(Mutex::new(None));
        let session = NowherePackets {
            out,
            inbox: inbox.clone(),
            send_waker: send_waker.clone(),
            remote,
            closed: AtomicBool::new(false),
            cancel: tunnel.cancellation(),
        };
        tasks.spawn(pump(tunnel, rx, inbox, send_waker));
        session
    }
}

async fn pump(
    mut tunnel: UdpTunnel,
    mut rx: mpsc::Receiver<Bytes>,
    inbox: Arc<Mutex<Inbox>>,
    send_waker: Arc<Mutex<Option<Waker>>>,
) {
    let cancel = tunnel.cancellation();
    let mut buf = Vec::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            received = tunnel.recv_into(&mut buf) => {
                match received {
                    Ok(Some(packet)) => {
                        let payload = Bytes::copy_from_slice(packet.payload(&buf));
                        let waker = {
                            let mut inbox = lock(&inbox);
                            if inbox.packets.len() >= QUEUE {
                                inbox.packets.pop_front();
                            }
                            inbox.packets.push_back(payload);
                            inbox.waker.take()
                        };
                        if let Some(waker) = waker {
                            waker.wake();
                        }
                    }
                    Ok(None) => break,
                    Err(err) => {
                        let mut inbox = lock(&inbox);
                        inbox.error = Some((io::ErrorKind::Other, err.to_string()));
                        if let Some(waker) = inbox.waker.take() {
                            waker.wake();
                        }
                        break;
                    }
                }
            }
            payload = rx.recv() => {
                match payload {
                    Some(payload) => {
                        if tunnel.send(&payload).await.is_err() {
                            break;
                        }
                        if let Some(waker) = lock(&send_waker).take() {
                            waker.wake();
                        }
                    }
                    None => break,
                }
            }
        }
    }
    tunnel.close().await;
    let mut inbox = lock(&inbox);
    inbox.closed = true;
    if let Some(waker) = inbox.waker.take() {
        waker.wake();
    }
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "nowhere: UDP tunnel closed")
}

impl PacketSession for NowherePackets {
    fn poll_send(
        &self,
        cx: &mut Context<'_>,
        pkt: &mut PacketBuf,
        dst: &Address,
    ) -> Poll<io::Result<()>> {
        if self.closed.load(Ordering::Relaxed) {
            return Poll::Ready(Err(closed_error()));
        }
        if *dst != self.remote {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "nowhere: UDP tunnel is bound to one destination",
            )));
        }
        match self.out.try_send(Bytes::copy_from_slice(pkt.as_slice())) {
            Ok(()) => Poll::Ready(Ok(())),
            Err(mpsc::error::TrySendError::Full(_)) => {
                *lock(&self.send_waker) = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(mpsc::error::TrySendError::Closed(_)) => Poll::Ready(Err(closed_error())),
        }
    }

    fn poll_recv(&self, cx: &mut Context<'_>, out: &mut PacketBuf) -> Poll<io::Result<Address>> {
        let mut inbox = lock(&self.inbox);
        if let Some(packet) = inbox.packets.pop_front() {
            out.extend_from_slice(&packet);
            return Poll::Ready(Ok(self.remote.clone()));
        }
        if let Some((kind, message)) = &inbox.error {
            return Poll::Ready(Err(io::Error::new(*kind, message.clone())));
        }
        if inbox.closed {
            return Poll::Ready(Err(closed_error()));
        }
        inbox.waker = Some(cx.waker().clone());
        Poll::Pending
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Relaxed);
        self.cancel.cancel();
        if let Some(waker) = lock(&self.send_waker).take() {
            waker.wake();
        }
        if let Some(waker) = lock(&self.inbox).waker.take() {
            waker.wake();
        }
    }
}
