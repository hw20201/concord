use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use concord_common::Stream;
use nowhere::TcpTunnel;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A `TcpTunnel` as a Concord `Stream`. The tunnel owns its TLS or QUIC
/// carrier, so nothing beneath it is forwarded: the policy keeps the trait
/// defaults, which copy through this type's own I/O.
pub(crate) struct NowhereStream {
    inner: TcpTunnel,
}

impl NowhereStream {
    pub(crate) fn new(inner: TcpTunnel) -> Self {
        NowhereStream { inner }
    }
}

impl AsyncRead for NowhereStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NowhereStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Stream for NowhereStream {
    concord_common::stream_policy!(default: all);
}
