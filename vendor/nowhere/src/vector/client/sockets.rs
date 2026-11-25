// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

// Concord: embedding hosts create carrier sockets before Morph/TLS/QUIC wraps them,
// so their routing, VPN protection and descriptor-pressure policy cannot be skipped.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use tokio::net::TcpStream;

/// Carrier sockets for a client whose portal address has already been resolved.
pub trait ClientSockets: Send + Sync {
    fn connect_tcp(
        &self,
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<TcpStream>> + Send + '_>>;

    /// Returns an unconnected, nonblocking socket routed for `peer`.
    fn bind_udp(&self, peer: SocketAddr) -> io::Result<std::net::UdpSocket>;
}
