// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Library entry point for the Nowhere Portal, Vector and Egress runtimes.

mod common;
mod egress;
mod portal;
// Concord: `protocol`, `transport` and `vector` are public so Concord's proxy crate can use the
// Nowhere client surface; the other modules stay private.
pub mod protocol;
mod telemetry;
mod toolbox;
pub mod transport;
pub mod vector;

pub use common::{Logger, query_first, validate_endpoint_url_input};
pub use egress::Egress;
pub use portal::Portal;
// Concord: the client surface Concord's proxy crate uses, re-exported at the crate root so the
// protocol implementation does not reach through `vector::`/`protocol::` internals.
pub use protocol::{ALPN, Carrier, Credentials, FlowKind, SetupResult, Target};
pub use toolbox::{
    fingerprint as run_fingerprint, generate_key, probe as run_probe, status as run_status,
};
pub use transport::Stats;
pub use vector::Vector;
pub use vector::{
    OpenFlowError, PortalClient, PortalClientConfig, ReceivedUdpPacket, TcpTunnel, UdpTunnel,
    UdpTunnelReceiver, UdpTunnelSender,
};

#[cfg(test)]
#[path = "tests/common/tls_support.rs"]
mod tls_test_support;
