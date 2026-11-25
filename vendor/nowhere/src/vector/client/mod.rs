// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Vector client state, TLS flow setup, and bounded connection shutdown.

mod quic;
// Concord: the embedding host supplies carrier sockets before protocol wrapping.
mod sockets;

pub use self::sockets::ClientSockets;

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::protocol::{
    AuthTransport, Credentials, FlowKind, SetupResult, Target, encode_auth_frame,
    encode_flow_request_into,
};
use crate::transport::{QuicConnection, Stats};

use super::config::CarrierMode;
use super::tls::ClientTls;
use super::{BoxReader, BoxWriter, OpenFlowError, PortalClientConfig, TcpTunnel, TcpTunnelGuard};

pub(crate) use self::quic::connect_quic;

// Concord: `PortalClient` is the entry point of the public client surface.
pub struct PortalClient {
    pub(crate) config: PortalClientConfig,
    pub(crate) stats: Arc<Stats>,
    pub(super) account_stats: bool,
    credentials: Credentials,
    tls: ClientTls,
    flow_setup_timeout: Duration,
    udp_queue_bytes: usize,
    quic: Mutex<Option<(quinn::Endpoint, Arc<QuicConnection>)>>,
    pub(super) shutdown: CancellationToken,
    // Concord: `None` preserves standalone dialing; embedded clients never fall back.
    sockets: Option<Arc<dyn ClientSockets>>,
}

pub(crate) struct QuicFlow {
    pub(crate) send: quinn::SendStream,
    pub(crate) recv: quinn::RecvStream,
    pub(crate) udp: Option<(
        crate::transport::UdpRoute,
        tokio::sync::mpsc::Receiver<crate::common::BudgetedDatagram>,
    )>,
}

impl PortalClient {
    // Concord: public so Concord's proxy crate can build a client without the `Vector`
    // runtime (which additionally parses the SOCKS ingress and rate limits).
    pub fn new(
        config: PortalClientConfig,
        credentials: &Credentials,
        udp_queue_bytes: usize,
        stats: Arc<Stats>,
        account_stats: bool,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>> {
        Self::build(
            config,
            credentials,
            udp_queue_bytes,
            stats,
            account_stats,
            shutdown,
            None,
        )
    }

    // Concord: one constructor owns setup for standalone and injected clients.
    fn build(
        config: PortalClientConfig,
        credentials: &Credentials,
        udp_queue_bytes: usize,
        stats: Arc<Stats>,
        account_stats: bool,
        shutdown: CancellationToken,
        sockets: Option<Arc<dyn ClientSockets>>,
    ) -> Result<Arc<Self>> {
        crate::common::validate_timeout_env()?;
        let tls = ClientTls::new(&config)?;
        let setup_timeout = config.setup_timeout;
        Ok(Arc::new(Self {
            config,
            stats,
            account_stats,
            credentials: credentials.clone(),
            tls,
            // Concord: the flow-setup timeout comes from the client
            // configuration, which reads a `setup-timeout` URL value when present.
            flow_setup_timeout: setup_timeout,
            udp_queue_bytes,
            quic: Mutex::new(None),
            shutdown,
            sockets,
        }))
    }

    // Concord: builds a client directly from a `vector://` URL, mirroring the client
    // construction in `VectorRuntime::build` (which additionally parses the SOCKS ingress
    // and rate limits the `Vector` runtime needs).
    pub fn from_url(
        url: &Url,
        stats: Arc<Stats>,
        shutdown: CancellationToken,
    ) -> Result<Arc<Self>> {
        Self::from_url_inner(url, stats, shutdown, None)
    }

    // Concord: injected clients use a resolved portal IP and the host's socket policy.
    pub fn from_url_with_sockets(
        url: &Url,
        stats: Arc<Stats>,
        shutdown: CancellationToken,
        sockets: Arc<dyn ClientSockets>,
    ) -> Result<Arc<Self>> {
        Self::from_url_inner(url, stats, shutdown, Some(sockets))
    }

    fn from_url_inner(
        url: &Url,
        stats: Arc<Stats>,
        shutdown: CancellationToken,
        sockets: Option<Arc<dyn ClientSockets>>,
    ) -> Result<Arc<Self>> {
        let (config, credentials) = PortalClientConfig::from_probe_url(url)?;
        if sockets.is_some() && config.host().parse::<std::net::IpAddr>().is_err() {
            bail!("injected client sockets require a resolved portal IP");
        }
        let udp_queue_bytes =
            crate::common::read_quic_udp_queue_bytes(&mut crate::common::env_value)?;
        Self::build(
            config,
            &credentials,
            udp_queue_bytes,
            stats,
            true,
            shutdown,
            sockets,
        )
    }

    // Concord: public so Concord's proxy crate can open TCP flows.
    pub async fn open_tcp(
        self: &Arc<Self>,
        target: &Target,
    ) -> std::result::Result<TcpTunnel, OpenFlowError> {
        let (reader, writer, mut guard) = if self.config.net == CarrierMode::Tcp {
            self.open_tls_flow(FlowKind::Tcp, target).await?
        } else {
            let flow = self.open_quic_flow(FlowKind::Tcp, target).await?;
            (
                Box::pin(flow.recv) as BoxReader,
                Box::pin(flow.send) as BoxWriter,
                TcpTunnelGuard { _flow: None },
            )
        };
        if self.account_stats {
            self.stats.add_flow(false);
            guard._flow = Some(super::flow::FlowGuard::new(self.stats.clone(), false));
        }
        Ok(TcpTunnel::new(
            reader,
            writer,
            self.config.net.carrier(),
            guard,
        ))
    }

    // Concord: opens a UDP tunnel for `target`, mirroring `open_tcp`. The free function in
    // `super::udp_flow` does the work and takes the `Arc`, so this takes `&Arc<Self>` like
    // `open_tcp` does.
    pub async fn open_udp(
        self: &Arc<Self>,
        target: &Target,
    ) -> std::result::Result<super::udp_flow::UdpTunnel, OpenFlowError> {
        super::udp_flow::open_udp(self.clone(), target).await
    }

    pub(super) async fn open_tls_flow(
        &self,
        kind: FlowKind,
        target: &Target,
    ) -> std::result::Result<(BoxReader, BoxWriter, TcpTunnelGuard), OpenFlowError> {
        let deadline = Instant::now() + self.flow_setup_timeout;
        tokio::select! {
            biased;
            _ = self.shutdown.cancelled() => Err(OpenFlowError::Cancelled),
            result = timeout_at(deadline, async {
                let (mut reader, mut writer, guard) = self.open_tls_stream()
                    .await.map_err(OpenFlowError::Transport)?;
                write_start(&mut writer, kind, target).await.map_err(OpenFlowError::Protocol)?;
                read_ready(&mut reader).await?;
                Ok((reader, writer, guard))
            }) => result.map_err(|error| OpenFlowError::Transport(error.into()))?,
        }
    }

    pub(crate) async fn open_tls_stream(&self) -> Result<(BoxReader, BoxWriter, TcpTunnelGuard)> {
        if self.shutdown.is_cancelled() {
            bail!("client shutting down");
        }
        let endpoint = self.config.tcp_endpoint().context("TLS endpoint missing")?;
        let (stream, exporter) = self
            .tls
            .connect_tcp_with_sockets(
                &self.config.remote.carrier_addr(endpoint),
                &self.config.dial_policy,
                endpoint.family,
                self.sockets.as_deref(),
            )
            .await?;
        let (reader, mut writer) = tokio::io::split(stream);
        writer
            .write_all(&encode_auth_frame(
                self.credentials.vector_key,
                AuthTransport::TlsTcp,
                &exporter,
            ))
            .await?;
        Ok((
            Box::pin(reader),
            Box::pin(writer),
            TcpTunnelGuard { _flow: None },
        ))
    }

    // Concord: public so Concord's proxy crate can shut the client down.
    pub async fn close(&self, deadline: Instant) {
        self.shutdown.cancel();
        let Ok(mut state) = tokio::time::timeout_at(deadline, self.quic.lock()).await else {
            return;
        };
        let cached = state.take();
        drop(state);
        if let Some((endpoint, q)) = cached {
            q.close();
            let _ = tokio::time::timeout_at(deadline, endpoint.wait_idle()).await;
        }
    }
}

pub(crate) async fn write_start(
    writer: &mut BoxWriter,
    kind: FlowKind,
    target: &Target,
) -> Result<()> {
    let mut request = [0; crate::protocol::TARGET_MAX_ENCODED_LEN + 1];
    let length = encode_flow_request_into(kind, target, &mut request)?;
    writer.write_all(&request[..length]).await?;
    writer.flush().await?;
    Ok(())
}

pub(crate) async fn read_ready(reader: &mut BoxReader) -> std::result::Result<(), OpenFlowError> {
    let result = crate::protocol::read_flow_result(reader)
        .await
        .map_err(OpenFlowError::Protocol)?;
    match SetupResult::from(result) {
        SetupResult::Ready => Ok(()),
        result => Err(OpenFlowError::Setup(result)),
    }
}

#[cfg(test)]
#[path = "../../tests/vector/client/mod.rs"]
mod tests;
