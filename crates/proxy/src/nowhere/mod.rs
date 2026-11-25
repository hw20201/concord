mod packet;
#[cfg(test)]
#[path = "tests/sockets.rs"]
mod socket_tests;
mod stream;
#[cfg(test)]
mod tests;

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use concord_common::{
    Address, BoxStream, DialCx, IpVersion, Outbound, OutboundInfo, OutboundKind, PacketSession,
    SockOpts, SocketFactory, Tasks,
};
use concord_config::proxy::{NowhereCipher, NowhereOpts, ProxyDef};
use nowhere::{OpenFlowError, PortalClient, Stats, Target};
use tokio::sync::Mutex;
use tokio::time::Instant;
use url::Url;

use self::packet::NowherePackets;
use self::stream::NowhereStream;
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{info_for, ip_version, resolve_server};

/// Time to drain a cached QUIC connection after a reset: the vendored
/// client's own shutdown default.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(5);

/// One Nowhere node: a lazily built `PortalClient` shared by its flows.
///
/// The client is built on the first dial, with the portal host resolved through
/// Concord's DNS and carrier sockets opened through the session's socket factory.
/// The URL carries the resolved IP and preserves the configured TLS name in SNI.
/// A reset drops the client; the next dial resolves and builds a fresh one.
pub(crate) struct Nowhere {
    info: OutboundInfo,
    opts: NowhereOpts,
    version: IpVersion,
    stats: Arc<Stats>,
    client: Arc<Mutex<Option<Arc<PortalClient>>>>,
    tasks: Tasks,
}

struct NowhereSockets {
    sockets: Arc<dyn SocketFactory>,
    opts: SockOpts,
}

impl nowhere::ClientSockets for NowhereSockets {
    fn connect_tcp(
        &self,
        peer: SocketAddr,
    ) -> Pin<Box<dyn Future<Output = io::Result<tokio::net::TcpStream>> + Send + '_>> {
        self.sockets.connect_tcp(peer, &self.opts)
    }

    fn bind_udp(&self, peer: SocketAddr) -> io::Result<std::net::UdpSocket> {
        let opts = SockOpts {
            tunnel_udp_buffers: true,
            ..self.opts.clone()
        };
        self.sockets.bind_udp(peer.ip(), &opts)?.into_std()
    }
}

impl Nowhere {
    async fn client(&self, cx: &DialCx<'_>) -> io::Result<Arc<PortalClient>> {
        let mut slot = self.client.lock().await;
        if let Some(client) = slot.as_ref() {
            return Ok(client.clone());
        }
        let resolved = resolve_server(
            cx,
            &Address::new(&self.opts.server, self.opts.port),
            self.version,
        )
        .await?;
        let url = vector_url(&self.opts, &resolved.ip().to_string());
        let parsed = Url::parse(&url).map_err(io::Error::other)?;
        let client = PortalClient::from_url_with_sockets(
            &parsed,
            self.stats.clone(),
            tokio_util::sync::CancellationToken::new(),
            Arc::new(NowhereSockets {
                sockets: cx.env.sockets.clone(),
                opts: cx.env.sock_opts.clone(),
            }),
        )
        .map_err(io::Error::other)?;
        *slot = Some(client.clone());
        Ok(client)
    }
}

fn open_error(err: OpenFlowError) -> io::Error {
    match err {
        OpenFlowError::Cancelled => {
            io::Error::new(io::ErrorKind::Interrupted, "nowhere: flow cancelled")
        }
        err => io::Error::other(err),
    }
}

fn target(dst: &Address) -> io::Result<Target> {
    match dst {
        Address::Socket(addr) => Target::ip(*addr).map_err(io::Error::other),
        Address::Domain(host, port) => {
            Target::domain(host.to_string(), *port).map_err(io::Error::other)
        }
    }
}

#[async_trait]
impl Outbound for Nowhere {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let client = self.client(cx).await?;
        let tunnel = client.open_tcp(&target(dst)?).await.map_err(open_error)?;
        Ok(Box::new(NowhereStream::new(tunnel)))
    }

    async fn associate(
        &self,
        cx: &DialCx<'_>,
        hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        if !self.info.udp {
            return Err(io::Error::other("nowhere: UDP is disabled for this node"));
        }
        let client = self.client(cx).await?;
        let tunnel = client.open_udp(&target(hint)?).await.map_err(open_error)?;
        Ok(Arc::new(NowherePackets::new(
            tunnel,
            hint.clone(),
            &self.tasks,
        )))
    }

    /// A UDP tunnel is bound to the one destination it was opened for.
    fn multi_destination_udp(&self) -> bool {
        false
    }

    fn reset_sessions(&self) {
        let slot = self.client.clone();
        self.tasks.spawn_to_end(async move {
            if let Some(client) = slot.lock().await.take() {
                client.close(Instant::now() + SHUTDOWN_DRAIN).await;
            }
        });
    }
}

/// The `vector://` URL for a node, with the portal host already an IP literal.
/// The carrier rides in the path, since a bare `HOST:PORT` URL would open the
/// TLS carrier for both. The SNI rides in the query whenever it is a DNS name,
/// so the literal host does not become the TLS server name; an IP literal as
/// the SNI is left out and the client verifies the literal itself.
fn vector_url(opts: &NowhereOpts, host: &str) -> String {
    let carrier = if opts.network == "udp" { "udp" } else { "tcp" };
    let authority = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let mut url = format!(
        "vector://{}@{authority}/{carrier}:{}",
        opts.password, opts.port
    );
    let mut query = Vec::new();
    if !opts.morph {
        query.push("morph=0".to_string());
    }
    if opts.cipher != NowhereCipher::ChaCha {
        query.push(format!("cipher={}", opts.cipher.as_str()));
    }
    let sni = if opts.sni.is_empty() {
        opts.server.clone()
    } else {
        opts.sni.clone()
    };
    if sni.parse::<IpAddr>().is_err() {
        query.push(format!("sni={sni}"));
    }
    if !opts.pin.is_empty() {
        query.push(format!("pin={}", opts.pin));
    }
    if !opts.tcp_prelude.is_empty() {
        query.push(format!("tcp-prelude={}", opts.tcp_prelude));
    }
    if !opts.udp_prelude.is_empty() {
        query.push(format!("udp-prelude={}", opts.udp_prelude));
    }
    if opts.handshake_timeout > 0 {
        query.push(format!("handshake-timeout={}", opts.handshake_timeout));
    }
    if opts.setup_timeout > 0 {
        query.push(format!("setup-timeout={}", opts.setup_timeout));
    }
    if !query.is_empty() {
        url.push('?');
        url.push_str(&query.join("&"));
    }
    url
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &NowhereOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    Ok(Arc::new(Nowhere {
        info: info_for(
            def,
            OutboundKind::Nowhere,
            &opts.server,
            opts.port,
            def.common.udp,
        ),
        opts: opts.clone(),
        version: ip_version(def.common.ip_version),
        stats: Arc::new(Stats::default()),
        client: Arc::new(Mutex::new(None)),
        tasks: ctx.tasks.clone(),
    }))
}
