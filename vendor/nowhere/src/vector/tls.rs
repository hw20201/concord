// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared TLS 1.3 client policy for Vector's TCP and QUIC carriers.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use quinn::Connection;
use quinn::crypto::rustls::{HandshakeData, QuicClientConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
// Concord: aws-lc-rs is the workspace's only rustls crypto provider; ring
// would enable a second one and rustls could no longer pick a default.
use rustls::crypto::{
    WebPkiSupportedAlgorithms, aws_lc_rs, verify_tls12_signature, verify_tls13_signature,
};
#[cfg(target_os = "android")]
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use socket2::{SockRef, TcpKeepalive};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::{TlsConnector, client::TlsStream};

use crate::common::{AddressFamily, certificate_sha256, dial_tcp_with_policy};
use crate::protocol::{ALPN, TLS_EXPORTER_LEN, TlsExporter};
use crate::transport::{ClientPrelude, MorphKeys, MorphTcpStream};

use super::client::ClientSockets;
use super::config::PortalClientConfig;

pub(crate) use crate::protocol::AUTH_EXPORTER_LABEL as EXPORTER_LABEL;

#[derive(Clone)]
pub(crate) struct ClientTls {
    handshake_timeout: Duration,
    rustls: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    morph_keys: Option<MorphKeys>,
    prelude: Arc<ClientPrelude>,
}

impl ClientTls {
    pub(crate) fn new(config: &PortalClientConfig) -> Result<Self> {
        let provider = Arc::new(aws_lc_rs::default_provider());
        let builder = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("vector::tls::ClientTls::new: failed to enable TLS 1.3")?;
        let client = if let Some(pin) = &config.pin {
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(PinnedCertificateVerification {
                    pin: pin.clone(),
                    algorithms: provider.signature_verification_algorithms,
                }))
                .with_no_client_auth()
        } else {
            // Concord: `rustls-native-certs` cannot see Android's system store:
            // on Android it probes a Termux-only file and `/etc/ssl/certs`,
            // neither of which exists in a normal app, so the root set comes
            // back empty and every Nowhere node fails to build. Load the
            // roots the same way Concord's platform crate does instead.
            let roots = load_system_roots()
                .context("vector::tls::ClientTls::new: failed to load system roots")?;
            if roots.is_empty() {
                bail!("vector::tls::ClientTls::new: no system trust roots available");
            }
            builder.with_root_certificates(roots).with_no_client_auth()
        };
        Self::with_config(config, client)
    }

    fn with_config(config: &PortalClientConfig, mut client: rustls::ClientConfig) -> Result<Self> {
        client.alpn_protocols = vec![ALPN.to_vec()];
        client.enable_early_data = false;

        let server_name =
            ServerName::try_from(config.sni.as_deref().unwrap_or(config.host()).to_owned())
                .map_err(|_| anyhow!("vector::tls::ClientTls::new: invalid TLS server name"))?;
        Ok(Self {
            handshake_timeout: config.handshake_timeout,
            rustls: Arc::new(client),
            server_name,
            morph_keys: config.morph_keys.clone(),
            prelude: Arc::new(ClientPrelude::default()),
        })
    }

    pub(crate) fn quic_client_config(&self) -> Result<quinn::ClientConfig> {
        let quic_crypto = QuicClientConfig::try_from(self.rustls.clone())
            .map_err(|error| anyhow!("vector::tls::ClientTls::quic_client_config: {error}"))?;
        Ok(quinn::ClientConfig::new(Arc::new(quic_crypto)))
    }

    pub(crate) fn quic_server_name(&self) -> String {
        match &self.server_name {
            ServerName::DnsName(name) => name.as_ref().to_owned(),
            ServerName::IpAddress(address) => std::net::IpAddr::from(*address).to_string(),
            _ => self.server_name.to_str().into_owned(),
        }
    }

    pub(crate) async fn connect_tcp(
        &self,
        endpoint: &str,
        dial_policy: &crate::common::DialPolicy,
        family: AddressFamily,
    ) -> Result<(TlsStream<MorphTcpStream<TcpStream>>, TlsExporter)> {
        self.connect_tcp_with_keepalive(endpoint, dial_policy, family, None)
            .await
    }

    pub(crate) async fn connect_tcp_with_keepalive(
        &self,
        endpoint: &str,
        dial_policy: &crate::common::DialPolicy,
        family: AddressFamily,
        keepalive: Option<&TcpKeepalive>,
    ) -> Result<(TlsStream<MorphTcpStream<TcpStream>>, TlsExporter)> {
        self.connect_tcp_inner(endpoint, dial_policy, family, keepalive, None)
            .await
    }

    // Concord: injected sockets are already routed/protected before any carrier bytes.
    pub(crate) async fn connect_tcp_with_sockets(
        &self,
        endpoint: &str,
        dial_policy: &crate::common::DialPolicy,
        family: AddressFamily,
        sockets: Option<&dyn ClientSockets>,
    ) -> Result<(TlsStream<MorphTcpStream<TcpStream>>, TlsExporter)> {
        self.connect_tcp_inner(endpoint, dial_policy, family, None, sockets)
            .await
    }

    async fn connect_tcp_inner(
        &self,
        endpoint: &str,
        dial_policy: &crate::common::DialPolicy,
        family: AddressFamily,
        keepalive: Option<&TcpKeepalive>,
        sockets: Option<&dyn ClientSockets>,
    ) -> Result<(TlsStream<MorphTcpStream<TcpStream>>, TlsExporter)> {
        let stream = if let Some(sockets) = sockets {
            let peer = endpoint
                .parse::<std::net::SocketAddr>()
                .context("injected client sockets require a resolved TCP endpoint")?;
            if !dial_policy.accepts(peer.ip()) || !family.accepts(peer.ip()) {
                bail!("TCP endpoint does not match configured address family");
            }
            timeout(self.handshake_timeout, sockets.connect_tcp(peer))
                .await
                .context("TCP dial timeout")?
                .map_err(anyhow::Error::from)
        } else {
            dial_tcp_with_policy(dial_policy, endpoint, self.handshake_timeout, family).await
        }
        .with_context(|| format!("vector::tls::connect_tcp: failed to dial {endpoint}"))?;
        stream
            .set_nodelay(true)
            .context("vector::tls::connect_tcp: failed to set TCP_NODELAY")?;
        if let Some(keepalive) = keepalive {
            SockRef::from(&stream)
                .set_tcp_keepalive(keepalive)
                .context("Egress TLS: failed to configure TCP keepalive")?;
        }
        let connector = TlsConnector::from(self.rustls.clone());
        let tls = timeout(self.handshake_timeout, async {
            let stream =
                MorphTcpStream::connect(stream, self.morph_keys.clone(), &self.prelude).await?;
            connector.connect(self.server_name.clone(), stream).await
        })
        .await
        .context("vector::tls::connect_tcp: TLS handshake timeout")?
        .context("vector::tls::connect_tcp: TLS handshake failed")?;
        require_nw3(tls.get_ref().1.alpn_protocol())
            .context("vector::tls::connect_tcp: invalid negotiated protocol")?;
        let mut exporter = [0u8; TLS_EXPORTER_LEN];
        tls.get_ref()
            .1
            .export_keying_material(&mut exporter, EXPORTER_LABEL, Some(&[]))
            .context("vector::tls::connect_tcp: TLS exporter failed")?;
        Ok((tls, exporter))
    }
}

// Concord: public so Concord's proxy crate can fetch a leaf certificate's
// fingerprint for the `pin=` workflow.
pub async fn fetch_certificate_fingerprint(config: &PortalClientConfig) -> Result<String> {
    crate::common::validate_timeout_env()?;
    let endpoint = config
        .tcp_endpoint()
        .context("TCP carrier is not configured")?;
    let provider = Arc::new(aws_lc_rs::default_provider());
    let client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(FingerprintCertificateInspection {
            algorithms: provider.signature_verification_algorithms,
        }))
        .with_no_client_auth();
    let tls = ClientTls::with_config(config, client)?;
    let (stream, _) = tls
        .connect_tcp(
            &config.remote.carrier_addr(endpoint),
            &config.dial_policy,
            endpoint.family,
        )
        .await?;
    let certificate = stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|chain| chain.first())
        .context("Portal did not provide a TLS certificate")?;
    Ok(certificate_sha256(certificate))
}

pub(crate) fn require_quic_nw3(connection: &Connection) -> Result<()> {
    let handshake = connection
        .handshake_data()
        .ok_or_else(|| anyhow!("vector::tls: QUIC handshake data unavailable"))?
        .downcast::<HandshakeData>()
        .map_err(|_| anyhow!("vector::tls: unexpected QUIC handshake data"))?;
    require_nw3(handshake.protocol.as_deref())
        .context("vector::tls: invalid QUIC negotiated protocol")
}

fn require_nw3(alpn: Option<&[u8]>) -> Result<()> {
    match alpn {
        Some(ALPN) => Ok(()),
        Some(_) => bail!("unsupported negotiated ALPN"),
        None => bail!("peer did not negotiate ALPN"),
    }
}

#[derive(Clone)]
struct PinnedCertificateVerification {
    pin: String,
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for PinnedCertificateVerification {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PinnedCertificateVerification")
    }
}

impl ServerCertVerifier for PinnedCertificateVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if certificate_sha256(end_entity) != self.pin {
            return Err(rustls::Error::General(
                "server certificate pin mismatch".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[derive(Clone)]
struct FingerprintCertificateInspection {
    algorithms: WebPkiSupportedAlgorithms,
}

impl fmt::Debug for FingerprintCertificateInspection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FingerprintCertificateInspection")
    }
}

impl ServerCertVerifier for FingerprintCertificateInspection {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, certificate, signature, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, certificate, signature, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

// Concord: system root certificates, Android-aware. Android keeps its system
// CA store at `/system/etc/security/cacerts` and
// `/apex/com.android.conscrypt/cacerts`; `rustls-native-certs` does not look
// there (it probes a Termux-only file and `/etc/ssl/certs`), so on Android
// read those two directories directly. Elsewhere, use the OS store through
// `rustls-native-certs`, tolerating individual load errors instead of failing
// the whole client when one certificate cannot be read.
fn load_system_roots() -> Result<rustls::RootCertStore> {
    #[cfg(target_os = "android")]
    {
        let mut roots = rustls::RootCertStore::empty();
        for dir in [
            "/system/etc/security/cacerts",
            "/apex/com.android.conscrypt/cacerts",
        ] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let Ok(bytes) = std::fs::read(entry.path()) else {
                    continue;
                };
                for cert in CertificateDer::pem_slice_iter(&bytes).flatten() {
                    let _ = roots.add(cert);
                }
            }
        }
        Ok(roots)
    }
    #[cfg(not(target_os = "android"))]
    {
        let native = rustls_native_certs::load_native_certs();
        let mut roots = rustls::RootCertStore::empty();
        for certificate in native.certs {
            let _ = roots.add(certificate);
        }
        Ok(roots)
    }
}

#[cfg(test)]
#[path = "../tests/vector/tls.rs"]
mod tests;
