#![allow(
    clippy::disallowed_methods,
    reason = "loopback carrier fixtures never leave the test process"
)]

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::sync::lock;
use concord_common::{Address, DialCx, DialEnv, Initiator, Outbound, SockOpts, SocketFactory};
use concord_config::proxy::{Capabilities, ProxyKind, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use nowhere::OpenFlowError;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::ctx::BuildCtx;
use crate::testing::test_env;

const REFUSED: &str = "carrier socket factory refused the socket";
const WAIT: Duration = Duration::from_secs(2);

#[derive(Default)]
struct Factory {
    tcp_calls: Mutex<Vec<(SocketAddr, SockOpts)>>,
    udp_calls: Mutex<Vec<(IpAddr, SockOpts)>>,
    tcp: Mutex<Option<TcpStream>>,
    udp: Mutex<Option<UdpSocket>>,
}

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, REFUSED)
}

#[async_trait]
impl SocketFactory for Factory {
    async fn connect_tcp(&self, peer: SocketAddr, opts: &SockOpts) -> io::Result<TcpStream> {
        lock(&self.tcp_calls).push((peer, opts.clone()));
        lock(&self.tcp).take().ok_or_else(refused)
    }

    fn bind_udp(&self, peer: IpAddr, opts: &SockOpts) -> io::Result<UdpSocket> {
        lock(&self.udp_calls).push((peer, opts.clone()));
        lock(&self.udp).take().ok_or_else(refused)
    }
}

fn env(factory: Arc<Factory>) -> DialEnv {
    DialEnv {
        sockets: factory,
        sock_opts: SockOpts {
            interface: Some("test-interface".into()),
            routing_mark: Some(42),
            ..SockOpts::default()
        },
        ..test_env()
    }
}

fn node(carrier: &str, port: u16) -> Arc<dyn Outbound> {
    let serde_json::Value::Object(map) = json!({
        "name": "carrier-fixture",
        "type": "nowhere",
        "server": "127.0.0.1",
        "port": port,
        "password": "0".repeat(32),
        "pin": "0".repeat(64),
        "network": carrier,
        "morph": false,
        "udp": true
    }) else {
        unreachable!()
    };
    let ProxyParse::Ok(def) = parse_proxy(&map, &Capabilities::full()).unwrap() else {
        panic!("fixture configuration did not parse")
    };
    let ProxyKind::Nowhere(opts) = &def.kind else {
        panic!("fixture is not Nowhere")
    };
    super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new()))).unwrap()
}

fn factory_error(err: io::Error) {
    let Some(OpenFlowError::Transport(cause)) = err
        .get_ref()
        .and_then(|err| err.downcast_ref::<OpenFlowError>())
    else {
        panic!("expected the carrier factory's transport error, got {err:?}")
    };
    assert!(
        cause.chain().any(|cause| {
            cause.downcast_ref::<io::Error>().is_some_and(|err| {
                err.kind() == io::ErrorKind::PermissionDenied && err.to_string() == REFUSED
            })
        }),
        "factory error was replaced: {cause:#}"
    );
}

fn tcp_call(factory: &Factory, peer: SocketAddr) {
    let calls = lock(&factory.tcp_calls);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, peer);
    assert_eq!(calls[0].1.interface.as_deref(), Some("test-interface"));
    assert_eq!(calls[0].1.routing_mark, Some(42));
    assert!(lock(&factory.udp_calls).is_empty());
}

fn udp_call(factory: &Factory, peer: IpAddr) {
    let calls = lock(&factory.udp_calls);
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, peer);
    assert_eq!(calls[0].1.interface.as_deref(), Some("test-interface"));
    assert_eq!(calls[0].1.routing_mark, Some(42));
    assert!(calls[0].1.tunnel_udp_buffers);
    assert!(lock(&factory.tcp_calls).is_empty());
}

#[tokio::test]
async fn tcp_factory_error_prevents_a_raw_carrier_connection() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let peer = listener.local_addr().unwrap();
    let factory = Arc::new(Factory::default());
    let env = env(factory.clone());
    let cx = DialCx::new(&env, Initiator::App, None);
    let node = node("tcp", peer.port());
    let dst = Address::new("example.com", 443);
    let result = timeout(WAIT, node.connect(&cx, &dst)).await.unwrap();
    let err = match result {
        Ok(_) => panic!("a denied TCP factory opened a tunnel"),
        Err(err) => err,
    };
    factory_error(err);
    tcp_call(&factory, peer);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn quic_factory_error_prevents_raw_udp_packets() {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket.set_nonblocking(true).unwrap();
    let peer = socket.local_addr().unwrap();
    let factory = Arc::new(Factory::default());
    let env = env(factory.clone());
    let cx = DialCx::new(&env, Initiator::App, None);
    let node = node("udp", peer.port());
    let dst = Address::new("example.com", 443);
    let result = timeout(WAIT, node.connect(&cx, &dst)).await.unwrap();
    let err = match result {
        Ok(_) => panic!("a denied UDP factory opened a tunnel"),
        Err(err) => err,
    };
    factory_error(err);
    udp_call(&factory, peer.ip());
    assert_eq!(
        socket.recv_from(&mut [0; 2048]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn tcp_tls_uses_the_factory_stream_instead_of_dialing_the_portal() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let portal = listener.local_addr().unwrap();
    let (supplied, mut peer) = concord_test_support::tcp_pair().await;
    let factory = Arc::new(Factory {
        tcp: Mutex::new(Some(supplied)),
        ..Factory::default()
    });
    let env = env(factory.clone());
    let cx = DialCx::new(&env, Initiator::App, None);
    let node = node("tcp", portal.port());
    let dst = Address::new("example.com", 443);
    let opening = node.connect(&cx, &dst);
    tokio::pin!(opening);
    let mut first = [0];
    timeout(WAIT, async {
        tokio::select! {
            result = &mut opening => panic!("TLS setup completed without a peer: {}", result.is_ok()),
            result = peer.read_exact(&mut first) => { result.unwrap(); }
        }
    }).await.unwrap();
    assert_eq!(
        first[0], 0x16,
        "the supplied stream did not carry a TLS handshake"
    );
    tcp_call(&factory, portal);
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test]
async fn quic_packets_keep_the_factory_udp_socket_source_port() {
    let peer = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let portal = peer.local_addr().unwrap();
    let supplied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let source = supplied.local_addr().unwrap();
    let factory = Arc::new(Factory {
        udp: Mutex::new(Some(supplied)),
        ..Factory::default()
    });
    let env = env(factory.clone());
    let cx = DialCx::new(&env, Initiator::App, None);
    let node = node("udp", portal.port());
    let dst = Address::new("example.com", 443);
    let opening = node.connect(&cx, &dst);
    tokio::pin!(opening);
    let mut packet = [0; 2048];
    let (len, from) = timeout(WAIT, async {
        tokio::select! {
            result = &mut opening => panic!("QUIC setup completed without a peer: {}", result.is_ok()),
            result = peer.recv_from(&mut packet) => result.unwrap()
        }
    }).await.unwrap();
    assert!(len > 0);
    assert_eq!(
        from, source,
        "QUIC replaced the factory's protected UDP socket"
    );
    udp_call(&factory, portal.ip());
}
