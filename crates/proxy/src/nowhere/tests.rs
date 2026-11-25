use concord_config::proxy::{Capabilities, ProxyKind, ProxyParse, parse_proxy};
use concord_config::proxy::{NowhereOpts, ProxyDef};
use concord_tls::TrustStore;
use serde_json::json;

use super::*;

fn opts() -> NowhereOpts {
    NowhereOpts {
        server: "n.example".into(),
        port: 443,
        password: "0123456789abcdef0123456789abcdef".into(),
        network: "tcp".into(),
        morph: true,
        ..NowhereOpts::default()
    }
}

#[test]
fn the_url_names_the_carrier_and_keeps_the_server_as_sni() {
    assert_eq!(
        vector_url(&opts(), "203.0.113.9"),
        "vector://0123456789abcdef0123456789abcdef@203.0.113.9/tcp:443?sni=n.example"
    );
}

#[test]
fn the_url_carries_every_option_only_when_set() {
    let opts = NowhereOpts {
        network: "udp".into(),
        sni: "s.example".into(),
        pin: "a".repeat(64),
        morph: false,
        cipher: NowhereCipher::Aes128Ctr,
        tcp_prelude: "full8".into(),
        udp_prelude: "low7".into(),
        handshake_timeout: 5000,
        setup_timeout: 10000,
        ..opts()
    };
    assert_eq!(
        vector_url(&opts, "2001:db8::1"),
        "vector://0123456789abcdef0123456789abcdef@[2001:db8::1]/udp:443\
         ?morph=0&cipher=aes&sni=s.example&pin=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
         &tcp-prelude=full8&udp-prelude=low7&handshake-timeout=5000&setup-timeout=10000"
    );
}

#[test]
fn an_ip_literal_server_leaves_the_sni_out() {
    let opts = NowhereOpts {
        server: "203.0.113.9".into(),
        ..opts()
    };
    assert_eq!(
        vector_url(&opts, "203.0.113.9"),
        "vector://0123456789abcdef0123456789abcdef@203.0.113.9/tcp:443"
    );
}

#[test]
fn the_url_parses_back_into_a_client_config() {
    let url = Url::parse(&vector_url(&opts(), "203.0.113.9")).unwrap();
    let (config, _) = nowhere::PortalClientConfig::from_probe_url(&url).unwrap();
    assert_eq!(config.endpoint(), "203.0.113.9/tcp:443");
}

#[test]
fn imported_cipher_reaches_the_upstream_client_for_both_carriers() {
    for cipher in NowhereCipher::ALL {
        for carrier in ["tcp", "udp"] {
            for morph in [true, false] {
                let link = format!(
                    "nowhere://0123456789abcdef0123456789abcdef@n.example:443\
                     ?net={carrier}&cipher={}&morph={}",
                    cipher.as_str(),
                    u8::from(morph)
                );
                let mut imported = concord_config::share_link::decode_subscription(&link).unwrap();
                let proxy = def(serde_json::Value::Object(imported.remove(0)));
                let ProxyKind::Nowhere(opts) = &proxy.kind else {
                    panic!("not Nowhere")
                };
                assert_eq!(opts.cipher, cipher);
                assert_eq!(opts.morph, morph);
                let url = Url::parse(&vector_url(opts, "203.0.113.9")).unwrap();
                let actual = url
                    .query_pairs()
                    .find(|(key, _)| key == "cipher")
                    .map(|(_, value)| value.into_owned());
                let expected = (cipher == NowhereCipher::Aes128Ctr).then(|| "aes".to_string());
                assert_eq!(actual, expected);
                let (config, _) = nowhere::PortalClientConfig::from_probe_url(&url).unwrap();
                assert_eq!(config.endpoint(), format!("203.0.113.9/{carrier}:443"));
            }
        }
    }
}

fn def(value: serde_json::Value) -> ProxyDef {
    let serde_json::Value::Object(map) = value else {
        panic!("not a map")
    };
    match parse_proxy(&map, &Capabilities::full()).unwrap() {
        ProxyParse::Ok(def) => *def,
        other => panic!("expected a proxy, got {other:?}"),
    }
}

#[test]
fn build_keeps_the_node_identity() {
    let ctx = BuildCtx::new(TrustStore::new(b"", Vec::new()));
    let proxy = def(
        json!({"name": "n", "type": "nowhere", "server": "n.example", "port": 443,
            "password": "0123456789abcdef0123456789abcdef", "udp": true}),
    );
    let ProxyKind::Nowhere(opts) = &proxy.kind else {
        panic!("not nowhere")
    };
    let outbound = super::build(&proxy, opts, &ctx).unwrap();
    assert_eq!(outbound.info().kind, OutboundKind::Nowhere);
    assert_eq!(&*outbound.info().name, "n");
    assert_eq!(&*outbound.info().addr, "n.example:443");
    assert!(outbound.info().udp);
    assert!(!outbound.multi_destination_udp());
}
