use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use concord_config::proxy::{NowhereCipher, NowhereOpts};
use concord_config::share_link::{decode_subscription, encode_link};
use concord_config::{
    Capabilities, Map, ProxyKind, ProxyParse, parse_provider_content, parse_proxy,
};
use serde_json::{Value, json};

fn node() -> Map {
    json!({
        "name": "cipher-fixture",
        "type": "nowhere",
        "server": "n.example",
        "port": 443,
        "password": "0123456789abcdef0123456789abcdef"
    })
    .as_object()
    .unwrap()
    .clone()
}

fn opts(map: &Map) -> NowhereOpts {
    let ProxyParse::Ok(def) = parse_proxy(map, &Capabilities::full()).unwrap() else {
        panic!("Nowhere fixture was quarantined")
    };
    let ProxyKind::Nowhere(opts) = def.kind else {
        panic!("fixture is not Nowhere")
    };
    *opts
}

#[test]
fn nowhere_cipher_defaults_to_chacha_and_accepts_the_upstream_tokens() {
    let mut map = node();
    assert_eq!(opts(&map).cipher, NowhereCipher::ChaCha);
    assert_eq!(NowhereOpts::default().cipher, NowhereCipher::ChaCha);
    map.insert("cipher".into(), Value::Null);
    assert_eq!(opts(&map).cipher, NowhereCipher::ChaCha);
    for cipher in NowhereCipher::ALL {
        map.insert("cipher".into(), json!(cipher.as_str()));
        assert_eq!(opts(&map).cipher, cipher);
        map.insert("morph".into(), json!(false));
        let parsed = opts(&map);
        assert_eq!(parsed.cipher, cipher);
        assert!(!parsed.morph);
    }
}

#[test]
fn nowhere_rejects_invalid_cipher_values_even_when_morph_is_disabled() {
    for morph in [true, false] {
        for cipher in [
            json!(""),
            json!("AES"),
            json!("aes-128-ctr"),
            json!("chacha20"),
            json!("aes "),
            json!(false),
            json!(1),
            json!([]),
            json!({}),
        ] {
            let mut map = node();
            map.insert("morph".into(), json!(morph));
            map.insert("cipher".into(), cipher.clone());
            let error = parse_proxy(&map, &Capabilities::full()).unwrap_err();
            assert!(error.message.contains("cipher"), "{cipher:?}: {error:?}");
            assert!(encode_link(&map).is_empty(), "{cipher:?}");
        }
    }
}

#[test]
fn nowhere_cipher_survives_share_links_and_every_subscription_encoding() {
    for cipher in NowhereCipher::ALL {
        for carrier in ["tcp", "udp"] {
            for morph in [true, false] {
                let mut map = node();
                map.insert("cipher".into(), json!(cipher.as_str()));
                map.insert("network".into(), json!(carrier));
                map.insert("morph".into(), json!(morph));
                let expected = opts(&map);
                let link = encode_link(&map);
                assert!(link.contains(&format!("cipher={}", cipher.as_str())));
                let decoded = decode_subscription(&link).unwrap();
                assert_eq!(decoded.len(), 1);
                assert_eq!(decoded[0]["cipher"], cipher.as_str());
                assert_eq!(opts(&decoded[0]), expected);
                let yaml = json!({"proxies": [map]}).to_string();
                for subscription in [link.clone(), STANDARD.encode(&link), yaml] {
                    let imported = parse_provider_content(subscription.as_bytes(), None).unwrap();
                    assert_eq!(imported.len(), 1);
                    assert_eq!(opts(&imported[0]), expected, "{subscription}");
                }
            }
        }
    }
}

#[test]
fn nowhere_share_links_preserve_invalid_cipher_values_for_rejection() {
    for query in [
        "cipher",
        "cipher=",
        "cipher=AES",
        "cipher=aes-128-ctr",
        "cipher=&cipher=aes",
    ] {
        let link =
            format!("nowhere://0123456789abcdef0123456789abcdef@n.example:443?{query}#fixture");
        let imported = decode_subscription(&link).unwrap();
        assert_eq!(imported.len(), 1);
        assert!(imported[0].contains_key("cipher"));
        let error = parse_proxy(&imported[0], &Capabilities::full()).unwrap_err();
        assert_eq!(error.message, "nowhere: cipher must be chacha or aes");
    }
}

#[test]
fn nowhere_share_links_keep_the_first_cipher_and_legacy_default() {
    let legacy = encode_link(&node());
    assert!(!legacy.split('#').next().unwrap().contains("cipher"));
    let imported = decode_subscription(&legacy).unwrap();
    assert!(!imported[0].contains_key("cipher"));
    assert_eq!(opts(&imported[0]).cipher, NowhereCipher::ChaCha);
    let link = "nowhere://0123456789abcdef0123456789abcdef@n.example:443?cipher=aes&cipher=chacha";
    let imported = decode_subscription(link).unwrap();
    assert_eq!(opts(&imported[0]).cipher, NowhereCipher::Aes128Ctr);
}
