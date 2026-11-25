use serde_json::{Map, Value, json};

use concord_common::options::{CONGESTION_CONTROLLERS, FindProcessMode, LogLevel, TunnelMode};

use crate::dns::{CacheAlgorithm, EnhancedMode, FakeIpFilterMode};
use crate::keys;
use crate::proxy::{IP_STACK_MODES, NowhereCipher, T0_PROXY_TYPES, T1_PROXY_TYPES, T2_PROXY_TYPES};
use crate::rule::{T0_RULE_TYPES, T1_RULE_TYPES};
use crate::tun::TUN_STACKS;

fn tiers(t0: &[&str], t1: &[&str], t2: &[&str]) -> Value {
    json!({"t0": t0, "t1": t1, "t2": t2})
}

fn key_tiers(tiers: &keys::Tiers, defaults: Value) -> Value {
    json!({"t0": tiers.t0, "t1": tiers.t1, "t2": tiers.t2, "inert": tiers.inert, "defaults": defaults})
}

/// What a profile that leaves a key out gets, which is mihomo's default.
fn section_defaults(section: &str) -> Value {
    let dns = keys::dns_defaults();
    Value::Object(match section {
        "" => keys::general_defaults(),
        "dns" => dns,
        "dns.fallback-filter" => match dns.get("fallback-filter") {
            Some(Value::Object(filter)) => filter.clone(),
            _ => Map::new(),
        },
        "tun" => keys::tun_defaults(),
        "sniffer" => keys::sniffer_defaults(),
        "ntp" => keys::ntp_defaults(),
        "geox-url" => keys::geox_defaults(),
        "profile" => keys::profile_defaults(),
        _ => Map::new(),
    })
}

fn names<T: Copy>(all: &[T], name: fn(T) -> &'static str) -> Value {
    json!(all.iter().map(|value| name(*value)).collect::<Vec<_>>())
}

fn section_values(section: &str) -> Value {
    match section {
        "" => json!({
            "mode": names(&TunnelMode::ALL, TunnelMode::as_str),
            "log-level": names(&LogLevel::ALL, LogLevel::as_str),
            "find-process-mode": names(&FindProcessMode::ALL, FindProcessMode::as_str),
        }),
        "dns" => json!({
            "enhanced-mode": names(&EnhancedMode::ALL, EnhancedMode::as_str),
            "fake-ip-filter-mode": names(&FakeIpFilterMode::ALL, FakeIpFilterMode::as_str),
            "cache-algorithm": names(&CacheAlgorithm::ALL, CacheAlgorithm::as_str),
        }),
        "tun" => json!({
            "stack": TUN_STACKS,
            "congestion-controller": CONGESTION_CONTROLLERS,
        }),
        _ => json!({}),
    }
}

pub fn config_schema() -> Value {
    let mut schema = Map::new();
    schema.insert("version".into(), json!(1));
    for (section, tiers) in keys::SECTIONS {
        let name = if section.is_empty() { "keys" } else { section };
        let mut entry = key_tiers(tiers, section_defaults(section));
        if let (Some(entry), Value::Object(values)) =
            (entry.as_object_mut(), section_values(section))
            && !values.is_empty()
        {
            entry.insert("values".into(), Value::Object(values));
        }
        schema.insert(name.into(), entry);
    }
    schema.insert(
        "proxy-values".into(),
        json!({
            "ip-stack.mode": IP_STACK_MODES,
            "ip-stack.congestion-controller": CONGESTION_CONTROLLERS,
            "nowhere.cipher": names(&NowhereCipher::ALL, NowhereCipher::as_str),
        }),
    );
    schema.insert(
        "rule-types".into(),
        tiers(T0_RULE_TYPES, T1_RULE_TYPES, &[]),
    );
    schema.insert(
        "proxy-types".into(),
        tiers(T0_PROXY_TYPES, T1_PROXY_TYPES, T2_PROXY_TYPES),
    );
    schema.insert(
        "group-types".into(),
        json!(["select", "url-test", "fallback", "load-balance", "smart"]),
    );
    schema.insert("proxy-groups".into(), key_tiers(&keys::GROUP, json!({})));
    Value::Object(schema)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `cargo xtask mihomo-keys <checkout>` writes it from mihomo's `config/config.go`.
    const MIHOMO_KEYS: &str = include_str!("../../../schema/mihomo-keys.json");

    #[test]
    fn every_key_mihomo_decodes_has_a_tier() {
        let mihomo: Value = serde_json::from_str(MIHOMO_KEYS).unwrap();
        let mut untiered = Vec::new();
        for (section, tiers) in keys::SECTIONS {
            let name = if section.is_empty() { "keys" } else { section };
            let listed = mihomo[name].as_array().unwrap_or_else(|| panic!("{name}"));
            for key in listed.iter().filter_map(Value::as_str) {
                if tiers.of(key).is_none() {
                    untiered.push(format!("{name}: {key}"));
                }
            }
        }
        assert!(
            untiered.is_empty(),
            "keys mihomo {} decodes without a tier: {untiered:?}",
            mihomo["mihomo"]
        );
    }

    #[test]
    fn the_schema_lists_every_tier() {
        let schema = config_schema();
        assert_eq!(
            schema["keys"]["t0"].as_array().map(Vec::len),
            Some(keys::TOP_T0.len())
        );
        assert_eq!(schema["keys"]["inert"], json!(["geodata-loader"]));
        assert_eq!(
            schema["rule-types"]["t0"].as_array().map(Vec::len),
            Some(30)
        );
        assert!(
            schema["proxy-types"]["t2"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v == "tailscale"))
        );
    }

    fn listed(section: &str, key: &str) -> Vec<String> {
        config_schema()[section]["values"][key]
            .as_array()
            .unwrap_or_else(|| panic!("{section}.{key}"))
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn every_listed_value_is_accepted_by_its_parser() {
        use crate::dns::{DnsConfig, parse_enhanced, parse_filter_mode};
        use crate::tun::TunConfig;

        for stack in listed("tun", "stack") {
            let mut map = keys::tun_defaults();
            map.insert("stack".into(), json!(stack));
            assert!(TunConfig::from_map(&map).is_ok(), "{stack}");
        }
        for mode in listed("dns", "enhanced-mode") {
            assert_eq!(parse_enhanced(&mode).unwrap().as_str(), mode);
            let mut map = keys::dns_defaults();
            map.insert("enhanced-mode".into(), json!(mode));
            assert!(DnsConfig::from_map(&map, true).is_ok(), "{mode}");
        }
        for mode in listed("dns", "fake-ip-filter-mode") {
            assert_eq!(parse_filter_mode(&mode).unwrap().as_str(), mode);
        }
        for algorithm in listed("dns", "cache-algorithm") {
            assert_eq!(CacheAlgorithm::parse(&algorithm).as_str(), algorithm);
        }
        for mode in listed("keys", "mode") {
            assert_eq!(
                TunnelMode::parse(&mode).map(TunnelMode::as_str),
                Some(mode.as_str())
            );
        }
        for level in listed("keys", "log-level") {
            assert_eq!(
                LogLevel::parse(&level).map(LogLevel::as_str),
                Some(level.as_str())
            );
        }
        for mode in listed("keys", "find-process-mode") {
            assert_eq!(
                FindProcessMode::parse(&mode).map(FindProcessMode::as_str),
                Some(mode.as_str())
            );
        }
        let schema = config_schema();
        assert!(
            schema["proxy-values"]["ip-stack.mode"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
        );
    }
}
