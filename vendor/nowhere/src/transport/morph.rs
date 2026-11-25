// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Optional keyed wire transform below TLS and QUIC.

mod cipher;
mod policy;
mod prelude;
mod tcp;
mod udp;
mod udp_socket;

use std::{fmt, io};

use hmac::{Hmac, KeyInit as HmacKeyInit, Mac};
use sha2::Sha256;

pub(crate) use cipher::MorphCipher;
pub(crate) use prelude::{AuthenticatedPrelude, ClientPrelude};
pub(crate) use tcp::{MorphTcpStream, validate_tcp_prelude_env};
pub(crate) use udp::{
    UdpRole, configure_morph_mtu, morph_endpoint_config, validate_udp_prelude_env,
    wrap_morph_client_udp_socket, wrap_morph_udp_socket,
};

const NONCE_LEN: usize = 12;
const TCP_PRELUDE_LEN: usize = 64;
const UDP_PRELUDE_LEN: usize = 12;
const MORPH_ROOT_SALT: &[u8] = b"nowhere/nw3/morph";
const TCP_C2S_INFO: &[u8] = b"tcp c2s";
const TCP_S2C_INFO: &[u8] = b"tcp s2c";
const UDP_C2S_INFO: &[u8] = b"udp c2s";
const UDP_S2C_INFO: &[u8] = b"udp s2c";
const TCP_PRELUDE_AUTH_INFO: &[u8] = b"tcp prelude auth";
const TCP_PRELUDE_MASK_INFO: &[u8] = b"tcp prelude mask";

type MorphKeyBytes = [u8; 32];

use policy::{PreludePolicy, TCP_PRELUDE_ENV, UDP_PRELUDE_ENV};

#[derive(Clone)]
pub(crate) struct MorphKeys {
    cipher: MorphCipher,
    tcp_c2s: MorphKeyBytes,
    tcp_s2c: MorphKeyBytes,
    udp_c2s: MorphKeyBytes,
    udp_s2c: MorphKeyBytes,
    tcp_prelude_auth: MorphKeyBytes,
    tcp_prelude_mask: MorphKeyBytes,
    // Concord: per-client prelude policies, from the URL query when present
    // (`tcp-prelude`/`udp-prelude`), else the process environment, else fade.
    tcp_prelude: PreludePolicy,
    udp_prelude: PreludePolicy,
}

impl fmt::Debug for MorphKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MorphKeys(REDACTED)")
    }
}

impl MorphKeys {
    pub(crate) fn from_url(url: &url::Url, cipher: MorphCipher) -> anyhow::Result<Self> {
        Ok(Self {
            cipher,
            tcp_prelude: PreludePolicy::from_url_or_env(url, "tcp-prelude", TCP_PRELUDE_ENV)?,
            udp_prelude: PreludePolicy::from_url_or_env(url, "udp-prelude", UDP_PRELUDE_ENV)?,
            ..Self::derive(&crate::protocol::Credentials::decode_shared_key(url)?)
        })
    }

    // Concord: the prelude policy this client's TCP flows write.
    pub(crate) fn tcp_prelude_policy(&self) -> PreludePolicy {
        self.tcp_prelude
    }

    // Concord: the prelude policy this client's UDP flows write.
    pub(crate) fn udp_prelude_policy(&self) -> PreludePolicy {
        self.udp_prelude
    }

    pub(crate) fn cipher_query(&self) -> &'static str {
        self.cipher.query()
    }

    pub(crate) fn derive(shared_key: &[u8]) -> Self {
        let root = hmac_sha256(MORPH_ROOT_SALT, shared_key);
        Self {
            cipher: MorphCipher::ChaCha,
            tcp_c2s: hkdf_expand_one(root, TCP_C2S_INFO),
            tcp_s2c: hkdf_expand_one(root, TCP_S2C_INFO),
            udp_c2s: hkdf_expand_one(root, UDP_C2S_INFO),
            udp_s2c: hkdf_expand_one(root, UDP_S2C_INFO),
            tcp_prelude_auth: hkdf_expand_one(root, TCP_PRELUDE_AUTH_INFO),
            tcp_prelude_mask: hkdf_expand_one(root, TCP_PRELUDE_MASK_INFO),
            // Concord: derived keys carry no URL, so both policies stay fade.
            tcp_prelude: PreludePolicy::Fade,
            udp_prelude: PreludePolicy::Fade,
        }
    }

    pub(crate) fn udp_keys(&self) -> (MorphKeyBytes, MorphKeyBytes) {
        (self.udp_c2s, self.udp_s2c)
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> MorphKeyBytes {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn hkdf_expand_one(root: MorphKeyBytes, info: &[u8]) -> MorphKeyBytes {
    let mut mac =
        <Hmac<Sha256> as HmacKeyInit>::new_from_slice(&root).expect("HMAC accepts a 32-byte key");
    mac.update(info);
    mac.update(&[1]);
    mac.finalize().into_bytes().into()
}

fn exhausted() -> io::Error {
    io::Error::other("Morph ChaCha20 keystream exhausted")
}

#[cfg(test)]
#[path = "../tests/transport/morph.rs"]
mod tests;
