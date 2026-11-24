// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Nowhere wire codecs and the shared application protocol identifier.

mod auth;
mod datagram;
mod flow;
mod reassembly;
mod request;
mod result;
mod uot;
mod util;

// Concord: only the client-surface names are public; the codecs and frame helpers stay
// crate-visible.
pub use auth::Credentials;
pub(crate) use auth::{
    AUTH_EXPORTER_LABEL, AuthTransport, ConnectionRole, TLS_EXPORTER_LEN, TlsExporter,
    encode_auth_frame, read_auth_frame,
};
pub(crate) use datagram::{
    DatagramReassembler, OwnedUdpFrame, ReassemblyConfig, ReassemblyOutcome, UDP_HEADER_LEN,
    decode_udp_frame_owned, encode_udp_close, encode_udp_data_header, encode_udp_fragments,
};
pub use flow::{Carrier, FlowKind};
pub(crate) use flow::{FlowId, MAX_FLOW_ID, read_flow_start, udp_flow_id};
pub use request::Target;
pub(crate) use request::{TARGET_MAX_ENCODED_LEN, encode_flow_request_into, read_request};
pub use result::SetupResult;
pub(crate) use result::{FlowResult, read_flow_result, write_flow_result};
pub(crate) use uot::write_udp_packet;

pub const ALPN: &[u8] = b"nw3";

#[cfg(test)]
#[path = "../tests/protocol/support.rs"]
mod test_support;
#[cfg(test)]
#[path = "../tests/protocol/mod.rs"]
mod tests;

#[cfg(test)]
pub(crate) use test_support::*;
