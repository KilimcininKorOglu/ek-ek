// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health checks.
//!
//! Four probe types are supported (ADR-0020). A probe that runs an external
//! script is not one of them, because it turns a health check into arbitrary
//! code execution on every node.

use serde::{Deserialize, Serialize};

use crate::frontend::TransportProtocol;

/// The periodic check that decides whether a member takes traffic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    /// What is sent and what counts as a good answer.
    pub probe: HealthProbe,
    /// Gap between two consecutive probes, in milliseconds.
    pub interval_ms: u32,
    /// How long one probe may take before it counts as failed, in
    /// milliseconds. Validation rejects a value above `interval_ms`, because
    /// probes would otherwise overlap.
    pub timeout_ms: u32,
    /// Consecutive successes needed to move a member back into rotation.
    pub healthy_threshold: u8,
    /// Consecutive failures needed to take a member out of rotation.
    pub unhealthy_threshold: u8,
}

/// What a health check sends and expects.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum HealthProbe {
    /// Opens a connection to the member's port and closes it again.
    TcpConnect,
    /// Sends an HTTP request and inspects the response.
    Http {
        /// Request path, for example `/healthz`.
        path: String,
        /// Status codes that count as healthy.
        expected_status: Vec<u16>,
        /// Substring the response body must contain, when set.
        expected_body: Option<String>,
        /// `Host` header sent with the request, when the backend needs one.
        host_header: Option<String>,
    },
    /// Sends operator-supplied data and looks for an expected answer.
    ///
    /// This is the probe that covers protocols the product does not speak,
    /// such as SMTP or IMAP banners, over TCP as well as UDP.
    SendExpect {
        /// Data written to the member.
        send: ProbePayload,
        /// Data the answer must contain.
        expect: ProbePayload,
        /// Which socket the probe opens.
        ///
        /// Named rather than inferred from the frontends publishing the pool:
        /// a DNS pool is published from a TCP and a UDP frontend at once, so
        /// there would be no single answer to infer (ADR-0064).
        transport: TransportProtocol,
    },
    /// Sends a real DNS query and requires a valid answer.
    DnsQuery {
        /// Name to look up.
        name: String,
        /// Record type to ask for.
        record_type: DnsRecordType,
    },
}

/// Probe data, in the form the operator entered it.
///
/// Binary protocols cannot be expressed as text, and text protocols are
/// unreadable as hex, so the form is kept rather than normalised away.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "encoding", content = "value")]
pub enum ProbePayload {
    /// Literal text.
    Text(String),
    /// Hex digits, without separators.
    Hex(String),
}

/// Record type a DNS probe asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsRecordType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    Aaaa,
    /// Zone authority record, which answers without depending on a name
    /// existing in the zone.
    Soa,
}
