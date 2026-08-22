// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the two processes say to each other.

use std::collections::BTreeMap;
use std::fmt;

use ek_ek_config::validation::ValidationError;
use ek_ek_config::{CertificateId, Config};
use serde::{Deserialize, Serialize};

/// Anything `node-agent` sends to `data-plane`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum AgentMessage {
    /// The configuration to serve from now on.
    Config(ConfigUpdate),
}

/// Anything `data-plane` sends to `node-agent`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "message")]
pub enum DataPlaneMessage {
    /// Sent once, as soon as the connection is up.
    Hello(Hello),
    /// Sent on a timer while the process runs.
    Status(StatusReport),
    /// Sent when a delivered configuration was not applied.
    ConfigRejected(ConfigRejection),
}

/// The first thing `data-plane` says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    /// Process id, so the agent can match a connection to a process it
    /// started and tell an old one from its replacement during an upgrade.
    pub pid: u32,
    /// The release this process is running.
    pub version: String,
    /// The generation this process already holds, if any.
    ///
    /// A process that took over sockets from a predecessor starts with a
    /// configuration, so the agent can skip resending it.
    pub generation: Option<u64>,
}

/// One delivery of configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigUpdate {
    /// Counts up on every delivery, so a report can name which one is live.
    pub generation: u64,
    /// The whole configuration. There is no partial update, because the
    /// state machine behind the agent applies whole states as well.
    pub config: Config,
    /// Key material for the certificates the configuration references.
    ///
    /// It travels with the configuration rather than on a channel of its own,
    /// so `data-plane` never holds a configuration naming a certificate whose
    /// material has not arrived (ADR-0069). The agent reads it from the store
    /// and decrypts it; the socket is `0600` and never leaves the machine.
    #[serde(default)]
    pub certificates: BTreeMap<CertificateId, CertificateMaterial>,
}

/// One certificate's chain and private key, both as PEM.
///
/// PEM rather than raw bytes because that is what the TLS library loads and
/// what survives a JSON line without an encoding step.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CertificateMaterial {
    /// The chain, leaf first.
    pub chain_pem: String,
    /// The private key.
    pub key_pem: String,
}

impl fmt::Debug for CertificateMaterial {
    /// Prints neither half.
    ///
    /// The chain is public, but printing it beside a redacted key invites
    /// somebody to relax the rule for the other field too.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CertificateMaterial")
            .finish_non_exhaustive()
    }
}

/// What `data-plane` is doing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataPlaneState {
    /// Has a configuration and has not started serving yet.
    #[default]
    Starting,
    /// Serving traffic.
    Serving,
    /// Serving traffic, but something is wrong. The agent decides what that
    /// means for VRRP priority; this process only reports it.
    Degraded,
}

/// Counters the agent collects.
///
/// Every one only grows, so a reader can subtract two reports to get a rate
/// without this process holding a window. Nothing is reported that this
/// process cannot actually count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    /// Requests answered since the process started.
    pub requests_handled: u64,
    /// Configurations applied since the process started.
    pub configs_applied: u64,
    /// Configurations refused since the process started.
    pub configs_rejected: u64,
    /// Backend connections that could not be opened since the process
    /// started.
    ///
    /// A count rather than a state, because one refused connection is not a
    /// sick node. Deciding that a member is unhealthy is the health check's
    /// job (T-021, ADR-0034), and a state with no way back would drop this
    /// node's VRRP priority over a single blip.
    #[serde(default)]
    pub backend_connect_failures: u64,
    /// UDP sessions dropped because their table was full (ADR-0025).
    ///
    /// A number that keeps climbing says the limit is too low for the
    /// traffic, which is the only way an operator finds that out.
    #[serde(default)]
    pub udp_sessions_evicted: u64,
    /// TLS handshakes refused because no certificate covered what the client
    /// asked for (ADR-0070).
    ///
    /// A refusal is silent on this side and only visible to the client, so it
    /// is counted here or it is not visible at all.
    #[serde(default)]
    pub tls_handshakes_refused: u64,
}

/// How many connections one member is carrying, and from where (ADR-0061).
///
/// The frontend is part of the key because the same pool can be published
/// from two of them. Without it an operator sees a busy member and cannot
/// tell which published service is filling it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenConnections {
    /// The frontend the connections arrived on.
    pub frontend: String,
    /// The pool they were sent to.
    pub pool: String,
    /// The member inside that pool.
    pub member: String,
    /// How many are open right now.
    pub count: u64,
}

/// How many UDP sessions one frontend is holding (ADR-0066).
///
/// A live count rather than a total, so it belongs here and not in
/// [`Counters`], which only carries numbers that grow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpSessions {
    /// The frontend holding them.
    pub frontend: String,
    /// How many sessions are in its table right now.
    pub count: u64,
    /// How many the table holds at most.
    ///
    /// Reported beside the count so an operator reading one number sees how
    /// close it is to the limit without also reading the configuration.
    pub limit: u64,
}

/// What one member's health check says, and how often it has changed
/// (ADR-0063).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberHealth {
    /// The pool the member belongs to.
    pub pool: String,
    /// The member itself.
    pub member: String,
    /// Whether it is currently taking traffic.
    pub healthy: bool,
    /// How many times it has changed state since the process started.
    ///
    /// Two reports can both say healthy while the member went down and came
    /// back in between. This is what makes that visible, so a member that
    /// keeps flapping can be told from one that is simply up.
    pub transitions: u64,
}

/// A periodic report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    /// The generation being served.
    pub generation: u64,
    /// What the process is doing.
    pub state: DataPlaneState,
    /// The counters at the moment of the report.
    pub counters: Counters,
    /// Open connections, one entry per frontend, pool and member that has
    /// any (ADR-0061).
    ///
    /// This is not in [`Counters`] because it goes down as well as up, and
    /// a reader subtracting two reports of a counter would get nonsense from
    /// it. Defaulted so a release that does not send it still reads.
    #[serde(default)]
    pub open_connections: Vec<OpenConnections>,
    /// Health of every member that has a health check (ADR-0063).
    ///
    /// The whole state travels in every report rather than an event at the
    /// moment of a transition, because an event is lost when the link drops
    /// and the agent would then be blind until the next one. Members of a
    /// pool with no health check are left out: health does not exist there.
    #[serde(default)]
    pub member_health: Vec<MemberHealth>,
    /// How full each UDP frontend's session table is (ADR-0066).
    #[serde(default)]
    pub udp_sessions: Vec<UdpSessions>,
}

/// Why a delivered configuration was not applied.
///
/// The errors carry stable codes and field paths, never a sentence, so the
/// agent can log them and the interface can translate them (ADR-0015).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigRejection {
    /// The generation that was refused.
    pub generation: u64,
    /// What was wrong with it.
    pub errors: Vec<ValidationError>,
}
