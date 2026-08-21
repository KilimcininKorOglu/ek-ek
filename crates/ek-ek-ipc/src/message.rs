// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the two processes say to each other.

use ek_ek_config::Config;
use ek_ek_config::validation::ValidationError;
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
}

/// A periodic report.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusReport {
    /// The generation being served.
    pub generation: u64,
    /// What the process is doing.
    pub state: DataPlaneState,
    /// The counters at the moment of the report.
    pub counters: Counters,
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
