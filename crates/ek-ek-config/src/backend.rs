// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Backend pools and their members.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::health::HealthCheck;
use crate::id::{BackendId, MemberId};

/// A pool of servers traffic is distributed over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// Identity frontends and routing rules reference.
    pub id: BackendId,
    /// Servers in the pool. Validation rejects an empty pool.
    pub members: Vec<BackendMember>,
    /// How a request or connection picks a member.
    pub algorithm: LoadBalancingAlgorithm,
    /// Check that decides which members take traffic.
    ///
    /// Leaving it unset means every enabled member is assumed healthy.
    pub health_check: Option<HealthCheck>,
    /// Whether a client keeps returning to the same member.
    #[serde(default)]
    pub stickiness: SessionStickiness,
    /// Whether backend connections are reused across requests.
    #[serde(default)]
    pub connection_pooling: ConnectionPooling,
}

/// One server inside a pool.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendMember {
    /// Identity that survives an address change, which is what keeps a
    /// stickiness cookie valid when a server is renumbered.
    pub id: MemberId,
    /// Address traffic is sent to.
    ///
    /// Members are addressed numerically. Resolving a name would make
    /// routing depend on a DNS answer that can change under load.
    pub address: IpAddr,
    /// Port traffic is sent to.
    pub port: u16,
    /// Relative share of traffic against the other members.
    pub weight: u16,
    /// Whether an operator has taken this member out of service.
    #[serde(default)]
    pub admin_state: AdminState,
}

/// How a member is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingAlgorithm {
    /// Walks the members in order, respecting weights.
    RoundRobin,
    /// Picks the member with the fewest open connections.
    LeastConnections,
    /// Maps the client address onto a member.
    SourceIpHash,
    /// Maps the client address onto a member so that removing one member
    /// only redistributes that member's share.
    ///
    /// The UDP path depends on this property, because two processes must
    /// reach the same answer during an upgrade (ADR-0025).
    ConsistentHash,
}

/// Whether a client keeps returning to the same member.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "mode")]
pub enum SessionStickiness {
    /// Every request is distributed by the pool's algorithm.
    #[default]
    Disabled,
    /// The proxy sets its own signed cookie naming the chosen member.
    ///
    /// This applies to HTTP only. UDP affinity comes from consistent
    /// hashing instead, and validation rejects the combination.
    SignedCookie {
        /// Name the cookie is set under.
        cookie_name: String,
        /// `SameSite` attribute the cookie carries. `HttpOnly` and `Secure`
        /// are always set and are not configurable (ADR-0024).
        same_site: SameSitePolicy,
    },
}

/// `SameSite` attribute of the stickiness cookie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SameSitePolicy {
    /// Sent on same-site requests only.
    Strict,
    /// Sent on same-site requests and top-level navigations.
    Lax,
    /// Sent on cross-site requests too.
    None,
}

/// Whether backend connections are reused.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionPooling {
    /// Connections are kept and reused. This is the default (ADR-0045).
    #[default]
    Enabled,
    /// Every request opens its own connection and closes it afterwards.
    ///
    /// NTLM binds authentication to the TCP connection, so a pool that
    /// serves an NTLM backend must turn reuse off.
    Disabled,
}

/// Operator-controlled state of a member.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdminState {
    /// Takes new traffic while healthy.
    #[default]
    Enabled,
    /// Takes no new traffic and keeps its open connections until they end.
    Draining,
    /// Takes no traffic and is not probed.
    Disabled,
}
