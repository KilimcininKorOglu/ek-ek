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
    /// How many requests this pool may have in flight at once.
    ///
    /// Reaching the limit makes the next request wait for one to finish. It
    /// is never answered with an error: a burst that outruns the limit is a
    /// queue, not a failure (ADR-0045).
    #[serde(default = "Backend::default_pool_size")]
    pub connection_pool_size: u32,
    /// How long a pooled connection may be reused, in seconds.
    ///
    /// A backend that restarts leaves connections behind that still look
    /// usable. This bounds how long one of them can be handed a request.
    #[serde(default = "Backend::default_connection_lifetime_seconds")]
    pub connection_lifetime_seconds: u32,
}

impl Backend {
    /// Requests in flight a pool allows before the next one waits.
    ///
    /// The same number pingora uses for its own pool, so a document that
    /// names nothing behaves the way the library underneath already did.
    #[must_use]
    pub const fn default_pool_size() -> u32 {
        128
    }

    /// How long a pooled connection may be reused, in seconds.
    ///
    /// Five minutes, so connections to a restarted backend are gone within a
    /// span an operator does not have to wait out.
    #[must_use]
    pub const fn default_connection_lifetime_seconds() -> u32 {
        300
    }

    /// Whether this pool bounds how many requests it carries at once.
    ///
    /// Zero means no bound, so an operator can take the limit off rather
    /// than name a number large enough to never be reached.
    #[must_use]
    pub const fn limits_requests_in_flight(&self) -> bool {
        self.connection_pool_size > 0
    }

    /// The reuse group a connection opened now belongs to.
    ///
    /// Connections in different groups are never shared, so a group that has
    /// passed takes its connections out of use. The group is a division
    /// rather than a stopwatch per connection, which makes the lifetime an
    /// upper bound: a connection opened just before a boundary lives less
    /// than the configured span, never more.
    ///
    /// Returns the same group for every connection when no lifetime is
    /// named, so nothing is retired.
    #[must_use]
    pub const fn reuse_group(&self, seconds_since_epoch: u64) -> u64 {
        if self.connection_lifetime_seconds == 0 {
            return 0;
        }
        seconds_since_epoch / self.connection_lifetime_seconds as u64
    }
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
