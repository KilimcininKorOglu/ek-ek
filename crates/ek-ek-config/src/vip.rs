// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Virtual IPs.
//!
//! A VIP carries no VRID and no VRRP priority. Both are derived from the
//! preferred node and the cluster's node list, because asking an operator for
//! a VRID makes them own a number the product can compute (ADR-0006).

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::id::{NodeId, VipId};

/// An address that moves between nodes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vip {
    /// Identity frontends reference.
    pub id: VipId,
    /// Address clients connect to.
    pub address: IpAddr,
    /// Network mask, written as a prefix length.
    pub prefix_length: u8,
    /// Interface the address is added to, for example `eth0`.
    pub interface: String,
    /// Node that should hold this address while it is healthy.
    ///
    /// Spreading preferences across nodes is what makes the cluster
    /// active-active. Leaving it unset lets the cluster pick.
    pub preferred_node: Option<NodeId>,
}
