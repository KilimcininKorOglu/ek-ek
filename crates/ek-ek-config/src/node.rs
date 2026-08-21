// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cluster nodes.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::id::NodeId;

/// A member of the cluster.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    /// Identity other objects reference.
    pub id: NodeId,
    /// Management address peers reach this node on.
    pub address: IpAddr,
    /// What this node runs.
    pub roles: Vec<NodeRole>,
}

/// A responsibility a node carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    /// Runs the Raft member, the admin API and VRRP.
    ControlPlane,
    /// Runs the proxy that carries user traffic.
    DataPlane,
}
