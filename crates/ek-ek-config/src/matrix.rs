// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which node holds which virtual address, worked out from the configuration.
//!
//! An operator says "this address should live on that node" and nothing else.
//! The virtual router id and the priority every node claims it with are
//! computed here, because both are protocol numbers nobody should have to own
//! (ADR-0006).
//!
//! # Why this is a pure function
//!
//! Every node computes the matrix for itself from the configuration it holds.
//! Two nodes that disagree would fight over an address, so nothing here reads
//! a clock, a socket or a random source, and the same configuration produces
//! the same matrix on every machine and in every release.
//!
//! # Why the numbers are hashed rather than counted
//!
//! Counting is stable while a list only grows. Deleting the second of three
//! virtual addresses would renumber the third, and renumbering an address
//! that is serving traffic costs an outage on an address nobody touched.
//! Hashing the identity gives each address a number of its own, which nothing
//! else moves.
//!
//! Ranking the nodes works the same way, and for the same reason: a fourth
//! node joining the cluster must not move addresses that have nothing to do
//! with it. Rendezvous hashing moves about one in four of them, which is the
//! least any assignment can move while still using the new node.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::id::{NodeId, VipId};
use crate::node::{Node, NodeRole};

/// The priority the node that should hold an address claims it with.
///
/// Below 255, which RFC 5798 reserves for a node that owns the address
/// outright, and far enough below it that a gateway fault can subtract from
/// it without reaching zero (T-035).
pub const TOP: u8 = 200;

/// How much lower each following node claims.
///
/// A fault that has to push a node behind every other one has to subtract
/// more than this times one less than the node count.
pub const STEP: u8 = 10;

/// The lowest priority a node ever claims.
///
/// Zero is not a priority: RFC 5798 reads it as a master standing down.
pub const FLOOR: u8 = 1;

/// The lowest virtual router id.
pub const FIRST_VRID: u8 = 1;

/// The highest virtual router id.
pub const LAST_VRID: u8 = 255;

/// How many virtual routers one segment can hold.
pub const VRIDS: usize = 255;

/// One node's place in the order that takes over an address.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    /// Which node.
    pub node: NodeId,
    /// What it claims the address with.
    pub priority: u8,
}

/// One virtual address and everything VRRP needs to move it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualRouter {
    /// The address this is about.
    pub vip: VipId,
    /// The number every node uses for it on the wire.
    pub vrid: u8,
    /// Every node, strongest claim first.
    ///
    /// The first entry holds the address while it is healthy and the second
    /// takes over when it stops answering.
    pub ranking: Vec<Placement>,
    /// Whether the address got the number its own identity points at.
    ///
    /// False means another address was already there and this one moved on.
    /// It matters because deleting the address that was in the way moves this
    /// one back, which is the one case where removing an address disturbs a
    /// second one.
    pub vrid_is_first_choice: bool,
}

impl VirtualRouter {
    /// The node that should hold the address.
    #[must_use]
    pub fn holder(&self) -> Option<&NodeId> {
        self.ranking.first().map(|placement| &placement.node)
    }

    /// What one node claims this address with.
    #[must_use]
    pub fn priority_of(&self, node: &NodeId) -> Option<u8> {
        self.ranking
            .iter()
            .find(|placement| &placement.node == node)
            .map(|placement| placement.priority)
    }
}

/// Every virtual router a configuration describes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Matrix {
    /// One entry per virtual address, in the order their identities sort.
    pub routers: Vec<VirtualRouter>,
}

impl Matrix {
    /// The entry for one address.
    #[must_use]
    pub fn router(&self, vip: &VipId) -> Option<&VirtualRouter> {
        self.routers.iter().find(|router| &router.vip == vip)
    }

    /// How many addresses each node should hold.
    ///
    /// What "balanced" is measured against: with no preference stated, no
    /// node should be carrying the cluster on its own.
    #[must_use]
    pub fn load(&self) -> Vec<(NodeId, usize)> {
        let mut counted: Vec<(NodeId, usize)> = Vec::new();
        for router in &self.routers {
            let Some(holder) = router.holder() else {
                continue;
            };
            match counted.iter_mut().find(|(node, _)| node == holder) {
                Some((_, count)) => *count += 1,
                None => counted.push((holder.clone(), 1)),
            }
        }
        counted.sort_by(|left, right| left.0.cmp(&right.0));
        counted
    }

    /// The addresses whose number is not the one their identity points at.
    ///
    /// Reported rather than refused: two identities landing on the same
    /// number is what hashing does, not something an operator did wrong.
    #[must_use]
    pub fn moved_aside(&self) -> Vec<&VipId> {
        self.routers
            .iter()
            .filter(|router| !router.vrid_is_first_choice)
            .map(|router| &router.vip)
            .collect()
    }
}

/// Works out the whole matrix.
///
/// Addresses are taken in the order their identities sort rather than in the
/// order the configuration lists them, so moving a line in the document does
/// not move a number on the wire.
#[must_use]
pub fn matrix(config: &Config) -> Matrix {
    let carriers = carriers(&config.nodes);

    let mut ordered: Vec<&crate::vip::Vip> = config.vips.iter().collect();
    ordered.sort_by(|left, right| left.id.cmp(&right.id));

    let mut taken: BTreeSet<u8> = BTreeSet::new();
    let mut routers = Vec::with_capacity(ordered.len());

    for vip in ordered {
        let wanted = first_choice(&vip.id);
        let vrid = free_from(wanted, &taken);
        if let Some(vrid) = vrid {
            taken.insert(vrid);
            routers.push(VirtualRouter {
                vrid,
                vrid_is_first_choice: vrid == wanted,
                ranking: ranking(&vip.id, vip.preferred_node.as_ref(), &carriers),
                vip: vip.id.clone(),
            });
        }
    }

    Matrix { routers }
}

/// The nodes that can hold a virtual address.
///
/// Only the control plane runs VRRP, because the node agent is what moves an
/// address and a data plane process is replaced whenever a listener changes
/// (ADR-0002).
fn carriers(nodes: &[Node]) -> Vec<NodeId> {
    let mut found: Vec<NodeId> = nodes
        .iter()
        .filter(|node| node.roles.contains(&NodeRole::ControlPlane))
        .map(|node| node.id.clone())
        .collect();
    found.sort();
    found
}

/// The number an address's identity points at.
fn first_choice(vip: &VipId) -> u8 {
    let digest = hash(&[b"vrid", vip.as_str().as_bytes()]);
    // 255 numbers starting at one. The remainder is taken over the whole
    // digest rather than one byte of it, so two identities differing late do
    // not land together.
    let slot = digest % VRIDS as u64;
    // Cast is exact: the remainder is below 255 and one more still fits.
    u8::try_from(slot).unwrap_or(0) + FIRST_VRID
}

/// The first free number at or after the one wanted, wrapping once.
///
/// Returns nothing when every number is taken, which is what a cluster with
/// more virtual addresses than the protocol has numbers for looks like. The
/// validation layer refuses that configuration before it reaches here.
fn free_from(wanted: u8, taken: &BTreeSet<u8>) -> Option<u8> {
    (0..VRIDS).find_map(|step| {
        // Wrapping inside 1..=255 rather than 0..=254, because zero is not a
        // virtual router id.
        let offset = (u16::from(wanted - FIRST_VRID) + u16::try_from(step).unwrap_or(0))
            % u16::try_from(VRIDS).unwrap_or(u16::MAX);
        let candidate = u8::try_from(offset).unwrap_or(0) + FIRST_VRID;
        (!taken.contains(&candidate)).then_some(candidate)
    })
}

/// Every node in the order it should take one address.
///
/// The preferred node goes first when it is one of the carriers. The rest
/// keep the order rendezvous hashing gives them, which is what stops a new
/// node from moving addresses it has nothing to do with.
fn ranking(vip: &VipId, preferred: Option<&NodeId>, carriers: &[NodeId]) -> Vec<Placement> {
    let mut weighted: Vec<(u64, &NodeId)> = carriers
        .iter()
        .map(|node| (weight(vip, node), node))
        .collect();
    // Highest weight first, and the identity settles a tie so two nodes
    // hashing the same way still produce one order rather than two.
    weighted.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(right.1)));

    let mut order: Vec<&NodeId> = weighted.into_iter().map(|(_, node)| node).collect();
    if let Some(preferred) = preferred
        && let Some(at) = order.iter().position(|node| *node == preferred)
    {
        let chosen = order.remove(at);
        order.insert(0, chosen);
    }

    order
        .into_iter()
        .enumerate()
        .map(|(rank, node)| Placement {
            node: node.clone(),
            priority: priority(rank),
        })
        .collect()
}

/// What a node at one rank claims an address with.
///
/// Held above zero, which RFC 5798 reads as a master standing down. A cluster
/// large enough to reach the floor puts several nodes on the same number, and
/// the address settles that tie, which is the same rule VRRP already uses.
#[must_use]
pub fn priority(rank: usize) -> u8 {
    let drop = u8::try_from(rank.saturating_mul(STEP as usize)).unwrap_or(u8::MAX);
    let claimed = TOP.saturating_sub(drop);
    if claimed < FLOOR { FLOOR } else { claimed }
}

/// How strongly one node is drawn to one address.
fn weight(vip: &VipId, node: &NodeId) -> u64 {
    hash(&[b"rank", vip.as_str().as_bytes(), node.as_str().as_bytes()])
}

/// A number the same on every machine and in every release.
///
/// SHA-256 rather than the standard library's hasher, whose value is not
/// promised to stay the same between Rust releases. Two nodes built with
/// different compilers would then compute different matrices and fight over
/// every address.
fn hash(parts: &[&[u8]]) -> u64 {
    let mut digest = Sha256::new();
    for part in parts {
        // The length goes in first, so joining two parts differently cannot
        // produce the same input.
        digest.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(part);
    }
    let out = digest.finalize();
    let mut first = [0_u8; 8];
    first.copy_from_slice(&out[..8]);
    u64::from_be_bytes(first)
}
