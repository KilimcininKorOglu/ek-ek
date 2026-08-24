// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The number consensus calls a node, derived from the name an operator gave
//! it.
//!
//! # Why a number and not the name
//!
//! openraft asks a node id for `Copy`, and a `String` is not. The name stays
//! the identity everywhere else in the product: it is carried beside the
//! address in [`crate::types::PeerNode`], so metrics, logs and errors say
//! `node-a` rather than a digit string.
//!
//! # Why derived and not configured
//!
//! An operator who has to invent a second identity for a node can give two
//! nodes the same one, and the config already derives a number from a name
//! this way for the virtual router id (`ek_ek_config::matrix`). Deriving keeps
//! the config as it is.
//!
//! # What happens when two names derive to one number
//!
//! The membership is refused, by name, before the cluster starts
//! ([`unique`]). A collision is not something to survive quietly: two nodes
//! consensus believes are one node would count one vote twice.

use std::collections::BTreeMap;

use ek_ek_config::NodeId;
use sha2::{Digest, Sha256};

use crate::error::{Failure, Reason};

/// What goes into the digest before the name.
///
/// A domain separator, so the number a name derives to here can never equal
/// the number the same name derives to somewhere else in the product.
pub const DOMAIN: &[u8] = b"raft-node";

/// The number consensus calls this node.
#[must_use]
pub fn of(node: &NodeId) -> u64 {
    let mut digest = Sha256::new();
    // The length goes in first, so a domain and a name cannot be run together
    // into the same input as a different domain and a different name.
    digest.update(
        u64::try_from(DOMAIN.len())
            .unwrap_or(u64::MAX)
            .to_be_bytes(),
    );
    digest.update(DOMAIN);
    let name = node.as_str().as_bytes();
    digest.update(u64::try_from(name.len()).unwrap_or(u64::MAX).to_be_bytes());
    digest.update(name);

    let out = digest.finalize();
    let mut first = [0_u8; 8];
    first.copy_from_slice(&out[..8]);
    u64::from_be_bytes(first)
}

/// Checks that every name in a membership derives to its own number.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] naming both nodes when two of them
/// derive to one number.
pub fn unique<'a, I>(nodes: I) -> Result<(), Failure>
where
    I: IntoIterator<Item = &'a NodeId>,
{
    distinct(nodes.into_iter().map(|node| (of(node), node)))
}

/// The comparison [`unique`] makes, over numbers a caller already has.
///
/// Separate from the derivation so the refusal can be measured. No two short
/// names really collide, and a rule that could only be reached through the
/// digest would be a rule nothing ever exercises.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] naming both nodes when two different
/// names arrive under one number.
pub fn distinct<'a, I>(numbered: I) -> Result<(), Failure>
where
    I: IntoIterator<Item = (u64, &'a NodeId)>,
{
    let mut seen: BTreeMap<u64, &NodeId> = BTreeMap::new();
    for (number, node) in numbered {
        if let Some(held) = seen.get(&number)
            && *held != node
        {
            return Err(Failure::new(
                Reason::Configuration,
                format!(
                    "{} and {} are the same node to consensus; rename one of them",
                    held.as_str(),
                    node.as_str()
                ),
            ));
        }
        seen.insert(number, node);
    }
    Ok(())
}
