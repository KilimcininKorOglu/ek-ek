// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A certificate order that is still running.
//!
//! Not configuration. Nobody writes an order by hand, validation has nothing
//! to say about one, and a rollback to last week must not resurrect an order
//! that finished days ago. So it sits beside the config in a state, exactly as
//! the join tokens and the cluster authority do (ADR-0084, ADR-0086).
//!
//! # Why it is replicated at all
//!
//! Two reasons, and they are different. The challenge answer has to be on
//! every node, because the certificate authority connects to whatever the name
//! resolves to and that is not always the node driving the order. The order
//! URL and its signing key have to be on every node, because the node driving
//! the order can disappear halfway through and the one that takes over needs
//! both to finish it (ADR-0032, ADR-0086).
//!
//! # What is stored and what is not
//!
//! The signing key is stored, under the identity [`OrderRecord::key`] names,
//! sealed like every other secret (ADR-0018). The account key is not here: it
//! is one key for the whole installation and it lives under its own identity.

use std::collections::BTreeMap;

use ek_ek_config::{NodeId, SecretId};

/// Which challenge an order answers.
///
/// Carried rather than derived from the configuration, because the
/// configuration can change while an order is running and the order has to be
/// finished the way it was started.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OrderChallenge {
    /// Answered at a path on port 80, by every node's traffic path.
    Http01,
    /// Answered by a TXT record, which only the driving node publishes.
    Dns01,
}

impl OrderChallenge {
    /// A stable identifier, as it is stored and as it travels.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Http01 => "http-01",
            Self::Dns01 => "dns-01",
        }
    }

    /// Reads one back, or nothing when the value names no challenge.
    #[must_use]
    pub fn from_key(value: &str) -> Option<Self> {
        match value {
            "http-01" => Some(Self::Http01),
            "dns-01" => Some(Self::Dns01),
            _ => None,
        }
    }
}

/// One certificate order, as the cluster holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderRecord {
    /// The names the order covers.
    ///
    /// Taken from the configuration when the order started and kept, so a
    /// certificate whose names changed mid-order is still finished for the
    /// names the certificate authority was asked about.
    pub names: Vec<String>,
    /// Which challenge it answers.
    pub challenge: OrderChallenge,
    /// The URL the certificate authority named the order with.
    ///
    /// `None` until the server has answered the first request. A record with
    /// none is an order nothing was placed for yet, so a node taking it over
    /// starts it rather than resuming it.
    pub order_url: Option<String>,
    /// The identity the signing key is stored under.
    ///
    /// Written before the first request goes out. The certificate is issued
    /// against this key, so a node that takes the order over has to hold it or
    /// it would download a certificate it cannot serve (ADR-0086).
    pub key: SecretId,
    /// What every node has to answer while the server checks, token to value.
    ///
    /// Only HTTP-01 puts anything here. A DNS-01 answer sits at a name server,
    /// which no node in this cluster is.
    pub answers: BTreeMap<String, String>,
    /// Which node wrote this record last, when one is running in a cluster.
    ///
    /// For the audit trail and for an operator reading a status screen. Not
    /// what decides who may drive the order: leadership decides that. `None`
    /// is the single node command, which is a member of no cluster.
    pub driven_by: Option<NodeId>,
    /// When the order started, as a Unix timestamp in seconds.
    pub started_at_unix: i64,
}

impl OrderRecord {
    /// Whether the certificate authority has named this order yet.
    #[must_use]
    pub const fn placed(&self) -> bool {
        self.order_url.is_some()
    }
}

/// The orders a cluster is running, by the certificate each one is for.
pub type Orders = BTreeMap<ek_ek_config::CertificateId, OrderRecord>;
