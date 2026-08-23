// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who the cluster is, as opposed to what an operator configured.
//!
//! The authority every node's peer certificate comes from is not
//! configuration. Nobody writes it by hand, validation has nothing to say
//! about it, and it must survive a rollback: reverting a configuration to last
//! week must not revert the authority every peer connection depends on
//! (ADR-0082).
//!
//! So it sits beside the config in a state rather than inside it, and it never
//! reaches the version log or the diff.

/// What identifies this cluster to its own nodes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterIdentity {
    /// The cluster authority certificate, in PEM.
    ///
    /// The private key that goes with it is a secret like any other and is
    /// sealed with the node's own master key (ADR-0018). This half is public:
    /// it is what a joining node is asked to trust.
    pub authority_pem: String,
}

impl ClusterIdentity {
    /// Builds an identity from an authority certificate.
    #[must_use]
    pub fn new(authority_pem: impl Into<String>) -> Self {
        Self {
            authority_pem: authority_pem.into(),
        }
    }
}
