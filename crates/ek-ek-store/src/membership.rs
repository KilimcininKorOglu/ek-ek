// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Who may join the cluster, and who may no longer speak to it.
//!
//! Neither of these is configuration. Nobody writes a join token by hand,
//! validation has nothing to say about it, and a rollback to last week must
//! not resurrect a token that was used or a node that was removed. So they sit
//! beside the config in a state, exactly as the cluster authority does
//! (ADR-0082, ADR-0084).
//!
//! # What is stored and what is not
//!
//! The token's secret is never stored. Its digest is. A backup that leaks
//! therefore hands over nothing that can be replayed against the cluster.

use std::collections::BTreeSet;

use ek_ek_config::NodeId;

/// Identifies one join token.
///
/// Public: it travels in the token and it names the record. Knowing it lets
/// somebody find the record and nothing else, because the secret beside it is
/// what a join is checked against.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenId(String);

impl TokenId {
    /// Wraps a value that is already an identifier.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Borrows the wrapped value.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TokenId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// One join token, as the cluster holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRecord {
    /// The digest of the secret the token carries.
    ///
    /// Never the secret. A join presents the secret, this node digests it and
    /// compares; a leaked backup hands over a digest nobody can present.
    pub secret_digest: String,
    /// When the token stops being usable, as a Unix timestamp in seconds.
    pub expires_at_unix: i64,
    /// Which node used it, when one has.
    ///
    /// A token is used once. The name is kept rather than the record deleted,
    /// so a second attempt is refused with a reason instead of "no such
    /// token", and so an operator can see which node a token let in.
    pub used_by: Option<NodeId>,
    /// Who asked for the token, for the audit trail.
    pub issued_by: String,
    /// When it was issued, as a Unix timestamp in seconds.
    pub issued_at_unix: i64,
}

impl JoinRecord {
    /// Whether this token can still let a node in at the moment given.
    #[must_use]
    pub const fn usable(&self, now_unix: i64) -> bool {
        self.used_by.is_none() && now_unix < self.expires_at_unix
    }

    /// Whether the token has run out at the moment given.
    #[must_use]
    pub const fn expired(&self, now_unix: i64) -> bool {
        now_unix >= self.expires_at_unix
    }
}

/// The nodes this cluster has removed.
///
/// A removed node's certificate stays valid until it runs out, and there is no
/// revocation list anybody consults (R-32). This is what closes the gap: every
/// node holds the same list, so every node refuses the same caller, and no
/// single node can quietly drop a name from it.
pub type Removed = BTreeSet<NodeId>;
