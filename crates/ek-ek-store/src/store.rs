// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The interface the rest of the product sees.
//!
//! Nothing in this file names a database. That is the point: M6 wraps this
//! trait in a Raft state machine, and a caller written against it does not
//! change when the implementation behind it does.
//!
//! State is read and written whole. There is no partial update, because a
//! Raft state machine applies a complete state as well, and matching that
//! shape now is what keeps the M6 change small.

use std::collections::BTreeMap;

use ek_ek_config::{Config, NodeId, SecretId};

use crate::cluster::ClusterIdentity;
use crate::error::Result;
use crate::membership::{JoinRecord, Removed, TokenId};
use crate::secret::Secret;
use crate::version::{Change, VersionId};

/// A complete store state: the config, plus the key material it references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// What an operator configured.
    pub config: Config,
    /// Key material, keyed by the identity the config refers to.
    pub secrets: BTreeMap<SecretId, Secret>,
    /// Who the cluster is, when it has been bootstrapped.
    ///
    /// Written whole like everything else here: a state carrying `None` is a
    /// node with no cluster authority, and writing one removes what was
    /// stored. Every caller reads the state before it writes one, which is the
    /// same rule the key material already lives by, and the one thing that
    /// must not happen is the authority certificate and its key parting
    /// company (ADR-0082).
    ///
    /// What keeps a rollback from taking the authority with it is that the
    /// identity is not in the config document at all: `roll_back_to` restores
    /// a document and carries this field forward untouched.
    pub cluster: Option<ClusterIdentity>,
    /// Join tokens the cluster has issued, by their identity.
    ///
    /// Here rather than in the config for the same reason the authority is: an
    /// operator writes none of it, and a rollback to last week must not
    /// resurrect a token that was already used (ADR-0084).
    pub joins: BTreeMap<TokenId, JoinRecord>,
    /// Nodes this cluster has removed.
    ///
    /// A removed node's certificate stays valid until it runs out, so this is
    /// what stops it speaking to the cluster in the meantime. Every node holds
    /// the same list, which is what keeps one node from quietly readmitting a
    /// caller the others refuse (ADR-0084).
    pub removed: Removed,
}

impl Snapshot {
    /// Builds a state that holds a config and no key material.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            secrets: BTreeMap::new(),
            cluster: None,
            joins: BTreeMap::new(),
            removed: Removed::new(),
        }
    }

    /// Adds a join token.
    #[must_use]
    pub fn with_join(mut self, id: TokenId, record: JoinRecord) -> Self {
        self.joins.insert(id, record);
        self
    }

    /// Marks a node as removed.
    #[must_use]
    pub fn with_removed(mut self, node: NodeId) -> Self {
        self.removed.insert(node);
        self
    }

    /// Adds key material under an identity.
    #[must_use]
    pub fn with_secret(mut self, id: SecretId, secret: Secret) -> Self {
        self.secrets.insert(id, secret);
        self
    }

    /// Says who the cluster is.
    #[must_use]
    pub fn with_cluster(mut self, identity: ClusterIdentity) -> Self {
        self.cluster = Some(identity);
        self
    }
}

/// Somewhere a config state can be kept.
pub trait Store {
    /// Reads the stored state, or nothing when none has been written yet.
    ///
    /// # Errors
    ///
    /// Fails when the state cannot be read or does not open.
    fn read(&self) -> Result<Option<Snapshot>>;

    /// Replaces the stored state and appends one version to the log.
    ///
    /// One call is one version, however many objects it touched. A template
    /// that creates a dozen objects is therefore one entry in the history and
    /// one step to undo.
    ///
    /// # Errors
    ///
    /// Fails when the state cannot be written. A failed write leaves the
    /// previous state intact.
    fn write(&self, snapshot: &Snapshot, change: &Change) -> Result<VersionId>;

    /// Replaces the stored state, recording the version at the moment given.
    ///
    /// The moment is a parameter because a replicated write must land on the
    /// same second on every node. The leader decides it once and it travels in
    /// the log entry; a node reading its own clock would produce a version
    /// history that drifts between nodes (ADR-0083).
    ///
    /// # Errors
    ///
    /// Fails when the state cannot be written. A failed write leaves the
    /// previous state intact.
    fn write_at(&self, snapshot: &Snapshot, change: &Change, now_unix: i64) -> Result<VersionId>;
}
