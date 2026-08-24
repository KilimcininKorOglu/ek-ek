// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What travels in a log record, and what a node is called.
//!
//! # Why these types exist beside the store's own
//!
//! The store's state types carry key material and deliberately do not
//! serialise: a secret that can be written out by accident is a secret in a
//! log file. A replicated write has to travel, so the conversion is written
//! out here, in one file, as a deliberate act (ADR-0083).

use std::collections::BTreeMap;
use std::io::Cursor;

use ek_ek_config::{Config, NodeId, SecretId};
use ek_ek_store::{
    AuditRecord, Change, ClusterIdentity, FullState, JoinRecord, Secret, Snapshot, StoredVersion,
    TokenId, VersionId,
};
use serde::{Deserialize, Serialize};

/// What consensus calls a node.
///
/// A number, not a name: openraft asks a node id for `Copy`. The number is
/// derived from the name ([`crate::identity`]).
pub type NodeNumber = u64;

openraft::declare_raft_types!(
    /// The types this cluster's Raft runs on.
    ///
    /// `NodeId` is a number rather than the config model's own `NodeId`,
    /// because openraft asks a node id for `Copy` and a `String` is not one.
    /// The number is derived from the name ([`crate::identity`]) and the name
    /// travels beside the address in [`PeerNode`], so nothing an operator
    /// reads is reduced to a digit string (ADR-0083).
    pub TypeConfig:
        D = WriteRequest,
        R = WriteResponse,
        NodeId = NodeNumber,
        Node = PeerNode,
);

/// What a node is called and where it can be reached.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerNode {
    /// The name an operator gave this node.
    ///
    /// Carried so a metric, a log line or an error can name the node the way
    /// the config does. Consensus itself never reads it.
    pub name: String,
    /// Host and port of the node's peer channel.
    pub address: String,
}

impl PeerNode {
    /// Names a node at an address.
    #[must_use]
    pub fn new(name: impl Into<String>, address: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            address: address.into(),
        }
    }

    /// The identity the rest of the product knows this node by.
    #[must_use]
    pub fn node(&self) -> ek_ek_config::NodeId {
        ek_ek_config::NodeId::new(&self.name)
    }
}

/// One replicated configuration write.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteRequest {
    /// The whole state to apply. There is no partial update, because the state
    /// machine applies a complete state and matching that shape is what keeps
    /// this layer small.
    pub state: WireSnapshot,
    /// Who asked for the change and why.
    pub change: WireChange,
    /// The moment the leader stamped on it.
    ///
    /// Decided once, by the leader, and carried here. Every node writing its
    /// own clock into the version log would give three nodes three histories
    /// (ADR-0083).
    pub now_unix: i64,
    /// Audit rows to write in the same transaction as the state.
    ///
    /// Carried here rather than written by a second call, because two calls
    /// mean a leader can fall between them and leave a change nobody can
    /// account for. What the caller knows (which token, which address) is not
    /// in the state machine, so the state machine cannot derive these rows
    /// either (ADR-0008, ADR-0084).
    #[serde(default)]
    pub audit: Vec<WireAudit>,
}

/// What a replicated write produced.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WriteResponse {
    /// The version the write appended.
    pub version: i64,
}

/// A change note, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireChange {
    /// The account that asked for the change.
    pub author: String,
    /// A short note the author wrote.
    pub description: String,
}

impl From<&Change> for WireChange {
    fn from(change: &Change) -> Self {
        Self {
            author: change.author.clone(),
            description: change.description.clone(),
        }
    }
}

impl From<&WireChange> for Change {
    fn from(change: &WireChange) -> Self {
        Self::new(&change.author, &change.description)
    }
}

/// A store state, as it travels.
///
/// Key material is here in the clear. The channel it crosses is mutually
/// authenticated and encrypted, and every node seals what it receives with its
/// own master key before it reaches the disk. A sealed byte cannot travel
/// instead, because the master key is the one thing nodes never share
/// (ADR-0018).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireSnapshot {
    /// What an operator configured.
    pub config: Config,
    /// Key material, keyed by the identity the config refers to.
    pub secrets: BTreeMap<String, Vec<u8>>,
    /// The cluster authority certificate, when this cluster has one.
    pub cluster: Option<String>,
    /// Join tokens the cluster has issued, by their identity.
    #[serde(default)]
    pub joins: BTreeMap<String, WireJoin>,
    /// Nodes this cluster has removed, by name.
    #[serde(default)]
    pub removed: Vec<String>,
}

/// One join token, as it travels.
///
/// The secret is not here and never was. Only its digest is stored, so only its
/// digest replicates (ADR-0084).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireJoin {
    /// The digest of the secret the token carries.
    pub secret_digest: String,
    /// When the token stops being usable, as a Unix timestamp in seconds.
    pub expires_at_unix: i64,
    /// Which node used it, when one has.
    pub used_by: Option<String>,
    /// Who asked for the token.
    pub issued_by: String,
    /// When it was issued, as a Unix timestamp in seconds.
    pub issued_at_unix: i64,
}

impl From<&Snapshot> for WireSnapshot {
    fn from(state: &Snapshot) -> Self {
        Self {
            config: state.config.clone(),
            secrets: state
                .secrets
                .iter()
                .map(|(id, secret)| (id.as_str().to_owned(), secret.expose().to_vec()))
                .collect(),
            cluster: state
                .cluster
                .as_ref()
                .map(|identity| identity.authority_pem.clone()),
            joins: state
                .joins
                .iter()
                .map(|(id, record)| {
                    (
                        id.as_str().to_owned(),
                        WireJoin {
                            secret_digest: record.secret_digest.clone(),
                            expires_at_unix: record.expires_at_unix,
                            used_by: record.used_by.as_ref().map(|node| node.as_str().to_owned()),
                            issued_by: record.issued_by.clone(),
                            issued_at_unix: record.issued_at_unix,
                        },
                    )
                })
                .collect(),
            removed: state
                .removed
                .iter()
                .map(|node| node.as_str().to_owned())
                .collect(),
        }
    }
}

impl From<&WireSnapshot> for Snapshot {
    fn from(state: &WireSnapshot) -> Self {
        Self {
            config: state.config.clone(),
            secrets: state
                .secrets
                .iter()
                .map(|(id, bytes)| (SecretId::new(id), Secret::new(bytes.clone())))
                .collect(),
            cluster: state.cluster.as_ref().map(ClusterIdentity::new),
            joins: state
                .joins
                .iter()
                .map(|(id, record)| {
                    (
                        TokenId::new(id),
                        JoinRecord {
                            secret_digest: record.secret_digest.clone(),
                            expires_at_unix: record.expires_at_unix,
                            used_by: record.used_by.as_ref().map(NodeId::new),
                            issued_by: record.issued_by.clone(),
                            issued_at_unix: record.issued_at_unix,
                        },
                    )
                })
                .collect(),
            removed: state.removed.iter().map(NodeId::new).collect(),
        }
    }
}

/// Everything a node catching up receives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireState {
    /// The config, the key material and the cluster identity.
    pub snapshot: Option<WireSnapshot>,
    /// The version log, oldest first, with the numbers it was written under.
    pub versions: Vec<WireVersion>,
    /// The audit log, oldest first.
    pub audit: Vec<WireAudit>,
}

/// One version log entry, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireVersion {
    /// Identity of this version.
    pub id: i64,
    /// When it was written, as a Unix timestamp in seconds.
    pub recorded_at_unix: i64,
    /// Who wrote it.
    pub author: String,
    /// The note the author wrote.
    pub description: String,
    /// The schema the config was written against.
    pub schema_version: u32,
    /// The version whose config was restored, when this was a rollback.
    pub restored_from: Option<i64>,
    /// The config itself, as it was stored.
    pub document: String,
}

/// One audit row, as it travels.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WireAudit {
    /// When it happened, as a Unix timestamp in seconds.
    pub recorded_at_unix: i64,
    /// Who did it.
    pub actor: String,
    /// A stable action key.
    pub action: String,
    /// What it was done to.
    pub subject: Option<String>,
    /// Anything else worth keeping.
    pub detail: Option<String>,
}

impl From<&AuditRecord> for WireAudit {
    fn from(record: &AuditRecord) -> Self {
        Self {
            recorded_at_unix: record.recorded_at_unix,
            actor: record.actor.clone(),
            action: record.action.clone(),
            subject: record.subject.clone(),
            detail: record.detail.clone(),
        }
    }
}

impl From<&WireAudit> for AuditRecord {
    fn from(record: &WireAudit) -> Self {
        Self {
            recorded_at_unix: record.recorded_at_unix,
            actor: record.actor.clone(),
            action: record.action.clone(),
            subject: record.subject.clone(),
            detail: record.detail.clone(),
        }
    }
}

impl From<&FullState> for WireState {
    fn from(state: &FullState) -> Self {
        Self {
            snapshot: state.snapshot.as_ref().map(WireSnapshot::from),
            versions: state
                .versions
                .iter()
                .map(|version| WireVersion {
                    id: version.id.get(),
                    recorded_at_unix: version.recorded_at_unix,
                    author: version.author.clone(),
                    description: version.description.clone(),
                    schema_version: version.schema_version,
                    restored_from: version.restored_from.map(VersionId::get),
                    document: version.document.clone(),
                })
                .collect(),
            audit: state.audit.iter().map(WireAudit::from).collect(),
        }
    }
}

impl From<&WireState> for FullState {
    fn from(state: &WireState) -> Self {
        Self {
            snapshot: state.snapshot.as_ref().map(Snapshot::from),
            versions: state
                .versions
                .iter()
                .map(|version| StoredVersion {
                    id: VersionId::new(version.id),
                    recorded_at_unix: version.recorded_at_unix,
                    author: version.author.clone(),
                    description: version.description.clone(),
                    schema_version: version.schema_version,
                    restored_from: version.restored_from.map(VersionId::new),
                    document: version.document.clone(),
                })
                .collect(),
            audit: state.audit.iter().map(AuditRecord::from).collect(),
        }
    }
}
