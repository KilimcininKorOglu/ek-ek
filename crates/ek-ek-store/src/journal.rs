// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The replication log, and the whole state a node must hold to match its
//! peers.
//!
//! Nothing here names a consensus library. The log is a numbered sequence of
//! opaque records and a handful of named markers; what a record means is
//! `ek-ek-raft`'s business (ADR-0083). Keeping it that way is what lets the
//! store be opened, written and measured on one node with no consensus
//! anywhere near it.
//!
//! # Why the log lives in the config database
//!
//! Applying a record and moving the "applied up to here" marker have to happen
//! together. In two files a node that stops between them either applies a
//! record twice or never applies it at all, and nothing on disk would say
//! which.

use crate::error::Result;
use crate::store::Snapshot;
use crate::version::VersionId;

/// One record in the replication log.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// Where it sits in the sequence. Positions start at one and never repeat.
    pub index: u64,
    /// What it carries, as the layer above wrote it out.
    pub payload: String,
}

/// A named value the replication layer keeps beside the log.
///
/// Names rather than columns, so the layer above can keep what it needs
/// without a schema change here for each one.
pub mod marker {
    /// The term and candidate this node last voted for.
    pub const VOTE: &str = "vote";
    /// The highest record known to be agreed by a quorum.
    pub const COMMITTED: &str = "committed";
    /// The highest record removed by compaction.
    pub const PURGED: &str = "purged";
    /// The highest record already applied to the state.
    pub const APPLIED: &str = "applied";
    /// The cluster membership the applied state carries.
    pub const MEMBERSHIP: &str = "membership";
}

/// One entry of the version log, with the numbers it was written under.
///
/// Carried whole in a snapshot, because a node that catches up from one has to
/// end with the same version numbers as its peers and not with numbers of its
/// own (ADR-0083).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredVersion {
    /// Identity of this version.
    pub id: VersionId,
    /// When it was written, as a Unix timestamp in seconds.
    pub recorded_at_unix: i64,
    /// Who wrote it.
    pub author: String,
    /// The note the author wrote.
    pub description: String,
    /// The schema the config was written against.
    pub schema_version: u32,
    /// The version whose config was restored, when this was a rollback.
    pub restored_from: Option<VersionId>,
    /// The config itself, as it was stored.
    pub document: String,
}

/// One audit row.
///
/// M8 owns what goes in here. The rows travel now, because an audit log that
/// does not replicate is one an attacker removes on the node they hold
/// (ADR-0008).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
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

/// Everything a node must hold to be identical to its peers.
///
/// Key material travels in the clear here. The channel it crosses is
/// mutually authenticated and encrypted, and every node seals what it receives
/// with its own master key before it reaches the disk. A sealed byte cannot
/// travel instead, because the master key is the one thing nodes never share
/// (ADR-0018, ADR-0083).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FullState {
    /// The config, the key material and the cluster identity, or nothing when
    /// nothing has been written yet.
    pub snapshot: Option<Snapshot>,
    /// The version log, oldest first.
    pub versions: Vec<StoredVersion>,
    /// The audit log, oldest first.
    pub audit: Vec<AuditRecord>,
}

/// A numbered log of opaque records, with named markers beside it.
pub trait Journal {
    /// Appends records. They must follow whatever is already there.
    ///
    /// # Errors
    ///
    /// Fails when the records cannot be written.
    fn append(&self, records: &[Record]) -> Result<()>;

    /// Reads the records in `[from, to)`.
    ///
    /// # Errors
    ///
    /// Fails when the records cannot be read.
    fn records(&self, from: u64, to: u64) -> Result<Vec<Record>>;

    /// The lowest and highest positions still held, or nothing when the log is
    /// empty.
    ///
    /// # Errors
    ///
    /// Fails when the log cannot be read.
    fn span(&self) -> Result<Option<(u64, u64)>>;

    /// Removes every record from `index` upward.
    ///
    /// This is what a follower does when it learns its tail disagrees with the
    /// leader's.
    ///
    /// # Errors
    ///
    /// Fails when the records cannot be removed.
    fn truncate_from(&self, index: u64) -> Result<()>;

    /// Removes every record up to and including `index`.
    ///
    /// # Errors
    ///
    /// Fails when the records cannot be removed.
    fn purge_upto(&self, index: u64) -> Result<()>;

    /// Writes a named marker, or removes it when the value is nothing.
    ///
    /// # Errors
    ///
    /// Fails when the marker cannot be written.
    fn set_marker(&self, name: &str, value: Option<&str>) -> Result<()>;

    /// Reads a named marker.
    ///
    /// # Errors
    ///
    /// Fails when the marker cannot be read.
    fn marker(&self, name: &str) -> Result<Option<String>>;

    /// Replaces the stored snapshot.
    ///
    /// # Errors
    ///
    /// Fails when the snapshot cannot be written.
    fn set_snapshot(&self, meta: &str, data: &[u8]) -> Result<()>;

    /// Reads the stored snapshot.
    ///
    /// # Errors
    ///
    /// Fails when the snapshot cannot be read.
    fn snapshot(&self) -> Result<Option<(String, Vec<u8>)>>;
}
