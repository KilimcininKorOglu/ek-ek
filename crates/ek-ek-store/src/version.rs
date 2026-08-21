// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The version log and rolling back to an earlier config.
//!
//! One write produces one version, whatever it touched. That is what lets a
//! template create a dozen objects and still be one entry in the history, and
//! one step to undo (ADR-0046).
//!
//! Certificates are the deliberate exception. A rollback restores everything
//! except them, because reverting a certificate ACME renewed in the meantime
//! would break TLS on a node that was working a moment earlier. Certificate
//! lifetime runs on its own clock, not on the config's.

use ek_ek_config::{Config, SchemaVersion};

use crate::error::Result;

/// How many versions are kept.
///
/// A count rather than an age, so the behaviour is the same on a cluster
/// changed twice a year and on one changed twice a day.
pub const MAX_VERSIONS: usize = 100;

/// Who made a change and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The account that asked for the change.
    pub author: String,
    /// A short note the author wrote.
    pub description: String,
}

impl Change {
    /// Records a change by this author.
    #[must_use]
    pub fn new(author: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            author: author.into(),
            description: description.into(),
        }
    }
}

/// Identifies one entry in the version log.
///
/// Values increase over the life of the store and are never reused, so an id
/// held by a UI stays meaningful after older versions are cleaned up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionId(i64);

impl VersionId {
    /// Wraps an id read from storage.
    #[must_use]
    pub const fn new(value: i64) -> Self {
        Self(value)
    }

    /// Returns the wrapped number.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

/// What produced a version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeKind {
    /// An ordinary write.
    Write,
    /// A return to an earlier version, which is itself a write.
    Rollback {
        /// The version whose config was restored.
        restored: VersionId,
    },
}

/// One entry in the version log, without the config it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionRecord {
    /// Identity of this version.
    pub id: VersionId,
    /// When it was written, as a Unix timestamp in seconds.
    pub recorded_at_unix: i64,
    /// Who wrote it.
    pub author: String,
    /// The note the author wrote.
    pub description: String,
    /// The schema the config was written against.
    pub schema_version: SchemaVersion,
    /// Whether this was an ordinary write or a rollback.
    pub kind: ChangeKind,
}

/// A note that an old version was removed to stay inside the retention limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PruningRecord {
    /// When the removal happened, as a Unix timestamp in seconds.
    pub recorded_at_unix: i64,
    /// The account whose write pushed the log over the limit.
    pub author: String,
    /// The version that was removed.
    pub removed: VersionId,
}

/// A log of config versions that can be read and returned to.
pub trait History {
    /// Lists the version log, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the log cannot be read.
    fn versions(&self) -> Result<Vec<VersionRecord>>;

    /// Reads the config a version holds, or nothing when there is no such
    /// version.
    ///
    /// # Errors
    ///
    /// Fails when the record cannot be read back into a config.
    fn version_config(&self, id: VersionId) -> Result<Option<Config>>;

    /// Returns to the config an earlier version holds.
    ///
    /// This is a write like any other and appends a new version, so the
    /// history is never shortened by undoing something. Certificates and key
    /// material keep their current values.
    ///
    /// # Errors
    ///
    /// Fails when the version does not exist, or when it was written against
    /// a different schema. In the second case it refuses rather than loading
    /// fields it happens to recognise.
    fn roll_back_to(&self, id: VersionId, change: &Change) -> Result<VersionId>;

    /// Lists what the retention limit removed, newest first.
    ///
    /// # Errors
    ///
    /// Fails when the records cannot be read.
    fn prunings(&self) -> Result<Vec<PruningRecord>>;
}
