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

use ek_ek_config::{Config, SecretId};

use crate::error::Result;
use crate::secret::Secret;
use crate::version::{Change, VersionId};

/// A complete store state: the config, plus the key material it references.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    /// What an operator configured.
    pub config: Config,
    /// Key material, keyed by the identity the config refers to.
    pub secrets: BTreeMap<SecretId, Secret>,
}

impl Snapshot {
    /// Builds a state that holds a config and no key material.
    #[must_use]
    pub fn new(config: Config) -> Self {
        Self {
            config,
            secrets: BTreeMap::new(),
        }
    }

    /// Adds key material under an identity.
    #[must_use]
    pub fn with_secret(mut self, id: SecretId, secret: Secret) -> Self {
        self.secrets.insert(id, secret);
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
}
