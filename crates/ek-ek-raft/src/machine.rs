// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The state machine: the config store, driven by an agreed log.
//!
//! # Why applying and marking happen together
//!
//! Every applied record moves the config and the "applied up to here" marker
//! in one transaction. A node that stops between the two either applies the
//! same record twice or never applies it, and nothing on disk would say which
//! (ADR-0083).
//!
//! # What a snapshot carries
//!
//! Everything a node must hold to be identical to its peers: the config, the
//! key material, the cluster authority, the version log with its numbers and
//! the audit log. Key material travels in the clear and every node seals what
//! it receives with its own master key, because that key is the one thing
//! nodes never share (ADR-0018).

use std::fmt::Debug;
use std::io::Cursor;
use std::sync::Arc;

use ek_ek_store::journal::marker;
use ek_ek_store::{
    AuditRecord, Change, FullState, Journal, Snapshot as StoredSnapshot, SqliteStore, Store,
};
use openraft::storage::{RaftSnapshotBuilder, RaftStateMachine};
use openraft::{
    Entry, EntryPayload, LogId, Snapshot, SnapshotMeta, StorageError, StoredMembership,
};

use crate::fault;
use crate::types::{NodeNumber, PeerNode, TypeConfig, WireState, WriteResponse};

/// Where a node has applied to, and the membership that position carries.
///
/// The two travel together because openraft reads them together: a node that
/// knew its position but not its membership could not tell who may vote.
pub type Applied = (
    Option<LogId<NodeNumber>>,
    StoredMembership<NodeNumber, PeerNode>,
);

/// The state machine, backed by the node's own store.
#[derive(Clone)]
pub struct StateMachine {
    store: Arc<SqliteStore>,
}

impl Debug for StateMachine {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateMachine")
            .finish_non_exhaustive()
    }
}

impl StateMachine {
    /// Builds a state machine over one store.
    #[must_use]
    pub const fn new(store: Arc<SqliteStore>) -> Self {
        Self { store }
    }

    /// The store this machine applies to.
    #[must_use]
    pub fn store(&self) -> &Arc<SqliteStore> {
        &self.store
    }

    fn read_marker<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, StorageError<NodeNumber>> {
        let held = self
            .store
            .marker(name)
            .map_err(|error| fault::read_state_machine(&error))?;
        let Some(held) = held else {
            return Ok(None);
        };
        serde_json::from_str(&held)
            .map(Some)
            .map_err(|error| fault::read_state_machine(&error))
    }

    /// The applied position and the membership it carries.
    fn applied(&self) -> Result<Applied, StorageError<NodeNumber>> {
        let applied = self.read_marker(marker::APPLIED)?;
        let membership = self.read_marker(marker::MEMBERSHIP)?.unwrap_or_default();
        Ok((applied, membership))
    }

    /// Writes the two markers that follow an applied record.
    fn markers(
        applied: &LogId<NodeNumber>,
        membership: Option<&StoredMembership<NodeNumber, PeerNode>>,
    ) -> Result<Vec<(String, String)>, StorageError<NodeNumber>> {
        let mut written = vec![(
            marker::APPLIED.to_owned(),
            serde_json::to_string(applied).map_err(|error| fault::write_state_machine(&error))?,
        )];
        if let Some(membership) = membership {
            written.push((
                marker::MEMBERSHIP.to_owned(),
                serde_json::to_string(membership)
                    .map_err(|error| fault::write_state_machine(&error))?,
            ));
        }
        Ok(written)
    }
}

impl RaftSnapshotBuilder<TypeConfig> for StateMachine {
    async fn build_snapshot(&mut self) -> Result<Snapshot<TypeConfig>, StorageError<NodeNumber>> {
        let state = self
            .store
            .export()
            .map_err(|error| fault::read_state_machine(&error))?;
        let (applied, membership) = self.applied()?;

        let meta = SnapshotMeta {
            last_log_id: applied,
            last_membership: membership,
            // Named after the position it was taken at, so two snapshots of
            // the same state are the same snapshot and a follower can tell
            // whether it already has one.
            snapshot_id: applied.map_or_else(|| "empty".to_owned(), |log_id| log_id.to_string()),
        };

        let payload = serde_json::to_vec(&WireState::from(&state))
            .map_err(|error| fault::write_snapshot(Some(meta.signature()), &error))?;

        self.store
            .set_snapshot(
                &serde_json::to_string(&meta)
                    .map_err(|error| fault::write_snapshot(Some(meta.signature()), &error))?,
                &payload,
            )
            .map_err(|error| fault::write_snapshot(Some(meta.signature()), &error))?;

        Ok(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(payload)),
        })
    }
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = Self;

    async fn applied_state(&mut self) -> Result<Applied, StorageError<NodeNumber>> {
        self.applied()
    }

    async fn apply<I>(&mut self, entries: I) -> Result<Vec<WriteResponse>, StorageError<NodeNumber>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut answers = Vec::new();

        for entry in entries {
            let log_id = entry.log_id;
            match entry.payload {
                EntryPayload::Blank => {
                    self.store
                        .set_marker(
                            marker::APPLIED,
                            Some(
                                &serde_json::to_string(&log_id)
                                    .map_err(|error| fault::write_state_machine(&error))?,
                            ),
                        )
                        .map_err(|error| fault::write_state_machine(&error))?;
                    answers.push(WriteResponse { version: 0 });
                }
                EntryPayload::Membership(membership) => {
                    let stored = StoredMembership::new(Some(log_id), membership);
                    for (name, value) in Self::markers(&log_id, Some(&stored))? {
                        self.store
                            .set_marker(&name, Some(&value))
                            .map_err(|error| fault::write_state_machine(&error))?;
                    }
                    answers.push(WriteResponse { version: 0 });
                }
                EntryPayload::Normal(request) => {
                    let state = StoredSnapshot::from(&request.state);
                    let change = Change::from(&request.change);
                    let markers = Self::markers(&log_id, None)?;
                    let borrowed: Vec<(&str, &str)> = markers
                        .iter()
                        .map(|(name, value)| (name.as_str(), value.as_str()))
                        .collect();

                    let audit: Vec<AuditRecord> =
                        request.audit.iter().map(AuditRecord::from).collect();

                    let version = self
                        .store
                        .apply_write(&state, &change, request.now_unix, &borrowed, &audit)
                        .map_err(|error| fault::apply(log_id, &error))?;
                    answers.push(WriteResponse {
                        version: version.get(),
                    });
                }
            }
        }

        Ok(answers)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        self.clone()
    }

    async fn begin_receiving_snapshot(
        &mut self,
    ) -> Result<Box<Cursor<Vec<u8>>>, StorageError<NodeNumber>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<NodeNumber, PeerNode>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> Result<(), StorageError<NodeNumber>> {
        let payload = snapshot.into_inner();
        let wire: WireState = serde_json::from_slice(&payload)
            .map_err(|error| fault::read_snapshot(Some(meta.signature()), &error))?;
        let state = FullState::from(&wire);

        let mut markers: Vec<(String, String)> = Vec::new();
        if let Some(applied) = &meta.last_log_id {
            markers = Self::markers(applied, Some(&meta.last_membership))?;
        }
        let borrowed: Vec<(&str, &str)> = markers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();

        // One transaction. A node catching up must never be left holding half
        // of one peer's state and half of its own.
        self.store
            .import(&state, &borrowed)
            .map_err(|error| fault::write_state_machine(&error))?;

        self.store
            .set_snapshot(
                &serde_json::to_string(meta)
                    .map_err(|error| fault::write_snapshot(Some(meta.signature()), &error))?,
                &payload,
            )
            .map_err(|error| fault::write_snapshot(Some(meta.signature()), &error))?;

        Ok(())
    }

    async fn get_current_snapshot(
        &mut self,
    ) -> Result<Option<Snapshot<TypeConfig>>, StorageError<NodeNumber>> {
        let held = self
            .store
            .snapshot()
            .map_err(|error| fault::read_snapshot(None, &error))?;
        let Some((meta, data)) = held else {
            return Ok(None);
        };
        let meta: SnapshotMeta<NodeNumber, PeerNode> =
            serde_json::from_str(&meta).map_err(|error| fault::read_snapshot(None, &error))?;

        Ok(Some(Snapshot {
            meta,
            snapshot: Box::new(Cursor::new(data)),
        }))
    }
}

/// Reads the config a node holds, without going near consensus.
///
/// This is the read path (ADR-0004). It touches the local store and nothing
/// else, so it keeps working while quorum is lost.
///
/// # Errors
///
/// Fails when the local state cannot be read.
pub fn read_local(store: &SqliteStore) -> ek_ek_store::Result<Option<StoredSnapshot>> {
    store.read()
}

/// Takes a snapshot now, whatever the log looks like.
///
/// # Errors
///
/// Fails when the state cannot be read or the snapshot cannot be written.
pub async fn snapshot_now(
    machine: &mut StateMachine,
) -> Result<Snapshot<TypeConfig>, StorageError<NodeNumber>> {
    machine.build_snapshot().await
}
