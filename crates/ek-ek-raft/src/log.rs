// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The replication log, on the store's own journal.
//!
//! Records are written out as JSON and read back the same way. The journal
//! underneath knows nothing about what they mean, which is what lets the store
//! be opened and measured with no consensus anywhere near it (ADR-0083).

use std::fmt::Debug;
use std::ops::RangeBounds;
use std::sync::Arc;

use ek_ek_store::journal::marker;
use ek_ek_store::{Journal, Record, SqliteStore};
use openraft::storage::{LogFlushed, LogState, RaftLogStorage};
use openraft::{Entry, LogId, RaftLogReader, StorageError, Vote};

use crate::fault;
use crate::types::{NodeNumber, TypeConfig};

/// The log, backed by the node's own store.
#[derive(Clone)]
pub struct LogStore {
    store: Arc<SqliteStore>,
}

impl Debug for LogStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("LogStore").finish_non_exhaustive()
    }
}

impl LogStore {
    /// Opens the log kept beside the config in one store.
    #[must_use]
    pub const fn new(store: Arc<SqliteStore>) -> Self {
        Self { store }
    }

    fn read_marker<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, StorageError<NodeNumber>> {
        let held = self
            .store
            .marker(name)
            .map_err(|error| fault::read_logs(&error))?;
        let Some(held) = held else {
            return Ok(None);
        };
        serde_json::from_str(&held)
            .map(Some)
            .map_err(|error| fault::read_logs(&error))
    }

    /// Writes records to the journal.
    ///
    /// Separate from the trait method because the callback openraft passes it
    /// cannot be built outside openraft, and a rule nothing can drive is a rule
    /// nothing measures.
    ///
    /// # Errors
    ///
    /// Returns a write fault when a record cannot be written out or stored.
    pub fn keep<I>(&self, entries: I) -> Result<(), StorageError<NodeNumber>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>>,
    {
        let mut records = Vec::new();
        for entry in entries {
            records.push(Record {
                index: entry.log_id.index,
                payload: serde_json::to_string(&entry)
                    .map_err(|error| fault::write_logs(&error))?,
            });
        }

        self.store
            .append(&records)
            .map_err(|error| fault::write_logs(&error))
    }

    fn write_marker<T: serde::Serialize>(
        &self,
        name: &str,
        value: Option<&T>,
    ) -> Result<(), StorageError<NodeNumber>> {
        let written = value
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| fault::write_logs(&error))?;
        self.store
            .set_marker(name, written.as_deref())
            .map_err(|error| fault::write_logs(&error))
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> Result<Vec<Entry<TypeConfig>>, StorageError<NodeNumber>> {
        let from = match range.start_bound() {
            std::ops::Bound::Included(value) => *value,
            std::ops::Bound::Excluded(value) => value.saturating_add(1),
            std::ops::Bound::Unbounded => 0,
        };
        let to = match range.end_bound() {
            std::ops::Bound::Included(value) => value.saturating_add(1),
            std::ops::Bound::Excluded(value) => *value,
            std::ops::Bound::Unbounded => u64::MAX,
        };

        let records = self
            .store
            .records(from, to)
            .map_err(|error| fault::read_logs(&error))?;

        let mut entries = Vec::with_capacity(records.len());
        for record in records {
            entries.push(
                serde_json::from_str(&record.payload).map_err(|error| fault::read_logs(&error))?,
            );
        }
        Ok(entries)
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> Result<LogState<TypeConfig>, StorageError<NodeNumber>> {
        let purged: Option<LogId<NodeNumber>> = self.read_marker(marker::PURGED)?;

        let span = self
            .store
            .span()
            .map_err(|error| fault::read_logs(&error))?;

        // The last present entry, or the last purged one when nothing is
        // present. An empty log after compaction still has a last id, and
        // reporting nothing there would make a follower ask for records that
        // were deliberately removed.
        //
        // The record at the end of the span is read rather than assumed: the
        // id carries a term as well as an index, and only the record itself
        // holds the term.
        let mut last = purged;
        if let Some((_, end)) = span {
            let held = self
                .store
                .records(end, end.saturating_add(1))
                .map_err(|error| fault::read_logs(&error))?;
            if let Some(record) = held.first() {
                let entry: Entry<TypeConfig> = serde_json::from_str(&record.payload)
                    .map_err(|error| fault::read_logs(&error))?;
                last = Some(entry.log_id);
            }
        }

        Ok(LogState {
            last_purged_log_id: purged,
            last_log_id: last,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<NodeNumber>) -> Result<(), StorageError<NodeNumber>> {
        self.write_marker(marker::VOTE, Some(vote))
    }

    async fn read_vote(&mut self) -> Result<Option<Vote<NodeNumber>>, StorageError<NodeNumber>> {
        self.read_marker(marker::VOTE)
    }

    async fn save_committed(
        &mut self,
        committed: Option<LogId<NodeNumber>>,
    ) -> Result<(), StorageError<NodeNumber>> {
        self.write_marker(marker::COMMITTED, committed.as_ref())
    }

    async fn read_committed(
        &mut self,
    ) -> Result<Option<LogId<NodeNumber>>, StorageError<NodeNumber>> {
        self.read_marker(marker::COMMITTED)
    }

    async fn append<I>(
        &mut self,
        entries: I,
        callback: LogFlushed<TypeConfig>,
    ) -> Result<(), StorageError<NodeNumber>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        self.keep(entries)?;

        // The records are on disk before this is called, because the journal
        // commits its transaction before it returns. Telling openraft
        // otherwise would let it acknowledge a write nothing has stored.
        callback.log_io_completed(Ok(()));
        Ok(())
    }

    async fn truncate(
        &mut self,
        log_id: LogId<NodeNumber>,
    ) -> Result<(), StorageError<NodeNumber>> {
        self.store
            .truncate_from(log_id.index)
            .map_err(|error| fault::write_logs(&error))
    }

    async fn purge(&mut self, log_id: LogId<NodeNumber>) -> Result<(), StorageError<NodeNumber>> {
        self.write_marker(marker::PURGED, Some(&log_id))?;
        self.store
            .purge_upto(log_id.index)
            .map_err(|error| fault::write_logs(&error))
    }
}
