// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Store failures, in the shape consensus expects.
//!
//! openraft treats a storage failure as a reason to stop this node rather than
//! carry on with state it cannot trust, and it wants to know which part of the
//! store failed and whether the failure was a read or a write. These helpers
//! carry that classification, so a store failure never arrives as "something
//! went wrong".

use std::error::Error;

use openraft::storage::SnapshotSignature;
use openraft::{AnyError, ErrorSubject, ErrorVerb, LogId, StorageError, StorageIOError};

use crate::types::NodeNumber;

fn raised<E: Error + 'static>(
    subject: ErrorSubject<NodeNumber>,
    verb: ErrorVerb,
    error: &E,
) -> StorageError<NodeNumber> {
    StorageIOError::new(subject, verb, AnyError::new(error)).into()
}

/// The replication log could not be read.
pub fn read_logs<E: Error + 'static>(error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Logs, ErrorVerb::Read, error)
}

/// The replication log could not be written.
pub fn write_logs<E: Error + 'static>(error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Logs, ErrorVerb::Write, error)
}

/// The vote could not be read.
pub fn read_vote<E: Error + 'static>(error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Vote, ErrorVerb::Read, error)
}

/// The vote could not be written.
pub fn write_vote<E: Error + 'static>(error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Vote, ErrorVerb::Write, error)
}

/// The state machine could not be read.
pub fn read_state_machine<E: Error + 'static>(error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::StateMachine, ErrorVerb::Read, error)
}

/// The state machine could not be written.
pub fn write_state_machine<E: Error + 'static>(error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::StateMachine, ErrorVerb::Write, error)
}

/// One agreed record could not be applied.
///
/// Named after the record, so an operator reading the failure knows which
/// change stopped the node.
pub fn apply<E: Error + 'static>(log_id: LogId<NodeNumber>, error: &E) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Apply(log_id), ErrorVerb::Write, error)
}

/// The snapshot could not be read.
pub fn read_snapshot<E: Error + 'static>(
    signature: Option<SnapshotSignature<NodeNumber>>,
    error: &E,
) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Snapshot(signature), ErrorVerb::Read, error)
}

/// The snapshot could not be written.
pub fn write_snapshot<E: Error + 'static>(
    signature: Option<SnapshotSignature<NodeNumber>>,
    error: &E,
) -> StorageError<NodeNumber> {
    raised(ErrorSubject::Snapshot(signature), ErrorVerb::Write, error)
}
