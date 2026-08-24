// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Config replication: one agreed history of the configuration, on every node.
//!
//! Every node holds the whole configuration and serves traffic from its own
//! copy. A change is agreed by a quorum before any node applies it, so the
//! copies do not drift, and a read never asks a quorum for permission, so
//! losing one does not stop traffic (ADR-0004, ADR-0083).
//!
//! # What is replicated
//!
//! The configuration, the key material the configuration refers to, the
//! cluster authority, the version history (T-015) and the audit log. All of it
//! travels together, because a node that held the config without the keys
//! could not terminate a single connection.
//!
//! # Where each piece lives
//!
//! - [`types`] is what travels: the request, the answer and the wire shapes
//!   the store's own types convert to.
//! - [`identity`] is the number consensus calls a node, derived from its name.
//! - [`log`] is the replication log, on the store's journal.
//! - [`machine`] is the state machine: the store, driven by an agreed log.
//! - [`network`] is the transport: Raft calls on the peer channel (ADR-0082).
//! - [`cluster`] is what the rest of the product uses.
//!
//! # What never appears in an error
//!
//! Key material. A replicated write carries private keys, and a failure about
//! that write names the write and never its contents (ADR-0018).

// openraft's `StorageError` is 224 bytes wide and it is named by every
// storage trait method this crate implements. Boxing it is not open to us:
// the trait signatures fix the type. The alternative to one allow here is the
// same allow repeated on two dozen functions.
#![allow(clippy::result_large_err)]

pub mod cluster;
pub mod error;
pub mod fault;
pub mod identity;
pub mod log;
pub mod machine;
pub mod network;
pub mod types;

pub use cluster::{
    Cluster, ELECTION_TIMEOUT_MAX_MS, ELECTION_TIMEOUT_MIN_MS, HEARTBEAT_MS, Membership,
    SNAPSHOT_EVERY, WRITE_PATIENCE,
};
pub use error::{Failure, Reason, Result};
pub use identity::DOMAIN;
pub use log::LogStore;
pub use machine::Applied;
pub use machine::{StateMachine, read_local, snapshot_now};
pub use network::{APPEND_ENTRIES, Dialler, INSTALL_SNAPSHOT, RaftService, VOTE, Wire, service};
pub use types::{
    NodeNumber, PeerNode, TypeConfig, WireAudit, WireChange, WireSnapshot, WireState, WireVersion,
    WriteRequest, WriteResponse,
};
