// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Raft replicated configuration store on a SQLite state machine.
//!
//! Holds configuration, its version history, certificates and the audit log.
//! Writes go through Raft consensus, so they require a quorum.
//!
//! Losing quorum must never affect traffic (ADR-0004). This crate is part of
//! the control plane only; nothing here sits on a request path.
//!
//! Every SQL statement is parameterised. Never build a query by concatenation.
//!
//! # What is here now
//!
//! Raft arrives in M6. Until then the store runs on a single node, because
//! M3, M4 and M5 need somewhere to keep a config and cannot wait for
//! consensus to be wired up.
//!
//! The [`Store`] trait is what the rest of the product uses, and it names no
//! database. M6 wraps it in a state machine, and a caller written against it
//! does not change when that happens. State is read and written whole, which
//! is the shape a Raft state machine applies as well.
//!
//! # Secrets
//!
//! The config model holds only a `SecretId`. The bytes behind that identity
//! live here and are sealed with the node's own master key before they touch
//! the disk (ADR-0018). The key is generated on this node, kept readable by
//! its owner alone, and never replicated.

pub mod crypto;
pub mod error;
pub mod master_key;
pub mod secret;
pub mod sqlite;
pub mod store;

pub use crypto::Sealed;
pub use error::{Error, ErrorKind, Result};
pub use master_key::{KEY_LENGTH, KEY_MODE, MASTER_KEY_FILE, MasterKey};
pub use secret::Secret;
pub use sqlite::{DATABASE_FILE, DEFAULT_DATA_DIRECTORY, SqliteStore};
pub use store::{Snapshot, Store};
