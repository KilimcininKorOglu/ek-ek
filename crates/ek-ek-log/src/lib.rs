// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Structured logging and the access log.
//!
//! Every record is one JSON object on one line of standard output. Collection
//! and retention belong to journald, so nothing here rotates a file or fills a
//! disk (ADR-0037).
//!
//! # Two kinds of record
//!
//! An application record says what the process did. An access record says what
//! one request or connection did. Both carry a `kind` field, because an
//! operator filtering a busy log needs to separate them without guessing from
//! the other fields.
//!
//! # Field names are a contract
//!
//! Whatever reads these lines matches on field names. Renaming one is a
//! breaking change, so the set is pinned by a test rather than left to
//! whoever edits a struct next (ADR-0037).
//!
//! # Nothing waits on the log
//!
//! Records go to a bounded queue and a writer thread drains it. A slow or
//! blocked consumer of standard output therefore costs a dropped record, never
//! a request that waits. The drops are counted, because a silent gap in a log
//! is worse than a number saying how big the gap is.
//!
//! # Language
//!
//! Log messages are written in English and never translated. They are read by
//! whoever is diagnosing a fault, and a translated message cannot be searched
//! for (ADR-0015).

pub mod access;
pub mod level;
pub mod logger;
pub mod mask;
pub mod sink;
pub mod time;

pub use access::{Access, Protocol};
pub use level::Level;
pub use logger::{Logger, access, dropped, install, install_to, installed, set_level};
pub use sink::{Captured, Sink, Slow, Stdout};
