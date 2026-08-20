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
