// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unix socket protocol between `node-agent` and `data-plane`.
//!
//! The two processes are separate so that replacing the `data-plane` on a
//! listener change never disturbs the VRRP state machine (ADR-0002). This
//! crate carries the message types they exchange over `/run/ek-ek/agent.sock`.
//!
//! The protocol must stay readable by the previous release, because upgrades
//! are rolling and the two processes can briefly run different versions.
