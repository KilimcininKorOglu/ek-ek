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
//!
//! # Framing
//!
//! One JSON object per line. A reader takes a line, a writer appends a
//! newline, and nothing has to agree on a length prefix or a struct layout.
//! That keeps the format readable in a log and lets a test speak it without
//! linking this crate, which is what proves it is a wire format rather than a
//! shared type.
//!
//! Both directions are tagged, so a message from a newer release arrives as an
//! unknown tag and is refused by name instead of being read as the wrong
//! message.

pub mod message;
pub mod wire;

pub use message::{
    AgentMessage, CertificateMaterial, ConfigRejection, ConfigUpdate, Counters, DataPlaneMessage,
    DataPlaneState, Hello, MemberHealth, OpenConnections, StatusReport, UdpSessions,
};
pub use wire::{Error, Result, decode, encode};

/// Where the agent listens in a real installation (ADR-0010).
pub const SOCKET_PATH: &str = "/run/ek-ek/agent.sock";
