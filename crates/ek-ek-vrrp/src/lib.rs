// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! VRRP state machine, VIP management through netlink, and gratuitous ARP.
//!
//! This code runs inside `node-agent`, never inside the pingora process. A
//! listener change replaces that process, which would duplicate the VRID and
//! flap the VIP (ADR-0002).
//!
//! VIP ownership is never derived from Raft leadership (ADR-0004).
//!
//! Send gratuitous ARP after every failover. Without it the VIP move does not
//! propagate and the failure is silent.
//!
//! This is the only platform specific crate. It requires Linux, `NET_ADMIN`
//! and `NET_RAW`.
//!
//! The advertisement parser reads raw, unauthenticated network data. It must
//! be covered by fuzz tests.

pub mod header;
pub mod packet;
#[cfg(target_os = "linux")]
pub mod socket;
pub mod state;
pub mod transport;

pub use packet::{ADVERTISEMENT, Advertisement, GIVING_UP, Malformed, PROTOCOL, VERSION};
#[cfg(target_os = "linux")]
pub use socket::RawSocket;
pub use state::{Action, Ignored, Machine, Reason, Settings, State, Transition};
pub use transport::Transport;
