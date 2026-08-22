// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Integration test harness for the three node docker cluster (ADR-0012).
//!
//! Everything that touches the network layer is tested here rather than in a
//! unit test, because VRRP, multicast and netlink only work on Linux while
//! development happens on macOS.
//!
//! The harness owns the container lifecycle. A test never depends on a cluster
//! someone brought up by hand, because CI has no manual step.
//!
//! Measurement runs inside the cluster, never across the host boundary. A
//! published port would put docker's port forwarding in the measured path, and
//! on macOS that path drops connections under load, which reads as a fault in
//! whatever is under test.

mod capture;
mod cluster;
mod error;
mod load;
mod node;

pub use capture::{Capture, CaptureResult};
pub use cluster::{Cluster, MAIL_PLAIN_PORT, MAIL_PROXIED_PORT, VIP_RANGE};
pub use error::{Error, Result};
pub use load::LoadReport;
pub use node::{Background, Node, Output};
