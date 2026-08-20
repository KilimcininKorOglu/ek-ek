// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The traffic path: HTTP, TCP and UDP proxying, TLS termination and health
//! checks.
//!
//! Runs as the `data-plane` process. This is the only crate that depends on
//! pingora, so the effect of a pingora change stays contained here.
//!
//! Pingora declares its listeners before `run_forever()` and cannot add one at
//! runtime. Backend, health check and routing changes swap in place. A new
//! listener needs a graceful upgrade with socket handover.
//!
//! Pingora provides no UDP load balancing, so this crate also carries a second,
//! hand-written UDP path. UDP listeners use `SO_REUSEPORT` for upgrades instead
//! of file descriptor handover.
//!
//! Every configuration change must preserve open connections. Apply new
//! configuration only to new connections.
