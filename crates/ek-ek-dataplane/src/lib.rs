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

pub mod balance;
pub mod certs;
pub mod error;
pub mod handshake;
pub mod hashring;
pub mod health;
pub mod link;
pub mod live;
pub mod probe;
pub mod proxy;
pub mod proxyproto;
pub mod route;
pub mod server;
pub mod sticky;
pub mod stream;
pub mod udp;
pub mod udpproxy;

pub use balance::{Balancer, ring_for};
pub use certs::{Certificates, LoadFailure, Loaded};
pub use error::{Error, ErrorKind, Result};
pub use handshake::SniResolver;
pub use hashring::{HashRing, hash};
pub use health::{Change, Checked, Health, checked};
pub use link::{AgentLink, RECONNECT_DELAY, STATUS_INTERVAL};
pub use live::{Live, LiveConfig, Status};
pub use probe::{Outcome, PROBE_AGENT};
pub use proxy::{Proxy, upstream};
pub use proxyproto::{header, unknown};
pub use route::{Decision, decide, host_matches, normalise, path_matches};
pub use server::{Binding, DrainCount, ListenerKind, bindings, build, shutdown_conf};
pub use stream::StreamProxy;
