// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificate inspection and upload for the control plane.
//!
//! An operator uploads a certificate and its private key. This crate reads
//! them, refuses what cannot be served, says what is worth knowing about what
//! can, and turns the result into a store state (ADR-0026).
//!
//! # Why this is not in the traffic path
//!
//! Nothing here runs while a request does. The traffic path receives material
//! that has already been through this crate, and its own loader in
//! `ek-ek-dataplane` only has to turn bytes into a handshake.
//!
//! Both use the same library (ADR-0068), so a certificate accepted here is
//! one that path can load. A second parser would let the two disagree about
//! what a certificate is, and the disagreement would show up as a handshake
//! failure on a certificate the interface called valid.
//!
//! # Where the material goes
//!
//! Into the store, sealed with the node's own master key (ADR-0018). Nothing
//! here writes to disk: [`install`] returns the state to write, and the
//! caller writes it, so one Raft entry carries the certificate and its
//! material together.
//!
//! # What never appears in an error
//!
//! The material. Every fault is a stable code and the field it blames, and a
//! private key never travels inside one, because an error is written to a log
//! eventually.

pub mod inspect;
pub mod record;

pub use inspect::{MOST_CERTIFICATES, Upload, inspect};
pub use record::{CHAIN_SUFFIX, KEY_SUFFIX, chain_id, install, key_id, remove};
