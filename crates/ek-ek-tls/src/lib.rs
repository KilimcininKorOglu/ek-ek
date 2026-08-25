// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificates for the control plane: what an operator uploads and what ACME
//! obtains.
//!
//! An operator uploads a certificate and its private key. This crate reads
//! them, refuses what cannot be served, says what is worth knowing about what
//! can, and turns the result into a store state (ADR-0026).
//!
//! The other source is an ACME server. [`order`] decides what to ask it and
//! reads the answers with no socket anywhere in it; [`acme`] carries those
//! asks over HTTPS, holds the nonce and waits between attempts. Both ends up
//! in the same place: material that [`install`] files in the store.
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

pub mod acme;
pub mod attempt;
pub mod csr;
pub mod dns;
pub mod error;
pub mod inspect;
pub mod jws;
pub mod metrics;
pub mod order;
pub mod record;
pub mod renewal;

pub use acme::{
    Obtained, POLL_INTERVAL, Plan, Reached, Reply, Transport, obtain, obtain_over, obtain_planned,
    obtain_planned_over, run,
};
pub use attempt::{ATTEMPTS, FIRST_WAIT, wait_before, whole_run};
pub use csr::{Request, generate, key_from_pem, key_to_pem, request, request_with};
pub use dns::{CHALLENGE_LABEL, challenge_name};
pub use error::{Failure, Reason};
pub use inspect::{MOST_CERTIFICATES, Upload, inspect};
pub use jws::{
    Account, Identify, account_from_pem, account_key, account_to_pem, base64url, jwk,
    key_authorization, record_value, sign, thumbprint,
};
pub use metrics::{EXPIRY_METRIC, OBTAINED_METRIC, exposition};
pub use order::{
    Answer, Ask, Challenge, Flow, MOST_NONCE_RETRIES, MOST_POLLS, Progress, Publication,
};
pub use record::{
    CHAIN_SUFFIX, KEY_SUFFIX, ORDER_KEY_SUFFIX, carry_obtained, chain_id, install, key_id,
    order_key_id, remove,
};
pub use renewal::{
    ALARM_AFTER, Attempts, Because, Due, FIRST_BACKOFF, GROWING_WAITS, LONGEST_BACKOFF, RENEW_AT,
    backoff, due, remaining, renewable, why,
};
