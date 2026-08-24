// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cluster's own certificate authority, and the channel its nodes talk
//! over.
//!
//! Peer traffic carries configuration and private key material, so it is
//! encrypted and both ends are authenticated (ADR-0008). The certificates on
//! both ends come from an authority this cluster generated for itself and
//! nobody else trusts.
//!
//! # Why this is not `ek-ek-tls`
//!
//! That crate handles the certificates an operator uploads and the ones ACME
//! issues: material a browser will meet. This one handles material only the
//! cluster ever meets. ADR-0008 calls them separate trust domains, and the
//! separation is enforced by the build: neither crate may depend on the other
//! (`scripts/check-layering.sh`).
//!
//! # Where the material goes
//!
//! The authority certificate goes into the store as the cluster identity, and
//! its private key goes in as a secret, sealed with the node's own master key
//! (ADR-0018). [`record`] does both together, because half an authority is
//! useless.
//!
//! # What never appears in an error
//!
//! Key material. Every failure here is a stable reason and a detail written
//! for a log, and a private key never travels inside one.

pub mod authority;
pub mod channel;
pub mod error;
pub mod fingerprint;
pub mod message;
pub mod record;
pub mod renewal;
pub mod request;
pub mod wire;

pub use authority::{
    AUTHORITY_COMMON_NAME, AUTHORITY_LIFETIME_DAYS, Authority, CLOCK_SKEW_ALLOWANCE_SECONDS,
    Issued, NODE_LIFETIME_DAYS, Signed, authority_certificate, authority_key, create, identity_of,
    issue, sign_for, signed_by,
};
pub use channel::{
    Credentials, DEFAULT_PORT, Gate, Listener, Listening, NoGate, NoServices, PATIENCE, Peer,
    Served, Service, ask_health,
};
pub use error::{Failure, Reason};
pub use fingerprint::{FINGERPRINT_CHARACTERS, fingerprint, matches, well_formed};
pub use message::{
    Answer, Ask, Call, HealthAnswer, HealthAsk, Hello, HelloAnswer, NO_HELLO, NO_SERVICE, NOT_OPEN,
    PROTOCOL, REMOVED, Refusal, Reply, UNREADABLE, WRONG_PROTOCOL, WRONG_SCHEMA,
};
pub use record::{AUTHORITY_KEY_SECRET, authority_key_id, install, present, read};
pub use renewal::{RENEW_AT, due, expired, remaining, unix_of, window_of, window_of_pem};
pub use request::{REQUEST_COMMON_NAME, Requested, certify, key_of, public_key, request};
pub use wire::{MOST_LINE_BYTES, decode, encode};
