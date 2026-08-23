// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What can go wrong while building the cluster's own trust.
//!
//! # Why the reason and the detail are separate
//!
//! The reason is a stable value, so a caller can decide what to do without
//! reading text. The detail is what the library said, kept for the log so an
//! operator has something to search on.
//!
//! # What never travels in one
//!
//! Key material. Every failure here can end up in a log record, and the CA
//! private key must never appear in one (T-036).

use std::fmt;

/// What kind of thing went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// A key, a certificate or a signature could not be produced.
    Crypto,
    /// What was asked for cannot be built at all.
    Configuration,
    /// The stored cluster identity is missing or does not read back.
    Storage,
    /// A peer could not be reached, or the answer never arrived.
    Network,
    /// A peer was reached and its certificate was refused.
    Rejected,
    /// A peer answered something this release cannot read.
    Protocol,
}

impl Reason {
    /// Every reason, so a test can walk the whole set.
    pub const ALL: [Self; 6] = [
        Self::Crypto,
        Self::Configuration,
        Self::Storage,
        Self::Network,
        Self::Rejected,
        Self::Protocol,
    ];

    /// A stable identifier for logs and reports.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Crypto => "peer.crypto",
            Self::Configuration => "peer.configuration",
            Self::Storage => "peer.storage",
            Self::Network => "peer.network",
            Self::Rejected => "peer.rejected",
            Self::Protocol => "peer.protocol",
        }
    }
}

/// One failure, and why.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    reason: Reason,
    detail: String,
}

impl Failure {
    /// Builds a failure.
    #[must_use]
    pub fn new(reason: Reason, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }

    /// What kind of thing went wrong.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }

    /// What the library, or this crate, said about it.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.reason.key(), self.detail)
    }
}

impl std::error::Error for Failure {}

/// Builds a `Crypto` failure from an OpenSSL error.
pub(crate) fn crypto(what: &'static str) -> impl Fn(openssl::error::ErrorStack) -> Failure {
    move |error| Failure::new(Reason::Crypto, format!("{what}: {error}"))
}
