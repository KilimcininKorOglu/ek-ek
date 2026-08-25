// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What can go wrong while obtaining a certificate.
//!
//! An upload that is refused produces a `ValidationError`, because an operator
//! has to fix the file they sent. An order that fails produces this instead:
//! nothing was submitted, and what went wrong is a state of the world rather
//! than a field on a form.
//!
//! # Why the reason and the detail are separate
//!
//! The reason is a stable value, so a caller can decide whether to try again
//! without reading text. The detail is what the server said, kept for the log
//! so an operator has something to search on. Nothing secret travels in
//! either: no key, no signature, and no challenge answer.

use std::fmt;

/// What kind of thing went wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The server could not be reached, or the answer never arrived.
    Network,
    /// The server answered, and the answer says the request failed.
    Server,
    /// The server answered something this client cannot read.
    Protocol,
    /// The server checked the challenge and refused it.
    Challenge,
    /// A key, a signature or a request could not be produced.
    Crypto,
    /// The configuration cannot support an order at all.
    Configuration,
    /// The cluster could not agree, so nothing was written and no order was
    /// placed.
    ///
    /// Here rather than folded into [`Self::Network`] because it says
    /// something different to an operator: the certificate authority is fine
    /// and the cluster is not. Nothing was sent anywhere, so no allowance was
    /// spent (ADR-0086).
    NoQuorum,
    /// The order failed and the attempt limit is used up.
    TooManyAttempts,
}

impl Reason {
    /// Every reason, so a test can walk the whole set.
    pub const ALL: [Self; 8] = [
        Self::Network,
        Self::Server,
        Self::Protocol,
        Self::Challenge,
        Self::Crypto,
        Self::Configuration,
        Self::NoQuorum,
        Self::TooManyAttempts,
    ];

    /// A stable identifier for logs and reports.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::Network => "acme.network",
            Self::Server => "acme.server",
            Self::Protocol => "acme.protocol",
            Self::Challenge => "acme.challenge",
            Self::Crypto => "acme.crypto",
            Self::Configuration => "acme.configuration",
            Self::NoQuorum => "acme.no_quorum",
            Self::TooManyAttempts => "acme.too_many_attempts",
        }
    }

    /// Whether trying the same order again could succeed.
    ///
    /// A refused challenge is not retried on this list: the name does not
    /// point here, or the listener does not answer, and repeating the order
    /// spends the account's rate limit on a fault nothing here can fix
    /// (ADR-0026).
    #[must_use]
    pub const fn worth_retrying(self) -> bool {
        matches!(
            self,
            Self::Network | Self::Server | Self::Protocol | Self::NoQuorum
        )
    }
}

/// One failed order, and why.
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

    /// What the server, or this client, said about it.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }

    /// Whether trying the same order again could succeed.
    #[must_use]
    pub const fn worth_retrying(&self) -> bool {
        self.reason.worth_retrying()
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.reason.key(), self.detail)
    }
}

impl std::error::Error for Failure {}
