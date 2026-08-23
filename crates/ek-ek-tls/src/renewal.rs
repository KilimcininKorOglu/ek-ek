// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! When a certificate has to be obtained again, and what to do when it is not.
//!
//! A certificate that runs out stops every handshake at once, and nothing in
//! the configuration looks wrong when it happens. So renewal starts well
//! before the end, and a renewal that keeps failing becomes something an
//! operator is told about rather than something that is only discovered by the
//! outage (ADR-0026).
//!
//! # What this never does
//!
//! It opens no socket, reads no file and reads no clock. Every function here
//! takes the time it works against, so a rule about a window months wide is
//! measured in microseconds and the same code answers "what is due next
//! month?" (ADR-0079).

use std::time::Duration;

use ek_ek_config::{Certificate, CertificateSource, CertificateValidity};
use serde::{Deserialize, Serialize};

/// The share of a certificate's lifetime that must remain before it is
/// renewed.
///
/// One third. On a 90 day certificate that is 30 days of margin, which is
/// enough to notice a failure and fix what caused it. It is not configurable,
/// for the same reason the attempt count is not (ADR-0077): renewing earlier
/// spends an allowance that belongs to the ACME server, and the operator
/// cannot see how much of it is left.
pub const RENEW_AT: i64 = 3;

/// How many failed orders in a row raise the alarm.
///
/// Three, which the growing waits spread over at least seven hours, and each
/// of the three spends fifteen minutes of its own on five attempts. A network
/// fault that clears by itself does not last that long, so an alarm means
/// something an operator has to look at.
pub const ALARM_AFTER: u32 = 3;

/// How long to wait after the first failed order.
pub const FIRST_BACKOFF: Duration = Duration::from_secs(3_600);

/// The longest wait between two orders of the same certificate.
///
/// A day. The renewal window is a third of the lifetime, so even at this
/// interval there are dozens of attempts left before the certificate runs out.
pub const LONGEST_BACKOFF: Duration = Duration::from_secs(86_400);

/// How many waits double before the longest one takes over.
///
/// Four: one, two, four and eight hours. A fault that has survived all of
/// those is one somebody has to look at, and asking every hour after that only
/// spends the ACME server's allowance on an answer nobody is reading.
pub const GROWING_WAITS: u32 = 4;

/// Why one certificate is being ordered again.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Because {
    /// Nothing has been obtained for it yet.
    NeverObtained,
    /// Less than a third of its lifetime is left.
    RunningOut,
}

/// One certificate that should be ordered now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Due<'a> {
    /// Which certificate it is.
    pub certificate: &'a Certificate,
    /// What made it due.
    pub because: Because,
}

/// How long a certificate has left, in seconds.
///
/// Negative once the window has passed, which is what lets one comparison
/// answer both "is it running out?" and "has it gone?".
#[must_use]
pub const fn remaining(validity: &CertificateValidity, now_unix: i64) -> i64 {
    validity.not_after_unix.saturating_sub(now_unix)
}

/// Whether a certificate is obtained from an ACME server.
///
/// An uploaded one is never renewed here. Somebody bought it or asked an
/// internal authority for it, and this product has no way to ask again
/// (ADR-0026). It still gets the expiry warning, which is the whole point of
/// having one.
#[must_use]
pub const fn renewable(certificate: &Certificate) -> bool {
    matches!(
        certificate.source,
        CertificateSource::AcmeHttp01 | CertificateSource::AcmeDns01 { .. }
    )
}

/// Why one certificate is due, or `None` when it is not.
#[must_use]
pub fn why(certificate: &Certificate, now_unix: i64) -> Option<Because> {
    if !renewable(certificate) {
        return None;
    }
    // Configured but never obtained. There is no material to serve, so there
    // is nothing to wait for either.
    let Some(validity) = certificate.validity else {
        return Some(Because::NeverObtained);
    };

    let lifetime = validity
        .not_after_unix
        .saturating_sub(validity.not_before_unix);
    // A window that is not a window at all. Treated as due, because the safe
    // direction is to obtain a certificate that can actually be served.
    if lifetime <= 0 {
        return Some(Because::RunningOut);
    }
    (remaining(&validity, now_unix) <= lifetime / RENEW_AT).then_some(Because::RunningOut)
}

/// Every certificate that should be ordered now, in configuration order.
#[must_use]
pub fn due(certificates: &[Certificate], now_unix: i64) -> Vec<Due<'_>> {
    certificates
        .iter()
        .filter_map(|certificate| {
            why(certificate, now_unix).map(|because| Due {
                certificate,
                because,
            })
        })
        .collect()
}

/// How long to wait before ordering again, after this many failures in a row.
///
/// One, two, four and eight hours, then a day for as long as it keeps failing.
/// Zero failures is no wait, which is what a certificate that has never failed
/// gets.
#[must_use]
pub fn backoff(failures: u32) -> Duration {
    if failures == 0 {
        return Duration::ZERO;
    }
    if failures > GROWING_WAITS {
        return LONGEST_BACKOFF;
    }
    // The exponent is bounded by the branch above, so the product cannot
    // overflow whatever the caller passes.
    FIRST_BACKOFF * 2_u32.pow(failures - 1)
}

/// What is known about one certificate's renewal attempts.
///
/// Kept beside the store rather than inside it, because a configuration
/// rollback must not roll back the fact that a renewal failed three times
/// (ADR-0079).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempts {
    /// How many orders have failed in a row.
    pub failures: u32,
    /// When the first of them failed.
    pub first_failed_unix: i64,
    /// Why the last one failed, as a stable reason key.
    pub last_reason: String,
    /// The earliest time another order may be made.
    pub next_attempt_unix: i64,
}

impl Attempts {
    /// Records one failed order and returns what to do next.
    pub fn failed(&mut self, reason: &str, now_unix: i64) {
        if self.failures == 0 {
            self.first_failed_unix = now_unix;
        }
        self.failures = self.failures.saturating_add(1);
        self.last_reason = reason.to_owned();
        let wait = i64::try_from(backoff(self.failures).as_secs()).unwrap_or(i64::MAX);
        self.next_attempt_unix = now_unix.saturating_add(wait);
    }

    /// Whether this certificate has failed often enough to be an alarm.
    #[must_use]
    pub const fn alarming(&self) -> bool {
        self.failures >= ALARM_AFTER
    }

    /// Whether another order may be made yet.
    #[must_use]
    pub const fn ready(&self, now_unix: i64) -> bool {
        now_unix >= self.next_attempt_unix
    }
}
