// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! When a node certificate has to be signed again.
//!
//! A node certificate that runs out takes the node out of the cluster, and
//! nothing in the configuration looks wrong when it happens. So renewal starts
//! well before the end.
//!
//! # What this never does
//!
//! It reads no clock. Every function takes the moment it works against, so a
//! rule about a window ninety days wide is measured in microseconds and the
//! same code answers "what is due next month?" (ADR-0079).

use openssl::asn1::{Asn1Time, Asn1TimeRef};
use openssl::x509::X509;

use crate::error::{Failure, crypto};

/// The share of a certificate's lifetime that must remain before it is signed
/// again.
///
/// One third, the same rule public certificates are renewed on
/// (`ek-ek-tls::renewal::RENEW_AT`). On a ninety day certificate that is
/// thirty days of margin, which is enough to notice a failure and fix what
/// caused it.
pub const RENEW_AT: i64 = 3;

/// How long a certificate has left, in seconds.
///
/// Negative once it has run out, which is what lets one comparison answer both
/// "is it running out?" and "has it gone?".
#[must_use]
pub const fn remaining(not_after_unix: i64, now_unix: i64) -> i64 {
    not_after_unix.saturating_sub(now_unix)
}

/// Whether a certificate has run out.
#[must_use]
pub const fn expired(not_after_unix: i64, now_unix: i64) -> bool {
    remaining(not_after_unix, now_unix) <= 0
}

/// Whether a certificate should be signed again now.
///
/// True once less than a third of the window is left, and true for a window
/// that is not a window at all: the safe direction is to hold a certificate
/// that can actually be presented.
#[must_use]
pub const fn due(not_before_unix: i64, not_after_unix: i64, now_unix: i64) -> bool {
    let lifetime = not_after_unix.saturating_sub(not_before_unix);
    if lifetime <= 0 {
        return true;
    }
    remaining(not_after_unix, now_unix) <= lifetime / RENEW_AT
}

/// The validity window of a certificate, in seconds since the epoch.
///
/// # Errors
///
/// Returns [`crate::Reason::Crypto`] when a time cannot be compared, which
/// would mean the certificate carries something that is not a time.
pub fn window_of(certificate: &X509) -> Result<(i64, i64), Failure> {
    Ok((
        unix_of(certificate.not_before())?,
        unix_of(certificate.not_after())?,
    ))
}

/// The validity window of a certificate in PEM.
///
/// # Errors
///
/// Returns [`crate::Reason::Crypto`] when the bytes are not a certificate or a
/// time cannot be compared.
pub fn window_of_pem(pem: &[u8]) -> Result<(i64, i64), Failure> {
    let certificate = X509::from_pem(pem).map_err(crypto("the certificate does not read back"))?;
    window_of(&certificate)
}

/// One certificate time as seconds since the epoch.
///
/// Measured as the distance from the epoch rather than parsed out of the
/// printed form, because the printed form is a locale-shaped string and this
/// has to be a number.
///
/// # Errors
///
/// Returns [`crate::Reason::Crypto`] when the two times cannot be compared.
pub fn unix_of(time: &Asn1TimeRef) -> Result<i64, Failure> {
    let epoch = Asn1Time::from_unix(0).map_err(crypto("the epoch could not be built"))?;
    let difference = epoch
        .diff(time)
        .map_err(crypto("a certificate time could not be compared"))?;
    Ok(i64::from(difference.days).saturating_mul(86_400) + i64::from(difference.secs))
}
