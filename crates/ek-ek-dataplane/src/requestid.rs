// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The identity every record of one request shares.
//!
//! An operator following a fault needs the access record and whatever the
//! application log said about the same request to be joinable. That only works
//! if both carry the same value (ADR-0037).
//!
//! # Why an arriving value is checked before it is used
//!
//! A client sets `X-Request-Id` to whatever it likes. Written into a log
//! unchecked, a newline in it splits one record into two and a long value
//! makes every line unreadable. The value is kept only when it is short and
//! made of characters that mean nothing to a log reader.

use std::sync::atomic::{AtomicU64, Ordering};

/// Header a request id arrives in and is answered with.
pub const HEADER: &str = "X-Request-Id";

/// The most characters an arriving id may carry.
///
/// Long enough for a UUID and for the identifiers proxies in front of us
/// generate, short enough that one cannot fill a log line.
const LONGEST: usize = 64;

/// Counts requests, so two ids generated in the same millisecond differ.
static NEXT: AtomicU64 = AtomicU64::new(0);

/// Whether an arriving value may be used as it stands.
///
/// Letters, digits and the three separators identifiers are written with.
/// Anything else, and anything empty or overlong, is refused.
#[must_use]
pub fn acceptable(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= LONGEST
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// The id this request is known by.
///
/// An acceptable arriving value is kept, so a request crossing two proxies
/// keeps one identity and the two logs can be joined. Anything else is
/// replaced rather than cleaned up, because a cleaned value is neither what
/// the client sent nor something we generated.
#[must_use]
pub fn for_request(arrived: Option<&str>) -> String {
    match arrived {
        Some(value) if acceptable(value) => value.to_owned(),
        _ => generate(),
    }
}

/// A new id, unique within this process.
///
/// Built from the process id and a counter rather than drawn at random, so it
/// needs no dependency and two ids can never collide inside one process.
#[must_use]
pub fn generate() -> String {
    let counter = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("{:x}-{:x}", std::process::id(), counter)
}
