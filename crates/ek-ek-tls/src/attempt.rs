// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! How often a failed order is tried again, and how long the waits are.
//!
//! An ACME server's rate limits count failed orders per account. An
//! installation that retries a misconfigured order in a tight loop uses the
//! account's whole allowance in minutes, and then the certificates that would
//! have worked cannot be obtained either (ADR-0026).
//!
//! So the limit is small and the waits grow. Nothing here is configurable: an
//! operator raising the number would be spending an allowance they cannot see,
//! against a server that is not theirs.

use std::time::Duration;

/// How many times one order is attempted, counting the first.
pub const ATTEMPTS: u32 = 5;

/// How long the first wait is.
///
/// Long enough that a DNS record that was just written has a chance to
/// propagate, and short enough that a transient network fault does not cost an
/// afternoon.
pub const FIRST_WAIT: Duration = Duration::from_secs(60);

/// How long to wait before an attempt, or `None` when there is none left.
///
/// Attempt 1 runs immediately. Each wait after that is twice the one before:
/// 1, 2, 4 and 8 minutes, so five attempts span fifteen minutes. A fault that
/// clears by itself clears inside that; one that does not is a fault an
/// operator has to look at, and repeating it for hours would only take the
/// account's allowance with it.
#[must_use]
pub fn wait_before(attempt: u32) -> Option<Duration> {
    if attempt == 0 || attempt > ATTEMPTS {
        return None;
    }
    if attempt == 1 {
        return Some(Duration::ZERO);
    }
    // Doubling per attempt. `attempt` is at most ATTEMPTS, so the shift is
    // small and the product cannot overflow.
    let doublings = attempt - 2;
    Some(FIRST_WAIT * 2_u32.pow(doublings))
}

/// How long every wait adds up to, for the whole run.
#[must_use]
pub fn whole_run() -> Duration {
    (1..=ATTEMPTS)
        .filter_map(wait_before)
        .fold(Duration::ZERO, |total, wait| total + wait)
}
