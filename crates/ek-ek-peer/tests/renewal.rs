// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! When a node certificate has to be signed again.
//!
//! Both sides of the rule are measured. A check that only ever saw "due" would
//! pass against a build that signs a new certificate every time it is asked,
//! which spends nothing but also means the rule is not there.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_peer::{NODE_LIFETIME_DAYS, RENEW_AT};

mod common;

use common::{DAY, authority, issue_at};

/// A fixed moment, so a window can be read as a number.
const AT: i64 = 1_800_000_000;

/// The window a node certificate carries when it is signed at [`AT`].
fn window() -> (i64, i64) {
    let issued = issue_at(&authority(), "node-1", AT);
    (issued.not_before_unix, issued.not_after_unix)
}

#[test]
fn a_fresh_certificate_is_not_due() {
    let (started, ends) = window();
    assert!(
        !ek_ek_peer::due(started, ends, AT),
        "a certificate signed a moment ago is already due"
    );
}

#[test]
fn a_certificate_is_due_once_a_third_of_its_life_is_left() {
    let (started, ends) = window();
    let lifetime = ends - started;

    // A second before the boundary: not yet.
    assert!(!ek_ek_peer::due(
        started,
        ends,
        ends - lifetime / RENEW_AT - 1
    ));
    // At it: due.
    assert!(ek_ek_peer::due(started, ends, ends - lifetime / RENEW_AT));
}

#[test]
fn a_certificate_is_renewed_well_before_it_runs_out() {
    // The whole point. Renewal has to start while the certificate still works,
    // or the first failed attempt is also the outage.
    let (started, ends) = window();
    let becomes_due = ends - (ends - started) / RENEW_AT;

    assert!(ek_ek_peer::due(started, ends, becomes_due));
    assert!(
        !ek_ek_peer::expired(ends, becomes_due),
        "a certificate only becomes due once it has already run out"
    );
    // Exactly a third of the window, which is what the rule says.
    assert_eq!(
        ek_ek_peer::remaining(ends, becomes_due),
        (ends - started) / RENEW_AT
    );
    // And that third is at least thirty days on a ninety day certificate:
    // enough to notice a failure and fix what caused it. Stated as a floor
    // rather than an equality because the window starts slightly before the
    // certificate was signed, to absorb clock skew.
    assert!(ek_ek_peer::remaining(ends, becomes_due) >= NODE_LIFETIME_DAYS * DAY / RENEW_AT);
}

#[test]
fn a_certificate_that_has_run_out_is_due_and_says_so() {
    let (started, ends) = window();
    assert!(ek_ek_peer::due(started, ends, ends + 1));
    assert!(ek_ek_peer::expired(ends, ends + 1));
    assert!(ek_ek_peer::remaining(ends, ends + 1) < 0);
}

#[test]
fn a_certificate_that_has_not_run_out_says_so() {
    // The other side of the check above.
    let (_, ends) = window();
    assert!(!ek_ek_peer::expired(ends, ends - 1));
    assert!(ek_ek_peer::remaining(ends, ends - 1) > 0);
}

#[test]
fn the_last_second_of_the_window_is_already_gone() {
    // The boundary itself. A certificate whose end has arrived is one a peer
    // will refuse, so treating that moment as still valid would have a node
    // present a certificate it has already lost.
    let (_, ends) = window();
    assert!(ek_ek_peer::expired(ends, ends));
    assert_eq!(ek_ek_peer::remaining(ends, ends), 0);
}

#[test]
fn a_window_that_is_not_a_window_is_due() {
    // The safe direction. Whatever produced it, the answer is to hold a
    // certificate that can actually be presented.
    assert!(ek_ek_peer::due(AT, AT, AT));
    assert!(ek_ek_peer::due(AT, AT - DAY, AT));

    // A window that ends before it starts, asked about before either. The
    // share rule alone answers "not due" here, because a third of a negative
    // window is a moment further back still. Only the check for a window that
    // is not a window reaches this case.
    assert!(
        ek_ek_peer::due(AT + DAY, AT, AT - DAY),
        "a certificate with no usable window was left alone"
    );
}

#[test]
fn signing_again_moves_the_window_forward() {
    // What renewal buys. A second certificate with the same window would leave
    // the node exactly as close to running out as it was.
    let authority = authority();
    let first = issue_at(&authority, "node-1", AT);
    let becomes_due =
        first.not_after_unix - (first.not_after_unix - first.not_before_unix) / RENEW_AT;
    let second = issue_at(&authority, "node-1", becomes_due);

    assert!(ek_ek_peer::due(
        first.not_before_unix,
        first.not_after_unix,
        becomes_due
    ));
    assert!(!ek_ek_peer::due(
        second.not_before_unix,
        second.not_after_unix,
        becomes_due
    ));
    assert!(second.not_after_unix > first.not_after_unix);
    // A fresh key with it. Renewing onto the same key would mean a key that
    // never changes for as long as the node lives.
    assert_ne!(first.key_pem.expose(), second.key_pem.expose());
}

#[test]
fn the_window_is_read_out_of_the_encoding() {
    // The numbers the rules run on come off the certificate, not off the value
    // that was returned beside it. A peer only ever sees the encoding.
    let issued = issue_at(&authority(), "node-1", AT);
    let read = ek_ek_peer::window_of_pem(issued.certificate_pem.as_bytes()).expect("a window");
    assert_eq!(read, (issued.not_before_unix, issued.not_after_unix));
}
