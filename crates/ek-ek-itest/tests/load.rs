// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The load generator, checked both ways.
//!
//! A generator that reports zero failures is only worth something if it can
//! report a failure at all, so the clean run is paired with a broken one.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use ek_ek_itest::Cluster;

const RATE: u32 = 50;
const WINDOW: Duration = Duration::from_secs(2);

#[test]
fn a_clean_path_reports_no_failures() {
    let cluster = Cluster::start().expect("cluster should start");
    let from = cluster.node("node1").expect("node1 exists");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 exists");

    let report = cluster
        .load(from, &format!("{backend}:80"), RATE, WINDOW)
        .expect("the load generator should run");

    // This is also the baseline for every later measurement. If the path is not
    // clean while nothing is being changed, a failure during an upgrade says
    // nothing about the upgrade.
    assert!(
        report.sent >= 80,
        "only {} request(s) went out",
        report.sent
    );
    assert_eq!(
        report.failed, 0,
        "{} of {} request(s) failed on an idle backend: {:?}",
        report.failed, report.sent, report.first_error
    );
    assert!(
        report.p50_ms >= 0.0 && report.max_ms >= report.p50_ms,
        "latency report is inconsistent"
    );
}

#[test]
fn a_broken_path_is_counted_and_explained() {
    let cluster = Cluster::start().expect("cluster should start");
    let from = cluster.node("node1").expect("node1 exists");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 exists");

    // Nothing listens on this port. Every request must be counted as a failure,
    // and the report has to say why rather than only how often.
    let report = cluster
        .load(from, &format!("{backend}:9"), RATE, Duration::from_secs(1))
        .expect("the load generator should run even when every request fails");

    assert!(report.sent > 0, "no request was attempted");
    assert_eq!(
        report.failed, report.sent,
        "only {} of {} request(s) to a closed port were counted as failures",
        report.failed, report.sent
    );
    let reason = report
        .first_error
        .expect("a failing run should carry its first error");
    assert!(
        reason.contains("connect"),
        "the first error does not name the failure: {reason}"
    );
}
