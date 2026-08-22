// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a log record is made of, read off the bytes that were written.
//!
//! Every measurement here goes through a sink and parses the line back as
//! JSON. Reading a struct the formatter returned would prove that two pieces
//! of our own code agree; whatever collects these lines parses them, so the
//! line is what has to be measured.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::time::Duration;

use ek_ek_log::{Access, Captured, Level, Logger, Protocol, Sink, Slow};
use log::Log;
use serde_json::Value;

/// A logger writing into a sink a test can read.
fn logger(level: Level) -> (Logger, Captured) {
    let captured = Captured::new();
    (Logger::new(level, Box::new(captured.clone())), captured)
}

/// Waits for the writer thread to catch up, then returns the parsed lines.
fn lines(captured: &Captured, expected: usize) -> Vec<Value> {
    let start = std::time::Instant::now();
    while captured.lines().len() < expected && start.elapsed() < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(5));
    }
    captured
        .lines()
        .iter()
        .map(|line| serde_json::from_str(line).expect("every line must be JSON"))
        .collect()
}

/// The field names one record carries.
fn keys(record: &Value) -> BTreeSet<String> {
    record
        .as_object()
        .expect("a record is an object")
        .keys()
        .cloned()
        .collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn an_application_record_is_one_json_object_on_one_line() {
    let (logger, captured) = logger(Level::Info);

    logger.log(
        &log::Record::builder()
            .args(format_args!("listening on {}", "127.0.0.1:8080"))
            .level(log::Level::Info)
            .target("ek_ek_dataplane::server")
            .build(),
    );

    let written = lines(&captured, 1);
    assert_eq!(written.len(), 1);
    assert!(
        !captured.lines()[0].contains('\n'),
        "a record must not span two lines, or a reader sees two records"
    );
    assert_eq!(written[0]["kind"], "app");
    assert_eq!(written[0]["level"], "info");
    assert_eq!(written[0]["target"], "ek_ek_dataplane::server");
    assert_eq!(written[0]["message"], "listening on 127.0.0.1:8080");
    assert!(
        written[0]["ts"]
            .as_str()
            .is_some_and(|ts| ts.ends_with('Z')),
        "the timestamp is UTC, so two nodes can be compared"
    );
}

#[test]
fn an_application_record_and_an_access_record_can_be_told_apart() {
    let (logger, captured) = logger(Level::Info);

    logger.log(
        &log::Record::builder()
            .args(format_args!("a thing happened"))
            .level(log::Level::Info)
            .target("ek_ek_dataplane")
            .build(),
    );
    logger.access(&Access::new(Protocol::Http, "web", "127.0.0.1:5000", 1.5));

    let written = lines(&captured, 2);
    assert_eq!(written[0]["kind"], "app");
    assert_eq!(written[1]["kind"], "access");
    assert_ne!(
        written[0]["kind"], written[1]["kind"],
        "one field has to separate them, or a filter cannot"
    );
}

#[test]
fn each_transport_carries_its_own_field_set() {
    // Pinned, because whatever reads these lines matches on field names.
    // Renaming one is a breaking change (ADR-0037).
    let (logger, captured) = logger(Level::Info);

    logger.access(
        &Access::new(Protocol::Http, "web", "127.0.0.1:5000", 1.5)
            .with_request_id("r-1")
            .to_backend("pool-web", "web-1")
            .http("GET", "/owa", 200),
    );
    logger.access(
        &Access::new(Protocol::Tcp, "db", "127.0.0.1:5001", 30.0)
            .with_request_id("r-2")
            .to_backend("pool-db", "db-1")
            .tcp(120, 4096),
    );
    logger.access(
        &Access::new(Protocol::Udp, "dns", "127.0.0.1:5002", 0.4)
            .with_request_id("r-3")
            .to_backend("pool-dns", "dns-1")
            .udp("127.0.0.1:5002"),
    );

    let written = lines(&captured, 3);
    let shared = [
        "ts",
        "kind",
        "protocol",
        "frontend",
        "client",
        "duration_ms",
    ];
    let named = ["request_id", "backend_pool", "backend_member"];

    let http: Vec<&str> = shared
        .iter()
        .chain(named.iter())
        .chain(["method", "path", "status"].iter())
        .copied()
        .collect();
    assert_eq!(keys(&written[0]), set(&http));
    assert_eq!(written[0]["protocol"], "http");
    assert_eq!(written[0]["method"], "GET");
    assert_eq!(written[0]["path"], "/owa");
    assert_eq!(written[0]["status"], 200);

    let tcp: Vec<&str> = shared
        .iter()
        .chain(named.iter())
        .chain(["bytes_to_backend", "bytes_from_backend"].iter())
        .copied()
        .collect();
    assert_eq!(keys(&written[1]), set(&tcp));
    assert_eq!(written[1]["bytes_to_backend"], 120);
    assert_eq!(written[1]["bytes_from_backend"], 4096);

    let udp: Vec<&str> = shared
        .iter()
        .chain(named.iter())
        .chain(["session"].iter())
        .copied()
        .collect();
    assert_eq!(keys(&written[2]), set(&udp));
    assert_eq!(written[2]["session"], "127.0.0.1:5002");

    // A field belonging to one transport must not appear on another.
    assert!(!keys(&written[0]).contains("bytes_to_backend"));
    assert!(!keys(&written[1]).contains("status"));
    assert!(!keys(&written[2]).contains("method"));
}

#[test]
fn a_record_below_the_level_is_not_written_and_one_above_it_is() {
    let (logger, captured) = logger(Level::Warn);

    for level in [log::Level::Debug, log::Level::Info] {
        logger.log(
            &log::Record::builder()
                .args(format_args!("quiet"))
                .level(level)
                .target("t")
                .build(),
        );
    }
    logger.log(
        &log::Record::builder()
            .args(format_args!("loud"))
            .level(log::Level::Error)
            .target("t")
            .build(),
    );

    let written = lines(&captured, 1);
    assert_eq!(
        written.len(),
        1,
        "only the record above the level may be written"
    );
    assert_eq!(written[0]["message"], "loud");
}

#[test]
fn the_level_changes_without_the_logger_being_replaced() {
    let (logger, captured) = logger(Level::Error);

    let info = || {
        log::Record::builder()
            .args(format_args!("detail"))
            .level(log::Level::Info)
            .target("t")
            .build()
    };

    logger.log(&info());
    assert!(
        captured.lines().is_empty(),
        "info is below error and must not be written"
    );

    logger.set_level(Level::Debug);
    assert_eq!(logger.level(), Level::Debug);
    logger.log(&info());
    assert_eq!(lines(&captured, 1).len(), 1, "the new level must apply");

    // And back down again, so the change is measured in both directions.
    logger.set_level(Level::Error);
    logger.log(&info());
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(captured.lines().len(), 1, "the level must come back down");
}

#[test]
fn an_access_record_is_written_whatever_the_application_level_is() {
    // An operator quieting the application log still wants to know which
    // requests arrived (ADR-0037).
    let (logger, captured) = logger(Level::Error);

    logger.access(&Access::new(Protocol::Http, "web", "127.0.0.1:5000", 1.0));

    assert_eq!(lines(&captured, 1).len(), 1);
}

#[test]
fn a_blocked_sink_costs_records_rather_than_the_caller() {
    // The one condition the queue exists for: standard output has stopped.
    // What must not happen is the caller waiting on it.
    let logger = Logger::new(Level::Info, Box::new(Slow::new(Duration::from_secs(30))));

    let started = std::time::Instant::now();
    for _ in 0..50_000 {
        logger.access(&Access::new(Protocol::Http, "web", "127.0.0.1:5000", 1.0));
    }
    let spent = started.elapsed();

    assert!(
        spent < Duration::from_secs(5),
        "writing records took {spent:?}, so the caller waited on the sink"
    );
    assert!(
        logger.dropped() > 0,
        "a blocked sink must cost dropped records, and the drops must be counted"
    );
}

#[test]
fn the_stopwatch_notices_a_caller_that_really_does_wait() {
    // Without this the measurement above proves nothing: a stopwatch that
    // never noticed anything would pass it too. The same sink, written to
    // with no queue in between, is what waiting on the sink looks like, and
    // the same stopwatch has to see it.
    let sink = Slow::new(Duration::from_millis(20));

    let started = std::time::Instant::now();
    for _ in 0..100 {
        sink.write("a record");
    }
    let spent = started.elapsed();

    assert!(
        spent >= Duration::from_secs(1),
        "the stopwatch read {spent:?} for a sink that waits 20ms a line, so it measures nothing"
    );
    assert_eq!(sink.written(), 100);
}

#[test]
fn nothing_is_dropped_when_the_sink_keeps_up() {
    // The other side of the previous measurement. Without it, a logger that
    // dropped everything would pass that one.
    let (logger, captured) = logger(Level::Info);

    for _ in 0..1000 {
        logger.access(&Access::new(Protocol::Http, "web", "127.0.0.1:5000", 1.0));
    }

    assert_eq!(lines(&captured, 1000).len(), 1000);
    assert_eq!(logger.dropped(), 0);
}

#[test]
fn every_level_has_a_name_and_survives_a_round_trip() {
    for level in Level::ALL {
        assert!(!level.name().is_empty());
        assert_eq!(Level::from_code(level.code()), level);
        assert_eq!(Level::of(level.filter().to_level().unwrap()), level);
    }
    assert_eq!(Level::default(), Level::Info);
}

#[test]
fn every_protocol_has_a_name_that_matches_what_is_written() {
    let (logger, captured) = logger(Level::Info);
    for protocol in [Protocol::Http, Protocol::Tcp, Protocol::Udp] {
        logger.access(&Access::new(protocol, "f", "c", 0.0));
    }

    let written = lines(&captured, 3);
    for (record, protocol) in written
        .iter()
        .zip([Protocol::Http, Protocol::Tcp, Protocol::Udp])
    {
        assert_eq!(record["protocol"], protocol.name());
    }
}

#[test]
fn a_captured_sink_reports_exactly_what_was_written() {
    // The harness the other measurements rest on. A sink that always reported
    // something, or nothing, would make every one of them meaningless.
    let captured = Captured::new();
    assert!(captured.lines().is_empty());

    captured.write("one");
    captured.write("two");
    assert_eq!(captured.lines(), vec!["one".to_owned(), "two".to_owned()]);
    assert_eq!(captured.text(), "one\ntwo");

    captured.clear();
    assert!(captured.lines().is_empty());
}
