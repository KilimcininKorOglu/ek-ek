// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! What the `renew` command does, measured against the real binary.
//!
//! Nothing here reaches an ACME server. The documents name no server at all,
//! which is what the configuration layer already calls a fault, so an order
//! stops before it opens a socket. That is what makes the growing waits and
//! the alarm measurable in milliseconds rather than in hours.
//!
//! Everything is read off the bytes the process wrote: its records on standard
//! output, the state file it left behind and the exposition it produced.

use std::path::Path;
use std::process::{Command, Output};

/// A day, in seconds.
const DAY: i64 = 86_400;

/// The moment the documents below are written against.
const ISSUED: i64 = 1_800_000_000;

/// The certificate every document carries.
const CERTIFICATE: &str = "web";

/// A configuration with one certificate, from the source and window named.
///
/// It names no ACME server on purpose. Ordering is then refused by the same
/// rule an operator is warned by, before anything is sent anywhere.
fn document(source: &str, validity: &str, warning_days: Option<u32>) -> String {
    let threshold = warning_days.map_or_else(String::new, |days| {
        format!(r#""certificate_expiry_warning_days": {days},"#)
    });
    format!(
        r#"{{
  "schema_version": 1,
  "nodes": [{{"id":"node1","address":"127.0.0.1","roles":["control_plane","data_plane"]}}],
  "vips": [{{"id":"vip","address":"127.0.0.1","prefix_length":8,"interface":"lo","preferred_node":"node1"}}],
  "frontends": [{{
    "id": "web-https",
    "vip": "vip",
    "port": 443,
    "transport": "tcp",
    "application": "http",
    "tls": {{"certificates":["{CERTIFICATE}"],"default_certificate":"{CERTIFICATE}","policy":"dengeli"}},
    "proxy_protocol": "disabled",
    "routing_rules": [],
    "sni_rules": [],
    "default_backend": "pool",
    "http2": "enabled",
    "connect_timeout_seconds": 5,
    "request_timeout_seconds": 30,
    "idle_timeout_seconds": 0,
    "drain_timeout_seconds": 5,
    "udp_session_limit": 0
  }}],
  "backends": [{{
    "id": "pool",
    "algorithm": "round_robin",
    "members": [{{"id":"one","address":"127.0.0.1","port":8080,"weight":1,"admin_state":"enabled"}}],
    "health_check": null,
    "stickiness": {{"mode":"disabled"}},
    "connection_pooling": "enabled",
    "connection_pool_size": 0,
    "connection_lifetime_seconds": 0
  }}],
  "certificates": [{{
    "id": "{CERTIFICATE}",
    "sni_names": ["lab.example.test"],
    "source": {{"type":"{source}"}},
    "validity": {validity},
    "chain": null,
    "private_key": null
  }}],
  "dns_providers": [],
  {threshold}
  "acme": null
}}"#
    )
}

/// A window that starts at `ISSUED` and runs for `days`.
fn window(days: i64) -> String {
    format!(
        r#"{{"not_before_unix":{ISSUED},"not_after_unix":{}}}"#,
        ISSUED + days * DAY
    )
}

/// Runs one sweep against a document, at a moment.
fn sweep(directory: &Path, document: &str, at: i64, metrics: Option<&Path>) -> Output {
    let config = directory.join("config.json");
    std::fs::write(&config, document).expect("the document should be writable");

    let mut command = Command::new(env!("CARGO_BIN_EXE_ek-ek"));
    command
        .arg("renew")
        .arg("--config")
        .arg(&config)
        .arg("--data-dir")
        .arg(directory)
        .arg("--challenges")
        .arg(directory.join("challenges.json"))
        .arg("--now")
        .arg(at.to_string());
    if let Some(path) = metrics {
        command.arg("--metrics").arg(path);
    }
    command.output().expect("the binary should run")
}

/// The standard output of a run, as text.
fn said(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// The renewal state the last run left behind.
fn state(directory: &Path) -> serde_json::Value {
    let text = std::fs::read_to_string(directory.join("renewal-state.json"))
        .expect("the sweep should have written its state");
    serde_json::from_str(&text).expect("the state should be JSON")
}

#[test]
fn a_certificate_with_most_of_its_life_left_is_not_ordered_again() {
    let directory = tempfile::tempdir().expect("a directory");
    let output = sweep(
        directory.path(),
        &document("acme_http01", &window(90), None),
        ISSUED + 30 * DAY,
        None,
    );

    let text = said(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        !text.contains(r#""event":"renewing""#),
        "a certificate with two thirds of its life left was ordered again: {text}"
    );
    assert!(text.contains(r#""renewed":0,"failed":0"#), "{text}");
}

#[test]
fn moving_the_clock_forward_is_what_starts_the_renewal() {
    // The same document and the same store. One thing changes: the moment the
    // sweep decides against.
    let directory = tempfile::tempdir().expect("a directory");
    let document = document("acme_http01", &window(90), None);

    let early = said(&sweep(directory.path(), &document, ISSUED + 30 * DAY, None));
    assert!(!early.contains(r#""event":"renewing""#), "{early}");

    let late = said(&sweep(directory.path(), &document, ISSUED + 61 * DAY, None));
    assert!(
        late.contains(&format!(
            r#""event":"renewing","certificate":"{CERTIFICATE}","because":"running_out""#
        )),
        "the clock passed two thirds of the window and nothing was ordered: {late}"
    );
}

#[test]
fn an_uploaded_certificate_is_never_ordered_however_little_is_left() {
    let directory = tempfile::tempdir().expect("a directory");
    let output = sweep(
        directory.path(),
        &document("manual_upload", &window(90), None),
        ISSUED + 89 * DAY,
        None,
    );

    let text = said(&output);
    assert!(
        !text.contains(r#""event":"renewing""#),
        "nothing here can ask anybody for this certificate again: {text}"
    );
    assert!(
        text.contains(r#""code":"certificate.expiring_soon""#),
        "the warning is the only thing standing between the operator and an outage: {text}"
    );
}

#[test]
fn the_warning_threshold_is_what_the_document_says_it_is() {
    let directory = tempfile::tempdir().expect("a directory");
    let at = ISSUED + 45 * DAY;

    let default = said(&sweep(
        directory.path(),
        &document("manual_upload", &window(90), None),
        at,
        None,
    ));
    assert!(
        !default.contains(r#""code":"certificate.expiring_soon""#),
        "forty five days out is outside the default thirty day window: {default}"
    );

    let widened = said(&sweep(
        directory.path(),
        &document("manual_upload", &window(90), Some(60)),
        at,
        None,
    ));
    assert!(
        widened.contains(r#""code":"certificate.expiring_soon""#),
        "an operator who asked for sixty days was not told at forty five: {widened}"
    );
}

#[test]
fn a_frontend_serving_an_expired_certificate_is_named() {
    let directory = tempfile::tempdir().expect("a directory");
    let output = sweep(
        directory.path(),
        &document("manual_upload", &window(90), None),
        ISSUED + 91 * DAY,
        None,
    );

    let text = said(&output);
    assert!(
        text.contains(r#""code":"config.frontend.certificate_expired""#),
        "{text}"
    );
    assert!(
        text.contains(r#""path":"frontends[0].tls.certificates[0]""#),
        "the warning has to point at the listener that stopped serving: {text}"
    );
}

#[test]
fn a_failed_order_is_recorded_and_the_next_one_waits() {
    let directory = tempfile::tempdir().expect("a directory");
    let document = document("acme_http01", "null", None);
    let at = ISSUED;

    let first = sweep(directory.path(), &document, at, None);
    let text = said(&first);
    assert!(
        !first.status.success(),
        "a sweep that could renew nothing must not report success: {text}"
    );
    assert!(text.contains(r#""event":"renewal_failed""#), "{text}");
    assert!(
        text.contains(&format!(r#""failures":1,"next_attempt":{}"#, at + 3_600)),
        "the first wait is an hour: {text}"
    );

    // The same moment again. The wait is not over, so nothing is ordered.
    let second = said(&sweep(directory.path(), &document, at, None));
    assert!(
        second.contains(&format!(
            r#""event":"waiting","certificate":"{CERTIFICATE}""#
        )),
        "an order right after a failure spends the server's allowance on the same fault: {second}"
    );
    assert!(!second.contains(r#""event":"renewing""#), "{second}");

    // An hour later it is tried again, and the next wait has doubled.
    let third = said(&sweep(directory.path(), &document, at + 3_600, None));
    assert!(third.contains(r#""event":"renewing""#), "{third}");
    assert!(
        third.contains(&format!(
            r#""failures":2,"next_attempt":{}"#,
            at + 3_600 + 7_200
        )),
        "the second wait is two hours: {third}"
    );
}

#[test]
fn the_alarm_starts_at_the_third_failure_and_says_when_it_started() {
    let directory = tempfile::tempdir().expect("a directory");
    let document = document("acme_http01", "null", None);

    let first = said(&sweep(directory.path(), &document, ISSUED, None));
    assert!(
        !first.contains(r#""event":"alarm""#),
        "one passing fault is not worth waking anybody: {first}"
    );
    let second = said(&sweep(directory.path(), &document, ISSUED + 3_600, None));
    assert!(!second.contains(r#""event":"alarm""#), "{second}");

    let third = said(&sweep(
        directory.path(),
        &document,
        ISSUED + 3_600 + 7_200,
        None,
    ));
    assert!(third.contains(r#""event":"alarm""#), "{third}");
    assert!(
        third.contains(&format!(r#""failures":3,"since":{ISSUED},"#)),
        "the alarm has to say when the trouble started, not when it was raised: {third}"
    );
}

#[test]
fn the_attempt_state_outlives_the_process() {
    // "Failing repeatedly" is only countable across runs, so the count has to
    // come back the way it went in.
    let directory = tempfile::tempdir().expect("a directory");
    let document = document("acme_http01", "null", None);

    sweep(directory.path(), &document, ISSUED, None);
    let held = state(directory.path());

    assert_eq!(held[CERTIFICATE]["failures"], 1);
    assert_eq!(held[CERTIFICATE]["first_failed_unix"], ISSUED);
    assert_eq!(held[CERTIFICATE]["next_attempt_unix"], ISSUED + 3_600);
    assert_eq!(held[CERTIFICATE]["last_reason"], "acme.configuration");
}

#[test]
fn a_certificate_that_never_failed_leaves_no_record_behind() {
    // The other side. A file that grew an entry for every certificate would
    // make the count above say nothing.
    let directory = tempfile::tempdir().expect("a directory");
    sweep(
        directory.path(),
        &document("acme_http01", &window(90), None),
        ISSUED,
        None,
    );

    assert_eq!(state(directory.path()), serde_json::json!({}));
}

#[test]
fn the_certificate_metrics_are_written_where_they_were_asked_for() {
    let directory = tempfile::tempdir().expect("a directory");
    let metrics = directory.path().join("certificates.prom");

    let output = sweep(
        directory.path(),
        &document("manual_upload", &window(90), None),
        ISSUED + 60 * DAY,
        Some(&metrics),
    );

    assert!(output.status.success(), "{}", said(&output));
    let text = std::fs::read_to_string(&metrics).expect("the file should be there");
    assert!(
        text.contains(&format!(
            "ek_ek_certificate_expiry_seconds{{certificate=\"{CERTIFICATE}\",source=\"manual_upload\"}} {}\n",
            30 * DAY
        )),
        "{text}"
    );
    assert!(
        said(&output).contains(r#""event":"metrics""#),
        "the run has to say it wrote them"
    );
}

#[test]
fn no_metrics_file_is_written_when_none_was_asked_for() {
    // The other side. A command that always wrote one would put a file into a
    // directory nobody asked it to touch.
    let directory = tempfile::tempdir().expect("a directory");
    let output = sweep(
        directory.path(),
        &document("manual_upload", &window(90), None),
        ISSUED,
        None,
    );

    assert!(!directory.path().join("certificates.prom").exists());
    assert!(
        !said(&output).contains(r#""event":"metrics""#),
        "the run wrote an exposition nobody asked for: {}",
        said(&output)
    );
}

#[test]
fn a_document_that_does_not_validate_stops_the_sweep() {
    let directory = tempfile::tempdir().expect("a directory");
    let broken = document("acme_http01", &window(90), None).replace(
        r#""default_backend": "pool""#,
        r#""default_backend": "missing""#,
    );

    let output = sweep(directory.path(), &broken, ISSUED, None);
    let text = said(&output);

    assert!(!output.status.success(), "{text}");
    assert!(text.contains(r#""event":"invalid""#), "{text}");
    assert!(
        !text.contains(r#""event":"sweeping""#),
        "nothing may be decided from a document that was refused: {text}"
    );
}

#[test]
fn a_state_file_that_cannot_be_read_stops_the_sweep() {
    // Throwing it away would restart every backoff from zero, which is exactly
    // what the ACME server's allowance cannot afford.
    let directory = tempfile::tempdir().expect("a directory");
    std::fs::write(directory.path().join("renewal-state.json"), "not json")
        .expect("the file should be writable");

    let output = sweep(
        directory.path(),
        &document("acme_http01", &window(90), None),
        ISSUED,
        None,
    );
    let text = said(&output);

    assert!(!output.status.success(), "{text}");
    assert!(
        text.contains("is not a renewal state"),
        "the failure has to name what it could not read: {text}"
    );
}
