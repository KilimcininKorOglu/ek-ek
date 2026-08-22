// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the running binary writes to its log.
//!
//! Every measurement runs the real binary over real sockets and reads the
//! bytes it wrote to standard output, which is where journald collects them
//! from (ADR-0037). Nothing here calls a formatting function and checks what
//! it returned: what matters is the line a collector would see.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

mod common;

use common::{
    Document, Member, RawBehaviour, RawMember, Running, UdpClient, UdpMember, ask_once, connect,
    free_port, request_to,
};

/// How long a test waits for something that should already have happened.
const PATIENCE: Duration = Duration::from_secs(15);

/// A request carrying a header of the test's choosing.
async fn request_with(port: u16, header: &str) -> String {
    let mut stream = connect(port).await;
    let request = format!(
        "GET /owa HTTP/1.1\r\nHost: mail.example.test\r\n{header}Connection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request must go");
    stream.flush().await.expect("the request must flush");

    let mut answer = Vec::new();
    let _ = tokio::time::timeout(PATIENCE, stream.read_to_end(&mut answer)).await;
    String::from_utf8_lossy(&answer).into_owned()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http_request_produces_an_access_record_naming_the_member_that_served_it() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]);
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &request_to("mail.example.test", "/owa"))
        .await
        .expect("the request must be answered");
    assert_eq!(answer.status, 200);

    let records = running.wait_for_access_records("http", 1).await;
    let record = &records[0];

    assert_eq!(record["kind"], "access");
    assert_eq!(record["frontend"], "web");
    assert_eq!(record["method"], "GET");
    assert_eq!(record["path"], "/owa");
    assert_eq!(record["status"], 200);
    assert_eq!(record["backend_pool"], "web");
    assert_eq!(
        record["backend_member"], "web-1",
        "the record must name the member that actually served the request"
    );
    assert!(
        record["client"]
            .as_str()
            .is_some_and(|client| client.starts_with("127.0.0.1:")),
        "the record must carry the client's own address and port, it carried {}",
        record["client"]
    );
    assert!(
        record["duration_ms"].as_f64().is_some_and(|ms| ms >= 0.0),
        "the record must say how long the request took"
    );
    assert_eq!(
        backend.hits(),
        1,
        "the member named in the record is the one that took the request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tcp_connection_produces_an_access_record_with_the_bytes_that_crossed() {
    let echo = RawMember::start("echo", RawBehaviour::Echo).await;
    let port = free_port();
    let document = Document::new(port, vec![echo.entry(1, "enabled")]).raw();
    let running = Running::start_l4(&document, &[&echo]).await;

    let sent = b"SELECT 1;\r\n";
    let mut stream = connect(running.port).await;
    stream.write_all(sent).await.expect("the write must go");
    stream.flush().await.expect("the write must flush");
    let mut back = vec![0_u8; sent.len()];
    tokio::time::timeout(PATIENCE, stream.read_exact(&mut back))
        .await
        .expect("the echo must arrive")
        .expect("the whole echo must arrive");
    drop(stream);

    // The readiness probe is a connection too, so the record measured is the
    // one that actually carried bytes rather than whichever arrived first.
    let start = tokio::time::Instant::now();
    let record = loop {
        let found = running
            .access_records("tcp")
            .into_iter()
            .find(|record| record["bytes_to_backend"].as_u64() == Some(sent.len() as u64));
        if let Some(record) = found {
            break record;
        }
        assert!(
            start.elapsed() <= PATIENCE,
            "no record carries the bytes that crossed; the log holds:\n{}",
            running.log_text()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let record = &record;

    assert_eq!(record["frontend"], "web");
    assert_eq!(record["backend_pool"], "web");
    assert_eq!(record["backend_member"], "echo");
    assert_eq!(record["bytes_to_backend"], sent.len() as u64);
    assert_eq!(record["bytes_from_backend"], sent.len() as u64);
    assert!(
        record["client"]
            .as_str()
            .is_some_and(|client| client.starts_with("127.0.0.1:"))
    );
    assert!(
        record.get("method").is_none() && record.get("status").is_none(),
        "an L4 record must not carry HTTP fields it never had"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_udp_session_produces_an_access_record_naming_its_session_and_member() {
    let member = UdpMember::start("dns-1").await;
    let port = free_port();
    let document = Document::new(port, vec![member.entry(1, "enabled")]).udp();
    let running = Running::start_udp(&document, &[&member]).await;

    let client = UdpClient::open(running.port).await;
    let _ = client.ask("who?").await;

    let records = running.wait_for_access_records("udp", 1).await;
    let record = records.last().expect("a udp session must produce a record");

    assert_eq!(record["frontend"], "web");
    assert_eq!(record["backend_pool"], "web");
    assert_eq!(record["backend_member"], "dns-1");
    assert!(
        record["session"]
            .as_str()
            .is_some_and(|session| session.starts_with("127.0.0.1:")),
        "the record must name the session, which is the client that owns it"
    );
    assert!(
        record.get("bytes_to_backend").is_none(),
        "a udp record must not carry fields belonging to another transport"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_record_of_one_request_carries_the_same_identity() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]);
    let running = Running::start(&document).await;

    // The client sets one, so the identity in the record and the one the
    // client holds are the same value and can be compared.
    let answer = request_with(running.port, "X-Request-Id: probe-abc-123\r\n").await;

    assert!(
        answer
            .to_lowercase()
            .contains("x-request-id: probe-abc-123"),
        "the identity must come back to the client, the answer was:\n{answer}"
    );

    let records = running.wait_for_access_records("http", 1).await;
    assert_eq!(
        records[0]["request_id"], "probe-abc-123",
        "the record and the answer must carry the same identity"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_identity_the_client_invented_is_replaced_when_it_is_not_usable() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]);
    let running = Running::start(&document).await;

    // A value with a space in it. Written into a log unchecked it would end
    // the field early and the rest would read as something else.
    let answer = request_with(running.port, "X-Request-Id: not a valid id\r\n").await;

    let records = running.wait_for_access_records("http", 1).await;
    let used = records[0]["request_id"]
        .as_str()
        .expect("a record always carries an identity")
        .to_owned();

    assert_ne!(used, "not a valid id", "an unusable value must be replaced");
    assert!(
        !used.contains(' '),
        "the identity written must be usable, it was {used}"
    );
    assert!(
        answer
            .to_lowercase()
            .contains(&format!("x-request-id: {used}")),
        "the client must be told which identity was actually used"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_with_the_access_log_off_writes_no_access_record() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]).access_log(false, 1);
    let running = Running::start(&document).await;

    for _ in 0..5 {
        assert_eq!(
            ask_once(running.port, &request_to("mail.example.test", "/owa"))
                .await
                .expect("the request must be answered")
                .status,
            200
        );
    }
    // Long enough that a record would have been written by now.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert!(
        running.access_records("http").is_empty(),
        "no access record may be written with the log off; the log holds:\n{}",
        running.log_text()
    );
    assert_eq!(
        backend.hits(),
        5,
        "the requests were served, so the absence is the setting and not a broken frontend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_that_never_names_the_access_log_writes_one_record_per_request() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document =
        Document::new(port, vec![backend.entry(1, "enabled")]).without_access_log_named();
    assert!(
        !document.render().contains("access_log"),
        "this measures a document that does not name the setting"
    );
    let running = Running::start(&document).await;

    for _ in 0..3 {
        assert_eq!(
            ask_once(running.port, &request_to("mail.example.test", "/owa"))
                .await
                .expect("the request must be answered")
                .status,
            200
        );
    }

    let records = running.wait_for_access_records("http", 3).await;
    assert_eq!(
        records.len(),
        3,
        "an operator who never touched the setting must get a record per request"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sampled_access_log_writes_one_record_in_the_named_number_of_requests() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]).access_log(true, 4);
    let running = Running::start(&document).await;

    for _ in 0..12 {
        assert_eq!(
            ask_once(running.port, &request_to("mail.example.test", "/owa"))
                .await
                .expect("the request must be answered")
                .status,
            200
        );
    }

    let records = running.wait_for_access_records("http", 3).await;
    // Counted rather than drawn at random, so the number is exact.
    assert_eq!(
        records.len(),
        3,
        "twelve requests at one in four must produce three records; the log holds:\n{}",
        running.log_text()
    );
    assert_eq!(backend.hits(), 12, "every request was still served");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_application_log_level_changes_without_the_process_restarting() {
    let backend = Member::start("web-1").await;
    let port = free_port();
    // At error, nothing the process records at info may appear.
    let quiet = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("error");
    let running = Running::start(&quiet).await;
    let pid = running.pid();

    running
        .agent
        .wait_for_counter("configs_applied", 1)
        .await
        .expect("the first configuration must be applied");

    assert_eq!(
        info_records(&running),
        0,
        "an info record must not be written at level error; the log holds:\n{}",
        running.log_text()
    );

    // The same process is handed a new level, and applying that very delivery
    // is what it records.
    let louder = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("debug");
    running.agent.push(&louder.delivery(2));
    running
        .agent
        .wait_for_counter("configs_applied", 2)
        .await
        .expect("the second configuration must be applied");

    let start = tokio::time::Instant::now();
    while info_records(&running) == 0 {
        assert!(
            start.elapsed() <= PATIENCE,
            "raising the level wrote no info record; the log holds:\n{}",
            running.log_text()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    assert_eq!(
        running.pid(),
        pid,
        "the level changed without the process being replaced"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_level_the_configuration_lowers_stops_the_records_again() {
    // The other direction. Without it, a logger that ignored the setting and
    // always wrote everything would pass the measurement above.
    let backend = Member::start("web-1").await;
    let port = free_port();
    let loud = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("info");
    let running = Running::start(&loud).await;

    let start = tokio::time::Instant::now();
    while info_records(&running) == 0 {
        assert!(
            start.elapsed() <= PATIENCE,
            "the first apply must be recorded"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let before = info_records(&running);

    let quiet = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("error");
    running.agent.push(&quiet.delivery(2));
    running
        .agent
        .wait_for_counter("configs_applied", 2)
        .await
        .expect("the second configuration must be applied");

    // A third delivery, which at error must record nothing.
    let still_quiet = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("error");
    running.agent.push(&still_quiet.delivery(3));
    running
        .agent
        .wait_for_counter("configs_applied", 3)
        .await
        .expect("the third configuration must be applied");
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The level is set before the record is written, so the delivery that
    // lowered it is already quiet, and so is every delivery after it.
    assert_eq!(
        info_records(&running),
        before,
        "no info record may be written once the level is lowered; the log holds:\n{}",
        running.log_text()
    );
}

/// How many application records at info the process has written.
fn info_records(running: &Running) -> usize {
    running
        .records()
        .into_iter()
        .filter(|record| {
            record["kind"] == "app"
                && record["level"] == "info"
                // Only this project's own records. pingora writes through the
                // same logger, which is why it is installed on the facade, but
                // its records are not what the level setting is measured on.
                && record["target"]
                    .as_str()
                    .is_some_and(|target| target.starts_with("ek_ek"))
        })
        .count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn log_messages_are_written_in_english_and_never_translated() {
    // The log is read by whoever is diagnosing a fault, and a translated
    // message cannot be searched for (ADR-0015).
    let backend = Member::start("web-1").await;
    let port = free_port();
    let document = Document::new(port, vec![backend.entry(1, "enabled")]).log_level("info");
    let running = Running::start(&document).await;

    let start = tokio::time::Instant::now();
    while info_records(&running) == 0 {
        assert!(start.elapsed() <= PATIENCE, "the apply must be recorded");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let text = running.log_text();
    assert!(
        text.contains("configuration generation"),
        "the message must be the English one; the log holds:\n{text}"
    );
    for turkish in [
        '\u{131}', '\u{15f}', '\u{11f}', '\u{e7}', '\u{f6}', '\u{fc}',
    ] {
        assert!(
            !text.contains(turkish),
            "a log message must not be translated, {turkish} appears in:\n{text}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_high_volume_of_requests_is_served_without_the_log_holding_them_up() {
    // The record is handed to a queue and written by another thread, so the
    // request path never waits on standard output. Measured over the real
    // binary: the same requests are served twice, once with the access log
    // writing a record for every one of them and once with it off, and the
    // run that logs must not cost noticeably more.
    const REQUESTS: usize = 300;

    async fn spend(document: &Document) -> (Duration, Running) {
        let running = Running::start(document).await;
        // One request first, so connection setup and the first-request cost
        // land outside the measurement.
        let _ = ask_once(running.port, &request_to("mail.example.test", "/owa")).await;

        let started = tokio::time::Instant::now();
        for _ in 0..REQUESTS {
            assert_eq!(
                ask_once(running.port, &request_to("mail.example.test", "/owa"))
                    .await
                    .expect("every request must be answered")
                    .status,
                200
            );
        }
        (started.elapsed(), running)
    }

    let backend = Member::start("web-1").await;
    let logging = Document::new(free_port(), vec![backend.entry(1, "enabled")]).access_log(true, 1);
    let (with_log, running) = spend(&logging).await;

    let quiet_backend = Member::start("web-1").await;
    let quiet =
        Document::new(free_port(), vec![quiet_backend.entry(1, "enabled")]).access_log(false, 1);
    let (without_log, _quiet_running) = spend(&quiet).await;

    // Every request really was logged, or the run measured nothing.
    let records = running.wait_for_access_records("http", REQUESTS + 1).await;
    assert_eq!(
        records.len(),
        REQUESTS + 1,
        "the logging run must have written a record for every request"
    );
    assert_eq!(
        running
            .agent
            .last_report()
            .await
            .expect("the traffic path reports its counters")
            .log_records_dropped,
        0,
        "no record may be lost at this volume"
    );

    // A logger that wrote from the request path would show up as time the
    // client waited. The allowance is generous on purpose: what is being
    // ruled out is a cost per request, not a few milliseconds of noise.
    let allowed = without_log * 2 + Duration::from_millis(200);
    assert!(
        with_log <= allowed,
        "logging {REQUESTS} requests took {with_log:?} against {without_log:?} without it, \
         so the log is holding the request path up"
    );
}
