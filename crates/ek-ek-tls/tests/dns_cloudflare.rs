// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The Cloudflare provider, measured against a transport written here.
//!
//! Nothing in this file reaches the real API, and nothing may: a test that
//! writes into somebody's zone is a test nobody can run twice. What is
//! measured is what leaves this machine and what is made of what comes back.

use std::sync::{Arc, Mutex};

use ek_ek_tls::Reason;
use ek_ek_tls::dns::cloudflare::{self, Api, Connection};

const BASE: &str = "https://api.example.org/client/v4";
const ZONE: &str = "0123456789abcdef";
const TOKEN: &str = "a-token-nobody-else-holds";
const NAME: &str = "_acme-challenge.ek-ek.test";
const VALUE: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";

/// One call, as it left.
#[derive(Clone, Debug)]
struct Call {
    method: String,
    url: String,
    token: String,
    body: Option<String>,
}

/// A transport that answers from a script and records what it was given.
struct Scripted {
    answers: Vec<(u16, String)>,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl Scripted {
    fn new(answers: Vec<(u16, String)>) -> Self {
        Self {
            answers,
            calls: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

impl Api for Scripted {
    fn call(
        &mut self,
        method: &str,
        url: &str,
        token: &str,
        body: Option<&str>,
    ) -> Result<(u16, String), ek_ek_tls::Failure> {
        self.calls
            .lock()
            .expect("nothing else holds it")
            .push(Call {
                method: method.to_owned(),
                url: url.to_owned(),
                token: token.to_owned(),
                body: body.map(str::to_owned),
            });
        if self.answers.is_empty() {
            return Ok((200, r#"{"success":true,"result":[]}"#.to_owned()));
        }
        Ok(self.answers.remove(0))
    }
}

fn connection() -> Connection<'static> {
    Connection {
        base: BASE,
        zone_id: ZONE,
        token: TOKEN,
    }
}

fn listing(records: &[(&str, &str)]) -> String {
    let entries: Vec<String> = records
        .iter()
        .map(|(id, content)| format!(r#"{{"id":"{id}","name":"{NAME}","content":"{content}"}}"#))
        .collect();
    format!(r#"{{"success":true,"result":[{}]}}"#, entries.join(","))
}

const CREATED: &str = r#"{"success":true,"result":{"id":"new"}}"#;

#[test]
fn publishing_reads_the_name_clears_it_and_writes_the_values() {
    let mut api = Scripted::new(vec![
        (200, listing(&[("old", "stale")])),
        (200, r#"{"success":true,"result":{}}"#.to_owned()),
        (200, CREATED.to_owned()),
    ]);
    let calls = Arc::clone(&api.calls);

    cloudflare::publish(&mut api, connection(), NAME, &[VALUE.to_owned()]).expect("it publishes");

    let calls = calls.lock().expect("nothing else holds it").clone();
    let shape: Vec<&str> = calls.iter().map(|call| call.method.as_str()).collect();
    assert_eq!(
        shape,
        vec!["GET", "DELETE", "POST"],
        "a record left from an earlier order has to go before the new one is written"
    );
    assert!(
        calls[0].url.contains("type=TXT") && calls[0].url.contains(NAME),
        "the list is asked for by type and name, not read whole: {}",
        calls[0].url
    );
    assert!(calls[1].url.ends_with("/dns_records/old"));
    assert_eq!(
        calls[2].body.as_deref(),
        Some(format!(r#"{{"type":"TXT","name":"{NAME}","content":"{VALUE}","ttl":60}}"#).as_str())
    );
}

#[test]
fn every_call_carries_the_token_and_no_url_does() {
    // A record to delete, so the read, the delete and the write are all
    // covered. A run with nothing at the name never builds a delete URL.
    let mut api = Scripted::new(vec![
        (200, listing(&[("old", "stale")])),
        (200, r#"{"success":true,"result":{}}"#.to_owned()),
        (200, CREATED.to_owned()),
    ]);
    let calls = Arc::clone(&api.calls);

    cloudflare::publish(&mut api, connection(), NAME, &[VALUE.to_owned()]).expect("it publishes");

    assert_eq!(
        calls.lock().expect("nothing else holds it").len(),
        3,
        "one of the three calls was not made, so it was not checked either"
    );
    for call in calls.lock().expect("nothing else holds it").iter() {
        assert_eq!(call.token, TOKEN, "a call without the token is refused");
        assert!(
            !call.url.contains(TOKEN),
            "a token in a URL lands in every proxy log on the way: {}",
            call.url
        );
    }
}

#[test]
fn two_values_at_one_name_are_both_written() {
    let mut api = Scripted::new(vec![
        (200, listing(&[])),
        (200, CREATED.to_owned()),
        (200, CREATED.to_owned()),
    ]);
    let calls = Arc::clone(&api.calls);

    cloudflare::publish(
        &mut api,
        connection(),
        NAME,
        &["first".to_owned(), "second".to_owned()],
    )
    .expect("it publishes");

    let written: Vec<String> = calls
        .lock()
        .expect("nothing else holds it")
        .iter()
        .filter(|call| call.method == "POST")
        .filter_map(|call| call.body.clone())
        .collect();
    assert_eq!(
        written.len(),
        2,
        "an apex and its wildcard are answered at one name with two values"
    );
    assert!(written[0].contains("first") && written[1].contains("second"));
}

#[test]
fn withdrawing_deletes_every_record_at_the_name() {
    let mut api = Scripted::new(vec![
        (200, listing(&[("one", "a"), ("two", "b")])),
        (200, r#"{"success":true,"result":{}}"#.to_owned()),
        (200, r#"{"success":true,"result":{}}"#.to_owned()),
    ]);
    let calls = Arc::clone(&api.calls);

    cloudflare::withdraw(&mut api, connection(), NAME).expect("it withdraws");

    let deleted: Vec<String> = calls
        .lock()
        .expect("nothing else holds it")
        .iter()
        .filter(|call| call.method == "DELETE")
        .map(|call| call.url.clone())
        .collect();
    assert_eq!(
        deleted.len(),
        2,
        "a record left behind is one that accumulates"
    );
    assert!(deleted[0].ends_with("/one") && deleted[1].ends_with("/two"));
}

#[test]
fn withdrawing_a_name_that_holds_nothing_deletes_nothing() {
    let mut api = Scripted::new(vec![(200, listing(&[]))]);
    let calls = Arc::clone(&api.calls);

    cloudflare::withdraw(&mut api, connection(), NAME).expect("nothing to do is not a failure");

    assert_eq!(calls.lock().expect("nothing else holds it").len(), 1);
}

#[test]
fn a_refused_token_says_so_and_is_not_worth_another_attempt() {
    let mut api = Scripted::new(vec![(
        403,
        r#"{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}]}"#.to_owned(),
    )]);

    let failure = cloudflare::withdraw(&mut api, connection(), NAME)
        .expect_err("a token the API will not take is not a fault that passes");
    assert_eq!(failure.reason(), Reason::Configuration);
    assert!(
        !failure.worth_retrying(),
        "retrying a refused token only spends the rate limit"
    );
    assert!(
        failure.detail().contains("9109"),
        "the API's own code is what its documentation is indexed by: {}",
        failure.detail()
    );
    assert!(
        !failure.detail().contains(TOKEN),
        "the token itself never reaches a message: {}",
        failure.detail()
    );
}

#[test]
fn a_server_fault_is_worth_another_attempt() {
    let mut api = Scripted::new(vec![(
        503,
        r#"{"success":false,"errors":[{"code":0,"message":"service unavailable"}]}"#.to_owned(),
    )]);

    let failure = cloudflare::withdraw(&mut api, connection(), NAME).expect_err("it failed");
    assert_eq!(failure.reason(), Reason::Server);
    assert!(failure.worth_retrying());
}

#[test]
fn an_answer_that_says_it_failed_is_a_failure_whatever_the_status_is() {
    let mut api = Scripted::new(vec![(
        200,
        r#"{"success":false,"errors":[{"code":1004,"message":"DNS validation error"}]}"#.to_owned(),
    )]);

    let failure = cloudflare::withdraw(&mut api, connection(), NAME)
        .expect_err("the API says what happened in the body, not only in the status");
    assert_eq!(failure.reason(), Reason::Configuration);
    assert!(failure.detail().contains("1004"));
}

#[test]
fn an_answer_that_is_not_json_is_refused() {
    let mut api = Scripted::new(vec![(
        200,
        "<html>a proxy answered instead</html>".to_owned(),
    )]);

    let failure = cloudflare::withdraw(&mut api, connection(), NAME)
        .expect_err("something in the way answered, and it is not the API");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn a_name_that_could_change_the_meaning_of_a_url_is_refused() {
    let mut api = Scripted::new(vec![(200, listing(&[]))]);

    let failure = cloudflare::withdraw(&mut api, connection(), "a name&per_page=1000")
        .expect_err("a name is pasted into a query string and is not trusted to be safe there");
    assert_eq!(failure.reason(), Reason::Protocol);
    assert!(
        api.calls.lock().expect("nothing else holds it").is_empty(),
        "the call went out before the name was checked"
    );
}

#[test]
fn a_wildcard_name_is_still_a_name_that_can_be_sent() {
    let mut api = Scripted::new(vec![(200, listing(&[]))]);
    cloudflare::withdraw(&mut api, connection(), "*.ek-ek.test")
        .expect("a star is part of a DNS name and not part of a URL's grammar");
}

#[test]
fn the_real_transport_reaches_the_handshake_rather_than_stopping_the_process() {
    // Something has to accept the connection, or the call never gets as far
    // as TLS and this measures nothing: a transport that names no provider
    // stops the whole process the moment it starts a handshake, and a refused
    // connection never starts one.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = listener.local_addr().expect("it is bound");
    let closing = std::thread::spawn(move || {
        // Accepted and dropped. The handshake is started and gets nowhere,
        // which is exactly the point: it was started.
        let _ = listener.accept();
    });

    let mut api = cloudflare::HttpsApi::new(std::time::Duration::from_secs(5));
    let failure = api
        .call(
            "GET",
            &format!("https://{address}/client/v4/zones/x/dns_records"),
            TOKEN,
            None,
        )
        .expect_err("the other end says nothing a TLS peer would say");
    let _ = closing.join();

    assert_eq!(
        failure.reason(),
        Reason::Network,
        "a handshake that got nowhere is a network fault, not anything else"
    );
    assert!(
        !failure.detail().contains(TOKEN),
        "the token reached the message: {}",
        failure.detail()
    );
}
