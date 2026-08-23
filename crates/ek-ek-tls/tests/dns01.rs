// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The DNS-01 side of the order flow, and the wait for a record to appear.
//!
//! No socket and no name server. What is measured is which challenge the
//! flow picks, what it asks to be published, where a wildcard's record goes,
//! and that the wait ends rather than holding an order open for ever.

use std::collections::BTreeMap;
use std::time::Duration;

use ek_ek_tls::dns::{LOOK_INTERVAL, challenge_name, settle};
use ek_ek_tls::{Answer, Ask, Challenge, Failure, Flow, Progress, Reason};

const DIRECTORY: &str = "https://acme.example.org/dir";
const NONCE_URL: &str = "https://acme.example.org/nonce";
const ACCOUNT_URL: &str = "https://acme.example.org/new-account";
const ORDER_URL: &str = "https://acme.example.org/new-order";
const AUTHZ_URL: &str = "https://acme.example.org/authz/1";
const SECOND_AUTHZ_URL: &str = "https://acme.example.org/authz/2";
const CHALLENGE_URL: &str = "https://acme.example.org/chall/1";
const PLACED_URL: &str = "https://acme.example.org/order/9";
const FINALIZE_URL: &str = "https://acme.example.org/order/9/finalize";
const ACCOUNT: &str = "https://acme.example.org/account/7";
const THUMBPRINT: &str = "AAAABBBBCCCCDDDD";
const TOKEN: &str = "tokenTOKENtoken";
const OTHER_TOKEN: &str = "secondSECONDsecond";
const RECORD: &str = "_acme-challenge.ek-ek.test";

fn flow(names: Vec<String>) -> Flow {
    Flow::new(
        DIRECTORY,
        names,
        THUMBPRINT,
        "yonetici@ek-ek.test",
        "Q1NSCg",
        Challenge::Dns01,
    )
}

fn moved(flow: &mut Flow, answer: &Answer) {
    assert_eq!(
        flow.accept(answer).expect("the flow reads this"),
        Progress::Moved
    );
}

fn directory_body() -> String {
    format!(r#"{{"newNonce":"{NONCE_URL}","newAccount":"{ACCOUNT_URL}","newOrder":"{ORDER_URL}"}}"#)
}

fn order_body(authorizations: &[&str]) -> String {
    let listed: Vec<String> = authorizations
        .iter()
        .map(|url| format!("\"{url}\""))
        .collect();
    format!(
        r#"{{"status":"pending","authorizations":[{}],"finalize":"{FINALIZE_URL}"}}"#,
        listed.join(",")
    )
}

/// An authorization offering both challenges, with DNS-01 second.
fn authorization(identifier: &str, token: &str, wildcard: bool) -> String {
    let star = if wildcard { r#","wildcard":true"# } else { "" };
    format!(
        r#"{{"status":"pending","identifier":{{"type":"dns","value":"{identifier}"}}{star},"challenges":[{{"type":"http-01","url":"https://acme.example.org/chall/http","token":"{token}"}},{{"type":"dns-01","url":"{CHALLENGE_URL}","token":"{token}"}}]}}"#
    )
}

fn up_to(flow: &mut Flow, authorizations: &[&str], bodies: &[String]) {
    moved(flow, &Answer::new(200, directory_body(), None));
    moved(flow, &Answer::new(204, String::new(), None));
    moved(flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        flow,
        &Answer::new(201, order_body(authorizations), Some(PLACED_URL.to_owned())),
    );
    for body in bodies {
        moved(flow, &Answer::new(200, body.clone(), None));
        if body != bodies.last().expect("there is one") {
            // Accepting the challenge moves on to the next authorization.
            moved(flow, &Answer::new(200, "{}", None));
        }
    }
}

#[test]
fn the_dns_challenge_is_the_one_taken_even_when_http_comes_first() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL],
        &[authorization("ek-ek.test", TOKEN, false)],
    );

    let Some(Ask::Send { url, .. }) = flow.next() else {
        panic!("the challenge is accepted with a signed request");
    };
    assert_eq!(
        url, CHALLENGE_URL,
        "the flow answered the challenge it cannot serve"
    );
    assert_eq!(flow.published().kind, Some(Challenge::Dns01));
}

#[test]
fn a_server_that_offers_no_dns_challenge_ends_the_order() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        &mut flow,
        &Answer::new(201, order_body(&[AUTHZ_URL]), Some(PLACED_URL.to_owned())),
    );

    let failure = flow
        .accept(&Answer::new(
            200,
            format!(
                r#"{{"status":"pending","identifier":{{"type":"dns","value":"ek-ek.test"}},"challenges":[{{"type":"http-01","url":"{CHALLENGE_URL}","token":"{TOKEN}"}}]}}"#
            ),
            None,
        ))
        .expect_err("a provider was configured for a challenge the server does not offer");
    assert_eq!(failure.reason(), Reason::Challenge);
    assert!(
        !failure.worth_retrying(),
        "asking the same server the same question again changes nothing"
    );
}

#[test]
fn the_record_sits_under_the_challenge_label_of_the_name() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL],
        &[authorization("ek-ek.test", TOKEN, false)],
    );

    let entries = &flow.published().entries;
    assert_eq!(entries.len(), 1);
    let values = entries.get(RECORD).expect("the record is named after it");
    assert_eq!(values.len(), 1);
}

#[test]
fn a_wildcard_is_proven_at_the_name_it_stands_for() {
    assert_eq!(challenge_name("*.ek-ek.test"), RECORD);
    assert_eq!(challenge_name("ek-ek.test"), RECORD);
}

#[test]
fn the_record_value_is_a_digest_and_not_the_answer_itself() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL],
        &[authorization("ek-ek.test", TOKEN, false)],
    );

    let value = flow.published().entries[RECORD][0].clone();
    assert_eq!(
        value,
        ek_ek_tls::record_value(TOKEN, THUMBPRINT).expect("it digests")
    );
    assert_eq!(
        value.len(),
        43,
        "a digest of a fixed length is what keeps the record inside one string"
    );
    assert!(
        !value.contains(TOKEN),
        "publishing the answer itself would put it in a place anybody can read"
    );
    assert!(
        !value.contains('=') && !value.contains('+') && !value.contains('/'),
        "the value is base64url without padding, so it needs no quoting: {value}"
    );
}

#[test]
fn an_apex_and_its_wildcard_both_land_at_one_name() {
    let mut flow = flow(vec!["ek-ek.test".to_owned(), "*.ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL, SECOND_AUTHZ_URL],
        &[
            authorization("ek-ek.test", TOKEN, false),
            authorization("ek-ek.test", OTHER_TOKEN, true),
        ],
    );

    let values = &flow.published().entries[RECORD];
    assert_eq!(
        values.len(),
        2,
        "dropping either value fails the authorization it belongs to: {values:?}"
    );
    assert_ne!(values[0], values[1]);
    assert!(values.contains(&ek_ek_tls::record_value(TOKEN, THUMBPRINT).expect("it digests")));
    assert!(
        values.contains(&ek_ek_tls::record_value(OTHER_TOKEN, THUMBPRINT).expect("it digests"))
    );
}

#[test]
fn a_token_with_a_separator_is_fine_for_a_record() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL],
        &[authorization("ek-ek.test", "a/b", false)],
    );
    assert_eq!(
        flow.published().entries[RECORD].len(),
        1,
        "a token becomes a digest here, not a path, so a separator means nothing"
    );
}

#[test]
fn an_authorization_without_an_identifier_is_refused() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        &mut flow,
        &Answer::new(201, order_body(&[AUTHZ_URL]), Some(PLACED_URL.to_owned())),
    );

    let failure = flow
        .accept(&Answer::new(
            200,
            format!(
                r#"{{"status":"pending","challenges":[{{"type":"dns-01","url":"{CHALLENGE_URL}","token":"{TOKEN}"}}]}}"#
            ),
            None,
        ))
        .expect_err("there is nowhere to put the record without a name");
    assert_eq!(failure.reason(), Reason::Protocol);
    assert!(flow.published().is_empty());
}

#[test]
fn giving_up_takes_the_records_away_too() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL],
        &[authorization("ek-ek.test", TOKEN, false)],
    );
    assert!(!flow.published().is_empty());

    flow.abandon();
    assert!(
        flow.published().is_empty(),
        "a record left behind is one nobody is watching"
    );
}

/// A lookup that answers from a script, one call at a time.
fn scripted(answers: Vec<Vec<String>>) -> impl FnMut(&str) -> Result<Vec<String>, Failure> {
    let mut answers = answers.into_iter();
    move |_| Ok(answers.next().unwrap_or_default())
}

#[test]
fn the_wait_ends_as_soon_as_the_value_is_there() {
    let mut records = BTreeMap::new();
    records.insert(RECORD.to_owned(), vec!["value".to_owned()]);
    let mut waits = Vec::new();
    let mut look = scripted(vec![vec!["value".to_owned()]]);

    settle(&records, Duration::from_secs(120), &mut look, &mut |wait| {
        waits.push(wait)
    })
    .expect("the record is there");

    assert!(
        waits.is_empty(),
        "a record that is already visible is not waited for"
    );
}

#[test]
fn the_wait_keeps_looking_until_the_value_appears() {
    let mut records = BTreeMap::new();
    records.insert(RECORD.to_owned(), vec!["value".to_owned()]);
    let mut waits = Vec::new();
    let mut look = scripted(vec![
        Vec::new(),
        vec!["something else".to_owned()],
        vec!["value".to_owned()],
    ]);

    settle(&records, Duration::from_secs(120), &mut look, &mut |wait| {
        waits.push(wait)
    })
    .expect("it appears on the third look");

    assert_eq!(waits, vec![LOOK_INTERVAL, LOOK_INTERVAL]);
}

#[test]
fn a_record_that_never_appears_ends_the_attempt_with_the_name_that_is_missing() {
    let mut records = BTreeMap::new();
    records.insert(RECORD.to_owned(), vec!["value".to_owned()]);
    let mut waited = Duration::ZERO;
    let mut look = scripted(Vec::new());

    let failure = settle(&records, LOOK_INTERVAL * 3, &mut look, &mut |wait| {
        waited += wait
    })
    .expect_err("telling the authority to look at a name that holds nothing loses the identifier");

    assert_eq!(failure.reason(), Reason::Challenge);
    assert!(
        failure.detail().contains(RECORD),
        "the name is what an operator has to go and look at: {}",
        failure.detail()
    );
    assert!(
        !failure.detail().contains("value"),
        "the answer to the challenge is not for a log: {}",
        failure.detail()
    );
    assert_eq!(
        waited,
        LOOK_INTERVAL * 3,
        "the wait spends the configured time and not a look more"
    );
}

#[test]
fn every_value_at_a_name_has_to_be_there_before_the_wait_ends() {
    let mut records = BTreeMap::new();
    records.insert(
        RECORD.to_owned(),
        vec!["first".to_owned(), "second".to_owned()],
    );
    let mut look = scripted(vec![vec!["first".to_owned()]]);

    let failure = settle(&records, Duration::ZERO, &mut look, &mut |_| {})
        .expect_err("one of the two authorizations would fail");
    assert_eq!(failure.reason(), Reason::Challenge);
}

#[test]
fn a_name_server_that_cannot_be_asked_ends_the_wait_rather_than_being_retried_here() {
    let mut records = BTreeMap::new();
    records.insert(RECORD.to_owned(), vec!["value".to_owned()]);
    let mut look =
        |_: &str| Err::<Vec<String>, Failure>(Failure::new(Reason::Network, "nothing answered"));

    let failure = settle(&records, Duration::from_secs(120), &mut look, &mut |_| {
        panic!("a wait between looks is not a wait for a server that is not there")
    })
    .expect_err("the attempt ends and the order decides whether to make another");
    assert_eq!(failure.reason(), Reason::Network);
}

#[test]
fn a_publication_is_refused_by_the_publisher_of_the_other_challenge() {
    let mut flow = flow(vec!["ek-ek.test".to_owned()]);
    up_to(
        &mut flow,
        &[AUTHZ_URL],
        &[authorization("ek-ek.test", TOKEN, false)],
    );

    let publication = flow.published();
    publication
        .meant_for(Challenge::Dns01)
        .expect("this is what it is");

    let failure = publication
        .meant_for(Challenge::Http01)
        .expect_err("a record cannot be served from a listener, and nobody would find it");
    assert_eq!(failure.reason(), Reason::Protocol);
    assert!(failure.detail().contains("dns-01") && failure.detail().contains("http-01"));
}

#[test]
fn an_empty_publication_belongs_to_whoever_is_closing_up() {
    let empty = ek_ek_tls::Publication::default();
    empty
        .meant_for(Challenge::Http01)
        .expect("taking nothing away is not a mismatch");
    empty
        .meant_for(Challenge::Dns01)
        .expect("and neither is it");
}
