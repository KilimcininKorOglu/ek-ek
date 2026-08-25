// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The ACME order flow, measured against answers written by hand.
//!
//! No server is involved, so every rule is measured directly: what the flow
//! asks for, in what order, what a rejected nonce does to it, what an invalid
//! order does, and above all when the challenge answer is published and when
//! it is taken away again.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_tls::{Answer, Ask, Challenge, Flow, Identify, MOST_POLLS, Progress};

const DIRECTORY: &str = "https://acme.example.org/dir";
const NONCE_URL: &str = "https://acme.example.org/nonce";
const ACCOUNT_URL: &str = "https://acme.example.org/new-account";
const ORDER_URL: &str = "https://acme.example.org/new-order";
const AUTHZ_URL: &str = "https://acme.example.org/authz/1";
const CHALLENGE_URL: &str = "https://acme.example.org/chall/1";
const PLACED_URL: &str = "https://acme.example.org/order/9";
const FINALIZE_URL: &str = "https://acme.example.org/order/9/finalize";
const CERTIFICATE_URL: &str = "https://acme.example.org/cert/9";
const ACCOUNT: &str = "https://acme.example.org/account/7";
const THUMBPRINT: &str = "AAAABBBBCCCCDDDD";
const TOKEN: &str = "tokenTOKENtoken";

fn flow() -> Flow {
    Flow::new(
        DIRECTORY,
        vec!["www.example.org".to_owned()],
        THUMBPRINT,
        "yonetici@example.org",
        "Q1NSCg",
        Challenge::Http01,
    )
}

fn directory_body() -> String {
    format!(r#"{{"newNonce":"{NONCE_URL}","newAccount":"{ACCOUNT_URL}","newOrder":"{ORDER_URL}"}}"#)
}

fn order_body(status: &str) -> String {
    format!(
        r#"{{"status":"{status}","authorizations":["{AUTHZ_URL}"],"finalize":"{FINALIZE_URL}"}}"#
    )
}

fn authorization_body() -> String {
    format!(
        r#"{{"status":"pending","challenges":[
            {{"type":"dns-01","url":"https://acme.example.org/chall/dns","token":"other"}},
            {{"type":"http-01","url":"{CHALLENGE_URL}","token":"{TOKEN}"}}
        ]}}"#
    )
}

/// Feeds an answer and says the flow moved on.
fn moved(flow: &mut Flow, answer: &Answer) {
    assert_eq!(
        flow.accept(answer).expect("the answer must be readable"),
        Progress::Moved
    );
}

/// Walks the flow up to the point where the challenge is published.
fn up_to_publication(flow: &mut Flow) {
    moved(flow, &Answer::new(200, directory_body(), None));
    moved(flow, &Answer::new(204, String::new(), None));
    moved(flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        flow,
        &Answer::new(201, order_body("pending"), Some(PLACED_URL.to_owned())),
    );
    moved(flow, &Answer::new(200, authorization_body(), None));
}

#[test]
fn the_flow_asks_the_directory_the_configuration_names() {
    let flow = flow();
    let Some(Ask::Read { url }) = flow.next() else {
        panic!("the first thing asked for is the directory");
    };
    assert_eq!(
        url, DIRECTORY,
        "the directory address is what switches between staging and production"
    );

    // A different address is asked for when the configuration says so, which
    // is the whole of the staging switch.
    let other = Flow::new(
        "https://staging.example.org/dir",
        vec!["www.example.org".to_owned()],
        THUMBPRINT,
        "",
        "Q1NSCg",
        Challenge::Http01,
    );
    assert_eq!(
        other.next().expect("an ask").url(),
        "https://staging.example.org/dir"
    );
}

#[test]
fn the_account_request_carries_the_key_and_everything_after_it_carries_the_account() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));

    let Some(Ask::Send {
        url,
        payload,
        identify,
    }) = flow.next()
    else {
        panic!("the account is created with a signed request");
    };
    assert_eq!(url, ACCOUNT_URL);
    assert_eq!(
        identify,
        Identify::Key,
        "the server does not know the key yet, so it has to be carried"
    );
    let payload = payload.expect("the account request carries a body");
    assert!(payload.contains(r#""termsOfServiceAgreed":true"#));
    assert!(payload.contains("mailto:yonetici@example.org"));

    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    assert_eq!(flow.account(), Some(ACCOUNT));

    let Some(Ask::Send { identify, .. }) = flow.next() else {
        panic!("the order is placed with a signed request");
    };
    assert_eq!(
        identify,
        Identify::Account,
        "once the server knows the account, the envelope names it instead"
    );
}

#[test]
fn an_account_the_server_does_not_name_stops_the_order() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));

    let failure = flow
        .accept(&Answer::new(201, "{}", None))
        .expect_err("an account with no address is unusable");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Protocol);
}

#[test]
fn nothing_is_published_before_the_server_asks_for_it() {
    let mut flow = flow();
    assert!(
        flow.published().is_empty(),
        "a flow that has not started published something"
    );

    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    assert!(
        flow.published().is_empty(),
        "the answer was published before the order even existed"
    );
}

#[test]
fn the_challenge_answer_is_the_token_tied_to_the_account_key() {
    let mut flow = flow();
    up_to_publication(&mut flow);

    assert_eq!(flow.published().entries.len(), 1);
    assert_eq!(
        flow.published().entries.get(TOKEN).map(Vec::as_slice),
        Some([format!("{TOKEN}.{THUMBPRINT}")].as_slice()),
        "anybody who saw the token could answer if it were not tied to the key"
    );

    // And the HTTP-01 challenge is the one accepted, not the DNS-01 one that
    // came first in the list.
    let Some(Ask::Send { url, payload, .. }) = flow.next() else {
        panic!("the challenge is accepted with a signed request");
    };
    assert_eq!(url, CHALLENGE_URL);
    assert_eq!(payload.as_deref(), Some("{}"));
}

#[test]
fn an_authorization_with_no_http01_challenge_stops_the_order() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        &mut flow,
        &Answer::new(201, order_body("pending"), Some(PLACED_URL.to_owned())),
    );

    let failure = flow
        .accept(&Answer::new(
            200,
            r#"{"status":"pending","challenges":[{"type":"dns-01","url":"u","token":"t"}]}"#,
            None,
        ))
        .expect_err("there is nothing this flow can answer");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Challenge);
    assert!(
        !failure.worth_retrying(),
        "asking the same server the same question again would only spend the allowance"
    );
}

#[test]
fn a_token_that_could_name_a_deeper_path_is_refused() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        &mut flow,
        &Answer::new(201, order_body("pending"), Some(PLACED_URL.to_owned())),
    );

    let failure = flow
        .accept(&Answer::new(
            200,
            format!(
                r#"{{"status":"pending","challenges":[{{"type":"http-01","url":"{CHALLENGE_URL}","token":"a/b"}}]}}"#
            ),
            None,
        ))
        .expect_err("a token with a separator in it names no single path");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Protocol);
    assert!(
        flow.published().is_empty(),
        "a token that was refused was published anyway"
    );
}

#[test]
fn the_answer_is_taken_away_once_the_certificate_is_in_hand() {
    let mut flow = flow();
    up_to_publication(&mut flow);
    assert_eq!(flow.published().entries.len(), 1);

    moved(&mut flow, &Answer::new(200, "{}", None));
    moved(&mut flow, &Answer::new(200, order_body("ready"), None));
    moved(&mut flow, &Answer::new(200, order_body("processing"), None));
    moved(
        &mut flow,
        &Answer::new(
            200,
            format!(r#"{{"status":"valid","certificate":"{CERTIFICATE_URL}"}}"#),
            None,
        ),
    );

    // Still published while the certificate is being collected: the server may
    // check again until the order is closed.
    assert_eq!(flow.published().entries.len(), 1);

    moved(
        &mut flow,
        &Answer::new(200, "-----BEGIN CERTIFICATE-----", None),
    );
    assert!(flow.finished());
    assert_eq!(
        flow.chain(),
        Some("-----BEGIN CERTIFICATE-----"),
        "the certificate is what the order was for"
    );
    assert!(
        flow.published().is_empty(),
        "the challenge path is still open after the order finished"
    );
    assert!(flow.next().is_none(), "a finished order still wants to ask");
}

#[test]
fn giving_up_takes_the_answer_away_too() {
    let mut flow = flow();
    up_to_publication(&mut flow);
    assert_eq!(flow.published().entries.len(), 1);

    flow.abandon();

    assert!(
        flow.published().is_empty(),
        "a failed order left a path anybody could reach"
    );
    assert!(flow.next().is_none());
}

#[test]
fn a_rejected_nonce_repeats_the_same_request() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    let before = flow.next().expect("an ask");

    let progress = flow
        .accept(&Answer::new(
            400,
            r#"{"type":"urn:ietf:params:acme:error:badNonce","detail":"stale"}"#,
            None,
        ))
        .expect("a rejected nonce is not a failure");
    assert_eq!(progress, Progress::Again);
    assert_eq!(
        flow.next().expect("the same ask"),
        before,
        "the flow moved on from a request the server never took"
    );
}

#[test]
fn any_other_refusal_is_a_failure() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));

    let failure = flow
        .accept(&Answer::new(
            429,
            r#"{"type":"urn:ietf:params:acme:error:rateLimited","detail":"too many"}"#,
            None,
        ))
        .expect_err("a refusal is a refusal");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Server);
    assert!(
        failure.detail().contains("rateLimited"),
        "an operator has to be able to search on what the server said: {}",
        failure.detail()
    );
}

#[test]
fn an_order_the_server_refused_is_not_tried_again() {
    let mut flow = flow();
    up_to_publication(&mut flow);
    moved(&mut flow, &Answer::new(200, "{}", None));

    let failure = flow
        .accept(&Answer::new(200, r#"{"status":"invalid"}"#, None))
        .expect_err("an invalid order cannot go on");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Challenge);
    assert!(
        !failure.worth_retrying(),
        "the name does not point here, and repeating that spends the allowance"
    );
    assert!(
        failure.detail().contains("www.example.org"),
        "the name that failed has to be in the record: {}",
        failure.detail()
    );
}

#[test]
fn a_server_that_never_decides_ends_the_attempt() {
    let mut flow = flow();
    up_to_publication(&mut flow);
    moved(&mut flow, &Answer::new(200, "{}", None));

    for _ in 0..MOST_POLLS {
        moved(&mut flow, &Answer::new(200, order_body("pending"), None));
    }
    let failure = flow
        .accept(&Answer::new(200, order_body("pending"), None))
        .expect_err("the reads have to stop somewhere");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Network);
    assert!(
        failure.worth_retrying(),
        "a server that was busy this time may not be next time"
    );
}

#[test]
fn an_authorization_that_is_already_proven_publishes_nothing() {
    let mut flow = flow();
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        &mut flow,
        &Answer::new(201, order_body("pending"), Some(PLACED_URL.to_owned())),
    );
    moved(&mut flow, &Answer::new(200, r#"{"status":"valid"}"#, None));

    assert!(
        flow.published().is_empty(),
        "a path was opened for a question nobody is going to ask"
    );
    // And the flow went straight to reading the order.
    let Some(Ask::Send { url, payload, .. }) = flow.next() else {
        panic!("the order is read next");
    };
    assert_eq!(url, PLACED_URL);
    assert_eq!(payload, None, "reading an order is a POST-as-GET");
}

#[test]
fn an_empty_certificate_is_refused() {
    let mut flow = flow();
    up_to_publication(&mut flow);
    moved(&mut flow, &Answer::new(200, "{}", None));
    moved(
        &mut flow,
        &Answer::new(
            200,
            format!(r#"{{"status":"valid","certificate":"{CERTIFICATE_URL}"}}"#),
            None,
        ),
    );

    let failure = flow
        .accept(&Answer::new(200, "   ", None))
        .expect_err("an empty answer is not a certificate");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Protocol);
}

#[test]
fn every_name_asked_for_reaches_the_order() {
    let mut flow = Flow::new(
        DIRECTORY,
        vec!["www.example.org".to_owned(), "posta.example.org".to_owned()],
        THUMBPRINT,
        "",
        "Q1NSCg",
        Challenge::Http01,
    );
    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));

    let Some(Ask::Send { payload, .. }) = flow.next() else {
        panic!("the order is placed with a signed request");
    };
    let payload = payload.expect("the order carries a body");
    assert!(payload.contains(r#"{"type":"dns","value":"www.example.org"}"#));
    assert!(payload.contains(r#"{"type":"dns","value":"posta.example.org"}"#));
}

#[test]
fn the_signing_request_is_handed_over_when_the_order_is_ready() {
    let mut flow = flow();
    up_to_publication(&mut flow);
    moved(&mut flow, &Answer::new(200, "{}", None));
    moved(&mut flow, &Answer::new(200, order_body("ready"), None));

    let Some(Ask::Send { url, payload, .. }) = flow.next() else {
        panic!("the order is finalised with a signed request");
    };
    assert_eq!(url, FINALIZE_URL);
    assert_eq!(payload.as_deref(), Some(r#"{"csr":"Q1NSCg"}"#));
}

/// A flow that takes over an order the server already named.
fn resumed() -> Flow {
    Flow::resume(
        DIRECTORY,
        vec!["www.example.org".to_owned()],
        THUMBPRINT,
        "yonetici@example.org",
        "Q1NSCg",
        Challenge::Http01,
        PLACED_URL,
    )
}

/// Walks a resuming flow up to the point where it reads the order.
fn up_to_the_carried_order(flow: &mut Flow) {
    moved(flow, &Answer::new(200, directory_body(), None));
    moved(flow, &Answer::new(204, String::new(), None));
    moved(flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
}

#[test]
fn the_order_the_server_named_is_there_before_anything_is_published() {
    let mut flow = flow();
    assert_eq!(
        flow.order_url(),
        None,
        "an order nothing was placed for named one"
    );

    moved(&mut flow, &Answer::new(200, directory_body(), None));
    moved(&mut flow, &Answer::new(204, String::new(), None));
    moved(&mut flow, &Answer::new(201, "{}", Some(ACCOUNT.to_owned())));
    moved(
        &mut flow,
        &Answer::new(201, order_body("pending"), Some(PLACED_URL.to_owned())),
    );

    // The order is named and nothing has been published yet. That order is
    // what lets a caller write the URL down before the step that can lose it
    // (ADR-0086).
    assert_eq!(flow.order_url(), Some(PLACED_URL));
    assert!(
        flow.published().is_empty(),
        "the challenge answer was there before the order was even read"
    );
}

#[test]
fn a_taken_over_order_is_read_rather_than_placed_again() {
    let mut flow = resumed();
    assert_eq!(
        flow.order_url(),
        Some(PLACED_URL),
        "a flow taking an order over did not carry the order it takes over"
    );
    up_to_the_carried_order(&mut flow);

    let Some(Ask::Send {
        url,
        payload,
        identify,
    }) = flow.next()
    else {
        panic!("the carried order is read with a signed request");
    };
    assert_eq!(
        url, PLACED_URL,
        "the flow placed a second order instead of reading the one it was given, \
         which would spend the server's allowance twice for one certificate"
    );
    assert_eq!(
        payload, None,
        "reading an order is a POST-as-GET; a body would create something"
    );
    assert_eq!(identify, Identify::Account);
}

#[test]
fn an_order_taken_over_while_it_still_needs_an_answer_publishes_again() {
    let mut flow = resumed();
    up_to_the_carried_order(&mut flow);
    moved(&mut flow, &Answer::new(200, order_body("pending"), None));
    moved(&mut flow, &Answer::new(200, authorization_body(), None));

    assert_eq!(
        flow.published().entries.keys().collect::<Vec<&String>>(),
        vec![TOKEN],
        "the node that took the order over left the challenge path closed, \
         so the server would check a path nothing answers"
    );
    let Some(Ask::Send { url, .. }) = flow.next() else {
        panic!("the server is told the challenge is ready");
    };
    assert_eq!(url, CHALLENGE_URL);
}

#[test]
fn an_order_taken_over_after_it_was_finalised_collects_the_certificate() {
    let mut flow = resumed();
    up_to_the_carried_order(&mut flow);
    moved(
        &mut flow,
        &Answer::new(
            200,
            format!(
                r#"{{"status":"valid","authorizations":["{AUTHZ_URL}"],"finalize":"{FINALIZE_URL}","certificate":"{CERTIFICATE_URL}"}}"#
            ),
            None,
        ),
    );

    // Straight to the certificate. Walking the authorizations again would ask
    // the server about work it has already finished, and finalising again
    // would be refused.
    let Some(Ask::Send { url, .. }) = flow.next() else {
        panic!("the certificate is collected with a signed request");
    };
    assert_eq!(
        url, CERTIFICATE_URL,
        "an order that was already finalised was taken over as if it were new"
    );
    assert!(
        flow.published().is_empty(),
        "an order the server has already decided on left a challenge path open"
    );
}

#[test]
fn an_order_taken_over_that_is_ready_is_finalised_and_not_restarted() {
    let mut flow = resumed();
    up_to_the_carried_order(&mut flow);
    moved(&mut flow, &Answer::new(200, order_body("ready"), None));

    let Some(Ask::Send { url, payload, .. }) = flow.next() else {
        panic!("the order is finalised with a signed request");
    };
    assert_eq!(url, FINALIZE_URL);
    assert_eq!(
        payload.as_deref(),
        Some(r#"{"csr":"Q1NSCg"}"#),
        "the signing request the taking over node holds is what finalises the order"
    );
}

#[test]
fn an_order_taken_over_after_it_failed_says_so_rather_than_waiting() {
    let mut flow = resumed();
    up_to_the_carried_order(&mut flow);

    let failure = flow
        .accept(&Answer::new(200, order_body("invalid"), None))
        .expect_err("an order the server refused cannot be finished");
    assert_eq!(
        failure.reason(),
        ek_ek_tls::Reason::Challenge,
        "a refused order was reported as something worth another attempt"
    );
    assert!(
        !failure.worth_retrying(),
        "the same refused order would be read again for ever"
    );
}
