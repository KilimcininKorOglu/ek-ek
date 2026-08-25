// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The carrier that drives an order, measured without a network.
//!
//! The transport, the publisher and the wait are all handed in, so a whole run
//! of five attempts with growing waits is measured in milliseconds instead of
//! the quarter of an hour it takes in production. What is measured here is the
//! driver: how often it tries, how long it says it is waiting, when it opens
//! the challenge path and when it closes it again.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use ek_ek_config::AcmeSettings;
use ek_ek_tls::{
    ATTEMPTS, Challenge, FIRST_WAIT, Failure, Publication, Reached, Reason, Reply, Transport,
    obtain_over, wait_before,
};

const DIRECTORY: &str = "https://acme.example.org/dir";
const NONCE_URL: &str = "https://acme.example.org/nonce";
const ACCOUNT_URL: &str = "https://acme.example.org/new-account";
const ORDER_URL: &str = "https://acme.example.org/new-order";
const AUTHZ_URL: &str = "https://acme.example.org/authz/1";
const CHALLENGE_URL: &str = "https://acme.example.org/chall/1";
const PLACED_URL: &str = "https://acme.example.org/order/9";
const FINALIZE_URL: &str = "https://acme.example.org/order/9/finalize";
const CERTIFICATE_URL: &str = "https://acme.example.org/cert/9";
const TOKEN: &str = "tokenTOKENtoken";
const CHAIN: &str = "-----BEGIN CERTIFICATE-----\nnot a real one\n-----END CERTIFICATE-----\n";

fn settings(directory: &str) -> AcmeSettings {
    AcmeSettings {
        directory_url: directory.to_owned(),
        contact_email: "yonetici@example.org".to_owned(),
        accepted_terms: true,
        trusted_root_pem: String::new(),
    }
}

/// One scripted answer.
struct Scripted {
    status: u16,
    body: String,
    location: Option<String>,
}

fn ok(body: impl Into<String>) -> Scripted {
    Scripted {
        status: 200,
        body: body.into(),
        location: None,
    }
}

fn made(body: impl Into<String>, location: &str) -> Scripted {
    Scripted {
        status: 201,
        body: body.into(),
        location: Some(location.to_owned()),
    }
}

/// Everything that happened, in the order it happened.
///
/// The publisher and the transport both write here, so a measurement can say
/// that the answer went up *before* the server was told to come and read it.
/// Two separate lists could only say that both happened.
type Timeline = Arc<Mutex<Vec<String>>>;

/// What the publisher writes into the timeline.
const PUBLISHED: &str = "published";
/// What the publisher writes when it takes the answer away.
const WITHDRAWN: &str = "withdrawn";

/// A server that answers from a script and remembers what it was asked.
struct Fake {
    script: Vec<Scripted>,
    at: usize,
    /// Shared with the publisher.
    timeline: Timeline,
    /// How many times the transport refused to answer at all.
    refusals: usize,
    /// Answers this many calls with a network fault before the script starts.
    refuse_first: usize,
    nonce: u32,
}

impl Fake {
    fn new(script: Vec<Scripted>) -> Self {
        Self {
            script,
            at: 0,
            timeline: Arc::new(Mutex::new(Vec::new())),
            refusals: 0,
            refuse_first: 0,
            nonce: 0,
        }
    }

    /// A transport that never answers.
    fn unreachable() -> Self {
        let mut fake = Self::new(Vec::new());
        fake.refuse_first = usize::MAX;
        fake
    }

    fn note(&self, what: &str) {
        self.timeline
            .lock()
            .expect("nothing else holds it")
            .push(what.to_owned());
    }
}

impl Transport for Fake {
    fn call(&mut self, url: &str, _body: Option<&str>) -> Result<Reply, Failure> {
        self.note(url);

        if self.refusals < self.refuse_first {
            self.refusals += 1;
            return Err(Failure::new(
                Reason::Network,
                format!("{url} is not reachable"),
            ));
        }

        let answer = self.script.get(self.at).unwrap_or_else(|| {
            panic!("nothing scripted for call {} to {url}", self.at + 1);
        });
        self.at += 1;
        self.nonce += 1;

        Ok(Reply {
            answer: ek_ek_tls::Answer::new(
                answer.status,
                answer.body.clone(),
                answer.location.clone(),
            ),
            nonce: Some(format!("nonce-{}", self.nonce)),
        })
    }
}

/// The script of a server that issues the certificate.
fn issuing() -> Vec<Scripted> {
    vec![
        ok(format!(
            r#"{{"newNonce":"{NONCE_URL}","newAccount":"{ACCOUNT_URL}","newOrder":"{ORDER_URL}"}}"#
        )),
        Scripted {
            status: 204,
            body: String::new(),
            location: None,
        },
        made("{}", "https://acme.example.org/account/7"),
        made(
            format!(
                r#"{{"status":"pending","authorizations":["{AUTHZ_URL}"],"finalize":"{FINALIZE_URL}"}}"#
            ),
            PLACED_URL,
        ),
        ok(format!(
            r#"{{"status":"pending","challenges":[{{"type":"http-01","url":"{CHALLENGE_URL}","token":"{TOKEN}"}}]}}"#
        )),
        ok("{}"),
        ok(r#"{"status":"ready"}"#),
        ok(format!(
            r#"{{"status":"valid","certificate":"{CERTIFICATE_URL}"}}"#
        )),
        ok(CHAIN),
    ]
}

/// The same order, read rather than placed, with an answer already up.
///
/// The account is read first either way. After that the driver reads the order
/// the previous node named instead of asking for a new one, so there is no
/// `newOrder` reply in this script and the first read answers with the order
/// itself.
fn resuming() -> Vec<Scripted> {
    vec![
        ok(format!(
            r#"{{"newNonce":"{NONCE_URL}","newAccount":"{ACCOUNT_URL}","newOrder":"{ORDER_URL}"}}"#
        )),
        Scripted {
            status: 204,
            body: String::new(),
            location: None,
        },
        made("{}", "https://acme.example.org/account/7"),
        ok(format!(
            r#"{{"status":"pending","authorizations":["{AUTHZ_URL}"],"finalize":"{FINALIZE_URL}"}}"#
        )),
        ok(format!(
            r#"{{"status":"pending","challenges":[{{"type":"http-01","url":"{CHALLENGE_URL}","token":"{TOKEN}"}}]}}"#
        )),
        ok("{}"),
        ok(r#"{"status":"ready"}"#),
        ok(format!(
            r#"{{"status":"valid","certificate":"{CERTIFICATE_URL}"}}"#
        )),
        ok(CHAIN),
    ]
}

/// What the publisher was told, in order.
type Published = Vec<Publication>;

/// Only the waits between attempts.
///
/// The driver also pauses a second between two reads of an order the server is
/// still deciding on, and counting those as attempt waits would make a healthy
/// order look like a retried one.
fn between_attempts(waits: &[Duration]) -> Vec<Duration> {
    waits
        .iter()
        .copied()
        .filter(|wait| *wait >= FIRST_WAIT)
        .collect()
}

/// Runs an order against a fake server and reports everything observed.
struct Run {
    outcome: Result<ek_ek_tls::Obtained, Failure>,
    published: Published,
    waits: Vec<Duration>,
    /// Every call and every publication, in the order they happened.
    timeline: Vec<String>,
}

impl Run {
    /// Only the calls, for a measurement that does not care about publishing.
    fn asked(&self) -> Vec<&str> {
        self.timeline
            .iter()
            .map(String::as_str)
            .filter(|entry| *entry != PUBLISHED && *entry != WITHDRAWN)
            .collect()
    }
}

fn run_with(transport: Fake, directory: &str) -> Run {
    run_kind(transport, directory, Challenge::Http01)
}

fn run_kind(mut transport: Fake, directory: &str, kind: Challenge) -> Run {
    let key = ek_ek_tls::account_key().expect("an account key");
    let published: Mutex<Published> = Mutex::new(Vec::new());
    let waits: Mutex<Vec<Duration>> = Mutex::new(Vec::new());
    let timeline = Arc::clone(&transport.timeline);

    let outcome = {
        let mut publish = |reached: &Reached| -> Result<(), Failure> {
            let challenges = &reached.publication;
            // Only a change to the path counts. The driver also reports the
            // order URL the moment the server names it, and that record
            // carries no publication: counting it as one would make an order
            // that opened the path once look like one that opened it twice.
            let mut held = published.lock().expect("nothing else holds it");
            // An empty publication before anything went up is not the path
            // closing either: nothing was open.
            if held
                .last()
                .is_none_or(|last| last.entries == challenges.entries)
                && (held.last().is_some() || challenges.is_empty())
            {
                return Ok(());
            }
            held.push(challenges.clone());
            drop(held);
            timeline
                .lock()
                .expect("nothing else holds it")
                .push(if challenges.is_empty() {
                    WITHDRAWN.to_owned()
                } else {
                    PUBLISHED.to_owned()
                });
            Ok(())
        };
        let mut pause = |wait: Duration| {
            waits.lock().expect("nothing else holds it").push(wait);
        };
        obtain_over(
            &settings(directory),
            &key,
            &["www.example.org".to_owned()],
            kind,
            &mut transport,
            &mut publish,
            &mut pause,
        )
    };

    Run {
        outcome,
        published: published.into_inner().expect("nothing else holds it"),
        waits: waits.into_inner().expect("nothing else holds it"),
        timeline: transport
            .timeline
            .lock()
            .expect("nothing else holds it")
            .clone(),
    }
}

#[test]
fn a_completed_order_returns_the_chain_and_a_key_that_belongs_to_it() {
    let run = run_with(Fake::new(issuing()), DIRECTORY);
    let obtained = run.outcome.expect("the order completes");

    assert_eq!(String::from_utf8_lossy(&obtained.chain_pem), CHAIN);
    assert!(String::from_utf8_lossy(&obtained.key_pem).contains("BEGIN PRIVATE KEY"));
    assert!(
        between_attempts(&run.waits).is_empty(),
        "an order that worked first time waited between attempts: {:?}",
        run.waits
    );
}

#[test]
fn the_directory_the_configuration_names_is_the_first_thing_asked() {
    let run = run_with(Fake::new(issuing()), "https://staging.example.org/dir");
    assert!(run.outcome.is_ok());
    assert_eq!(
        run.asked().first().copied(),
        Some("https://staging.example.org/dir"),
        "switching between staging and production is this one address"
    );
}

#[test]
fn the_challenge_is_published_before_the_server_is_asked_to_check_it() {
    let run = run_with(Fake::new(issuing()), DIRECTORY);
    assert!(run.outcome.is_ok());

    // Exactly two changes: the answer goes up, then it comes down.
    assert_eq!(
        run.published.len(),
        2,
        "the path was opened or closed more often than the order needed: {:?}",
        run.published
    );
    let published = run.published[0]
        .entries
        .get(TOKEN)
        .and_then(|values| values.first())
        .expect("the token the server sent is the one published");
    assert!(
        published.starts_with(&format!("{TOKEN}.")) && published.len() > TOKEN.len() + 1,
        "{published} is not the token tied to the account key"
    );
    assert!(
        run.published[1].is_empty(),
        "the path was left open after the order finished"
    );

    // And it went up before the server was told to come and read it. A server
    // that arrives at a path answering 404 marks the name invalid, and no
    // retry undoes that.
    let up = run
        .timeline
        .iter()
        .position(|entry| entry == PUBLISHED)
        .expect("the answer was published");
    let told = run
        .timeline
        .iter()
        .position(|entry| entry == CHALLENGE_URL)
        .expect("the server was told to check");
    assert!(
        up < told,
        "the server was told to check before the answer was live: {:?}",
        run.timeline
    );
    // And the withdrawal came after, not before.
    let down = run
        .timeline
        .iter()
        .position(|entry| entry == WITHDRAWN)
        .expect("the answer was taken away");
    assert!(
        down > told,
        "the answer came down while the server was still checking: {:?}",
        run.timeline
    );
}

#[test]
fn a_failed_order_still_closes_the_challenge_path() {
    let mut script = issuing();
    // The order turns out invalid after the challenge was published.
    script[6] = ok(r#"{"status":"invalid"}"#);
    script.truncate(7);

    let run = run_with(Fake::new(script), DIRECTORY);
    let failure = run.outcome.expect_err("the order fails");
    assert_eq!(failure.reason(), Reason::Challenge);

    assert_eq!(run.published.len(), 2);
    assert!(run.published[0].entries.contains_key(TOKEN));
    assert!(
        run.published[1].is_empty(),
        "a failed order left the path open for anybody to reach"
    );
}

#[test]
fn a_refused_challenge_is_not_tried_again() {
    let mut script = issuing();
    script[6] = ok(r#"{"status":"invalid"}"#);
    script.truncate(7);

    let run = run_with(Fake::new(script), DIRECTORY);
    assert!(run.outcome.is_err());
    assert!(
        between_attempts(&run.waits).is_empty(),
        "the order was retried after the server said the name does not point here: {:?}",
        run.waits
    );
}

#[test]
fn an_unreachable_server_is_tried_five_times_with_growing_waits() {
    let run = run_with(Fake::unreachable(), DIRECTORY);
    let asked = run.asked().len();
    let failure = run.outcome.expect_err("nothing answered");
    assert_eq!(failure.reason(), Reason::TooManyAttempts);

    // One call per attempt, because the first thing every attempt does is read
    // the directory and nothing answered.
    assert_eq!(
        asked, ATTEMPTS as usize,
        "the attempt limit is what keeps a broken installation from spending the account's allowance"
    );

    assert_eq!(
        between_attempts(&run.waits),
        vec![
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(240),
            Duration::from_secs(480),
        ],
        "the waits between attempts are not the ones the policy states"
    );
}

#[test]
fn an_order_that_works_on_the_third_attempt_stops_there() {
    let mut transport = Fake::new(issuing());
    transport.refuse_first = 2;

    let run = run_with(transport, DIRECTORY);
    assert!(run.outcome.is_ok(), "the third attempt should succeed");
    assert_eq!(
        between_attempts(&run.waits).len(),
        2,
        "two waits before the third attempt, and none after it"
    );
}

#[test]
fn the_waits_are_the_policy_and_nothing_else() {
    assert_eq!(wait_before(0), None, "there is no attempt zero");
    assert_eq!(
        wait_before(1),
        Some(Duration::ZERO),
        "the first one runs now"
    );
    assert_eq!(wait_before(2), Some(Duration::from_secs(60)));
    assert_eq!(wait_before(3), Some(Duration::from_secs(120)));
    assert_eq!(wait_before(4), Some(Duration::from_secs(240)));
    assert_eq!(wait_before(5), Some(Duration::from_secs(480)));
    assert_eq!(
        wait_before(ATTEMPTS + 1),
        None,
        "there is no attempt past the limit"
    );
    assert_eq!(
        ek_ek_tls::whole_run(),
        Duration::from_secs(900),
        "five attempts span fifteen minutes"
    );
}

#[test]
fn a_rejected_nonce_costs_one_extra_call_and_not_an_attempt() {
    let mut script = issuing();
    // The server refuses the nonce on the account request, then takes it.
    script.insert(
        2,
        Scripted {
            status: 400,
            body: r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#.to_owned(),
            location: None,
        },
    );

    let run = run_with(Fake::new(script), DIRECTORY);
    assert!(
        run.outcome.is_ok(),
        "a rejected nonce is normal and the request is simply sent again"
    );
    let asked = run.asked();
    assert_eq!(
        asked.len(),
        10,
        "the repeated request should be the only extra call"
    );
    assert_eq!(asked[2], ACCOUNT_URL);
    assert_eq!(asked[3], ACCOUNT_URL, "the same request, sent again");
    assert!(
        between_attempts(&run.waits).is_empty(),
        "a rejected nonce cost an attempt: {:?}",
        run.waits
    );
}

#[test]
fn a_server_that_rejects_every_nonce_stops_rather_than_looping() {
    let mut script = vec![
        ok(format!(
            r#"{{"newNonce":"{NONCE_URL}","newAccount":"{ACCOUNT_URL}","newOrder":"{ORDER_URL}"}}"#
        )),
        Scripted {
            status: 204,
            body: String::new(),
            location: None,
        },
    ];
    for _ in 0..40 {
        script.push(Scripted {
            status: 400,
            body: r#"{"type":"urn:ietf:params:acme:error:badNonce"}"#.to_owned(),
            location: None,
        });
    }

    let run = run_with(Fake::new(script), DIRECTORY);
    let asked = run.asked().len();
    let failure = run.outcome.expect_err("this cannot go on forever");
    assert_eq!(failure.reason(), Reason::TooManyAttempts);
    assert!(
        asked < 40,
        "the client kept sending the same request: {asked} calls"
    );
}

#[test]
fn a_publisher_that_cannot_open_the_path_stops_the_order() {
    let key = ek_ek_tls::account_key().expect("an account key");
    let mut transport = Fake::new(issuing());
    let mut publish = |reached: &Reached| -> Result<(), Failure> {
        let challenges = &reached.publication;
        if challenges.is_empty() {
            Ok(())
        } else {
            Err(Failure::new(
                Reason::Configuration,
                "the challenge file cannot be written".to_owned(),
            ))
        }
    };
    let mut pause = |_: Duration| {};

    let outcome = obtain_over(
        &settings(DIRECTORY),
        &key,
        &["www.example.org".to_owned()],
        Challenge::Http01,
        &mut transport,
        &mut publish,
        &mut pause,
    );

    let failure = outcome.expect_err("an answer nobody can serve is not worth asking about");
    assert_eq!(failure.reason(), Reason::Configuration);
}

/// Every log record written while the tests in this file ran.
fn records() -> &'static Mutex<Vec<String>> {
    static RECORDS: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    RECORDS.get_or_init(|| Mutex::new(Vec::new()))
}

struct Capturing;

impl log::Log for Capturing {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }

    fn log(&self, record: &log::Record<'_>) {
        records()
            .lock()
            .expect("nothing else holds it")
            .push(format!("{}", record.args()));
    }

    fn flush(&self) {}
}

#[test]
fn nothing_secret_reaches_a_log_or_an_error() {
    static CAPTURING: Capturing = Capturing;
    let _ = log::set_logger(&CAPTURING);
    log::set_max_level(log::LevelFilter::Trace);

    let key = ek_ek_tls::account_key().expect("an account key");
    let key_pem = String::from_utf8(ek_ek_tls::account_to_pem(&key).expect("it writes out"))
        .expect("PEM is text");
    let thumbprint = ek_ek_tls::thumbprint(&key).expect("a thumbprint");
    let answer = ek_ek_tls::key_authorization(TOKEN, &thumbprint);

    // A run that goes all the way through, so the records cover the working
    // path as well as the failing one.
    let mut transport = Fake::new(issuing());
    let mut publish = |_: &Reached| Ok(());
    let mut pause = |_: Duration| {};
    let good = obtain_over(
        &settings(DIRECTORY),
        &key,
        &["www.example.org".to_owned()],
        Challenge::Http01,
        &mut transport,
        &mut publish,
        &mut pause,
    );
    assert!(good.is_ok());

    let mut transport = Fake::unreachable();
    let failure = obtain_over(
        &settings(DIRECTORY),
        &key,
        &["www.example.org".to_owned()],
        Challenge::Http01,
        &mut transport,
        &mut publish,
        &mut pause,
    )
    .expect_err("nothing answered");

    let mut written = records().lock().expect("nothing else holds it").join("\n");
    written.push_str(&format!("\n{failure}\n{failure:?}"));

    assert!(
        !written.is_empty(),
        "no record was written, so this measured nothing"
    );
    assert!(
        !written.contains("BEGIN PRIVATE KEY"),
        "a private key reached a log"
    );
    for line in key_pem.lines().filter(|line| line.len() > 20) {
        assert!(
            !written.contains(line),
            "a line of the account key reached a log"
        );
    }
    assert!(
        !written.contains(&answer),
        "the challenge answer reached a log"
    );
    assert!(
        !written.contains(&thumbprint),
        "the account key's fingerprint reached a log"
    );
}

#[test]
fn a_publication_that_failed_halfway_is_still_taken_away() {
    let key = ek_ek_tls::account_key().expect("an account key");
    let mut transport = Fake::new(issuing());
    let seen: Mutex<Published> = Mutex::new(Vec::new());
    let outcome = {
        // A publisher that put the answer somewhere and then failed on the
        // step after, which is what a record written to a zone that has not
        // caught up looks like.
        let mut publish = |reached: &Reached| -> Result<(), Failure> {
            let challenges = &reached.publication;
            seen.lock()
                .expect("nothing else holds it")
                .push(challenges.clone());
            if challenges.is_empty() {
                Ok(())
            } else {
                Err(Failure::new(
                    Reason::Challenge,
                    "the answer was written and never became reachable".to_owned(),
                ))
            }
        };
        let mut pause = |_: Duration| {};
        obtain_over(
            &settings(DIRECTORY),
            &key,
            &["www.example.org".to_owned()],
            Challenge::Http01,
            &mut transport,
            &mut publish,
            &mut pause,
        )
    };

    assert!(outcome.is_err());
    let seen = seen.into_inner().expect("nothing else holds it");
    assert!(
        seen.iter().any(|publication| publication.is_empty()),
        "the publisher was never told to take away what it had already put in place: {seen:?}"
    );
}

#[test]
fn a_taken_over_order_never_reports_an_empty_answer_before_it_publishes_again() {
    // The answer of the node that stopped is already in the state and already
    // being served. If the driver starts from nothing, its first record says
    // "no answer", the state is emptied, and every node stops answering until
    // the same value is put back. The certificate authority checking in that
    // window gets a 404 and refuses the challenge (ADR-0086).
    let key = ek_ek_tls::account_key().expect("an account key");
    let seen: Mutex<Vec<Reached>> = Mutex::new(Vec::new());
    let mut transport = Fake::new(resuming());

    let outcome = {
        let mut record = |reached: &Reached| -> Result<(), Failure> {
            seen.lock()
                .expect("nothing else holds it")
                .push(reached.clone());
            Ok(())
        };
        let mut pause = |_: Duration| {};
        ek_ek_tls::obtain_planned_over(
            &settings(DIRECTORY),
            &key,
            &["www.example.org".to_owned()],
            Challenge::Http01,
            ek_ek_tls::Plan {
                key: None,
                resume: Some(PLACED_URL),
            },
            &mut transport,
            &mut record,
            &mut pause,
        )
    };
    assert!(outcome.is_ok(), "the taken over order completes");

    let seen = seen.into_inner().expect("nothing else holds it");
    let first_answer = seen
        .iter()
        .position(|reached| !reached.publication.is_empty())
        .expect("the driver never published a challenge answer");
    // Nothing at all before the answer. Every record replaces what the state
    // holds, and a record carrying no answer empties it whichever kind it
    // names. A fresh order records the URL first and that is right, because
    // there is nothing to empty; a taken over order has both already in the
    // state, so the first record it may make is the one carrying the answer.
    assert_eq!(
        first_answer, 0,
        "the driver recorded {} thing(s) with no answer before it published \
         one, and each of them empties the answer the stopped node left in \
         place while the certificate authority may be reading it: {seen:?}",
        first_answer
    );

    // The order it was told to take over is the one it worked on. A driver
    // that placed a fresh order would report a different URL, and the record
    // the previous node left would name an order nobody finishes.
    assert_eq!(
        seen[0].order_url.as_deref(),
        Some(PLACED_URL),
        "the first thing recorded is not the order that was taken over"
    );
}

#[test]
fn the_order_url_is_recorded_before_the_challenge_answer_is_published() {
    let key = ek_ek_tls::account_key().expect("an account key");
    let seen: Mutex<Vec<Reached>> = Mutex::new(Vec::new());
    let mut transport = Fake::new(issuing());

    let outcome = {
        let mut record = |reached: &Reached| -> Result<(), Failure> {
            seen.lock()
                .expect("nothing else holds it")
                .push(reached.clone());
            Ok(())
        };
        let mut pause = |_: Duration| {};
        obtain_over(
            &settings(DIRECTORY),
            &key,
            &["www.example.org".to_owned()],
            Challenge::Http01,
            &mut transport,
            &mut record,
            &mut pause,
        )
    };
    assert!(outcome.is_ok(), "the order completes");

    let seen = seen.into_inner().expect("nothing else holds it");
    let first_url = seen
        .iter()
        .position(|reached| reached.order_url.is_some())
        .expect("the driver never reported the order the server named");
    let first_answer = seen
        .iter()
        .position(|reached| !reached.publication.is_empty())
        .expect("the driver never published a challenge answer");

    assert!(
        first_url < first_answer,
        "the challenge answer was recorded before the order it belongs to, \
         so a node that stopped in between would leave an answer for an order \
         nobody can find: {seen:?}"
    );
    assert_eq!(
        seen[first_url].order_url.as_deref(),
        Some(PLACED_URL),
        "the URL recorded is not the one the server named"
    );
    assert!(
        seen[first_url].publication.is_empty(),
        "the order URL and the answer were recorded together, \
         so nothing measures which of the two lands first"
    );
    // And the order stays named to the end, so the record a caller keeps while
    // the order runs never loses the one thing another node needs.
    assert_eq!(
        seen.last().and_then(|reached| reached.order_url.as_deref()),
        Some(PLACED_URL),
        "the driver dropped the order URL while closing the challenge path"
    );
}
