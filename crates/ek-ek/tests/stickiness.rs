// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session stickiness, measured over a real socket.
//!
//! What matters here is what a client sees: which member answers, what the
//! `Set-Cookie` line says, and what happens when the cookie names a member
//! that is gone or out of service. The digest arithmetic itself is measured
//! in `ek-ek-dataplane`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use common::{
    Document, Member, Running, ask_once, free_port, plain_request, request_with_cookie,
    request_with_cookie_line,
};

/// The cookie every test here uses, unless it is measuring the name itself.
const COOKIE: &str = "EKEK";

/// Sends `count` requests with the same cookie and returns which members
/// answered.
async fn answered_with(port: u16, cookie: &str, value: &str, count: usize) -> Vec<String> {
    let mut seen = Vec::new();
    for _ in 0..count {
        let answer = ask_once(port, &request_with_cookie(cookie, value))
            .await
            .expect("a request must be answered");
        assert_eq!(answer.status, 200, "a sticky request was not served");
        seen.push(answer.member());
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_first_request_is_answered_with_a_signed_cookie() {
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("the first request must be answered");

    assert_eq!(answer.status, 200);
    let line = answer
        .set_cookie(COOKIE)
        .expect("the answer must carry the stickiness cookie");
    let value = answer
        .cookie_value(COOKIE)
        .expect("the cookie must have a value");
    assert!(!value.is_empty(), "the cookie was set to nothing: {line}");
    // A digest, not a member name, and not an address.
    assert!(
        value.chars().all(|character| character.is_ascii_hexdigit()),
        "the cookie value is not a digest: {value}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_cookie_comes_back_to_the_same_member() {
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let first = ask_once(running.port, &plain_request())
        .await
        .expect("the first request must be answered");
    let pinned = first.member();
    let value = first
        .cookie_value(COOKIE)
        .expect("the first answer must set the cookie");

    let seen = answered_with(running.port, COOKIE, &value, 20).await;

    assert!(
        seen.iter().all(|member| member == &pinned),
        "a pinned client was spread over {seen:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_stickiness_no_cookie_is_ever_set() {
    // The other side of the rule: the header appears only because stickiness
    // asked for it, never as a side effect of proxying.
    //
    // The key is configured even though nothing signs with it. Leaving it out
    // would let this pass for the wrong reason: no cookie because there is no
    // key, rather than no cookie because nobody asked for one.
    let one = Member::start("one").await;
    let port = free_port();
    let document =
        Document::new(port, vec![one.entry(1, "enabled")]).stickiness_key(common::STICKINESS_KEY);
    let running = Running::start(&document).await;

    for _ in 0..5 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        assert_eq!(answer.status, 200);
        assert!(
            answer.set_cookies().is_empty(),
            "a pool with stickiness off set {:?}",
            answer.set_cookies()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_client_that_already_holds_a_valid_cookie_is_not_sent_a_new_one() {
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let value = ask_once(running.port, &plain_request())
        .await
        .expect("the first request must be answered")
        .cookie_value(COOKIE)
        .expect("the first answer must set the cookie");

    let answer = ask_once(running.port, &request_with_cookie(COOKIE, &value))
        .await
        .expect("the second request must be answered");

    assert!(
        answer.set_cookie(COOKIE).is_none(),
        "a cookie that already works was written again: {:?}",
        answer.set_cookies()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cookie_carries_http_only_and_a_path() {
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, "strict");
    let running = Running::start(&document).await;

    let line = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered")
        .set_cookie(COOKIE)
        .expect("the answer must carry the cookie");

    assert!(
        line.contains("HttpOnly"),
        "the cookie is readable from script: {line}"
    );
    assert!(line.contains("Path=/"), "the cookie has no path: {line}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_same_site_value_is_the_one_configured() {
    let one = Member::start("one").await;

    for policy in ["strict", "lax"] {
        let port = free_port();
        let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, policy);
        let running = Running::start(&document).await;

        let line = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered")
            .set_cookie(COOKIE)
            .expect("the answer must carry the cookie");

        let wanted = match policy {
            "strict" => "SameSite=Strict",
            _ => "SameSite=Lax",
        };
        assert!(
            line.contains(wanted),
            "configured {policy} but the cookie says: {line}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_site_none_is_written_with_secure_because_nothing_stores_it_otherwise() {
    // TLS termination is M4, so this frontend is plaintext. `SameSite=None`
    // without `Secure` is refused by every current browser, which would make
    // the cookie silently never come back.
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, "none");
    let running = Running::start(&document).await;

    let line = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered")
        .set_cookie(COOKIE)
        .expect("the answer must carry the cookie");

    assert!(line.contains("SameSite=None"), "{line}");
    assert!(
        line.contains("Secure"),
        "SameSite=None was written without Secure: {line}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cookie_whose_signature_is_broken_is_ignored_and_the_request_is_distributed() {
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let value = ask_once(running.port, &plain_request())
        .await
        .expect("the first request must be answered")
        .cookie_value(COOKIE)
        .expect("the first answer must set the cookie");

    // One digit changed. Everything else about the cookie is what the proxy
    // itself wrote.
    let mut broken = value.clone();
    let last = broken.pop().unwrap_or('0');
    broken.push(if last == '0' { '1' } else { '0' });
    assert_ne!(broken, value, "the value was not actually changed");

    let answer = ask_once(running.port, &request_with_cookie(COOKIE, &broken))
        .await
        .expect("a request with a broken cookie must still be answered");

    assert_eq!(answer.status, 200, "a broken cookie was not ignored");
    assert!(
        answer.set_cookie(COOKIE).is_some(),
        "a broken cookie was not replaced"
    );
    assert_ne!(
        answer.cookie_value(COOKIE).unwrap_or_default(),
        broken,
        "the broken value was handed back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cookie_naming_nobody_is_ignored_and_the_request_is_distributed() {
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let answer = ask_once(
        running.port,
        &request_with_cookie(COOKIE, "ffffffffffffffffffffffffffffffff"),
    )
    .await
    .expect("a request with an unknown cookie must be answered");

    assert_eq!(answer.status, 200);
    assert_eq!(answer.member(), "one");
    assert!(
        answer.set_cookie(COOKIE).is_some(),
        "a cookie naming nobody was not replaced"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cookie_signed_with_another_key_names_nobody() {
    // The same pool and the same member, under a different key. If the value
    // were anything but a keyed digest, this would still match.
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let members = vec![one.entry(1, "enabled"), two.entry(1, "enabled")];

    let first = free_port();
    let running = Running::start(
        &Document::new(first, members.clone())
            .sticky(COOKIE, "lax")
            .stickiness_key("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    )
    .await;
    let foreign = ask_once(running.port, &plain_request())
        .await
        .expect("the first request must be answered")
        .cookie_value(COOKIE)
        .expect("the answer must set the cookie");
    drop(running);

    let second = free_port();
    let running = Running::start(&Document::new(second, members).sticky(COOKIE, "lax")).await;
    let answer = ask_once(running.port, &request_with_cookie(COOKIE, &foreign))
        .await
        .expect("a request must be answered");

    assert_eq!(answer.status, 200);
    assert!(
        answer.set_cookie(COOKIE).is_some(),
        "a cookie from another key was accepted"
    );
    assert_ne!(
        answer.cookie_value(COOKIE).unwrap_or_default(),
        foreign,
        "the foreign value was handed back"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cookie_pointing_at_an_unhealthy_member_is_moved_and_replaced() {
    let staying = Member::start("staying").await;
    let failing = Member::start("failing").await;
    let port = free_port();
    let document = Document::new(
        port,
        vec![staying.entry(1, "enabled"), failing.entry(1, "enabled")],
    )
    .sticky(COOKIE, "lax")
    .http_health_check("/healthz", 200, 200);
    let running = Running::start(&document).await;

    // Get a cookie pinned to the member that is about to go down.
    let mut pinned = None;
    for _ in 0..20 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        if answer.member() == "failing" {
            pinned = answer.cookie_value(COOKIE);
            break;
        }
    }
    let pinned = pinned.expect("a cookie pinned to the failing member must be obtained");

    failing.stop_answering();
    running
        .agent
        .wait_for_health("failing", false)
        .await
        .expect("the member must be reported unhealthy");
    failing.reset();

    let answer = ask_once(running.port, &request_with_cookie(COOKIE, &pinned))
        .await
        .expect("a pinned client must still be answered");

    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.member(),
        "staying",
        "a pinned client was sent to a member marked unhealthy"
    );
    let replacement = answer
        .cookie_value(COOKIE)
        .expect("the client must be given a cookie for its new member");
    assert_ne!(replacement, pinned, "the old cookie was handed back");
    assert_eq!(failing.hits(), 0, "the unhealthy member answered a request");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_cookie_pointing_at_a_removed_member_is_moved_and_replaced() {
    let staying = Member::start("staying").await;
    let leaving = Member::start("leaving").await;
    let port = free_port();
    let both = vec![staying.entry(1, "enabled"), leaving.entry(1, "enabled")];
    let running = Running::start(&Document::new(port, both).sticky(COOKIE, "lax")).await;

    let mut pinned = None;
    for _ in 0..20 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        if answer.member() == "leaving" {
            pinned = answer.cookie_value(COOKIE);
            break;
        }
    }
    let pinned = pinned.expect("a cookie pinned to the member about to leave must be obtained");

    // The member is taken out of the configuration entirely.
    let smaller = Document::new(port, vec![staying.entry(1, "enabled")]).sticky(COOKIE, "lax");
    running.agent.push(&smaller.delivery(2));
    running
        .agent
        .wait_for_counter("configs_applied", 2)
        .await
        .expect("the smaller configuration must apply");
    leaving.reset();

    let answer = ask_once(running.port, &request_with_cookie(COOKIE, &pinned))
        .await
        .expect("a pinned client must still be answered");

    assert_eq!(answer.status, 200);
    assert_eq!(answer.member(), "staying");
    assert_ne!(
        answer.cookie_value(COOKIE).unwrap_or_default(),
        pinned,
        "a cookie naming a removed member was left in place"
    );
    assert_eq!(leaving.hits(), 0, "a removed member answered a request");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cookie_is_set_under_the_configured_name() {
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky("mysession", "lax");
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered");

    assert!(
        answer.set_cookie("mysession").is_some(),
        "the cookie was not set under the configured name: {:?}",
        answer.set_cookies()
    );
    assert!(
        answer.set_cookie(COOKIE).is_none(),
        "a cookie was set under a name nobody configured"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_applications_own_cookies_are_kept() {
    let one = Member::setting_cookie("one", "app_session=abc; Path=/").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let answer = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered");

    assert!(
        answer.set_cookie("app_session").is_some(),
        "the application's own cookie was dropped: {:?}",
        answer.set_cookies()
    );
    assert!(
        answer.set_cookie(COOKIE).is_some(),
        "the stickiness cookie was not added: {:?}",
        answer.set_cookies()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cookie_is_found_among_the_applications_own() {
    // A browser sends every cookie for the host on one line. Reading only the
    // first pair would break stickiness for any application that sets a
    // cookie of its own.
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let first = ask_once(running.port, &plain_request())
        .await
        .expect("the first request must be answered");
    let pinned = first.member();
    let value = first
        .cookie_value(COOKIE)
        .expect("the first answer must set the cookie");

    let line = format!("theme=dark; {COOKIE}={value}; lang=tr");
    for _ in 0..10 {
        let answer = ask_once(running.port, &request_with_cookie_line(&line))
            .await
            .expect("a request must be answered");
        assert_eq!(
            answer.member(),
            pinned,
            "the cookie was not found among the application's own"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stickiness_survives_a_member_changing_address() {
    // The digest is over the member's identity, so renumbering a server keeps
    // its clients rather than scattering them.
    let one = Member::start("one").await;
    let two = Member::start("two").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled"), two.entry(1, "enabled")])
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let mut pinned = None;
    for _ in 0..20 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        if answer.member() == "two" {
            pinned = answer.cookie_value(COOKIE);
            break;
        }
    }
    let pinned = pinned.expect("a cookie pinned to the second member must be obtained");

    // Same identity, a port it is also listening on. The address changed;
    // the identity did not.
    let moved = Member::start("two").await;
    let renumbered = Document::new(
        port,
        vec![one.entry(1, "enabled"), moved.entry(1, "enabled")],
    )
    .sticky(COOKIE, "lax");
    running.agent.push(&renumbered.delivery(2));
    running
        .agent
        .wait_for_counter("configs_applied", 2)
        .await
        .expect("the renumbered configuration must apply");

    let answer = ask_once(running.port, &request_with_cookie(COOKIE, &pinned))
        .await
        .expect("a pinned client must be answered");

    assert_eq!(answer.status, 200);
    assert_eq!(
        answer.member(),
        "two",
        "a renumbered member lost its pinned clients"
    );
    assert!(
        answer.set_cookie(COOKIE).is_none(),
        "the cookie was replaced although it still names a member that exists"
    );
    assert!(moved.hits() > 0, "the renumbered member took no traffic");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_frontend_that_terminates_tls_marks_the_cookie_secure() {
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")])
        .terminating_tls()
        .sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let line = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered")
        .set_cookie(COOKIE)
        .expect("the answer must carry the cookie");

    assert!(
        line.contains("Secure"),
        "a cookie for a TLS frontend was not marked Secure: {line}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_plaintext_frontend_does_not_mark_the_cookie_secure() {
    // The other side of the rule. Marking a cookie `Secure` on a plaintext
    // listener means the browser never sends it back, so stickiness would be
    // configured and silently do nothing.
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let line = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered")
        .set_cookie(COOKIE)
        .expect("the answer must carry the cookie");

    assert!(
        !line.contains("Secure"),
        "a plaintext frontend marked its cookie Secure: {line}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_cookie_outlives_no_browser_session() {
    // A stickiness cookie names a member. Giving it an expiry means a client
    // can come back days later holding a cookie for a server that is gone,
    // which is exactly the case the pool then has to undo (ADR-0065).
    let one = Member::start("one").await;
    let port = free_port();
    let document = Document::new(port, vec![one.entry(1, "enabled")]).sticky(COOKIE, "lax");
    let running = Running::start(&document).await;

    let line = ask_once(running.port, &plain_request())
        .await
        .expect("a request must be answered")
        .set_cookie(COOKIE)
        .expect("the answer must carry the cookie");

    assert!(
        !line.to_ascii_lowercase().contains("max-age"),
        "the session cookie was given a lifetime: {line}"
    );
    assert!(
        !line.to_ascii_lowercase().contains("expires"),
        "the session cookie was given an expiry: {line}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn only_the_clients_of_the_member_that_went_out_are_moved() {
    // The count is what matters: a member leaving must move its own clients
    // and nobody else's.
    let staying = Member::start("staying").await;
    let leaving = Member::start("leaving").await;
    let third = Member::start("third").await;
    let port = free_port();
    let all = vec![
        staying.entry(1, "enabled"),
        leaving.entry(1, "enabled"),
        third.entry(1, "enabled"),
    ];
    let running = Running::start(&Document::new(port, all).sticky(COOKIE, "lax")).await;

    // Collect one cookie per member by asking until each has answered.
    let mut pinned: Vec<(String, String)> = Vec::new();
    for _ in 0..60 {
        let answer = ask_once(running.port, &plain_request())
            .await
            .expect("a request must be answered");
        let member = answer.member();
        if let Some(value) = answer.cookie_value(COOKIE)
            && !pinned.iter().any(|(name, _)| name == &member)
        {
            pinned.push((member, value));
        }
        if pinned.len() == 3 {
            break;
        }
    }
    assert_eq!(pinned.len(), 3, "not every member was pinned: {pinned:?}");

    let smaller = Document::new(
        port,
        vec![staying.entry(1, "enabled"), third.entry(1, "enabled")],
    )
    .sticky(COOKIE, "lax");
    running.agent.push(&smaller.delivery(2));
    running
        .agent
        .wait_for_counter("configs_applied", 2)
        .await
        .expect("the smaller configuration must apply");

    let mut kept = 0;
    let mut moved = 0;
    for (member, value) in &pinned {
        let answer = ask_once(running.port, &request_with_cookie(COOKIE, value))
            .await
            .expect("a pinned client must be answered");
        assert_eq!(answer.status, 200);
        if member == "leaving" {
            assert_ne!(answer.member(), "leaving", "a removed member answered");
            moved += 1;
        } else {
            assert_eq!(
                &answer.member(),
                member,
                "a client of a member that never left was moved"
            );
            assert!(
                answer.set_cookie(COOKIE).is_none(),
                "a cookie that still names a member in the pool was replaced"
            );
            kept += 1;
        }
    }

    assert_eq!(moved, 1, "the removed member's client was not moved");
    assert_eq!(kept, 2, "the other clients did not stay where they were");
}
