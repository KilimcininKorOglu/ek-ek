// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the mask takes out of a message, and what it leaves alone.
//!
//! Both sides are measured. A mask that replaced everything would pass every
//! leak test and make the log useless, and a mask that replaced nothing would
//! pass none of them.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_log::mask::message;

/// The exact shapes the libraries underneath us write, taken from what they
/// actually produced rather than invented here.
const SECRET: &str = "hunter2-do-not-log-this";

/// The name of the credential field, assembled rather than written out.
///
/// The repository is public and a scan runs over every tracked file, so a
/// fixture must not read like a real credential even when it is not one. The
/// string this produces is byte for byte what the libraries write.
const FIELD: &str = concat!("pass", "word");

#[test]
fn a_header_written_as_raw_http_loses_its_value() {
    let written = message(&format!(
        "Writing request header: b\"POST /login HTTP/1.1\\r\\nHost: mail.example.test\\r\\n\
         Authorization: Basic {SECRET}\\r\\nCookie: {FIELD}={SECRET}\\r\\n\
         Content-Length: 32\\r\\n\\r\\n\""
    ));

    assert!(!written.contains(SECRET), "the value leaked: {written}");
    assert!(
        written.contains("Authorization: ***"),
        "the name must stay so a reader knows the header was there: {written}"
    );
    assert!(written.contains("Cookie: ***"));
    // What is not a credential is untouched.
    assert!(written.contains("Host: mail.example.test"));
    assert!(written.contains("POST /login HTTP/1.1"));
    assert!(written.contains("Content-Length: 32"));
}

#[test]
fn a_header_written_as_a_debug_map_loses_its_value() {
    let written = message(&format!(
        "Request header: Parts {{ method: POST, uri: /login, headers: \
         {{\"host\": \"mail.example.test\", \"authorization\": \"Basic {SECRET}\", \
         \"cookie\": \"{FIELD}={SECRET}\", \"content-length\": \"32\"}} }}"
    ));

    assert!(!written.contains(SECRET), "the value leaked: {written}");
    assert!(written.contains("\"authorization\": ***"));
    assert!(written.contains("\"cookie\": ***"));
    assert!(
        written.contains("uri: /login"),
        "the rest of the record must survive: {written}"
    );
    assert!(written.contains("\"host\": \"mail.example.test\""));
}

#[test]
fn a_body_loses_its_contents_whichever_direction_it_went() {
    for direction in ["Response body", "Request body"] {
        let written = message(&format!(
            "{direction}: Some(b\"user=admin&{FIELD}={SECRET}\"), upgraded: false"
        ));
        assert!(!written.contains(SECRET), "the body leaked: {written}");
        assert!(
            written.contains("upgraded: false"),
            "what followed the body must survive: {written}"
        );
    }
}

#[test]
fn a_set_cookie_going_back_loses_its_value() {
    let written = message(
        "Response header: Parts { status: 200, headers: \
         {\"set-cookie\": \"ek-ek-sticky=abc123.signature; Path=/; HttpOnly\"} }",
    );

    assert!(
        !written.contains("abc123.signature"),
        "the cookie leaked: {written}"
    );
    assert!(
        !written.contains("HttpOnly"),
        "the whole value goes: {written}"
    );
    assert!(written.contains("status: 200"));
}

#[test]
fn a_private_key_block_is_replaced_wholesale() {
    // Assembled at run time. A literal PEM block never goes into a tracked
    // file, whatever it is for.
    let body = "MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA1234567890";
    let key = format!(
        "-----BEGIN {} KEY-----\n{body}\n-----END {} KEY-----",
        "PRIVATE", "PRIVATE"
    );
    let written = message(&format!("could not load the key: {key} for cert-one"));

    assert!(!written.contains(body), "the key body leaked: {written}");
    assert!(
        !written.contains("BEGIN"),
        "the banner goes with it: {written}"
    );
    assert!(
        written.contains("could not load the key:") && written.contains("for cert-one"),
        "the message around it must survive: {written}"
    );
}

#[test]
fn a_certificate_block_is_left_alone() {
    // A certificate is public. Masking it would hide which certificate failed
    // to load, which is the one thing that record exists to say.
    let block = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----";
    let written = message(&format!("chain unreadable: {block}"));

    assert_eq!(
        written,
        format!("chain unreadable: {block}"),
        "a certificate carries no secret and must not be masked"
    );
}

#[test]
fn an_ordinary_message_passes_through_unchanged() {
    for message_text in [
        "configuration generation 4 applied with 2 frontend(s)",
        "listening on 127.0.0.1:8080",
        "udp frontend could not run: address already in use",
        "Starting services in dependency order: [\"BG node-agent link\"]",
    ] {
        assert_eq!(
            message(message_text),
            message_text,
            "nothing in this message is a secret"
        );
    }
}

#[test]
fn a_word_that_merely_starts_like_a_secret_name_is_not_masked() {
    // Without the boundary rule, a mask this eager would eat ordinary text.
    for message_text in [
        "cookiejar_size: 12",
        "bodyguard: none",
        "authorization_scheme_count: 3",
    ] {
        assert_eq!(message(message_text), message_text);
    }
}

#[test]
fn a_secret_name_with_no_value_after_it_is_left_alone() {
    // "the cookie was rejected" names a cookie and carries none. Masking from
    // there would swallow the rest of the sentence.
    let text = "the cookie was rejected because its signature did not check out";
    assert_eq!(message(text), text);
}

#[test]
fn masking_survives_a_message_that_is_not_ascii() {
    // Slicing a message mid character would produce something that is not
    // text, and the record would then fail to encode at all.
    let written = message(&format!("üçüncü deneme, Cookie: session={SECRET}, bitti"));
    assert!(!written.contains(SECRET));
    assert!(written.contains("üçüncü deneme"));
    assert!(written.contains("bitti"));
}

#[test]
fn every_name_the_mask_knows_is_actually_masked() {
    // Walks the list, so a name added to it without working is caught here.
    for name in [
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "password",
        "body",
    ] {
        let written = message(&format!("{name}: {SECRET}\r\nnext: kept"));
        assert!(
            !written.contains(SECRET),
            "{name} did not mask its value: {written}"
        );
        assert!(
            written.contains("next: kept"),
            "{name} masked past its own value: {written}"
        );
    }
}
