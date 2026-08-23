// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Transaction signatures, measured against messages built here.
//!
//! What matters is not that a signature is produced but that a wrong one is
//! caught. An answer nobody signed, one signed with another key, one signed
//! for another request and one signed long ago all have to be refused, or a
//! forged `NOERROR` would tell an order that a record was written when
//! nothing was.
//!
//! Whether the bytes are the ones RFC 8945 asks for is settled elsewhere, by
//! a real name server accepting them (`crates/ek-ek-itest`).

use ek_ek_config::TsigAlgorithm;
use ek_ek_tls::Reason;
use ek_ek_tls::dns::tsig::{self, FUDGE};
use ek_ek_tls::dns::wire::{self, Record};

const ZONE: &str = "ek-ek.test";
const NAME: &str = "_acme-challenge.ek-ek.test";
const KEY: &str = "ek-ek-update";
const SECRET: &[u8] = b"a shared key nobody outside this test has";
const OTHER: &[u8] = b"a different shared key of the same length!";
const NOW: u64 = 1_800_000_000;

fn request(id: u16) -> Vec<u8> {
    let record = Record::add_txt(NAME, "value", 60).expect("an ordinary value");
    wire::update(id, ZONE, &[record]).expect("it builds")
}

/// An answer that mirrors a request, signed the way a name server signs one.
///
/// Written out here rather than borrowed from the code under test, so the
/// layout RFC 8945 asks for is derived twice and the two have to agree.
fn answer(request: &[u8], request_mac: &[u8], secret: &[u8], signed_at: u64) -> Vec<u8> {
    let head = wire::header(request).expect("it has a header");
    let mut body = request.to_vec();
    // The response bit, which is what makes this an answer.
    body[2..4].copy_from_slice(&(head.flags | 0x8000).to_be_bytes());

    let variables = variables(signed_at);
    let mut digested = Vec::new();
    digested.extend_from_slice(
        &u16::try_from(request_mac.len())
            .expect("a signature fits")
            .to_be_bytes(),
    );
    digested.extend_from_slice(request_mac);
    digested.extend_from_slice(&body);
    digested.extend_from_slice(&variables);
    let mac = hmac(secret, &digested);

    let mut data = Vec::new();
    name_bytes("hmac-sha256", &mut data);
    data.extend_from_slice(&signed_at.to_be_bytes()[2..]);
    data.extend_from_slice(&FUDGE.to_be_bytes());
    data.extend_from_slice(
        &u16::try_from(mac.len())
            .expect("a signature fits")
            .to_be_bytes(),
    );
    data.extend_from_slice(&mac);
    data.extend_from_slice(&head.id.to_be_bytes());
    data.extend_from_slice(&0_u16.to_be_bytes());
    data.extend_from_slice(&0_u16.to_be_bytes());

    name_bytes(KEY, &mut body);
    body.extend_from_slice(&250_u16.to_be_bytes());
    body.extend_from_slice(&255_u16.to_be_bytes());
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(
        &u16::try_from(data.len())
            .expect("the record fits")
            .to_be_bytes(),
    );
    body.extend_from_slice(&data);

    let counted = head.counts[3] + 1;
    body[10..12].copy_from_slice(&counted.to_be_bytes());
    body
}

/// The part of the signature record the signature covers.
fn variables(signed_at: u64) -> Vec<u8> {
    let mut out = Vec::new();
    name_bytes(KEY, &mut out);
    out.extend_from_slice(&255_u16.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    name_bytes("hmac-sha256", &mut out);
    out.extend_from_slice(&signed_at.to_be_bytes()[2..]);
    out.extend_from_slice(&FUDGE.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out
}

fn name_bytes(name: &str, out: &mut Vec<u8>) {
    for label in name.split('.') {
        out.push(u8::try_from(label.len()).expect("a label fits"));
        out.extend(label.bytes().map(|byte| byte.to_ascii_lowercase()));
    }
    out.push(0);
}

fn hmac(secret: &[u8], over: &[u8]) -> Vec<u8> {
    let key = openssl::pkey::PKey::hmac(secret).expect("a key");
    let mut signer =
        openssl::sign::Signer::new(openssl::hash::MessageDigest::sha256(), &key).expect("a signer");
    signer.update(over).expect("it digests");
    signer.sign_to_vec().expect("it signs")
}

#[test]
fn signing_appends_a_record_and_counts_it() {
    let message = request(1);
    let before = wire::header(&message).expect("it has a header");

    let signed =
        tsig::sign(&message, KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("it signs");
    let after = wire::header(&signed.message).expect("it has a header");

    assert_eq!(
        after.counts[3],
        before.counts[3] + 1,
        "a signature a name server does not count is one it never looks at"
    );
    assert!(signed.message.len() > message.len());
    assert_eq!(
        signed.mac.len(),
        32,
        "an HMAC-SHA256 signature is 32 bytes and nothing else"
    );
    assert_eq!(
        after.id, before.id,
        "the identity is what ties the answer to the request"
    );
}

#[test]
fn the_algorithm_decides_the_length_of_the_signature() {
    let message = request(1);
    let long = tsig::sign(&message, KEY, TsigAlgorithm::HmacSha512, SECRET, NOW).expect("it signs");
    assert_eq!(long.mac.len(), 64);
}

#[test]
fn two_keys_never_produce_the_same_signature() {
    let message = request(1);
    let mine = tsig::sign(&message, KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("it signs");
    let theirs =
        tsig::sign(&message, KEY, TsigAlgorithm::HmacSha256, OTHER, NOW).expect("it signs");
    assert_ne!(mine.mac, theirs.mac);
}

#[test]
fn the_signature_covers_the_message_so_a_changed_record_changes_it() {
    let one =
        tsig::sign(&request(1), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("it signs");
    let two =
        tsig::sign(&request(2), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("it signs");
    assert_ne!(
        one.mac, two.mac,
        "a signature that does not change with the message signs nothing"
    );
}

#[test]
fn an_answer_signed_with_the_same_key_is_accepted() {
    let message = request(7);
    let signed = tsig::sign(&message, KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let reply = answer(&message, &signed.mac, SECRET, NOW);

    tsig::verify(
        &reply,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect("the name server signed it with the key this update was signed with");
}

#[test]
fn an_answer_signed_with_another_key_is_refused() {
    let message = request(7);
    let signed = tsig::sign(&message, KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let reply = answer(&message, &signed.mac, OTHER, NOW);

    let failure = tsig::verify(
        &reply,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("anybody can send bytes; only the key holder can sign them");
    assert_eq!(failure.reason(), Reason::Crypto);
}

#[test]
fn an_answer_to_another_request_is_refused() {
    let mine = tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let other =
        tsig::sign(&request(8), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    // Signed correctly, but against the signature of a request this is not
    // the answer to. That is a replay.
    let reply = answer(&request(8), &other.mac, SECRET, NOW);

    let failure = tsig::verify(
        &reply,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &mine.mac,
        NOW,
    )
    .expect_err("an answer to another question is not an answer to this one");
    assert_eq!(failure.reason(), Reason::Crypto);
}

#[test]
fn an_unsigned_answer_is_refused() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    // The answer a name server that ignores the key would send: correct in
    // every way except that nothing proves who sent it.
    let head = wire::header(&signed.message).expect("it has a header");
    let mut bare = request(7);
    bare[2..4].copy_from_slice(&(head.flags | 0x8000).to_be_bytes());

    let failure = tsig::verify(
        &bare,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("an unsigned answer proves nothing at all");
    assert_eq!(failure.reason(), Reason::Crypto);
    // Reading the last record as a signature would fail too, with a message
    // about a record that ends too early. What an operator has to know is
    // that the name server did not sign at all, which is a configuration on
    // its side rather than damage on the wire.
    assert!(
        failure.detail().contains("without signing"),
        "the message does not say what actually happened: {}",
        failure.detail()
    );
}

#[test]
fn an_answer_signed_too_long_ago_is_refused() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let old = NOW - u64::from(FUDGE) - 1;
    let reply = answer(&request(7), &signed.mac, SECRET, old);

    let failure = tsig::verify(
        &reply,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("a signature with no time limit can be replayed for ever");
    assert_eq!(failure.reason(), Reason::Crypto);
}

#[test]
fn an_answer_signed_at_the_edge_of_the_window_is_still_accepted() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let edge = NOW - u64::from(FUDGE);
    let reply = answer(&request(7), &signed.mac, SECRET, edge);

    tsig::verify(
        &reply,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect("the window is inclusive, so an ordinary clock difference still works");
}

#[test]
fn an_answer_signed_under_another_key_name_is_refused() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let reply = answer(&request(7), &signed.mac, SECRET, NOW);

    let failure = tsig::verify(
        &reply,
        "another-key",
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("a signature under a name nobody asked about answers nothing");
    assert_eq!(failure.reason(), Reason::Crypto);
    // The signature would not have matched either, so what this rule is worth
    // is the message: an operator reading "signed as X, not as Y" knows which
    // key name to go and change, and "the signature does not match" does not
    // tell them that.
    assert!(
        failure.detail().contains(KEY) && failure.detail().contains("another-key"),
        "the message names neither key: {}",
        failure.detail()
    );
}

#[test]
fn the_key_name_is_matched_without_regard_to_case() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let reply = answer(&request(7), &signed.mac, SECRET, NOW);

    tsig::verify(
        &reply,
        "EK-EK-Update",
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect("DNS names are matched without regard to case, and a name server may answer in any");
}

/// An answer that says the signature was refused, the way a name server does.
///
/// The signature field is empty: a server that could not verify the request
/// cannot sign its refusal either (RFC 8945 section 5.3.2).
fn refusal(request: &[u8], code: u16) -> Vec<u8> {
    let head = wire::header(request).expect("it has a header");
    let mut body = request.to_vec();
    body[2..4].copy_from_slice(&(head.flags | 0x8000).to_be_bytes());

    let mut data = Vec::new();
    name_bytes("hmac-sha256", &mut data);
    data.extend_from_slice(&NOW.to_be_bytes()[2..]);
    data.extend_from_slice(&FUDGE.to_be_bytes());
    data.extend_from_slice(&0_u16.to_be_bytes());
    data.extend_from_slice(&head.id.to_be_bytes());
    data.extend_from_slice(&code.to_be_bytes());
    data.extend_from_slice(&0_u16.to_be_bytes());

    name_bytes(KEY, &mut body);
    body.extend_from_slice(&250_u16.to_be_bytes());
    body.extend_from_slice(&255_u16.to_be_bytes());
    body.extend_from_slice(&0_u32.to_be_bytes());
    body.extend_from_slice(
        &u16::try_from(data.len())
            .expect("the record fits")
            .to_be_bytes(),
    );
    body.extend_from_slice(&data);
    body[10..12].copy_from_slice(&(head.counts[3] + 1).to_be_bytes());
    body
}

#[test]
fn a_name_server_that_holds_another_key_is_a_configuration_fault() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let reply = refusal(&request(7), 16);

    let failure = tsig::verify(
        &reply,
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("the name server said the signature is not one it accepts");
    assert_eq!(
        failure.reason(),
        Reason::Configuration,
        "the key an operator wrote down is what has to change, and no retry changes it"
    );
    assert!(
        !failure.worth_retrying(),
        "sending the same wrong key again only fills the name server's log"
    );
    assert!(
        failure.detail().contains("shared key"),
        "the message does not name what to go and fix: {}",
        failure.detail()
    );
}

#[test]
fn a_name_server_that_knows_no_such_key_says_so_in_its_own_words() {
    let signed =
        tsig::sign(&request(7), KEY, TsigAlgorithm::HmacSha256, SECRET, NOW).expect("signs");
    let named = tsig::verify(
        &refusal(&request(7), 17),
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("the key name is not one it holds");
    assert!(named.detail().contains("no key by this name"));

    let timed = tsig::verify(
        &refusal(&request(7), 18),
        KEY,
        TsigAlgorithm::HmacSha256,
        SECRET,
        &signed.mac,
        NOW,
    )
    .expect_err("the clocks are too far apart");
    assert!(
        timed.detail().contains("time"),
        "a clock difference and a wrong key are not the same thing to fix: {}",
        timed.detail()
    );
}
