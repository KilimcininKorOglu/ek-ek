// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

//! The DNS message format, measured against bytes rather than a name server.
//!
//! Every rule here is one a hand written encoder can get wrong quietly: a
//! label one byte too long, a name that overflows, a compression pointer that
//! leads back to itself, a TXT value split across strings. A name server
//! would answer a malformed message with a code and no explanation, so these
//! are measured where the bytes are.

use ek_ek_tls::Reason;
use ek_ek_tls::dns::wire::{
    self, CLASS_ANY, CLASS_IN, Case, OPCODE_UPDATE, Record, TYPE_SOA, TYPE_TXT,
};

const ZONE: &str = "ek-ek.test";
const NAME: &str = "_acme-challenge.ek-ek.test";
const VALUE: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";

fn encoded(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    wire::write_name(name, Case::AsGiven, &mut out).expect("an ordinary name encodes");
    out
}

#[test]
fn a_name_becomes_a_length_byte_before_every_label() {
    assert_eq!(encoded("a.bc"), vec![1, b'a', 2, b'b', b'c', 0]);
}

#[test]
fn a_trailing_dot_means_the_same_name() {
    assert_eq!(encoded("ek-ek.test."), encoded("ek-ek.test"));
}

#[test]
fn the_root_is_a_single_zero() {
    assert_eq!(encoded(""), vec![0]);
}

#[test]
fn a_canonical_name_is_lowercased_and_an_as_given_one_is_not() {
    let mut canonical = Vec::new();
    wire::write_name("EK-EK.Test", Case::Canonical, &mut canonical).expect("it encodes");
    assert_eq!(canonical, encoded("ek-ek.test"));

    let mut given = Vec::new();
    wire::write_name("EK-EK.Test", Case::AsGiven, &mut given).expect("it encodes");
    assert_ne!(
        given, canonical,
        "a signature is computed over the canonical form, so the two cannot be the same function"
    );
}

#[test]
fn a_label_longer_than_the_protocol_allows_is_refused() {
    let long = "x".repeat(64);
    let mut out = Vec::new();
    let failure = wire::write_name(&long, Case::AsGiven, &mut out)
        .expect_err("a label of 64 bytes has no length byte that can carry it");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn a_label_of_exactly_the_limit_still_encodes() {
    let long = "x".repeat(63);
    let mut out = Vec::new();
    wire::write_name(&long, Case::AsGiven, &mut out).expect("63 is the limit, not past it");
    assert_eq!(out.len(), 65);
}

#[test]
fn a_name_longer_than_the_protocol_allows_is_refused() {
    let name = vec!["x".repeat(60); 5].join(".");
    let mut out = Vec::new();
    let failure = wire::write_name(&name, Case::AsGiven, &mut out)
        .expect_err("305 bytes does not fit a name");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn an_empty_label_is_refused() {
    let mut out = Vec::new();
    let failure = wire::write_name("a..b", Case::AsGiven, &mut out)
        .expect_err("an empty label would encode as the end of the name");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn a_name_reads_back_as_what_was_written() {
    let bytes = encoded(NAME);
    let (read, after) = wire::read_name(&bytes, 0).expect("it reads back");
    assert_eq!(read, NAME);
    assert_eq!(after, bytes.len());
}

#[test]
fn a_compression_pointer_is_followed_and_reading_continues_past_it() {
    // "test" at offset 0, then a name that ends with a pointer to it.
    let mut bytes = vec![4, b't', b'e', b's', b't', 0];
    let target = 0_u16;
    bytes.extend_from_slice(b"\x05ek-ek");
    bytes.extend_from_slice(&(0xC000 | target).to_be_bytes());
    bytes.push(0xFF);

    let (read, after) = wire::read_name(&bytes, 6).expect("a pointer is followed");
    assert_eq!(read, "ek-ek.test");
    assert_eq!(
        bytes[after], 0xFF,
        "reading continues after the pointer, not after what it led to"
    );
}

#[test]
fn a_compression_pointer_that_leads_in_a_circle_ends_instead_of_looping() {
    // A pointer at offset 0 that points at offset 0.
    let bytes = vec![0xC0, 0x00];
    let failure = wire::read_name(&bytes, 0)
        .expect_err("a name server that answers this would hang a reader that trusts it");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn a_name_that_runs_off_the_end_is_refused() {
    let bytes = vec![4, b't', b'e'];
    let failure = wire::read_name(&bytes, 0).expect_err("the label claims more than there is");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn an_update_names_its_zone_and_counts_its_changes() {
    let record = Record::add_txt(NAME, VALUE, 60).expect("an ordinary value");
    let message = wire::update(0x1234, ZONE, std::slice::from_ref(&record)).expect("it builds");

    let head = wire::header(&message).expect("it has a header");
    assert_eq!(head.id, 0x1234);
    assert_eq!(
        head.flags >> 11 & 0x0F,
        u16::from(OPCODE_UPDATE),
        "a message that is not an update is a query, and a query writes nothing"
    );
    assert!(!head.is_response());
    assert_eq!(head.counts, [1, 0, 1, 0]);

    // The zone section is a question for the start of authority.
    let (zone, after) = wire::read_name(&message, 12).expect("the zone is named");
    assert_eq!(zone, ZONE);
    assert_eq!(
        u16::from_be_bytes([message[after], message[after + 1]]),
        TYPE_SOA
    );
    assert_eq!(
        u16::from_be_bytes([message[after + 2], message[after + 3]]),
        CLASS_IN
    );
}

#[test]
fn deleting_a_set_carries_the_class_that_means_delete_and_no_data() {
    let record = Record::delete_txt_set(NAME);
    assert_eq!(record.class, CLASS_ANY);
    assert_eq!(record.kind, TYPE_TXT);
    assert_eq!(record.ttl, 0);
    assert!(
        record.data.is_empty(),
        "a deletion that carries data deletes one record, not the set"
    );
}

#[test]
fn adding_a_record_carries_the_internet_class_and_the_value() {
    let record = Record::add_txt(NAME, VALUE, 60).expect("an ordinary value");
    assert_eq!(record.class, CLASS_IN);
    assert_eq!(record.ttl, 60);
    assert_eq!(record.data[0], u8::try_from(VALUE.len()).expect("it fits"));
    assert_eq!(&record.data[1..], VALUE.as_bytes());
}

#[test]
fn a_value_longer_than_one_string_is_refused() {
    let long = "x".repeat(256);
    let failure =
        wire::txt_data(&long).expect_err("256 bytes needs two strings and a rule for joining them");
    assert_eq!(failure.reason(), Reason::Protocol);
}

#[test]
fn a_text_answer_is_read_back_out_of_the_answer_section() {
    let answer = txt_answer(&[VALUE, "second"]);
    let read = wire::txt_answers(&answer).expect("it reads");
    assert_eq!(read, vec![VALUE.to_owned(), "second".to_owned()]);
}

#[test]
fn a_record_of_another_type_beside_the_answer_is_skipped() {
    let mut answer = txt_answer(&[VALUE]);
    // One more record, of a type nothing here reads.
    push_record(&mut answer, NAME, 5, b"\x03abc\0");
    answer[7] = 2;

    let read = wire::txt_answers(&answer).expect("it reads");
    assert_eq!(
        read,
        vec![VALUE.to_owned()],
        "a chain alongside the answer is not an answer"
    );
}

#[test]
fn a_value_split_across_strings_reads_back_joined() {
    let mut answer = header_bytes(1, 1);
    push_question(&mut answer, NAME);
    push_record(&mut answer, NAME, TYPE_TXT, b"\x03one\x03two");

    let read = wire::txt_answers(&answer).expect("it reads");
    assert_eq!(read, vec!["onetwo".to_owned()]);
}

#[test]
fn an_answer_that_ends_inside_a_record_is_refused() {
    let mut answer = txt_answer(&[VALUE]);
    answer.truncate(answer.len() - 5);
    let failure = wire::txt_answers(&answer).expect_err("a short answer is not a shorter answer");
    assert_eq!(failure.reason(), Reason::Protocol);
}

fn header_bytes(questions: u16, answers: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&0x1234_u16.to_be_bytes());
    out.extend_from_slice(&0x8180_u16.to_be_bytes());
    out.extend_from_slice(&questions.to_be_bytes());
    out.extend_from_slice(&answers.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out
}

fn push_question(out: &mut Vec<u8>, name: &str) {
    wire::write_name(name, Case::AsGiven, out).expect("it encodes");
    out.extend_from_slice(&TYPE_TXT.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
}

fn push_record(out: &mut Vec<u8>, name: &str, kind: u16, data: &[u8]) {
    wire::write_name(name, Case::AsGiven, out).expect("it encodes");
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    out.extend_from_slice(&60_u32.to_be_bytes());
    out.extend_from_slice(&u16::try_from(data.len()).expect("it fits").to_be_bytes());
    out.extend_from_slice(data);
}

fn txt_answer(values: &[&str]) -> Vec<u8> {
    let mut out = header_bytes(1, u16::try_from(values.len()).expect("it fits"));
    push_question(&mut out, NAME);
    for value in values {
        let data = wire::txt_data(value).expect("an ordinary value");
        push_record(&mut out, NAME, TYPE_TXT, &data);
    }
    out
}
