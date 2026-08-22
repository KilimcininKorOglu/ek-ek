// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a PROXY header is made of, byte by byte.
//!
//! The receiver of these bytes is somebody else's SMTP server, so the form is
//! not a matter of taste: a field in the wrong place or a length that does not
//! match makes the backend refuse the connection. Every field is therefore
//! measured at its offset rather than through a parser of our own, which would
//! only prove that two pieces of our code agree.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;

use ek_ek_config::ProxyProtocol;
use ek_ek_dataplane::{Header, Status, announce, header, unknown};

/// The twelve bytes every v2 header opens with.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

fn at(text: &str) -> SocketAddr {
    text.parse().expect("a literal address parses")
}

/// The bytes of a header that must exist.
fn bytes(header: Option<Header>) -> Vec<u8> {
    header
        .expect("this format produces a header")
        .bytes()
        .to_vec()
}

#[test]
fn nothing_is_sent_when_the_protocol_is_off() {
    let client = at("192.0.2.10:56324");
    let proxy = at("198.51.100.5:25");

    assert_eq!(
        header(ProxyProtocol::Disabled, client, proxy),
        None,
        "a frontend with the protocol off must put no byte of its own on the connection"
    );
    assert_eq!(unknown(ProxyProtocol::Disabled), None);

    // The other two formats do produce something, so the absence above is the
    // setting rather than the function never producing anything.
    assert!(header(ProxyProtocol::V1, client, proxy).is_some());
    assert!(header(ProxyProtocol::V2, client, proxy).is_some());
}

#[test]
fn the_v1_form_is_one_line_of_text() {
    let written = bytes(header(
        ProxyProtocol::V1,
        at("192.0.2.10:56324"),
        at("198.51.100.5:25"),
    ));
    let line = String::from_utf8(written.clone()).expect("the v1 form is text");

    // Source address, destination address, source port, destination port, in
    // that order and separated by single spaces.
    assert_eq!(line, "PROXY TCP4 192.0.2.10 198.51.100.5 56324 25\r\n");
    assert!(line.ends_with("\r\n"), "the line must end with CRLF");
    assert!(
        written.len() <= 107,
        "a v1 header is never longer than 107 bytes, this one is {}",
        written.len()
    );
    // No part of the binary form leaked into the text one.
    assert!(!written.starts_with(&SIGNATURE));
}

#[test]
fn the_v1_form_carries_an_ipv6_client_in_its_own_family() {
    let line = String::from_utf8(bytes(header(
        ProxyProtocol::V1,
        at("[2001:db8::10]:56324"),
        at("[2001:db8::5]:25"),
    )))
    .expect("the v1 form is text");

    assert_eq!(line, "PROXY TCP6 2001:db8::10 2001:db8::5 56324 25\r\n");
    assert!(
        !line.contains("TCP4"),
        "an IPv6 pair must not be announced as IPv4"
    );
}

#[test]
fn the_v2_form_is_a_binary_record_for_an_ipv4_client() {
    let bytes = bytes(header(
        ProxyProtocol::V2,
        at("192.0.2.10:56324"),
        at("198.51.100.5:25"),
    ));

    assert_eq!(&bytes[..12], &SIGNATURE, "the signature opens the record");
    assert_eq!(bytes[12], 0x21, "version 2, PROXY command");
    assert_eq!(bytes[13], 0x11, "TCP over IPv4");
    assert_eq!(
        u16::from_be_bytes([bytes[14], bytes[15]]),
        12,
        "four bytes each way plus two ports"
    );
    assert_eq!(&bytes[16..20], &[192, 0, 2, 10], "the source address");
    assert_eq!(&bytes[20..24], &[198, 51, 100, 5], "the destination");
    assert_eq!(u16::from_be_bytes([bytes[24], bytes[25]]), 56324);
    assert_eq!(u16::from_be_bytes([bytes[26], bytes[27]]), 25);
    assert_eq!(
        bytes.len(),
        28,
        "the record is the header and its stated length, and nothing more"
    );
    // Text belongs to the other format.
    assert!(!bytes.ends_with(b"\r\n"));
}

#[test]
fn the_v2_form_carries_a_full_ipv6_address() {
    let bytes = bytes(header(
        ProxyProtocol::V2,
        at("[2001:db8::10]:56324"),
        at("[2001:db8::5]:25"),
    ));

    assert_eq!(&bytes[..12], &SIGNATURE);
    assert_eq!(bytes[12], 0x21, "version 2, PROXY command");
    assert_eq!(bytes[13], 0x21, "TCP over IPv6");
    assert_eq!(
        u16::from_be_bytes([bytes[14], bytes[15]]),
        36,
        "sixteen bytes each way plus two ports"
    );

    let source: [u8; 16] = bytes[16..32].try_into().expect("sixteen bytes");
    let destination: [u8; 16] = bytes[32..48].try_into().expect("sixteen bytes");
    assert_eq!(
        std::net::Ipv6Addr::from(source),
        "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap(),
        "the source address arrives whole, not truncated to four bytes"
    );
    assert_eq!(
        std::net::Ipv6Addr::from(destination),
        "2001:db8::5".parse::<std::net::Ipv6Addr>().unwrap()
    );
    assert_eq!(u16::from_be_bytes([bytes[48], bytes[49]]), 56324);
    assert_eq!(u16::from_be_bytes([bytes[50], bytes[51]]), 25);
    assert_eq!(bytes.len(), 52);
}

#[test]
fn the_address_is_the_one_it_was_given() {
    // Two different clients must not produce the same header, which is what
    // would happen if the address were read from anywhere but the argument.
    let proxy = at("198.51.100.5:25");
    let one = bytes(header(ProxyProtocol::V2, at("192.0.2.10:56324"), proxy));
    let other = bytes(header(ProxyProtocol::V2, at("203.0.113.99:41000"), proxy));

    assert_ne!(one, other);
    assert_eq!(&one[16..20], &[192, 0, 2, 10]);
    assert_eq!(&other[16..20], &[203, 0, 113, 99]);
    assert_eq!(u16::from_be_bytes([other[24], other[25]]), 41000);

    // And the same in the text form.
    let one = bytes(header(ProxyProtocol::V1, at("192.0.2.10:56324"), proxy));
    let other = bytes(header(ProxyProtocol::V1, at("203.0.113.99:41000"), proxy));
    assert_ne!(one, other);
    assert!(String::from_utf8(other).unwrap().contains("203.0.113.99 "));
}

#[test]
fn a_pair_spanning_two_families_states_no_address() {
    // Neither format can write one address as IPv4 and the other as IPv6, so
    // rather than picking one and lying, the header says nothing is stated.
    let mixed = header(
        ProxyProtocol::V1,
        at("192.0.2.10:56324"),
        at("[2001:db8::5]:25"),
    )
    .expect("v1 still produces a header");
    assert_eq!(mixed.bytes(), b"PROXY UNKNOWN\r\n");
    assert!(
        !mixed.states_an_address(),
        "a header naming nobody must say so, or nothing counts it"
    );

    let bytes = bytes(header(
        ProxyProtocol::V2,
        at("[2001:db8::10]:56324"),
        at("198.51.100.5:25"),
    ));
    assert_eq!(bytes[12], 0x20, "version 2, LOCAL command");
    assert_eq!(bytes[13], 0x00, "neither family nor protocol stated");
    assert_eq!(u16::from_be_bytes([bytes[14], bytes[15]]), 0);
    assert_eq!(bytes.len(), 16, "nothing follows a zero length");
}

#[test]
fn an_unreadable_socket_still_gets_a_header() {
    // The backend is waiting for one. Sending nothing would leave it reading
    // the client's first bytes as a header and refusing the connection.
    let untold = unknown(ProxyProtocol::V1).expect("v1 produces a header");
    assert_eq!(untold.bytes(), b"PROXY UNKNOWN\r\n");
    assert!(!untold.states_an_address());

    let bytes = bytes(unknown(ProxyProtocol::V2));
    assert_eq!(&bytes[..12], &SIGNATURE);
    assert_eq!(bytes[12], 0x20);
    assert_eq!(bytes.len(), 16);
}

#[test]
fn a_header_that_names_the_client_says_so() {
    // The other side of the flag. Without this, a flag stuck at false would
    // still pass every measurement of the untold case.
    for format in [ProxyProtocol::V1, ProxyProtocol::V2] {
        let named = header(format, at("192.0.2.10:56324"), at("198.51.100.5:25"))
            .expect("this format produces a header");
        assert!(
            named.states_an_address(),
            "a header carrying an address must not be reported as carrying none"
        );
    }
}

#[test]
fn a_header_with_no_address_in_it_is_counted() {
    // The backend is about to decide on the load balancer's address. Nothing
    // else says so, so the count is the only way an operator finds out.
    let status = Status::default();

    let written = announce(ProxyProtocol::V2, None, &status).expect("a header still goes");
    assert_eq!(&written[12..14], &[0x20, 0x00], "the LOCAL form went out");
    assert_eq!(status.proxy_headers_without_an_address(), 1);

    // A pair spanning two families cannot be stated either, and counts too.
    let mixed = Some((at("192.0.2.10:56324"), at("[2001:db8::5]:25")));
    assert_eq!(
        announce(ProxyProtocol::V1, mixed, &status).expect("a header still goes"),
        b"PROXY UNKNOWN\r\n"
    );
    assert_eq!(status.proxy_headers_without_an_address(), 2);

    // A readable pair of one family is not counted, so the number means what
    // it says rather than counting every header.
    let told = Some((at("192.0.2.10:56324"), at("198.51.100.5:25")));
    assert!(announce(ProxyProtocol::V1, told, &status).is_some());
    assert_eq!(status.proxy_headers_without_an_address(), 2);

    // Nor is a frontend with the protocol off, which sends nothing at all.
    assert_eq!(announce(ProxyProtocol::Disabled, None, &status), None);
    assert_eq!(status.proxy_headers_without_an_address(), 2);

    // The count reaches the agent, or an operator never sees it.
    assert_eq!(status.counters().proxy_headers_without_an_address, 2);
}
