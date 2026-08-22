// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What an address change looks like on the netlink socket.
//!
//! Every field is read out of the bytes by index, against the layout in
//! `linux/netlink.h` and `linux/if_addr.h`. Handing the bytes back to our own
//! parser and checking they match would only show that two halves of the same
//! code agree, and the kernel is the reader that matters. The kernel reads
//! them for real in `ek-ek-itest`, where a refused message is the measurement.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ek_ek_vrrp::address::{
    Address, Answer, Change, DELETE_ADDRESS, ERROR, Family, GET_ADDRESS, HEADER, NEW_ADDRESS,
    addresses, answer, change, list, messages,
};

/// The address these measurements move.
const VIRTUAL: Ipv4Addr = Ipv4Addr::new(172, 28, 0, 100);
/// The interface it goes on.
const INTERFACE: u32 = 2;

/// The address as this product asks for it.
fn address() -> Address {
    Address {
        address: IpAddr::V4(VIRTUAL),
        prefix_length: 24,
        interface: INTERFACE,
    }
}

/// A number the kernel writes in the host's own order.
fn short(bytes: &[u8], at: usize) -> u16 {
    u16::from_ne_bytes([bytes[at], bytes[at + 1]])
}

/// A wider number, the same way.
fn long(bytes: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[test]
fn every_field_lands_where_the_kernel_reads_it() {
    let bytes = change(&address(), Change::Add, 7);

    // Sixteen of netlink header, eight of address message, and two
    // attributes of four plus four bytes each.
    assert_eq!(bytes.len(), 16 + 8 + 8 + 8);
    assert_eq!(long(&bytes, 0) as usize, bytes.len(), "the length field");
    assert_eq!(short(&bytes, 4), NEW_ADDRESS, "adding an address");
    assert_eq!(long(&bytes, 8), 7, "the sequence number comes back");
    assert_eq!(
        long(&bytes, 12),
        0,
        "zero lets the kernel fill in the port of an unbound socket"
    );

    assert_eq!(bytes[16], 2, "AF_INET");
    assert_eq!(bytes[17], 24, "the prefix length");
    assert_eq!(bytes[19], 0, "RT_SCOPE_UNIVERSE");
    assert_eq!(long(&bytes, 20), INTERFACE, "which interface");
}

#[test]
fn the_flags_ask_to_create_to_replace_and_to_answer() {
    // Every one of them matters. Without the acknowledgement the kernel says
    // nothing and a refusal is invisible. Without replace, putting an address
    // on an interface that already carries it answers EEXIST, and a node
    // retaking the role after a partial failure would stand down over a state
    // that is already the one it asked for.
    let adding = change(&address(), Change::Add, 1);
    let flags = short(&adding, 6);

    assert_eq!(flags & 0x0001, 0x0001, "NLM_F_REQUEST");
    assert_eq!(flags & 0x0004, 0x0004, "NLM_F_ACK");
    assert_eq!(flags & 0x0400, 0x0400, "NLM_F_CREATE");
    assert_eq!(flags & 0x0100, 0x0100, "NLM_F_REPLACE");
    assert_eq!(flags & 0x0200, 0, "NLM_F_EXCL is not asked for");

    // Removing asks for neither, because there is nothing to create.
    let removing = change(&address(), Change::Remove, 1);
    let flags = short(&removing, 6);
    assert_eq!(short(&removing, 4), DELETE_ADDRESS);
    assert_eq!(flags & 0x0001, 0x0001, "NLM_F_REQUEST");
    assert_eq!(flags & 0x0004, 0x0004, "NLM_F_ACK");
    assert_eq!(flags & 0x0400, 0, "nothing is created by a removal");
}

#[test]
fn both_address_attributes_are_sent() {
    // The kernel refuses the message when either one is missing, and the
    // refusal arrives in the answer rather than from the write (T-010).
    let bytes = change(&address(), Change::Add, 1);
    let attributes = &bytes[24..];

    assert_eq!(
        short(attributes, 0),
        8,
        "four of header and four of address"
    );
    assert_eq!(short(attributes, 2), 2, "IFA_LOCAL");
    assert_eq!(&attributes[4..8], &VIRTUAL.octets());

    assert_eq!(short(attributes, 8), 8);
    assert_eq!(short(attributes, 10), 1, "IFA_ADDRESS");
    assert_eq!(&attributes[12..16], &VIRTUAL.octets());
}

#[test]
fn an_ipv6_address_carries_its_own_family_and_width() {
    let six = Address {
        address: IpAddr::V6(Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100)),
        prefix_length: 64,
        interface: INTERFACE,
    };

    let bytes = change(&six, Change::Add, 1);

    assert_eq!(bytes[16], 10, "AF_INET6");
    assert_eq!(bytes[17], 64);
    // Sixteen byte addresses make each attribute twenty bytes rather than
    // eight, so the whole message grows by twenty four.
    assert_eq!(bytes.len(), 16 + 8 + 20 + 20);
    assert_eq!(short(&bytes, 24), 20, "IFA_LOCAL is four plus sixteen");
    assert_eq!(
        &bytes[28..44],
        &Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100).octets()
    );
}

#[test]
fn a_listing_asks_for_every_address_of_one_family() {
    let bytes = list(Family::V4, 3);

    assert_eq!(bytes.len(), 24, "a header and an address message, no more");
    assert_eq!(long(&bytes, 0) as usize, bytes.len());
    assert_eq!(short(&bytes, 4), GET_ADDRESS);
    let flags = short(&bytes, 6);
    assert_eq!(flags & 0x0001, 0x0001, "NLM_F_REQUEST");
    assert_eq!(flags & 0x0300, 0x0300, "NLM_F_DUMP");
    assert_eq!(bytes[16], 2, "AF_INET");

    assert_eq!(list(Family::V6, 3)[16], 10, "AF_INET6");
}

#[test]
fn an_acknowledgement_is_told_from_a_refusal() {
    assert_eq!(answer(&error_message(0)), Some(Answer::Accepted));
    // The kernel writes a negative errno. EADDRNOTAVAIL is 99 and is what
    // removing an address that is not there answers.
    assert_eq!(answer(&error_message(-99)), Some(Answer::Refused(99)));
    assert_eq!(answer(&error_message(-1)), Some(Answer::Refused(1)));

    // Anything else is named rather than read as an acknowledgement.
    let mut other = error_message(0);
    other[4..6].copy_from_slice(&NEW_ADDRESS.to_ne_bytes());
    assert_eq!(answer(&other), Some(Answer::Other(NEW_ADDRESS)));

    // And too short to hold one is refused rather than indexed into.
    assert_eq!(answer(&error_message(0)[..HEADER + 2]), None);
    assert_eq!(answer(&[]), None);
}

#[test]
fn one_read_is_split_into_the_messages_it_holds() {
    let first = change(&address(), Change::Add, 1);
    let second = change(&address(), Change::Remove, 2);
    let mut together = first.clone();
    together.extend_from_slice(&second);

    let split = messages(&together);

    assert_eq!(split.len(), 2);
    assert_eq!(split[0], first.as_slice());
    assert_eq!(split[1], second.as_slice());
}

#[test]
fn a_message_claiming_more_than_arrived_ends_the_walk() {
    // What a truncated read looks like. A walk that trusted the length field
    // would run past the end of the buffer.
    let mut bytes = change(&address(), Change::Add, 1);
    let claimed = u32::try_from(bytes.len() + 40).unwrap();
    bytes[..4].copy_from_slice(&claimed.to_ne_bytes());

    assert_eq!(messages(&bytes).len(), 0);

    // And a length no message can have, which would otherwise loop forever.
    let mut zero = change(&address(), Change::Add, 1);
    zero[..4].copy_from_slice(&0_u32.to_ne_bytes());
    assert_eq!(messages(&zero).len(), 0);

    // The other side: a message that fits exactly is walked.
    let whole = change(&address(), Change::Add, 1);
    assert_eq!(messages(&whole).len(), 1);
}

#[test]
fn the_addresses_of_a_listing_are_read_back_with_their_interface() {
    // A dump answers with the same message type an add uses, so the reply to
    // a listing is built here the way the kernel builds it.
    let four = change(&address(), Change::Add, 1);
    let six = change(
        &Address {
            address: IpAddr::V6(Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100)),
            prefix_length: 64,
            interface: 9,
        },
        Change::Add,
        1,
    );
    let mut together = four;
    together.extend_from_slice(&six);

    let found = addresses(&together);

    assert_eq!(
        found,
        vec![
            (IpAddr::V4(VIRTUAL), INTERFACE),
            (IpAddr::V6(Ipv6Addr::new(0xFD00, 0, 0, 0, 0, 0, 0, 100)), 9)
        ]
    );
}

#[test]
fn the_address_this_node_holds_is_read_and_not_the_far_end_of_a_link() {
    // On a point to point link `IFA_LOCAL` is this end and `IFA_ADDRESS` is
    // the far one. Our own messages carry the same value in both, so a
    // measurement built from one of them would pass whichever the code read.
    // This one is built by hand with the two apart.
    let mine = Ipv4Addr::new(10, 0, 0, 1);
    let theirs = Ipv4Addr::new(10, 0, 0, 2);
    let mut bytes = Vec::new();
    let length = u32::try_from(HEADER + 8 + 8 + 8).unwrap();
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&NEW_ADDRESS.to_ne_bytes());
    bytes.extend_from_slice(&0_u16.to_ne_bytes());
    bytes.extend_from_slice(&1_u32.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&[2, 32, 0, 0]);
    bytes.extend_from_slice(&5_u32.to_ne_bytes());
    // IFA_ADDRESS first, so reading the first attribute found is not enough.
    bytes.extend_from_slice(&8_u16.to_ne_bytes());
    bytes.extend_from_slice(&1_u16.to_ne_bytes());
    bytes.extend_from_slice(&theirs.octets());
    bytes.extend_from_slice(&8_u16.to_ne_bytes());
    bytes.extend_from_slice(&2_u16.to_ne_bytes());
    bytes.extend_from_slice(&mine.octets());

    assert_eq!(addresses(&bytes), vec![(IpAddr::V4(mine), 5)]);
}

#[test]
fn a_message_that_is_not_an_address_is_passed_over() {
    // A dump ends with a message of its own, and an error can arrive in the
    // middle of one. Neither names an address.
    let mut together = error_message(0);
    together.extend_from_slice(&change(&address(), Change::Add, 1));

    assert_eq!(addresses(&together), vec![(IpAddr::V4(VIRTUAL), INTERFACE)]);
    assert_eq!(addresses(&error_message(0)), vec![]);
}

/// The bytes the kernel answers a request with.
fn error_message(code: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    let length = u32::try_from(HEADER + 4 + HEADER).unwrap();
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&ERROR.to_ne_bytes());
    bytes.extend_from_slice(&0_u16.to_ne_bytes());
    bytes.extend_from_slice(&1_u32.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&code.to_ne_bytes());
    // The header of the message that caused it, which the kernel echoes.
    bytes.extend_from_slice(&[0; HEADER]);
    bytes
}
