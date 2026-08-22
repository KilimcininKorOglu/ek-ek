// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The rtnetlink messages that move an address on and off an interface.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        nlmsg_len                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |         nlmsg_type            |        nlmsg_flags            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        nlmsg_seq                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        nlmsg_pid                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | ifa_family    | ifa_prefixlen | ifa_flags     | ifa_scope     |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        ifa_index                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            rta_len            |           rta_type            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        attribute value                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # Why both address attributes are sent
//!
//! `IFA_LOCAL` and `IFA_ADDRESS` mean different things on a point to point
//! link, where the first is this end and the second is the far end. On an
//! ethernet interface they are the same value, and the kernel refuses the
//! message when either one is missing (T-010).
//!
//! # Why the answer has to be read
//!
//! A netlink write reports success once the message is queued. Whether the
//! kernel accepted it arrives afterwards, as an error message carrying zero
//! for an acknowledgement and a negative errno for a refusal. A caller that
//! does not read it believes every address change worked (T-010).
//!
//! Byte order is the host's, which is what netlink uses. Nothing here is sent
//! to another machine.

use std::net::IpAddr;

/// Add an address.
pub const NEW_ADDRESS: u16 = 20;
/// Remove an address.
pub const DELETE_ADDRESS: u16 = 21;
/// List addresses.
pub const GET_ADDRESS: u16 = 22;
/// An error or an acknowledgement.
pub const ERROR: u16 = 2;
/// The last message of a dump.
pub const DONE: u16 = 3;

/// This message is a request.
const REQUEST: u16 = 0x0001;
/// Answer even when nothing went wrong.
const ACK: u16 = 0x0004;
/// Create the object when it is not there.
const CREATE: u16 = 0x0400;
/// Update the one that is there rather than refusing.
const REPLACE: u16 = 0x0100;
/// Return every object rather than one.
const DUMP: u16 = 0x0300;

/// The far end of a point to point link, and the address itself elsewhere.
const IFA_ADDRESS: u16 = 1;
/// This end of the link.
const IFA_LOCAL: u16 = 2;

/// Bytes before the payload of a netlink message.
pub const HEADER: usize = 16;
/// Bytes of the address message that follows the header.
const IFADDRMSG: usize = 8;
/// Bytes before the value of an attribute.
const ATTRIBUTE: usize = 4;

/// The address family of an IPv4 address.
const INET: u8 = 2;
/// The address family of an IPv6 address.
const INET6: u8 = 10;

/// Reachable from anywhere, which is what a virtual address is.
const UNIVERSE: u8 = 0;

/// Which way an address change goes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Put the address on the interface.
    Add,
    /// Take it off.
    Remove,
}

impl Change {
    /// The message type this change is asked for with.
    const fn kind(self) -> u16 {
        match self {
            Self::Add => NEW_ADDRESS,
            Self::Remove => DELETE_ADDRESS,
        }
    }

    /// The flags this change carries.
    ///
    /// An add asks to create and to replace, so putting an address on an
    /// interface that already carries it succeeds. Without the second flag
    /// the kernel answers `EEXIST`, and a node retaking the role after a
    /// partial failure would stand down over a state that is already the one
    /// it asked for. What is wanted here is the end state, not a transaction.
    const fn flags(self) -> u16 {
        match self {
            Self::Add => REQUEST | ACK | CREATE | REPLACE,
            Self::Remove => REQUEST | ACK,
        }
    }
}

/// One address on one interface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    /// The address itself.
    pub address: IpAddr,
    /// How much of it is the network, written as a prefix length.
    pub prefix_length: u8,
    /// Index of the interface it belongs on.
    pub interface: u32,
}

impl Address {
    /// The address family byte this address is carried under.
    const fn family(&self) -> u8 {
        match self.address {
            IpAddr::V4(_) => INET,
            IpAddr::V6(_) => INET6,
        }
    }

    /// The address as it goes on the wire.
    fn octets(&self) -> Vec<u8> {
        match self.address {
            IpAddr::V4(address) => address.octets().to_vec(),
            IpAddr::V6(address) => address.octets().to_vec(),
        }
    }
}

/// The bytes that ask the kernel for one address change.
///
/// The sequence number comes back in the answer, which is how a reply is
/// matched to the request that caused it.
#[must_use]
pub fn change(what: &Address, how: Change, sequence: u32) -> Vec<u8> {
    let value = what.octets();
    let mut bytes = Vec::with_capacity(HEADER + IFADDRMSG + 2 * (ATTRIBUTE + value.len()));

    // Written as zero and filled in once the length is known.
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(&how.kind().to_ne_bytes());
    bytes.extend_from_slice(&how.flags().to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    // Zero lets the kernel fill in the port, which is what an unbound socket
    // needs.
    bytes.extend_from_slice(&0_u32.to_ne_bytes());

    bytes.push(what.family());
    bytes.push(what.prefix_length);
    bytes.push(0);
    bytes.push(UNIVERSE);
    bytes.extend_from_slice(&what.interface.to_ne_bytes());

    // Both, because the kernel refuses the message when either is missing.
    attribute(&mut bytes, IFA_LOCAL, &value);
    attribute(&mut bytes, IFA_ADDRESS, &value);

    let length = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    bytes[..4].copy_from_slice(&length.to_ne_bytes());
    bytes
}

/// The bytes that ask the kernel for every address it holds.
#[must_use]
pub fn list(family: Family, sequence: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + IFADDRMSG);
    let length = u32::try_from(HEADER + IFADDRMSG).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&GET_ADDRESS.to_ne_bytes());
    bytes.extend_from_slice(&(REQUEST | DUMP).to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());

    bytes.push(family.byte());
    bytes.extend_from_slice(&[0, 0, 0]);
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes
}

/// Which addresses a listing asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// IPv4 only.
    V4,
    /// IPv6 only.
    V6,
}

impl Family {
    /// The family byte the kernel expects.
    const fn byte(self) -> u8 {
        match self {
            Self::V4 => INET,
            Self::V6 => INET6,
        }
    }
}

/// Appends one attribute.
///
/// Netlink starts every attribute on a four byte boundary, and nothing here
/// pads: both attributes this code writes carry an address, which is four or
/// sixteen bytes, so each one already lands on it. An attribute of any other
/// length would have to be padded, and the assertion below is what would say
/// so rather than letting a malformed message reach the kernel.
fn attribute(bytes: &mut Vec<u8>, kind: u16, value: &[u8]) {
    let length = u16::try_from(ATTRIBUTE + value.len()).unwrap_or(u16::MAX);
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(value);
    debug_assert_eq!(
        bytes.len() % 4,
        0,
        "an attribute of {} bytes needs padding, which nothing here writes",
        value.len()
    );
}

/// What the kernel said about a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// The change was made.
    Accepted,
    /// The kernel refused it, with this errno.
    Refused(i32),
    /// A message this code does not read, named by its type.
    Other(u16),
}

/// Reads what the kernel answered.
///
/// Returns nothing when the bytes are too short to hold an answer, so a
/// truncated read is refused rather than indexed into.
#[must_use]
pub fn answer(bytes: &[u8]) -> Option<Answer> {
    let kind = u16::from_ne_bytes([*bytes.get(4)?, *bytes.get(5)?]);
    if kind != ERROR {
        return Some(Answer::Other(kind));
    }
    let code = i32::from_ne_bytes([
        *bytes.get(HEADER)?,
        *bytes.get(HEADER + 1)?,
        *bytes.get(HEADER + 2)?,
        *bytes.get(HEADER + 3)?,
    ]);
    // Zero is an acknowledgement. Anything else is a negative errno, and the
    // sign is dropped here so a caller reports the number an operator can
    // look up.
    if code == 0 {
        Some(Answer::Accepted)
    } else {
        Some(Answer::Refused(-code))
    }
}

/// Splits a netlink read into the messages it holds.
///
/// One read can carry several messages, each padded to a four byte boundary.
/// A message claiming a length outside what arrived ends the walk rather than
/// indexing past it.
#[must_use]
pub fn messages(bytes: &[u8]) -> Vec<&[u8]> {
    let mut found = Vec::new();
    let mut at = 0;
    while at + HEADER <= bytes.len() {
        let Some(head) = bytes.get(at..at + 4) else {
            break;
        };
        let length = u32::from_ne_bytes([head[0], head[1], head[2], head[3]]) as usize;
        if length < HEADER || at + length > bytes.len() {
            break;
        }
        // Indexing is safe: the bound was measured on the line above.
        found.push(&bytes[at..at + length]);
        at += length.next_multiple_of(4);
    }
    found
}

/// The addresses a listing answer names, with the interface each sits on.
///
/// Everything that is not an address message is passed over, because a dump
/// ends with a message of its own and carries whatever else the kernel had to
/// say.
#[must_use]
pub fn addresses(bytes: &[u8]) -> Vec<(IpAddr, u32)> {
    let mut found = Vec::new();
    for message in messages(bytes) {
        let kind = u16::from_ne_bytes([message[4], message[5]]);
        if kind != NEW_ADDRESS {
            continue;
        }
        let Some(body) = message.get(HEADER..) else {
            continue;
        };
        let (Some(&family), Some(index)) = (body.first(), body.get(4..8)) else {
            continue;
        };
        let interface = u32::from_ne_bytes([index[0], index[1], index[2], index[3]]);
        let Some(attributes) = body.get(IFADDRMSG..) else {
            continue;
        };
        if let Some(address) = local(attributes, family) {
            found.push((address, interface));
        }
    }
    found
}

/// The `IFA_LOCAL` value among a message's attributes.
///
/// `IFA_LOCAL` rather than `IFA_ADDRESS`, because on a point to point link the
/// second names the far end and would report an address this node does not
/// hold.
fn local(bytes: &[u8], family: u8) -> Option<IpAddr> {
    let mut at = 0;
    while at + ATTRIBUTE <= bytes.len() {
        let head = bytes.get(at..at + ATTRIBUTE)?;
        let length = u16::from_ne_bytes([head[0], head[1]]) as usize;
        let kind = u16::from_ne_bytes([head[2], head[3]]);
        if length < ATTRIBUTE || at + length > bytes.len() {
            return None;
        }
        if kind == IFA_LOCAL {
            let value = bytes.get(at + ATTRIBUTE..at + length)?;
            return address(value, family);
        }
        at += length.next_multiple_of(4);
    }
    None
}

/// An address of the family given, out of the bytes that carry it.
fn address(bytes: &[u8], family: u8) -> Option<IpAddr> {
    match family {
        INET => {
            let octets: [u8; 4] = bytes.try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        INET6 => {
            let octets: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::from(octets))
        }
        _ => None,
    }
}
