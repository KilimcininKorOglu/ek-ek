// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The rtnetlink messages that name the default gateway.
//!
//! A node that has lost its uplink must give the virtual address up, and the
//! gateway is what it asks to find out (ADR-0030). Nobody configures the
//! address: it is read from the routing table the machine already has.
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | rtm_family    | rtm_dst_len   | rtm_src_len   | rtm_tos       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! | rtm_table     | rtm_protocol  | rtm_scope     | rtm_type      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                        rtm_flags                              |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            rta_len            |           rta_type            |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! # What makes a route the default one
//!
//! A destination prefix length of zero. Such a route matches everything, and
//! the address in its `RTA_GATEWAY` attribute is the next hop every packet
//! leaving this segment goes through. A machine can hold several, so the one
//! with the lowest metric wins, which is the same rule the kernel uses to
//! pick between them.
//!
//! Byte order is the host's, which is what netlink uses. Nothing here is sent
//! to another machine.

use std::net::IpAddr;

use crate::address::{HEADER, messages};

/// A route the kernel is telling us about.
pub const NEW_ROUTE: u16 = 24;
/// List routes.
pub const GET_ROUTE: u16 = 26;

/// This message is a request.
const REQUEST: u16 = 0x0001;
/// Return every object rather than one.
const DUMP: u16 = 0x0300;

/// Bytes of the route message that follows the header.
const RTMSG: usize = 12;
/// Bytes before the value of an attribute.
const ATTRIBUTE: usize = 4;

/// The next hop of this route.
const RTA_GATEWAY: u16 = 5;
/// The interface the route leaves from.
const RTA_OIF: u16 = 4;
/// How much this route costs against another to the same place.
const RTA_PRIORITY: u16 = 6;

/// The address family of an IPv4 address.
const INET: u8 = 2;
/// The address family of an IPv6 address.
const INET6: u8 = 10;

/// One route out of the kernel's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    /// The next hop packets on this route go through.
    pub gateway: IpAddr,
    /// Index of the interface they leave from.
    pub interface: u32,
    /// What this route costs against another to the same place.
    pub metric: u32,
}

/// The bytes that ask the kernel for every route of one family.
#[must_use]
pub fn list(family: Family, sequence: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER + RTMSG);
    let length = u32::try_from(HEADER + RTMSG).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&length.to_ne_bytes());
    bytes.extend_from_slice(&GET_ROUTE.to_ne_bytes());
    bytes.extend_from_slice(&(REQUEST | DUMP).to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    // Zero lets the kernel fill in the port, which is what an unbound socket
    // needs.
    bytes.extend_from_slice(&0_u32.to_ne_bytes());

    bytes.push(family.byte());
    // Everything else asks for no filter. A dump answers with every route and
    // the reading below picks the ones that matter, because the kernel
    // ignores most of these fields on a dump anyway.
    bytes.extend_from_slice(&[0; RTMSG - 1]);
    bytes
}

/// Which routes a listing asks for.
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

/// Every default route a listing answer names.
///
/// A route with a destination prefix is not one: it says where to send a
/// particular network, not where to send everything.
#[must_use]
pub fn defaults(bytes: &[u8]) -> Vec<Route> {
    let mut found = Vec::new();
    for message in messages(bytes) {
        let kind = u16::from_ne_bytes([message[4], message[5]]);
        if kind != NEW_ROUTE {
            continue;
        }
        let Some(body) = message.get(HEADER..) else {
            continue;
        };
        let (Some(&family), Some(&destination)) = (body.first(), body.get(1)) else {
            continue;
        };
        // Anything else is a route to one network rather than the way out.
        if destination != 0 {
            continue;
        }
        let Some(attributes) = body.get(RTMSG..) else {
            continue;
        };
        if let Some(route) = read(attributes, family) {
            found.push(route);
        }
    }
    found
}

/// The gateway this node should watch.
///
/// The lowest metric wins, which is how the kernel picks between two default
/// routes. When an interface is named, only routes leaving from it count: a
/// node whose uplink is a second interface would otherwise watch a gateway it
/// does not serve the virtual address through.
///
/// Returns nothing when the machine has no default route at all, which is a
/// state to report rather than a failure to act on (ADR-0030).
#[must_use]
pub fn gateway(bytes: &[u8], interface: Option<u32>) -> Option<IpAddr> {
    cheapest(defaults(bytes), interface)
}

/// The gateway to watch, out of routes already read.
///
/// Held apart from [`gateway`] because a dump arrives in as many reads as it
/// needs, and the cheapest route of the whole answer is not the cheapest of
/// any one read.
#[must_use]
pub fn cheapest(routes: Vec<Route>, interface: Option<u32>) -> Option<IpAddr> {
    routes
        .into_iter()
        .filter(|route| interface.is_none_or(|wanted| route.interface == wanted))
        .min_by_key(|route| route.metric)
        .map(|route| route.gateway)
}

/// One route out of the attributes that describe it.
///
/// A default route without a gateway is a route out of an interface with no
/// next hop, which is nothing this check can ask a question of.
fn read(bytes: &[u8], family: u8) -> Option<Route> {
    let mut gateway = None;
    let mut interface = 0;
    // Absent means zero, which is what the kernel means by an unset metric.
    let mut metric = 0;

    let mut at = 0;
    while at + ATTRIBUTE <= bytes.len() {
        let head = bytes.get(at..at + ATTRIBUTE)?;
        let length = u16::from_ne_bytes([head[0], head[1]]) as usize;
        let kind = u16::from_ne_bytes([head[2], head[3]]);
        if length < ATTRIBUTE || at + length > bytes.len() {
            return None;
        }
        let value = bytes.get(at + ATTRIBUTE..at + length)?;
        match kind {
            RTA_GATEWAY => gateway = address(value, family),
            RTA_OIF => interface = number(value)?,
            RTA_PRIORITY => metric = number(value)?,
            _ => {}
        }
        at += length.next_multiple_of(4);
    }

    Some(Route {
        gateway: gateway?,
        interface,
        metric,
    })
}

/// A four byte number out of an attribute value.
fn number(bytes: &[u8]) -> Option<u32> {
    let octets: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_ne_bytes(octets))
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
