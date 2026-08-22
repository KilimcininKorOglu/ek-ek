// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Telling an L4 backend who is really on the other end.
//!
//! On the L4 path the backend sees the proxy's address, not the client's. An
//! Exchange receive connector grants relay by address and an anti-spam rule
//! reads address reputation, so without this the address every decision rests
//! on is the wrong one (ADR-0043).
//!
//! # Two formats, one meaning
//!
//! v1 is a line of text and v2 is a binary record. Which one a backend
//! understands is the backend's business, so both are produced and the
//! frontend picks (ADR-0043).
//!
//! # When the addresses cannot be told
//!
//! A socket whose ends cannot be read, or whose two ends are of different
//! families, has no truthful address pair to state. Both formats have a way
//! to say exactly that, and saying it is better than either stating an
//! address that was guessed or sending nothing to a backend that is waiting
//! for a header.

use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use ek_ek_config::ProxyProtocol;

/// The twelve bytes a v2 header opens with.
///
/// Chosen by the specification so that no other protocol can begin with them
/// by accident, which is what lets a backend accept both a header and a bare
/// connection on one port.
const SIGNATURE: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// Version 2, PROXY command: the addresses that follow are the client's.
const PROXY: u8 = 0x21;

/// Version 2, LOCAL command: no address follows and the connection's own
/// addresses stand.
const LOCAL: u8 = 0x20;

/// TCP over IPv4.
const TCP4: u8 = 0x11;

/// TCP over IPv6.
const TCP6: u8 = 0x21;

/// Neither family nor protocol is stated, which is what LOCAL carries.
const UNSPEC: u8 = 0x00;

/// A header ready to be written, and what it managed to say.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    bytes: Vec<u8>,
    stated: bool,
}

impl Header {
    /// The bytes to write.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Whether the header names the client, or says it cannot.
    ///
    /// A header that names nobody leaves the backend deciding on the load
    /// balancer's address, which is the very thing this exists to stop. It is
    /// counted so an operator can see it happening (ADR-0043).
    #[must_use]
    pub const fn states_an_address(&self) -> bool {
        self.stated
    }
}

/// The bytes to send before anything else on a backend connection.
///
/// Returns nothing when the frontend has the protocol turned off, which is
/// the default: a backend that is not expecting a header refuses a connection
/// that carries one (ADR-0043).
#[must_use]
pub fn header(format: ProxyProtocol, client: SocketAddr, proxy: SocketAddr) -> Option<Header> {
    write(format, pair(client, proxy))
}

/// The header to send when the ends of the connection cannot be read.
///
/// The backend is expecting a header, so one is still sent; it says that no
/// address is being stated rather than stating one that was made up.
#[must_use]
pub fn unknown(format: ProxyProtocol) -> Option<Header> {
    write(format, Ends::Untold)
}

/// Builds the header for one format and one reading of the two ends.
fn write(format: ProxyProtocol, ends: Ends) -> Option<Header> {
    let stated = !matches!(ends, Ends::Untold);
    let bytes = match format {
        ProxyProtocol::Disabled => return None,
        ProxyProtocol::V1 => v1(ends),
        ProxyProtocol::V2 => v2(ends),
    };
    Some(Header { bytes, stated })
}

/// What a header states about the two ends.
///
/// A pair spanning two families is not a case, because every form of the
/// header states one family for both addresses. Ruling it out here rather
/// than when writing means neither writer has an impossible case to answer
/// for.
enum Ends {
    /// Neither end can be stated.
    Untold,
    /// Both ends are IPv4.
    Four(SocketAddrV4, SocketAddrV4),
    /// Both ends are IPv6.
    Six(SocketAddrV6, SocketAddrV6),
}

/// Works out which of the three cases a connection is.
fn pair(client: SocketAddr, proxy: SocketAddr) -> Ends {
    match (client, proxy) {
        (SocketAddr::V4(client), SocketAddr::V4(proxy)) => Ends::Four(client, proxy),
        (SocketAddr::V6(client), SocketAddr::V6(proxy)) => Ends::Six(client, proxy),
        _ => Ends::Untold,
    }
}

/// The text form.
fn v1(ends: Ends) -> Vec<u8> {
    // Source first, then destination, then the two ports in the same order.
    match ends {
        Ends::Untold => b"PROXY UNKNOWN\r\n".to_vec(),
        Ends::Four(client, proxy) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            client.ip(),
            proxy.ip(),
            client.port(),
            proxy.port()
        )
        .into_bytes(),
        Ends::Six(client, proxy) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            client.ip(),
            proxy.ip(),
            client.port(),
            proxy.port()
        )
        .into_bytes(),
    }
}

/// The binary form.
fn v2(ends: Ends) -> Vec<u8> {
    let mut out = Vec::with_capacity(SIGNATURE.len() + 4 + 36);
    out.extend_from_slice(&SIGNATURE);

    match ends {
        Ends::Untold => {
            out.push(LOCAL);
            out.push(UNSPEC);
            // No address block follows, so the length is zero. A receiver
            // that reads the length and skips that many bytes lands on the
            // first byte the client sent.
            out.extend_from_slice(&0_u16.to_be_bytes());
        }
        Ends::Four(client, proxy) => {
            out.push(PROXY);
            out.push(TCP4);
            out.extend_from_slice(&12_u16.to_be_bytes());
            out.extend_from_slice(&client.ip().octets());
            out.extend_from_slice(&proxy.ip().octets());
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&proxy.port().to_be_bytes());
        }
        Ends::Six(client, proxy) => {
            out.push(PROXY);
            out.push(TCP6);
            out.extend_from_slice(&36_u16.to_be_bytes());
            out.extend_from_slice(&client.ip().octets());
            out.extend_from_slice(&proxy.ip().octets());
            out.extend_from_slice(&client.port().to_be_bytes());
            out.extend_from_slice(&proxy.port().to_be_bytes());
        }
    }
    out
}
