// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The raw socket advertisements really travel on.
//!
//! VRRP is its own IP protocol, number 112, so there is no port to bind and
//! no datagram socket to use. The socket needs `CAP_NET_RAW`, which is why
//! this is the only part of the crate behind a platform gate (ADR-0007).
//!
//! # What comes back
//!
//! A raw socket hands over the IP header along with the payload, so a read
//! has to step over it. That is done in [`crate::header`], which is where the
//! measurements of it are: the rule is about bytes, and gating it here would
//! only measure it where the socket can be opened.

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::header::{payload, sender};
use crate::packet::PROTOCOL;
use crate::transport::Transport;

/// The TTL every advertisement carries.
///
/// RFC 5798 requires 255 and requires a receiver to drop anything lower. It
/// is what stops an advertisement that crossed a router from being taken for
/// one from the local segment.
const TTL: u32 = 255;

/// The most bytes one read takes.
///
/// An advertisement with every address a byte-wide count allows, plus the
/// longest IPv4 header, fits well inside this.
const MOST: usize = 1_500;

/// A raw socket carrying VRRP.
pub struct RawSocket {
    socket: Socket,
}

impl RawSocket {
    /// Opens the socket.
    ///
    /// # Errors
    ///
    /// Returns what the operating system said. The usual failure is a missing
    /// `CAP_NET_RAW`, which arrives as a permission error.
    pub fn open() -> io::Result<Self> {
        let socket = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(i32::from(PROTOCOL))),
        )?;
        socket.set_ttl_v4(TTL)?;
        // Nothing here may wait: the same loop has to reach its timers, and a
        // quiet segment would otherwise hold it forever (ADR-0029).
        socket.set_nonblocking(true)?;
        Ok(Self { socket })
    }
}

impl Transport for RawSocket {
    type Error = io::Error;

    fn send(&self, to: Ipv4Addr, bytes: &[u8]) -> io::Result<()> {
        // Port zero: this protocol has no ports, and the value is ignored.
        let address = SockAddr::from(SocketAddrV4::new(to, 0));
        self.socket.send_to(bytes, &address)?;
        Ok(())
    }

    fn receive(&self) -> io::Result<Option<(Ipv4Addr, Vec<u8>)>> {
        let mut buffer = [0_u8; MOST];
        let read = match (&self.socket).read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        let packet = buffer.get(..read).unwrap_or_default();

        let Some(sender) = sender(packet) else {
            return Ok(None);
        };
        Ok(payload(packet).map(|payload| (sender, payload.to_vec())))
    }
}
