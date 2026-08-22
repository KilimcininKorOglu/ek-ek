// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The raw socket the gateway question travels on.
//!
//! ICMP is its own IP protocol, number 1, so there is no port to bind. The
//! socket needs `CAP_NET_RAW`, which the node agent already holds for VRRP
//! itself, so the check adds no privilege the product did not have.
//!
//! # What comes back
//!
//! A raw socket hands over the IP header along with the payload, so a read
//! steps over it with [`crate::header`]. Every reader of a raw ICMP socket
//! sees every reply on the machine, including answers to another process's
//! ping, so the identifier and the sequence number decide what is ours.

use std::io::{self, Read};
use std::net::{Ipv4Addr, SocketAddrV4};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use crate::echo::{Echo, reply, request};
use crate::header::{payload, sender};

/// The most bytes one read takes.
///
/// An echo reply carries back the payload that was sent, and this product
/// sends a short one, so the longest IPv4 header plus that fits well inside.
const MOST: usize = 1_500;

/// What goes in the payload of every question.
///
/// Short and constant. It is there to make the request look like an ordinary
/// ping to whatever is between this node and its gateway.
const PAYLOAD: &[u8] = b"ek-ek";

/// A raw socket carrying ICMP.
pub struct Pinger {
    socket: Socket,
    identifier: u16,
    sequence: u16,
}

impl Pinger {
    /// Opens the socket.
    ///
    /// The identifier tells this process's questions from another's. It comes
    /// from the process id, which is what an ordinary ping uses and what
    /// keeps two node agents on one machine apart.
    ///
    /// # Errors
    ///
    /// Returns what the operating system said. The usual failure is a missing
    /// `CAP_NET_RAW`, which arrives as a permission error.
    pub fn open() -> io::Result<Self> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        // Nothing here may wait: the same loop has to reach its timers, and a
        // gateway that never answers would otherwise hold it forever.
        socket.set_nonblocking(true)?;
        let identifier = u16::try_from(std::process::id() & 0xFFFF).unwrap_or(1);
        Ok(Self {
            socket,
            identifier,
            sequence: 0,
        })
    }

    /// Which question this asker is on.
    #[must_use]
    pub const fn sequence(&self) -> u16 {
        self.sequence
    }

    /// Asks the gateway whether it is still there.
    ///
    /// # Errors
    ///
    /// Returns what the socket said.
    pub fn ask(&mut self, gateway: Ipv4Addr) -> io::Result<u16> {
        // Wrapping on purpose. The number only has to tell one question from
        // the few around it, and a node runs for months.
        self.sequence = self.sequence.wrapping_add(1);
        let bytes = request(self.identifier, self.sequence, PAYLOAD);
        // Port zero: this protocol has no ports, and the value is ignored.
        let address = SockAddr::from(SocketAddrV4::new(gateway, 0));
        self.socket.send_to(&bytes, &address)?;
        Ok(self.sequence)
    }

    /// Takes whatever has arrived, and says what answered.
    ///
    /// Returns nothing when the socket is empty, and nothing for a reply that
    /// belongs to another asker. The caller decides what an answer means: a
    /// reply to a question two intervals old is still evidence the gateway is
    /// there.
    ///
    /// # Errors
    ///
    /// Returns what the socket said.
    pub fn collect(&self) -> io::Result<Option<(Ipv4Addr, Echo)>> {
        let mut buffer = [0_u8; MOST];
        let read = match (&self.socket).read(&mut buffer) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(None),
            Err(error) => return Err(error),
        };
        let packet = buffer.get(..read).unwrap_or_default();

        let (Some(from), Some(body)) = (sender(packet), payload(packet)) else {
            return Ok(None);
        };
        let Some(echo) = reply(body) else {
            return Ok(None);
        };
        if echo.identifier != self.identifier {
            return Ok(None);
        }
        Ok(Some((from, echo)))
    }
}
