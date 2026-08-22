// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The socket a whole ethernet frame goes out of.
//!
//! An announcement is not IP traffic. A gratuitous ARP has no IP header at
//! all, and a neighbor advertisement has to leave with a hop limit and a
//! destination the IP stack would not choose. Both are built whole in
//! [`crate::announce`] and handed to a packet socket, which sends what it is
//! given and adds nothing.
//!
//! The socket needs `CAP_NET_RAW`, which is why this is behind a platform
//! gate. What the frames hold is outside it, where it is measured.
//!
//! # The one `unsafe` in this crate
//!
//! A packet socket has to be told which interface to send from, and that is
//! carried in a `sockaddr_ll`. socket2 models the address structures of IP
//! and unix sockets and no others, so the bytes are laid out here. The
//! workspace denies `unsafe_code` rather than forbidding it for this case,
//! and the allow sits on the one function that needs it.

use std::io;

use socket2::{Domain, SockAddr, SockAddrStorage, Socket, Type, socklen_t};

/// The address family a packet socket lives in.
const PACKET: i32 = 17;

/// A socket that sends whole ethernet frames.
pub struct Frames {
    socket: Socket,
    interface: SockAddr,
}

impl Frames {
    /// Opens the socket for one interface.
    ///
    /// # Errors
    ///
    /// Returns what the operating system said. The usual failure is a missing
    /// `CAP_NET_RAW`, which arrives as a permission error.
    pub fn open(interface: u32) -> io::Result<Self> {
        // Protocol zero: this socket only sends, and the protocol decides
        // what a packet socket receives.
        let socket = Socket::new(Domain::from(PACKET), Type::RAW, None)?;
        Ok(Self {
            socket,
            interface: link(interface)?,
        })
    }

    /// Sends one frame.
    ///
    /// # Errors
    ///
    /// Returns what the socket said, and an error when the kernel took only
    /// part of the frame. Half an announcement is not an announcement.
    pub fn send(&self, frame: &[u8]) -> io::Result<()> {
        let sent = self.socket.send_to(frame, &self.interface)?;
        if sent == frame.len() {
            return Ok(());
        }
        Err(io::Error::other(format!(
            "the kernel took {sent} of {} bytes, so the frame left cut in half",
            frame.len()
        )))
    }
}

/// The address that names which interface a frame leaves from.
///
/// Only the family and the interface index are read when a frame carries its
/// own ethernet header. The hardware address fields are for the case where the
/// kernel builds that header, which is not this one.
#[allow(unsafe_code)]
fn link(interface: u32) -> io::Result<SockAddr> {
    let index = i32::try_from(interface).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface index {interface} is larger than the kernel's own field"),
        )
    })?;
    let length = socklen_t::try_from(size_of::<libc::sockaddr_ll>())
        .map_err(|_| io::Error::other("a link address does not fit the length the kernel uses"))?;

    let mut storage = SockAddrStorage::zeroed();
    // SAFETY: `sockaddr_ll` is one of this platform's `sockaddr_*` types and
    // is smaller than the storage, which is what `view_as` asks of a caller.
    // The fields are written through the reference it hands back, so nothing
    // here reads uninitialised memory or lays out bytes by hand.
    let view: &mut libc::sockaddr_ll = unsafe { storage.view_as() };
    view.sll_family = u16::try_from(libc::AF_PACKET).unwrap_or(17);
    view.sll_ifindex = index;

    // SAFETY: the storage now holds exactly one `sockaddr_ll`, and the length
    // is the size of that structure.
    Ok(unsafe { SockAddr::new(storage, length) })
}
