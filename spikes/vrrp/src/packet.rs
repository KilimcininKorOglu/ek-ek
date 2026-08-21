// Throwaway spike code for T-010. Not product code.
//
// VRRPv3 advertisement encoding and decoding, plus gratuitous ARP.
//
// The wire format is not taken on trust: the spike sends these packets and
// tcpdump parses them back. If tcpdump reports "VRRPv3, Advertisement" and
// "ARP, Reply", the layout is right. That check is part of the measurement.

use std::net::Ipv4Addr;

pub const VRRP_PROTO: i32 = 112;
pub const VRRP_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

const VERSION_TYPE: u8 = 0x31; // version 3, type 1 (advertisement)
const ARP_REPLY: u16 = 2;
const ETHERTYPE_ARP: u16 = 0x0806;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Advertisement {
    pub vrid: u8,
    pub priority: u8,
    /// Advertisement interval in centiseconds, as VRRPv3 carries it.
    pub max_adver_int: u16,
    pub vip: Ipv4Addr,
}

impl Advertisement {
    pub fn encode(&self, src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20);
        buf.push(VERSION_TYPE);
        buf.push(self.vrid);
        buf.push(self.priority);
        buf.push(1); // count of addresses
        // Four reserved bits then a twelve bit interval.
        buf.extend_from_slice(&(self.max_adver_int & 0x0fff).to_be_bytes());
        buf.extend_from_slice(&[0, 0]); // checksum placeholder
        buf.extend_from_slice(&self.vip.octets());

        let sum = checksum(&buf, src, dst);
        buf[6..8].copy_from_slice(&sum.to_be_bytes());
        buf
    }

    pub fn decode(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 || buf[0] != VERSION_TYPE {
            return None;
        }
        let interval = u16::from_be_bytes([buf[4], buf[5]]) & 0x0fff;
        Some(Self {
            vrid: buf[1],
            priority: buf[2],
            max_adver_int: interval,
            vip: Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]),
        })
    }
}

/// VRRPv3 over IPv4 checksums the message with a pseudo header, unlike v2.
/// Getting this wrong is invisible to our own code and visible to tcpdump,
/// which is exactly why tcpdump is the referee.
fn checksum(payload: &[u8], src: Ipv4Addr, dst: Ipv4Addr) -> u16 {
    let mut sum: u32 = 0;

    for octets in [src.octets(), dst.octets()] {
        sum += u32::from(u16::from_be_bytes([octets[0], octets[1]]));
        sum += u32::from(u16::from_be_bytes([octets[2], octets[3]]));
    }
    sum += VRRP_PROTO as u32;
    sum += payload.len() as u32;

    let mut i = 0;
    while i + 1 < payload.len() {
        sum += u32::from(u16::from_be_bytes([payload[i], payload[i + 1]]));
        i += 2;
    }
    if i < payload.len() {
        sum += u32::from(u16::from_be_bytes([payload[i], 0]));
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// A gratuitous ARP reply, broadcast so every switch and host on the segment
/// relearns which MAC owns the VIP.
///
/// Without this the VIP looks moved on the new node while traffic keeps going
/// to the old one. The failure is silent, which is why it is measured
/// separately rather than assumed.
pub fn gratuitous_arp(mac: [u8; 6], vip: Ipv4Addr) -> Vec<u8> {
    let mut f = Vec::with_capacity(42);
    f.extend_from_slice(&[0xff; 6]); // destination: broadcast
    f.extend_from_slice(&mac); // source
    f.extend_from_slice(&ETHERTYPE_ARP.to_be_bytes());

    f.extend_from_slice(&1u16.to_be_bytes()); // hardware type: ethernet
    f.extend_from_slice(&0x0800u16.to_be_bytes()); // protocol type: IPv4
    f.push(6); // hardware address length
    f.push(4); // protocol address length
    f.extend_from_slice(&ARP_REPLY.to_be_bytes());

    f.extend_from_slice(&mac); // sender hardware address
    f.extend_from_slice(&vip.octets()); // sender protocol address
    f.extend_from_slice(&[0xff; 6]); // target hardware address
    f.extend_from_slice(&vip.octets()); // target protocol address: the VIP itself
    f
}
