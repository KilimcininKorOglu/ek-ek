// Throwaway spike code for T-010. Not product code.
//
// The three kernel interfaces failover depends on, each behind a small wrapper:
// a raw socket on IP protocol 112, an rtnetlink address change, and an
// AF_PACKET frame for gratuitous ARP.
//
// All of it is raw syscalls on purpose. A wrapper crate would hide the exact
// behaviour under test, and the open question is whether these calls work at
// all inside a container with CAP_NET_ADMIN and CAP_NET_RAW.

use std::ffi::CString;
use std::fs;
use std::io;
use std::mem;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::packet::{self, VRRP_GROUP, VRRP_PROTO};

// rtnetlink constants. libc exposes some of these, but writing them out keeps
// the message layout readable next to the bytes it produces.
const NETLINK_ROUTE: libc::c_int = 0;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const NLM_F_REQUEST: u16 = 0x001;
const NLM_F_ACK: u16 = 0x004;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLMSG_ERROR: u16 = 2;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const RT_SCOPE_UNIVERSE: u8 = 0;

fn check(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Interface facts read from sysfs rather than through an ioctl. The values are
/// the same and the file is easier to verify by hand when a measurement looks
/// wrong.
pub struct Interface {
    pub index: u32,
    pub mac: [u8; 6],
}

impl Interface {
    pub fn lookup(name: &str) -> io::Result<Self> {
        let index: u32 = fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
            .trim()
            .parse()
            .map_err(|_| io::Error::other(format!("{name}: unreadable ifindex")))?;

        let raw = fs::read_to_string(format!("/sys/class/net/{name}/address"))?;
        let mut mac = [0u8; 6];
        let parts: Vec<&str> = raw.trim().split(':').collect();
        if parts.len() != 6 {
            return Err(io::Error::other(format!("{name}: unreadable mac {raw:?}")));
        }
        for (slot, part) in mac.iter_mut().zip(parts) {
            *slot = u8::from_str_radix(part, 16)
                .map_err(|_| io::Error::other(format!("{name}: unreadable mac {raw:?}")))?;
        }

        Ok(Self { index, mac })
    }
}

/// A raw socket on IP protocol 112, the one VRRP actually uses.
pub struct VrrpSocket {
    fd: OwnedFd,
}

impl VrrpSocket {
    /// `join_group` decides whether the socket takes part in multicast at all.
    /// With it off the spike is provably unicast only, which is what the R-02
    /// mitigation requires.
    pub fn open(iface: &str, join_group: bool, recv_timeout_ms: i64) -> io::Result<Self> {
        let raw = check(unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, VRRP_PROTO) })?;
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // RFC 5798 requires TTL 255 on advertisements so a router cannot forward
        // one into another segment. Receivers are expected to check it.
        set_int(&fd, libc::IPPROTO_IP, libc::IP_TTL, 255)?;
        set_int(&fd, libc::IPPROTO_IP, libc::IP_MULTICAST_TTL, 255)?;
        // Without this a multicast sender also receives its own advertisement
        // and reads it as a competing master.
        set_int(&fd, libc::IPPROTO_IP, libc::IP_MULTICAST_LOOP, 0)?;

        let device = CString::new(iface).map_err(io::Error::other)?;
        check(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                device.as_ptr().cast(),
                device.as_bytes_with_nul().len() as libc::socklen_t,
            )
        })?;

        // A receive timeout turns the whole state machine into one loop: wait
        // briefly for a packet, then check the timers. No second thread, so
        // nothing about the measurement depends on thread scheduling.
        let timeout = libc::timeval {
            tv_sec: recv_timeout_ms / 1000,
            tv_usec: ((recv_timeout_ms % 1000) * 1000) as libc::suseconds_t,
        };
        check(unsafe {
            libc::setsockopt(
                fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                (&raw const timeout).cast(),
                mem::size_of::<libc::timeval>() as libc::socklen_t,
            )
        })?;

        if join_group {
            let mreq = libc::ip_mreqn {
                imr_multiaddr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(VRRP_GROUP.octets()),
                },
                imr_address: libc::in_addr { s_addr: 0 },
                imr_ifindex: Interface::lookup(iface)?.index as libc::c_int,
            };
            check(unsafe {
                libc::setsockopt(
                    fd.as_raw_fd(),
                    libc::IPPROTO_IP,
                    libc::IP_ADD_MEMBERSHIP,
                    (&raw const mreq).cast(),
                    mem::size_of::<libc::ip_mreqn>() as libc::socklen_t,
                )
            })?;
        }

        Ok(Self { fd })
    }

    pub fn send_to(&self, payload: &[u8], dst: Ipv4Addr) -> io::Result<()> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(dst.octets()),
            },
            sin_zero: [0; 8],
        };
        check(unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                payload.as_ptr().cast(),
                payload.len(),
                0,
                (&raw const addr).cast(),
                mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) as libc::c_int
        })?;
        Ok(())
    }

    /// Returns `None` when the receive timed out, which is the normal case on
    /// most iterations. A raw socket hands back the IP header as well, so the
    /// payload starts after it.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<Option<(Ipv4Addr, packet::Advertisement)>> {
        let n = unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if n < 0 {
            let err = io::Error::last_os_error();
            return match err.kind() {
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => Ok(None),
                _ => Err(err),
            };
        }

        let n = n as usize;
        if n < 20 {
            return Ok(None);
        }
        let header_len = usize::from(buf[0] & 0x0f) * 4;
        if header_len < 20 || n <= header_len {
            return Ok(None);
        }
        let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
        Ok(packet::Advertisement::decode(&buf[header_len..n]).map(|adv| (src, adv)))
    }
}

/// Adds the VIP to the interface through rtnetlink.
pub fn add_vip(iface: &Interface, vip: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    netlink_addr(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        iface,
        vip,
        prefix_len,
    )
}

/// Removes the VIP again. The caller decides what a missing address means; this
/// function reports the kernel's answer instead of hiding it.
pub fn del_vip(iface: &Interface, vip: Ipv4Addr, prefix_len: u8) -> io::Result<()> {
    netlink_addr(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, iface, vip, prefix_len)
}

fn netlink_addr(
    kind: u16,
    flags: u16,
    iface: &Interface,
    vip: Ipv4Addr,
    prefix_len: u8,
) -> io::Result<()> {
    let raw = check(unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) })?;
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut local: libc::sockaddr_nl = unsafe { mem::zeroed() };
    local.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    check(unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const local).cast(),
            mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    })?;

    let mut msg = Vec::with_capacity(40);
    // nlmsghdr. The length is patched in once the body is known.
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&flags.to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // sequence
    msg.extend_from_slice(&0u32.to_ne_bytes()); // port, the kernel fills it in
    // ifaddrmsg
    msg.push(libc::AF_INET as u8);
    msg.push(prefix_len);
    msg.push(0); // ifa_flags
    msg.push(RT_SCOPE_UNIVERSE);
    msg.extend_from_slice(&iface.index.to_ne_bytes());
    // IFA_LOCAL and IFA_ADDRESS carry the same value on a broadcast interface,
    // and leaving either one out makes the kernel reject the message.
    for attr in [IFA_LOCAL, IFA_ADDRESS] {
        msg.extend_from_slice(&8u16.to_ne_bytes());
        msg.extend_from_slice(&attr.to_ne_bytes());
        msg.extend_from_slice(&vip.octets());
    }
    let len = msg.len() as u32;
    msg[0..4].copy_from_slice(&len.to_ne_bytes());

    check(unsafe {
        libc::send(fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) as libc::c_int
    })?;

    // The ACK is the only place the kernel reports a rejection, so it is read
    // rather than assumed.
    let mut reply = [0u8; 256];
    let n = check(unsafe {
        libc::recv(fd.as_raw_fd(), reply.as_mut_ptr().cast(), reply.len(), 0) as libc::c_int
    })? as usize;
    if n < 20 {
        return Err(io::Error::other("netlink: truncated reply"));
    }
    let reply_kind = u16::from_ne_bytes([reply[4], reply[5]]);
    if reply_kind != NLMSG_ERROR {
        return Err(io::Error::other(format!("netlink: unexpected reply {reply_kind}")));
    }
    let code = i32::from_ne_bytes([reply[16], reply[17], reply[18], reply[19]]);
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(-code))
    }
}

/// Broadcasts a gratuitous ARP reply for the VIP over AF_PACKET.
///
/// This is the step that makes the move visible to the switch. Skipping it
/// leaves the VIP configured on the new master while frames keep arriving at
/// the old one, which is why T-010 measures it on its own.
pub fn send_gratuitous_arp(iface: &Interface, vip: Ipv4Addr) -> io::Result<()> {
    let protocol = (libc::ETH_P_ARP as u16).to_be();
    let raw =
        check(unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, i32::from(protocol)) })?;
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };

    let mut addr: libc::sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = libc::AF_PACKET as libc::c_ushort;
    addr.sll_protocol = protocol;
    addr.sll_ifindex = iface.index as libc::c_int;
    addr.sll_halen = 6;
    addr.sll_addr[..6].copy_from_slice(&[0xff; 6]);

    let frame = packet::gratuitous_arp(iface.mac, vip);
    check(unsafe {
        libc::sendto(
            fd.as_raw_fd(),
            frame.as_ptr().cast(),
            frame.len(),
            0,
            (&raw const addr).cast(),
            mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
        ) as libc::c_int
    })?;
    Ok(())
}

fn set_int(fd: &OwnedFd, level: libc::c_int, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    check(unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            level,
            name,
            (&raw const value).cast(),
            mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })?;
    Ok(())
}
