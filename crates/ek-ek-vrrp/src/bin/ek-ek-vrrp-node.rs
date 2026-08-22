// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs one virtual router and says what it does.
//!
//! Every setting arrives as an argument rather than from a configuration
//! document, because the numbers a document would hold are computed from the
//! preferred node and do not exist yet (T-034). The loop, the sockets and the
//! records here are the ones the node agent will use.
//!
//! State changes are written to standard output as one JSON object per line,
//! the same shape the rest of the product writes (ADR-0037). Whatever reads
//! them parses the line; nothing here returns a value for a test to inspect.
//!
//! ```text
//! ek-ek-vrrp-node --address 172.28.0.11 --peer 172.28.0.12 \
//!     --interface eth0 --virtual-address 172.28.0.100/24 \
//!     --vrid 51 --priority 200
//! ```

#[cfg(target_os = "linux")]
use std::collections::VecDeque;
#[cfg(target_os = "linux")]
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::{Instant, SystemTime};

use ek_ek_vrrp::Settings;
#[cfg(target_os = "linux")]
use ek_ek_vrrp::{Action, Carried, Carrier, Machine, Transport};

/// How often the loop looks at its timers.
///
/// Short against the advertisement interval, so a deadline is acted on within
/// a fraction of it rather than at the next multiple of the tick (ADR-0029).
#[cfg(target_os = "linux")]
const TICK: Duration = Duration::from_millis(10);

/// Everything one virtual router was asked to be.
///
/// Read where the sockets are, which is Linux. The arguments are still read
/// everywhere, so a wrong one is refused with the same sentence on any
/// machine rather than only where it could have run.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Options {
    /// What the state machine needs.
    settings: Settings,
    /// Interface the addresses are put on.
    interface: String,
    /// Addresses this node carries while it holds the role.
    carried: Vec<Carrying>,
    /// Whether announcing is switched off.
    silent: bool,
}

/// One address and how much of it is the network.
///
/// Held here rather than taken from the crate, because the type that carries
/// it only exists on Linux and the arguments are read everywhere.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
struct Carrying {
    address: IpAddr,
    prefix_length: u8,
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let options = match read(&arguments) {
        Ok(options) => options,
        Err(complaint) => {
            eprintln!("ek-ek-vrrp-node: {complaint}");
            return ExitCode::FAILURE;
        }
    };

    #[cfg(target_os = "linux")]
    let transport = match ek_ek_vrrp::RawSocket::open() {
        Ok(socket) => socket,
        Err(error) => {
            eprintln!("ek-ek-vrrp-node: the raw socket could not be opened: {error}");
            eprintln!("ek-ek-vrrp-node: VRRP is IP protocol 112 and needs CAP_NET_RAW");
            return ExitCode::FAILURE;
        }
    };
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!(
            "ek-ek-vrrp-node: virtual router {} cannot run here; VRRP is IP protocol 112, \
             its addresses move over netlink, and both need Linux with CAP_NET_RAW and \
             CAP_NET_ADMIN",
            options.settings.vrid
        );
        ExitCode::FAILURE
    }

    #[cfg(target_os = "linux")]
    run(options, &transport)
}

/// Drives one machine until the process is stopped.
#[cfg(target_os = "linux")]
fn run(options: Options, transport: &impl Transport) -> ExitCode {
    let Options {
        settings,
        interface,
        carried,
        silent,
    } = options;

    let carried = carried
        .into_iter()
        .map(|one| Carried {
            address: one.address,
            prefix_length: one.prefix_length,
        })
        .collect();
    let mut carrier = match Carrier::open(&interface, carried, silent) {
        Ok(carrier) => carrier,
        Err(error) => {
            eprintln!("ek-ek-vrrp-node: {interface} could not be used: {error}");
            eprintln!(
                "ek-ek-vrrp-node: moving an address needs CAP_NET_ADMIN and sending a frame \
                 needs CAP_NET_RAW"
            );
            return ExitCode::FAILURE;
        }
    };

    let peers = settings.peers.clone();
    let mut machine = Machine::new(settings);
    // When an advertisement was last acted on. A takeover is timed from the
    // last one the dying master sent, and reading both moments off the same
    // clock in the same process is what makes the difference a failover time
    // rather than the spread between two machines (T-010).
    let mut heard_at = 0_u128;

    let now = Instant::now();
    let starting = machine.start(now);
    carry_out(
        &mut machine,
        &mut carrier,
        starting,
        transport,
        &peers,
        heard_at,
        now,
    );

    loop {
        let now = Instant::now();

        // Everything waiting is taken before the timers, so a takeover is
        // decided on what has already arrived.
        loop {
            match transport.receive() {
                Ok(Some((from, bytes))) => {
                    let before = machine.accepted();
                    let actions = machine.receive(from, &bytes, now);
                    if machine.accepted() > before {
                        heard_at = milliseconds();
                    }
                    carry_out(
                        &mut machine,
                        &mut carrier,
                        actions,
                        transport,
                        &peers,
                        heard_at,
                        now,
                    );
                }
                Ok(None) => break,
                Err(error) => {
                    say(&format!(
                        r#"{{"kind":"app","level":"error","target":"ek_ek_vrrp","message":"the socket could not be read: {}"}}"#,
                        escaped(&error.to_string())
                    ));
                    break;
                }
            }
        }

        let actions = machine.tick(now);
        carry_out(
            &mut machine,
            &mut carrier,
            actions,
            transport,
            &peers,
            heard_at,
            now,
        );

        // The announcement is spread over the loop rather than sent in one
        // block, so the advertisement and the socket read are not held for
        // the length of it (ADR-0029).
        if let Err(error) = carrier.tick(now) {
            say(&format!(
                r#"{{"kind":"vip","ts":{},"event":"announcement_failed","error":"{}"}}"#,
                milliseconds(),
                escaped(&error.to_string())
            ));
        }

        std::thread::sleep(TICK);
    }
}

/// Does what the machine asked for.
///
/// The actions are a queue rather than a list, because failing to take the
/// addresses makes the machine stand the node down and that produces more to
/// do. Standing down cannot ask to take them again, so the queue empties.
#[cfg(target_os = "linux")]
fn carry_out(
    machine: &mut Machine,
    carrier: &mut Carrier,
    actions: Vec<Action>,
    transport: &impl Transport,
    peers: &[Ipv4Addr],
    heard_at: u128,
    now: Instant,
) {
    let mut queue: VecDeque<Action> = actions.into();
    while let Some(action) = queue.pop_front() {
        match action {
            Action::Advertise(advertisement) => {
                for peer in peers {
                    // Encoded once per peer: the checksum covers the
                    // destination, so one peer's bytes are refused by another.
                    let bytes = advertisement.encode(machine.settings().address, *peer);
                    if let Err(error) = transport.send(*peer, &bytes) {
                        say(&format!(
                            r#"{{"kind":"app","level":"warn","target":"ek_ek_vrrp","message":"advertisement to {peer} did not go: {}"}}"#,
                            escaped(&error.to_string())
                        ));
                    }
                }
            }
            Action::Record(transition) => say(&format!(
                r#"{{"kind":"vrrp","ts":{},"heard":{},"vrid":{},"from":"{}","to":"{}","reason":"{}","address":"{}"}}"#,
                milliseconds(),
                heard_at,
                machine.settings().vrid,
                transition.from.name(),
                transition.to.name(),
                transition.reason.name(),
                machine.settings().address,
            )),
            Action::TakeAddresses => match carrier.take(now) {
                Ok(()) => say(&format!(
                    r#"{{"kind":"vip","ts":{},"event":"taken","addresses":{}}}"#,
                    milliseconds(),
                    listed(carrier)
                )),
                Err(error) => {
                    // A master without its addresses answers nothing and its
                    // advertisements stop every other node from answering
                    // either. Standing down turns a silent outage into a
                    // takeover.
                    say(&format!(
                        r#"{{"kind":"vip","ts":{},"event":"take_failed","error":"{}","addresses":{}}}"#,
                        milliseconds(),
                        escaped(&error.to_string()),
                        listed(carrier)
                    ));
                    queue.extend(machine.renounce(now));
                }
            },
            Action::DropAddresses => match carrier.drop_all() {
                Ok(()) => say(&format!(
                    r#"{{"kind":"vip","ts":{},"event":"dropped","addresses":{}}}"#,
                    milliseconds(),
                    listed(carrier)
                )),
                Err(error) => say(&format!(
                    r#"{{"kind":"vip","ts":{},"event":"drop_failed","error":"{}","addresses":{}}}"#,
                    milliseconds(),
                    escaped(&error.to_string()),
                    listed(carrier)
                )),
            },
        }
    }
}

/// The carried addresses as a JSON array.
#[cfg(target_os = "linux")]
fn listed(carrier: &Carrier) -> String {
    let inside: Vec<String> = carrier
        .addresses()
        .iter()
        .map(|carried| format!(r#""{}/{}""#, carried.address, carried.prefix_length))
        .collect();
    format!("[{}]", inside.join(","))
}

/// A string with the two characters JSON refuses inside one escaped.
///
/// An operating system message is written by somebody else and can hold
/// anything. A quote in it would end the field and leave a line nothing can
/// parse, which is exactly the line a failure has to be read from.
#[cfg(target_os = "linux")]
fn escaped(text: &str) -> String {
    text.replace('\\', r"\\").replace('"', "\\\"")
}

/// Writes one line and makes sure it left.
///
/// Flushed on purpose: a reader watching the stream for a transition would
/// otherwise see it whenever the buffer happened to fill, which is exactly
/// the moment a failover measurement is trying to time.
#[cfg(target_os = "linux")]
fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Milliseconds since the epoch, which is what a failover is timed in.
#[cfg(target_os = "linux")]
fn milliseconds() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis())
}

/// Reads the settings out of the arguments.
///
/// # Errors
///
/// Returns a sentence naming what is missing or unreadable.
fn read(arguments: &[String]) -> Result<Options, String> {
    let mut address = None;
    let mut peers = Vec::new();
    let mut carried: Vec<Carrying> = Vec::new();
    let mut interface = "eth0".to_owned();
    let mut vrid = 51_u8;
    let mut priority = 100_u8;
    let mut interval = Duration::from_millis(300);
    let mut preempt = true;
    let mut silent = false;

    let mut rest = arguments.iter().skip(1);
    while let Some(name) = rest.next() {
        match name.as_str() {
            "--address" => address = Some(number(rest.next(), "--address")?),
            "--peer" => peers.push(number(rest.next(), "--peer")?),
            "--interface" => {
                interface = rest
                    .next()
                    .ok_or_else(|| "--interface needs a value".to_owned())?
                    .clone();
            }
            "--virtual-address" => carried.push(carrying(rest.next())?),
            "--vrid" => vrid = parse(rest.next(), "--vrid")?,
            "--priority" => priority = parse(rest.next(), "--priority")?,
            "--interval-ms" => {
                interval = Duration::from_millis(parse(rest.next(), "--interval-ms")?);
            }
            "--no-preempt" => preempt = false,
            // The negative control. Without it there is no way to tell an
            // announcement that moved a cache from a cache that was going to
            // name this node anyway (T-010).
            "--silent" => silent = true,
            other => return Err(format!("{other} is not an argument this understands")),
        }
    }

    let address = address.ok_or_else(|| "--address is required".to_owned())?;
    if peers.is_empty() {
        return Err("at least one --peer is required; multicast is not offered".to_owned());
    }
    if carried.is_empty() {
        return Err("at least one --virtual-address is required".to_owned());
    }

    // RFC 5798 keeps one virtual router to one address family, so only the
    // IPv4 addresses go in the advertisement. Every one of them is carried on
    // the interface, which is where an IPv6 virtual address lives.
    let virtual_addresses = carried
        .iter()
        .filter_map(|one| match one.address {
            IpAddr::V4(address) => Some(address),
            IpAddr::V6(_) => None,
        })
        .collect();

    Ok(Options {
        settings: Settings {
            vrid,
            priority,
            interval,
            preempt,
            address,
            virtual_addresses,
            peers,
        },
        interface,
        carried,
        silent,
    })
}

/// Reads an address and prefix length argument, written `address/prefix`.
fn carrying(value: Option<&String>) -> Result<Carrying, String> {
    let text = value.ok_or_else(|| "--virtual-address needs a value".to_owned())?;
    let (address, prefix) = text.split_once('/').ok_or_else(|| {
        format!("--virtual-address needs a prefix length, as in {text}/24, and {text} has none")
    })?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| format!("{address} is not an IP address"))?;
    let prefix_length: u8 = prefix
        .parse()
        .map_err(|_| format!("{prefix} is not a prefix length"))?;

    let widest = if address.is_ipv4() { 32 } else { 128 };
    if prefix_length > widest {
        return Err(format!(
            "a prefix length of {prefix_length} is wider than the {widest} bits {address} has"
        ));
    }
    Ok(Carrying {
        address,
        prefix_length,
    })
}

/// Reads an address argument.
fn number(value: Option<&String>, name: &str) -> Result<Ipv4Addr, String> {
    value
        .ok_or_else(|| format!("{name} needs a value"))?
        .parse()
        .map_err(|_| format!("{name} needs an IPv4 address"))
}

/// Reads a numeric argument.
fn parse<T: std::str::FromStr>(value: Option<&String>, name: &str) -> Result<T, String> {
    value
        .ok_or_else(|| format!("{name} needs a value"))?
        .parse()
        .map_err(|_| format!("{name} needs a number"))
}
