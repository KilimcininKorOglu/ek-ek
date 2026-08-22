// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Runs one virtual router and says what it does.
//!
//! Every setting arrives as an argument rather than from a configuration
//! document, because the numbers a document would hold are computed from the
//! preferred node and do not exist yet (T-034). The loop, the socket and the
//! records here are the ones the node agent will use.
//!
//! State changes are written to standard output as one JSON object per line,
//! the same shape the rest of the product writes (ADR-0037). Whatever reads
//! them parses the line; nothing here returns a value for a test to inspect.
//!
//! ```text
//! ek-ek-vrrp-node --address 172.28.0.11 --peer 172.28.0.12 \
//!     --virtual-address 172.28.0.100 --vrid 51 --priority 200
//! ```

#[cfg(target_os = "linux")]
use std::io::Write;
use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::SystemTime;

#[cfg(target_os = "linux")]
use std::time::Instant;

use ek_ek_vrrp::Settings;
#[cfg(target_os = "linux")]
use ek_ek_vrrp::{Action, Machine, Transport};

/// How often the loop looks at its timers.
///
/// Short against the advertisement interval, so a deadline is acted on within
/// a fraction of it rather than at the next multiple of the tick (ADR-0029).
#[cfg(target_os = "linux")]
const TICK: Duration = Duration::from_millis(10);

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().collect();
    let settings = match read(&arguments) {
        Ok(settings) => settings,
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
            "ek-ek-vrrp-node: virtual router {} cannot run here; VRRP is IP protocol 112 \
             and its socket needs Linux and CAP_NET_RAW",
            settings.vrid
        );
        ExitCode::FAILURE
    }

    #[cfg(target_os = "linux")]
    run(settings, &transport)
}

/// Drives one machine until the process is stopped.
#[cfg(target_os = "linux")]
fn run(settings: Settings, transport: &impl Transport) -> ExitCode {
    let peers = settings.peers.clone();
    let mut machine = Machine::new(settings);
    // When an advertisement was last acted on. A takeover is timed from the
    // last one the dying master sent, and reading both moments off the same
    // clock in the same process is what makes the difference a failover time
    // rather than the spread between two machines (T-010).
    let mut heard_at = 0_u128;

    let starting = machine.start(Instant::now());
    carry_out(&machine, &starting, transport, &peers, heard_at);

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
                    carry_out(&machine, &actions, transport, &peers, heard_at);
                }
                Ok(None) => break,
                Err(error) => {
                    say(&format!(
                        r#"{{"kind":"app","level":"error","target":"ek_ek_vrrp","message":"the socket could not be read: {error}"}}"#
                    ));
                    break;
                }
            }
        }

        let actions = machine.tick(now);
        carry_out(&machine, &actions, transport, &peers, heard_at);

        std::thread::sleep(TICK);
    }
}

/// Does what the machine asked for.
#[cfg(target_os = "linux")]
fn carry_out(
    machine: &Machine,
    actions: &[Action],
    transport: &impl Transport,
    peers: &[Ipv4Addr],
    heard_at: u128,
) {
    for action in actions {
        match action {
            Action::Advertise(advertisement) => {
                for peer in peers {
                    // Encoded once per peer: the checksum covers the
                    // destination, so one peer's bytes are refused by another.
                    let bytes = advertisement.encode(machine.settings().address, *peer);
                    if let Err(error) = transport.send(*peer, &bytes) {
                        say(&format!(
                            r#"{{"kind":"app","level":"warn","target":"ek_ek_vrrp","message":"advertisement to {peer} did not go: {error}"}}"#
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
        }
    }
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
fn read(arguments: &[String]) -> Result<Settings, String> {
    let mut address = None;
    let mut peers = Vec::new();
    let mut virtual_addresses = Vec::new();
    let mut vrid = 51_u8;
    let mut priority = 100_u8;
    let mut interval = Duration::from_millis(300);
    let mut preempt = true;

    let mut rest = arguments.iter().skip(1);
    while let Some(name) = rest.next() {
        match name.as_str() {
            "--address" => address = Some(number(rest.next(), "--address")?),
            "--peer" => peers.push(number(rest.next(), "--peer")?),
            "--virtual-address" => {
                virtual_addresses.push(number(rest.next(), "--virtual-address")?);
            }
            "--vrid" => vrid = parse(rest.next(), "--vrid")?,
            "--priority" => priority = parse(rest.next(), "--priority")?,
            "--interval-ms" => {
                interval = Duration::from_millis(parse(rest.next(), "--interval-ms")?);
            }
            "--no-preempt" => preempt = false,
            other => return Err(format!("{other} is not an argument this understands")),
        }
    }

    let address = address.ok_or_else(|| "--address is required".to_owned())?;
    if peers.is_empty() {
        return Err("at least one --peer is required; multicast is not offered".to_owned());
    }
    if virtual_addresses.is_empty() {
        return Err("at least one --virtual-address is required".to_owned());
    }

    Ok(Settings {
        vrid,
        priority,
        interval,
        preempt,
        address,
        virtual_addresses,
        peers,
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
