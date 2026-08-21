// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Running one health check probe against one member.
//!
//! Four probe types and nothing else (ADR-0020). A probe that runs an external
//! script is not one of them: it would turn a health check into arbitrary code
//! execution on every node, reachable by anyone who can edit a backend pool.
//!
//! # What a probe decides
//!
//! A probe answers one question: did this member give a good answer just now.
//! It never decides whether the member is healthy. Turning a run of answers
//! into a state is the checker's job, because that needs thresholds and the
//! member's previous state.
//!
//! # Timeouts
//!
//! Every probe is run under one timeout covering connect, write and read
//! together. A probe that connected quickly and then hung would otherwise
//! outlive its own interval and overlap the next one.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ek_ek_config::{DnsRecordType, HealthProbe, ProbePayload, TransportProtocol};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

/// How much of an answer is read before giving up looking for the expected
/// data.
///
/// A banner or a small response fits easily. Reading without a bound would let
/// a member that streams forever hold the probe until its timeout.
const MOST: usize = 8 * 1024;

/// Identifies health check traffic in a backend's own logs.
///
/// Without it an operator cannot tell a probe from a real request, and a quiet
/// service looks busy for no reason.
pub const PROBE_AGENT: &str = "ek-ek-health/1";

/// What one probe run produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The member answered as expected.
    Good,
    /// The member did not. The reason is kept for the log, never shown to a
    /// client.
    Bad(String),
}

impl Outcome {
    /// Returns whether this run counts as a success.
    #[must_use]
    pub const fn is_good(&self) -> bool {
        matches!(self, Self::Good)
    }

    /// Builds a failure with a reason.
    fn bad(reason: impl Into<String>) -> Self {
        Self::Bad(reason.into())
    }
}

/// Decodes probe data into the bytes that go on the wire.
///
/// # Errors
///
/// Fails when hex data is not valid hex. Validation catches that first, so
/// reaching it here means something delivered a configuration unchecked.
pub fn payload(data: &ProbePayload) -> Result<Vec<u8>, String> {
    match data {
        ProbePayload::Text(text) => Ok(text.as_bytes().to_vec()),
        ProbePayload::Hex(digits) => {
            let cleaned: String = digits.chars().filter(|c| !c.is_whitespace()).collect();
            if !cleaned.len().is_multiple_of(2) {
                return Err("hex data has an odd number of digits".to_owned());
            }
            (0..cleaned.len())
                .step_by(2)
                .map(|at| {
                    u8::from_str_radix(&cleaned[at..at + 2], 16)
                        .map_err(|_| "hex data has a digit that is not hex".to_owned())
                })
                .collect()
        }
    }
}

/// Runs one probe against one member, under one timeout.
///
/// Returns [`Outcome::Bad`] rather than an error for every failure, because a
/// member that cannot be reached and a member that answers wrongly are the
/// same thing to the caller: this run did not succeed.
pub async fn run(probe: &HealthProbe, address: IpAddr, port: u16, timeout: Duration) -> Outcome {
    let target = SocketAddr::new(address, port);
    let attempt = async {
        match probe {
            HealthProbe::TcpConnect => tcp_connect(target).await,
            HealthProbe::Http {
                path,
                expected_status,
                expected_body,
                host_header,
            } => {
                http(
                    target,
                    path,
                    expected_status,
                    expected_body.as_deref(),
                    host_header.as_deref(),
                )
                .await
            }
            HealthProbe::SendExpect {
                send,
                expect,
                transport,
            } => match transport {
                // The transport is named rather than inferred, because a DNS
                // pool is published from a TCP and a UDP frontend at once and
                // there would be no single answer to infer (ADR-0064).
                TransportProtocol::Tcp => send_expect_tcp(target, send, expect).await,
                TransportProtocol::Udp => send_expect_udp(target, send, expect).await,
            },
            HealthProbe::DnsQuery { name, record_type } => dns(target, name, *record_type).await,
        }
    };

    match tokio::time::timeout(timeout, attempt).await {
        Ok(outcome) => outcome,
        Err(_) => Outcome::bad("the probe did not finish within its timeout"),
    }
}

/// Opens a connection and closes it again.
async fn tcp_connect(target: SocketAddr) -> Outcome {
    match TcpStream::connect(target).await {
        Ok(stream) => {
            drop(stream);
            Outcome::Good
        }
        Err(error) => Outcome::bad(format!("the connection was refused: {error}")),
    }
}

/// Sends an HTTP request and inspects the answer.
async fn http(
    target: SocketAddr,
    path: &str,
    expected_status: &[u16],
    expected_body: Option<&str>,
    host_header: Option<&str>,
) -> Outcome {
    let Ok(mut stream) = TcpStream::connect(target).await else {
        return Outcome::bad("the connection was refused");
    };

    let host = host_header.map_or_else(|| target.to_string(), str::to_owned);
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {PROBE_AGENT}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    if stream.write_all(request.as_bytes()).await.is_err() {
        return Outcome::bad("the request could not be sent");
    }

    let answer = match read_http(&mut stream).await {
        Ok(answer) => answer,
        Err(reason) => return Outcome::bad(reason),
    };
    let text = String::from_utf8_lossy(&answer);

    let Some(status) = text
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
    else {
        return Outcome::bad("the answer had no status line");
    };
    if !expected_status.contains(&status) {
        return Outcome::bad(format!("the answer was {status}, which is not expected"));
    }

    if let Some(wanted) = expected_body {
        // The body starts after the blank line. Searching the whole answer
        // would let a header match stand in for a body match.
        let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
        if !body.contains(wanted) {
            return Outcome::bad("the body did not contain what was expected");
        }
    }

    Outcome::Good
}

/// Sends operator-supplied data over TCP and looks for the expected answer.
async fn send_expect_tcp(
    target: SocketAddr,
    send: &ProbePayload,
    expect: &ProbePayload,
) -> Outcome {
    let (send, expect) = match (payload(send), payload(expect)) {
        (Ok(send), Ok(expect)) => (send, expect),
        _ => return Outcome::bad("the probe data is not valid hex"),
    };

    let Ok(mut stream) = TcpStream::connect(target).await else {
        return Outcome::bad("the connection was refused");
    };
    if stream.write_all(&send).await.is_err() {
        return Outcome::bad("the probe data could not be sent");
    }

    match read_until(&mut stream, &expect).await {
        Ok(found) => {
            if found {
                Outcome::Good
            } else {
                Outcome::bad("the answer did not contain what was expected")
            }
        }
        Err(reason) => Outcome::bad(reason),
    }
}

/// Sends operator-supplied data over UDP and looks for the expected answer.
async fn send_expect_udp(
    target: SocketAddr,
    send: &ProbePayload,
    expect: &ProbePayload,
) -> Outcome {
    let (send, expect) = match (payload(send), payload(expect)) {
        (Ok(send), Ok(expect)) => (send, expect),
        _ => return Outcome::bad("the probe data is not valid hex"),
    };

    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return Outcome::bad("no local port was available");
    };
    if socket.send_to(&send, target).await.is_err() {
        return Outcome::bad("the probe data could not be sent");
    }

    let mut answer = vec![0_u8; MOST];
    match socket.recv_from(&mut answer).await {
        Ok((read, _)) => {
            if contains(&answer[..read], &expect) {
                Outcome::Good
            } else {
                Outcome::bad("the answer did not contain what was expected")
            }
        }
        // On UDP this is silence, which does not separate a broken member from
        // a lost packet. That is why ADR-0020 asks for a higher unhealthy
        // threshold here.
        Err(error) => Outcome::bad(format!("no answer arrived: {error}")),
    }
}

/// Sends a real DNS query and requires a valid answer.
async fn dns(target: SocketAddr, name: &str, record_type: DnsRecordType) -> Outcome {
    let Some(query) = dns_query(name, record_type) else {
        return Outcome::bad("the name cannot be put in a DNS query");
    };

    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind).await else {
        return Outcome::bad("no local port was available");
    };
    if socket.send_to(&query, target).await.is_err() {
        return Outcome::bad("the query could not be sent");
    }

    let mut answer = vec![0_u8; MOST];
    let Ok((read, _)) = socket.recv_from(&mut answer).await else {
        return Outcome::bad("no answer arrived");
    };
    check_dns_answer(&answer[..read], &query)
}

/// The transaction id every query this process builds carries.
///
/// Fixed rather than random: the socket is freshly bound and talks to one
/// address, so nothing else can arrive on it, and a fixed id keeps the probe
/// reproducible.
const DNS_ID: [u8; 2] = [0x2b, 0x1a];

/// Builds a DNS query packet.
fn dns_query(name: &str, record_type: DnsRecordType) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&DNS_ID);
    // Standard query, recursion desired.
    packet.extend_from_slice(&[0x01, 0x00]);
    // One question, no answers, no authority, no additional.
    packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        packet.push(u8::try_from(label.len()).ok()?);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);

    let code: u16 = match record_type {
        DnsRecordType::A => 1,
        DnsRecordType::Soa => 6,
        DnsRecordType::Aaaa => 28,
    };
    packet.extend_from_slice(&code.to_be_bytes());
    // Class IN.
    packet.extend_from_slice(&[0x00, 0x01]);
    Some(packet)
}

/// Decides whether a DNS answer counts as valid.
///
/// A name server that answers `SERVFAIL` is running but broken, which is
/// exactly the state a health check exists to catch, so the response code is
/// checked rather than only the fact that bytes came back.
fn check_dns_answer(answer: &[u8], query: &[u8]) -> Outcome {
    if answer.len() < 12 {
        return Outcome::bad("the answer is too short to be DNS");
    }
    if answer[0..2] != query[0..2] {
        return Outcome::bad("the answer belongs to another query");
    }
    // High bit of byte 2 is the response flag.
    if answer[2] & 0x80 == 0 {
        return Outcome::bad("the answer is not marked as a response");
    }
    let code = answer[3] & 0x0f;
    if code != 0 {
        return Outcome::bad(format!("the name server answered with code {code}"));
    }
    let answers = u16::from_be_bytes([answer[6], answer[7]]);
    let authority = u16::from_be_bytes([answer[8], answer[9]]);
    if answers == 0 && authority == 0 {
        return Outcome::bad("the answer carried no record");
    }
    Outcome::Good
}

/// Reads one HTTP answer and stops when it is complete.
///
/// Completeness comes from `Content-Length` rather than from the connection
/// closing. A backend that keeps the connection open, which most do, would
/// otherwise hold the probe until its timeout and be called unhealthy while
/// answering perfectly.
async fn read_http(stream: &mut TcpStream) -> Result<Vec<u8>, String> {
    let mut answer = Vec::new();
    let mut buffer = vec![0_u8; 4096];

    loop {
        match stream.read(&mut buffer).await {
            Ok(0) => return Ok(answer),
            Ok(read) => answer.extend_from_slice(&buffer[..read]),
            Err(error) => {
                if answer.is_empty() {
                    return Err(format!("nothing could be read: {error}"));
                }
                return Ok(answer);
            }
        }

        if answer.len() >= MOST {
            return Ok(answer);
        }
        if let Some(end) = header_end(&answer) {
            match content_length(&answer[..end]) {
                // The whole body has arrived.
                Some(length) if answer.len() >= end + length => return Ok(answer),
                // No length given: the answer ends when the connection does.
                None => {}
                Some(_) => {}
            }
        }
    }
}

/// Returns where the headers end, counting the blank line.
fn header_end(answer: &[u8]) -> Option<usize> {
    answer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|at| at + 4)
}

/// Reads `Content-Length` out of a header block.
fn content_length(headers: &[u8]) -> Option<usize> {
    String::from_utf8_lossy(headers)
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|value| value.trim().to_owned())
        })
        .and_then(|value| value.parse().ok())
}

/// Reads until the expected data appears, or the connection ends.
///
/// Stopping at the match rather than at the close is what makes this work
/// against a banner protocol: an SMTP or IMAP server sends its greeting and
/// then waits, so waiting for a close would always time out.
async fn read_until(stream: &mut TcpStream, expect: &[u8]) -> Result<bool, String> {
    let mut answer = Vec::new();
    let mut buffer = vec![0_u8; 4096];

    loop {
        if contains(&answer, expect) {
            return Ok(true);
        }
        match stream.read(&mut buffer).await {
            Ok(0) => return Ok(contains(&answer, expect)),
            Ok(read) => {
                answer.extend_from_slice(&buffer[..read]);
                if answer.len() >= MOST {
                    return Ok(contains(&answer, expect));
                }
            }
            Err(error) => {
                if answer.is_empty() {
                    return Err(format!("nothing could be read: {error}"));
                }
                return Ok(contains(&answer, expect));
            }
        }
    }
}

/// Whether one byte slice appears inside another.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
