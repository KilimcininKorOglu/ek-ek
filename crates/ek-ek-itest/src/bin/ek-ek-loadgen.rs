// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTP load generator that runs inside a node container.
//!
//! It opens a fresh connection per request and asks the server to close it, so
//! every request exercises the whole path: accept, route, respond. A pool of
//! reused connections would hide exactly the failure a graceful upgrade has to
//! avoid, because an already open connection survives a handover that a new one
//! would not.
//!
//! It reports failures separately from requests sent, and keeps the first error
//! text, so a report says what went wrong instead of only how often.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::process::ExitCode;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_secs(3);

struct Settings {
    target: SocketAddr,
    host: String,
    rate: u32,
    duration: Duration,
    path: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ek-ek-loadgen: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let settings = parse_arguments()?;
    let mut report = generate(&settings);
    report.latencies_us.sort_unstable();

    println!("sent={}", report.sent);
    println!("failed={}", report.failed);
    println!("p50_ms={:.3}", percentile(&report.latencies_us, 50.0));
    println!("p95_ms={:.3}", percentile(&report.latencies_us, 95.0));
    println!("max_ms={:.3}", percentile(&report.latencies_us, 100.0));
    println!("first_error={}", report.first_error.unwrap_or_default());
    Ok(())
}

struct Raw {
    sent: u64,
    failed: u64,
    latencies_us: Vec<u128>,
    first_error: Option<String>,
}

fn generate(settings: &Settings) -> Raw {
    let mut raw = Raw {
        sent: 0,
        failed: 0,
        latencies_us: Vec::new(),
        first_error: None,
    };

    let start = Instant::now();
    let interval = Duration::from_secs_f64(1.0 / f64::from(settings.rate.max(1)));

    let mut index: u32 = 0;
    while start.elapsed() < settings.duration {
        // Paced against the start rather than the previous request, so a slow
        // response does not quietly lower the rate for the rest of the run.
        let due = start + interval * index;
        let now = Instant::now();
        if due > now {
            std::thread::sleep(due - now);
        }
        index = index.saturating_add(1);

        let began = Instant::now();
        raw.sent += 1;
        match request(settings) {
            Ok(()) => raw.latencies_us.push(began.elapsed().as_micros()),
            Err(message) => {
                raw.failed += 1;
                if raw.first_error.is_none() {
                    raw.first_error = Some(message.replace(['\n', '\r'], " "));
                }
            }
        }
    }
    raw
}

fn request(settings: &Settings) -> Result<(), String> {
    let mut stream = TcpStream::connect_timeout(&settings.target, CONNECT_TIMEOUT)
        .map_err(|e| format!("connect: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|e| format!("read timeout: {e}"))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|e| format!("write timeout: {e}"))?;

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        settings.path, settings.host
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {e}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("read: {e}"))?;

    let head = String::from_utf8_lossy(&response[..response.len().min(64)]).into_owned();
    let status_ok = head.starts_with("HTTP/1.1 2") || head.starts_with("HTTP/1.0 2");
    if status_ok {
        Ok(())
    } else if head.is_empty() {
        Err("empty response".to_string())
    } else {
        Err(format!(
            "unexpected status: {}",
            head.lines().next().unwrap_or(&head)
        ))
    }
}

/// Reads one percentile out of already sorted microsecond samples.
fn percentile(sorted: &[u128], percent: f64) -> f64 {
    let Some(last) = sorted.len().checked_sub(1) else {
        return 0.0;
    };
    let rank = ((percent / 100.0) * last as f64).round() as usize;
    let picked = sorted.get(rank.min(last)).copied().unwrap_or(0);
    picked as f64 / 1000.0
}

fn parse_arguments() -> Result<Settings, String> {
    let mut target = None;
    let mut rate = 100u32;
    let mut duration_ms = 5_000u64;
    let mut path = "/".to_string();

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut index = 0;
    while index < arguments.len() {
        let flag = arguments[index].as_str();
        let value = arguments
            .get(index + 1)
            .ok_or_else(|| format!("{flag} needs a value"))?;
        match flag {
            "--target" => target = Some(value.clone()),
            "--rate" => rate = value.parse().map_err(|_| format!("bad rate {value:?}"))?,
            "--duration-ms" => {
                duration_ms = value
                    .parse()
                    .map_err(|_| format!("bad duration {value:?}"))?;
            }
            "--path" => path = value.clone(),
            other => return Err(format!("unknown option {other:?}")),
        }
        index += 2;
    }

    let target = target.ok_or("--target is required")?;
    let resolved = target
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {target:?}: {e}"))?
        .next()
        .ok_or_else(|| format!("{target:?} resolved to nothing"))?;

    Ok(Settings {
        target: resolved,
        host: target,
        rate,
        duration: Duration::from_millis(duration_ms),
        path,
    })
}
