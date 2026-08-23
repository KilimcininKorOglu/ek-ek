// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A stand-in `node-agent` that runs inside a node container.
//!
//! The traffic path takes its configuration from an agent over a unix socket
//! and will not start without one (ADR-0002). The real agent is not written
//! yet, so a test that has to run the real traffic path in a container needs
//! something on the other end of that socket.
//!
//! It holds no opinion about the configuration: the file is passed through
//! byte for byte, so a test that writes an invalid document measures what the
//! traffic path does with it rather than what this would have done first.
//!
//! # The challenge file
//!
//! With `--challenges`, it watches a file and delivers the configuration again
//! whenever the contents change. That is what the real agent will do from its
//! own memory: an ACME order publishes the answers it is waiting on, and the
//! traffic path has to be serving them before the certificate authority comes
//! to read them (ADR-0026). Splitting it across a file is what lets two
//! processes stand in for the one that does not exist yet.
//!
//! Written against the standard library alone, like everything else in the
//! harness, so it can never quietly share a type with the product it measures
//! (ADR-0014).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// How often the challenge file is read.
///
/// Short, because an ACME server comes to check the moment it is told to and
/// the answer has to be live by then.
const WATCH_INTERVAL: Duration = Duration::from_millis(100);

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ek-ek-standin-agent: {message}");
            ExitCode::FAILURE
        }
    }
}

/// What the agent delivers, and what it watches for a change.
struct Delivery {
    config: String,
    challenges: Option<String>,
}

impl Delivery {
    /// The current challenge answers, as a JSON object.
    ///
    /// An absent or unreadable file counts as no challenge, which is the
    /// normal state: the order writes the file, and there is no order most of
    /// the time.
    fn challenges(&self) -> String {
        let Some(path) = &self.challenges else {
            return "{}".to_owned();
        };
        let read = std::fs::read_to_string(path).unwrap_or_default();
        let trimmed = read.trim();
        if trimmed.is_empty() {
            "{}".to_owned()
        } else {
            trimmed.to_owned()
        }
    }

    /// One delivery, at a generation.
    fn line(&self, generation: u64) -> String {
        format!(
            r#"{{"message":"config","generation":{generation},"config":{},"certificates":{{}},"challenges":{}}}"#,
            self.config.trim(),
            self.challenges()
        )
    }
}

fn run() -> Result<(), String> {
    let mut socket = None;
    let mut config = None;
    let mut challenges = None;

    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => socket = arguments.next(),
            "--config" => config = arguments.next(),
            "--challenges" => challenges = arguments.next(),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let socket = socket.ok_or("--socket is required")?;
    let config = config.ok_or("--config is required")?;
    let document = std::fs::read_to_string(&config)
        .map_err(|error| format!("cannot read {config}: {error}"))?;
    let delivery = Arc::new(Delivery {
        config: document,
        challenges,
    });

    // A leftover socket from a previous run would make the bind fail, and the
    // traffic path would then connect to nothing.
    let _ = std::fs::remove_file(&socket);
    let listener =
        UnixListener::bind(&socket).map_err(|error| format!("cannot bind {socket}: {error}"))?;
    println!("listening on {socket}");

    for stream in listener.incoming() {
        let stream = stream.map_err(|error| format!("cannot accept: {error}"))?;
        let delivery = Arc::clone(&delivery);
        std::thread::spawn(move || serve(stream, &delivery));
    }
    Ok(())
}

/// Answers one traffic path connection.
///
/// The traffic path greets first and says which generation it already holds.
/// Only a connection holding nothing needs the configuration sent to it; the
/// long lived one that follows is left alone until the challenge answers
/// change under it.
fn serve(stream: UnixStream, delivery: &Delivery) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let mut writer = stream;
    let mut lines = BufReader::new(reader).lines();

    let Some(Ok(hello)) = lines.next() else {
        return;
    };

    // Taken from the greeting, so a redelivery is never numbered below what
    // the traffic path already holds.
    let mut generation = held(&hello).unwrap_or(0) + 1;
    let mut sent = delivery.challenges();
    if hello.contains(r#""generation":null"#)
        && send(&mut writer, &delivery.line(generation)).is_err()
    {
        return;
    }

    if delivery.challenges.is_none() {
        // Nothing to watch. Status reports keep arriving for as long as the
        // link is up; they are read and dropped, because a socket nobody
        // drains eventually blocks the sender.
        for line in lines {
            if line.is_err() {
                return;
            }
        }
        return;
    }

    std::thread::spawn(move || {
        for line in lines {
            if line.is_err() {
                return;
            }
        }
    });

    loop {
        std::thread::sleep(WATCH_INTERVAL);
        let now = delivery.challenges();
        if now == sent {
            continue;
        }
        generation += 1;
        if send(&mut writer, &delivery.line(generation)).is_err() {
            return;
        }
        eprintln!("delivered generation {generation}");
        sent = now;
    }
}

/// The generation the traffic path says it already holds, if any.
fn held(hello: &str) -> Option<u64> {
    let rest = hello.split(r#""generation":"#).nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn send(writer: &mut UnixStream, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}
