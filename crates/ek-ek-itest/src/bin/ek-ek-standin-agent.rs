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
//! Written against the standard library alone, like everything else in the
//! harness, so it can never quietly share a type with the product it measures
//! (ADR-0014).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::process::ExitCode;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ek-ek-standin-agent: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut socket = None;
    let mut config = None;

    let mut arguments = std::env::args().skip(1);
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--socket" => socket = arguments.next(),
            "--config" => config = arguments.next(),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    let socket = socket.ok_or("--socket is required")?;
    let config = config.ok_or("--config is required")?;
    let document = std::fs::read_to_string(&config)
        .map_err(|error| format!("cannot read {config}: {error}"))?;
    let delivery = format!(
        r#"{{"message":"config","generation":1,"config":{},"certificates":{{}}}}"#,
        document.trim()
    );

    // A leftover socket from a previous run would make the bind fail, and the
    // traffic path would then connect to nothing.
    let _ = std::fs::remove_file(&socket);
    let listener =
        UnixListener::bind(&socket).map_err(|error| format!("cannot bind {socket}: {error}"))?;
    println!("listening on {socket}");

    for stream in listener.incoming() {
        let stream = stream.map_err(|error| format!("cannot accept: {error}"))?;
        let delivery = delivery.clone();
        std::thread::spawn(move || serve(stream, &delivery));
    }
    Ok(())
}

/// Answers one traffic path connection.
///
/// The traffic path greets first and says which generation it already holds.
/// Only a connection holding nothing needs the configuration sent to it; the
/// long lived one that follows is left alone.
fn serve(stream: UnixStream, delivery: &str) {
    let Ok(reader) = stream.try_clone() else {
        return;
    };
    let mut writer = stream;
    let mut lines = BufReader::new(reader).lines();

    let Some(Ok(hello)) = lines.next() else {
        return;
    };
    if hello.contains(r#""generation":null"#) {
        if writer.write_all(delivery.as_bytes()).is_err() || writer.write_all(b"\n").is_err() {
            return;
        }
        let _ = writer.flush();
    }

    // Status reports keep arriving for as long as the link is up. They are
    // read and dropped: a socket nobody drains eventually blocks the sender.
    for line in lines {
        if line.is_err() {
            return;
        }
    }
}
