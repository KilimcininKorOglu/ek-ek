// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Turning a peer message into a line and back.

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::error::{Failure, Reason};

/// The longest line a peer may send.
///
/// Sixty-four kilobytes. Everything this protocol carries today is a few
/// hundred bytes, and a reader with no limit is a peer that can spend this
/// node's memory by never sending a newline. The limit is not configurable,
/// because an operator raising it would be raising it for an attacker too.
pub const MOST_LINE_BYTES: u64 = 64 * 1024;

/// Writes a message as one line, newline included.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the message cannot be written out, which
/// would mean a type and its serialisation disagree.
pub fn encode<T: Serialize>(message: &T) -> Result<String, Failure> {
    let mut line = serde_json::to_string(message).map_err(|error| {
        Failure::new(
            Reason::Protocol,
            format!("a message could not be written out: {error}"),
        )
    })?;

    // A message that already carried a newline would split into two lines and
    // arrive as two half messages. JSON escapes newlines inside strings, so
    // this cannot happen, and the check keeps that assumption from going quiet
    // if the format ever changes.
    if line.contains('\n') {
        return Err(Failure::new(
            Reason::Protocol,
            "a message would have split across lines".to_owned(),
        ));
    }

    line.push('\n');
    Ok(line)
}

/// Reads one line back into a message.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the line is not a message this release
/// knows. A message from a newer release lands here by name rather than being
/// read as the wrong one.
pub fn decode<T: DeserializeOwned>(line: &str) -> Result<T, Failure> {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        return Err(Failure::new(
            Reason::Protocol,
            "an empty line is not a message".to_owned(),
        ));
    }

    serde_json::from_str(line).map_err(|error| {
        Failure::new(
            Reason::Protocol,
            format!("a message could not be read back: {error}"),
        )
    })
}
