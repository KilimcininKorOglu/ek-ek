// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Turning a message into a line and back.

use std::fmt;

use serde::Serialize;
use serde::de::DeserializeOwned;

/// The outcome of encoding or decoding.
pub type Result<T> = std::result::Result<T, Error>;

/// A message that could not be written out or read back.
///
/// The diagnostic is written for the log, which is English and never
/// translated.
#[derive(Clone, Debug)]
pub struct Error {
    diagnostic: String,
}

impl Error {
    /// Builds an error.
    #[must_use]
    pub fn new(diagnostic: impl Into<String>) -> Self {
        Self {
            diagnostic: diagnostic.into(),
        }
    }

    /// Returns the diagnostic.
    #[must_use]
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.diagnostic)
    }
}

impl std::error::Error for Error {}

/// Writes a message as one line, newline included.
///
/// # Errors
///
/// Fails when the message cannot be written out, which would mean a type and
/// its serialisation disagree.
pub fn encode<T: Serialize>(message: &T) -> Result<String> {
    let mut line = serde_json::to_string(message)
        .map_err(|error| Error::new(format!("a message could not be written out: {error}")))?;

    // A message that already carried a newline would split into two lines and
    // arrive as two half messages. JSON escapes newlines inside strings, so
    // this cannot happen, and the check keeps that assumption from going
    // quiet if the format ever changes.
    if line.contains('\n') {
        return Err(Error::new(
            "a message would have split across lines".to_owned(),
        ));
    }

    line.push('\n');
    Ok(line)
}

/// Reads one line back into a message.
///
/// A trailing newline is accepted, so a caller can pass a line straight from
/// a reader without trimming it first.
///
/// # Errors
///
/// Fails when the line is not a message this release knows. A message from a
/// newer release lands here by name rather than being read as the wrong one.
pub fn decode<T: DeserializeOwned>(line: &str) -> Result<T> {
    let line = line.trim_end_matches(['\n', '\r']);
    if line.is_empty() {
        return Err(Error::new("an empty line is not a message".to_owned()));
    }

    serde_json::from_str(line)
        .map_err(|error| Error::new(format!("a message could not be read back: {error}")))
}
