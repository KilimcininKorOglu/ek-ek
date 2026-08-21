// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One error type for the harness.
//!
//! Every failure carries the command that produced it and what came back. A
//! test that fails on "exit status 1" costs a debugging session; one that fails
//! on the command plus its stderr does not.

use std::fmt;
use std::io;

/// Result type used throughout the harness.
pub type Result<T> = std::result::Result<T, Error>;

/// A harness failure, always with enough context to act on.
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    /// Builds an error from a message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        Self::new(err.to_string())
    }
}
