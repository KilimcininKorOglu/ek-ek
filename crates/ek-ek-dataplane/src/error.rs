// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What can go wrong on the traffic path.

use std::fmt;

/// The outcome of a traffic path operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A stable classification of a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorKind {
    /// The agent socket could not be reached.
    ///
    /// At startup this is fatal. There is no configuration to serve and
    /// starting empty would look like a node nobody had configured yet.
    AgentUnreachable,
    /// The agent closed the connection or stopped answering.
    AgentGone,
    /// A message could not be read or written.
    Protocol,
    /// The agent's first delivery did not pass validation, so there is
    /// nothing safe to serve.
    InvalidConfig,
    /// The server could not be built or bound.
    Listener,
}

/// A traffic path failure, with a stable kind and an English diagnostic.
///
/// The diagnostic is for the log, which is English and never translated.
#[derive(Clone, Debug)]
pub struct Error {
    kind: ErrorKind,
    diagnostic: String,
}

impl Error {
    /// Builds an error of this kind.
    #[must_use]
    pub fn new(kind: ErrorKind, diagnostic: impl Into<String>) -> Self {
        Self {
            kind,
            diagnostic: diagnostic.into(),
        }
    }

    /// Returns what went wrong.
    #[must_use]
    pub const fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// Returns the diagnostic written for the log.
    #[must_use]
    pub fn diagnostic(&self) -> &str {
        &self.diagnostic
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:?}: {}", self.kind, self.diagnostic)
    }
}

impl std::error::Error for Error {}
