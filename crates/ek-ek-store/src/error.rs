// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What can go wrong in the store.

use std::fmt;

/// The outcome of a store operation.
pub type Result<T> = std::result::Result<T, Error>;

/// A stable classification of a store failure.
///
/// Callers branch on this rather than on a message, so the wording of a
/// diagnostic can change without breaking anything that depends on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ErrorKind {
    /// The data directory could not be created or read.
    DataDirectory,
    /// A database exists but its master key file does not.
    MasterKeyMissing,
    /// The master key file is readable by somebody other than its owner.
    MasterKeyPermissions,
    /// The master key file is not a key.
    MasterKeyMalformed,
    /// The database rejected an operation.
    Storage,
    /// Stored bytes did not decrypt, so they were altered or belong to
    /// another node's key.
    Decryption,
    /// A stored record could not be read back into a value.
    Serialisation,
    /// The system clock is set before the Unix epoch.
    Clock,
}

/// A store failure, with a stable kind and an English diagnostic.
///
/// The diagnostic exists for the log, which is written in English and never
/// translated. Anything shown to an operator is derived from `kind`.
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
