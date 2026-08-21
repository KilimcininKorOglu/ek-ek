// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Key material held by the store.
//!
//! The config model carries only a `SecretId`. The bytes behind that identity
//! live here, and they only ever touch the disk sealed (ADR-0018).

use std::fmt;

/// Bytes that must not be written to a log or a screen.
///
/// The `Debug` implementation redacts the contents, because a struct holding
/// a secret is printed by accident far more often than on purpose.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    /// Takes ownership of key material.
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the material, for the one place that has to use it.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Returns how many bytes are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether anything is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Secret({} bytes, redacted)", self.0.len())
    }
}
