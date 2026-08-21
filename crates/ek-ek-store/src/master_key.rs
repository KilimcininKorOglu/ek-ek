// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The node's local master key.
//!
//! The key is generated on this node, stays on this node and is never
//! replicated (ADR-0018). It seals what the store writes to disk.
//!
//! The boundary is deliberate and worth stating plainly: the key sits on the
//! same disk as the data it protects. This defends a stolen backup, a copied
//! disk image or a leaked file. It does not defend local root access.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::error::{Error, ErrorKind, Result};

/// Name of the key file inside the data directory.
pub const MASTER_KEY_FILE: &str = "master.key";

/// Length of the key in bytes.
pub const KEY_LENGTH: usize = 32;

/// Permissions the key file must carry.
pub const KEY_MODE: u32 = 0o600;

/// A key that never leaves this node.
#[derive(Clone)]
pub struct MasterKey([u8; KEY_LENGTH]);

impl MasterKey {
    /// Draws a new key from the operating system's secure random source and
    /// writes it out, readable by its owner only.
    ///
    /// # Errors
    ///
    /// Fails when the random source or the file system refuses.
    pub fn create(path: &Path) -> Result<Self> {
        let mut bytes = [0_u8; KEY_LENGTH];
        getrandom::fill(&mut bytes).map_err(|error| {
            Error::new(
                ErrorKind::DataDirectory,
                format!("the operating system refused to provide randomness: {error}"),
            )
        })?;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(KEY_MODE)
            .open(path)
            .map_err(|error| {
                Error::new(
                    ErrorKind::DataDirectory,
                    format!("{} could not be created: {error}", path.display()),
                )
            })?;
        file.write_all(&bytes).map_err(|error| {
            Error::new(
                ErrorKind::DataDirectory,
                format!("{} could not be written: {error}", path.display()),
            )
        })?;
        file.sync_all().map_err(|error| {
            Error::new(
                ErrorKind::DataDirectory,
                format!("{} could not be flushed: {error}", path.display()),
            )
        })?;

        Ok(Self(bytes))
    }

    /// Reads an existing key, refusing one that anybody else can read.
    ///
    /// # Errors
    ///
    /// Fails when the file is missing, too permissive, or not a key.
    pub fn read(path: &Path) -> Result<Self> {
        let mut file = File::open(path).map_err(|error| {
            Error::new(
                ErrorKind::MasterKeyMissing,
                format!("{} could not be opened: {error}", path.display()),
            )
        })?;

        let mode = file
            .metadata()
            .map_err(|error| {
                Error::new(
                    ErrorKind::DataDirectory,
                    format!("{} could not be inspected: {error}", path.display()),
                )
            })?
            .permissions()
            .mode()
            & 0o777;

        if mode & 0o077 != 0 {
            return Err(Error::new(
                ErrorKind::MasterKeyPermissions,
                format!(
                    "{} carries mode {mode:04o} and must carry {KEY_MODE:04o}",
                    path.display()
                ),
            ));
        }

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).map_err(|error| {
            Error::new(
                ErrorKind::DataDirectory,
                format!("{} could not be read: {error}", path.display()),
            )
        })?;

        let bytes: [u8; KEY_LENGTH] = bytes.try_into().map_err(|_| {
            Error::new(
                ErrorKind::MasterKeyMalformed,
                format!("{} does not hold {KEY_LENGTH} bytes", path.display()),
            )
        })?;

        Ok(Self(bytes))
    }

    /// Borrows the raw key, for the sealing routine only.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; KEY_LENGTH] {
        &self.0
    }
}

impl fmt::Debug for MasterKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MasterKey(redacted)")
    }
}
