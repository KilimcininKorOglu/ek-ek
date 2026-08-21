// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sealing and opening stored secrets.
//!
//! The algorithm is authenticated, so altered ciphertext fails to open rather
//! than decrypting into something plausible. Each record is bound to its own
//! identity as associated data, which stops one record's ciphertext from
//! being moved onto another row.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};

use crate::error::{Error, ErrorKind, Result};
use crate::master_key::MasterKey;

/// Length of the nonce in bytes.
///
/// The extended nonce is wide enough to draw at random for every record,
/// which removes the need to persist a counter and the risk of replaying one
/// after a restart.
pub const NONCE_LENGTH: usize = 24;

/// A sealed record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    /// The nonce this record was sealed with.
    pub nonce: Vec<u8>,
    /// The ciphertext, with its authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Seals `plaintext`, binding it to `associated`.
///
/// # Errors
///
/// Fails when the random source refuses or the algorithm rejects the input.
pub fn seal(key: &MasterKey, associated: &[u8], plaintext: &[u8]) -> Result<Sealed> {
    let mut nonce = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).map_err(|error| {
        Error::new(
            ErrorKind::Decryption,
            format!("the operating system refused to provide randomness: {error}"),
        )
    })?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: associated,
            },
        )
        .map_err(|error| Error::new(ErrorKind::Decryption, format!("sealing failed: {error}")))?;

    Ok(Sealed {
        nonce: nonce.to_vec(),
        ciphertext,
    })
}

/// Opens a sealed record, requiring the same `associated` value it was sealed
/// with.
///
/// # Errors
///
/// Fails when the nonce is the wrong length, the key is a different node's,
/// or either the ciphertext or the associated data was altered.
pub fn open(key: &MasterKey, associated: &[u8], sealed: &Sealed) -> Result<Vec<u8>> {
    if sealed.nonce.len() != NONCE_LENGTH {
        return Err(Error::new(
            ErrorKind::Decryption,
            format!(
                "a nonce of {} bytes cannot be used, {NONCE_LENGTH} are required",
                sealed.nonce.len()
            ),
        ));
    }

    let nonce = XNonce::try_from(sealed.nonce.as_slice()).map_err(|error| {
        Error::new(
            ErrorKind::Decryption,
            format!("a stored nonce could not be used: {error}"),
        )
    })?;

    let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: &sealed.ciphertext,
                aad: associated,
            },
        )
        .map_err(|error| {
            Error::new(
                ErrorKind::Decryption,
                format!("a stored record did not open: {error}"),
            )
        })
}
