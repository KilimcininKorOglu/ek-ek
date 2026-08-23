// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The short form of the cluster authority, as it goes into a join token.
//!
//! A joining node is given an address and a token. The address says where to
//! connect and the token says what to accept there. Without the second half a
//! node would trust whatever answered, which is the attack the token exists to
//! stop (ADR-0031).
//!
//! # Why this shape
//!
//! SHA-256 over the certificate's DER encoding, lowercase hex, no separators.
//! It is what `openssl x509 -fingerprint -sha256 -noout` prints with the
//! colons removed, so an operator holding a copy of the authority can check it
//! against a tool this project did not write. No separators, because the value
//! has to survive being copied as one word.

use openssl::hash::MessageDigest;
use openssl::x509::X509;

use crate::error::{Failure, Reason, crypto};

/// How many characters a fingerprint is.
///
/// Thirty-two bytes of digest, two hex characters each.
pub const FINGERPRINT_CHARACTERS: usize = 64;

/// The fingerprint of an authority certificate in PEM.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the PEM is not a certificate or the digest
/// cannot be taken.
pub fn fingerprint(certificate_pem: &str) -> Result<String, Failure> {
    let certificate = X509::from_pem(certificate_pem.as_bytes())
        .map_err(crypto("the authority certificate does not read back"))?;
    of(&certificate)
}

/// The fingerprint of a parsed certificate.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the digest cannot be taken.
pub fn of(certificate: &X509) -> Result<String, Failure> {
    let digest = certificate
        .digest(MessageDigest::sha256())
        .map_err(crypto("the fingerprint could not be taken"))?;
    Ok(hex(&digest))
}

/// Whether a value could be a fingerprint at all.
///
/// A join token is typed or pasted by a person, so the shape is checked before
/// anything is compared. A value of the wrong length compared byte for byte
/// would simply never match, and the operator would be told the authority is
/// wrong when what is wrong is the token.
#[must_use]
pub fn well_formed(value: &str) -> bool {
    value.len() == FINGERPRINT_CHARACTERS
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether a certificate is the one a fingerprint names.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the expected value is not a
/// fingerprint, and [`Reason::Crypto`] when the certificate does not read
/// back.
pub fn matches(certificate_pem: &str, expected: &str) -> Result<bool, Failure> {
    if !well_formed(expected) {
        return Err(Failure::new(
            Reason::Configuration,
            format!(
                "a fingerprint is {FINGERPRINT_CHARACTERS} lowercase hex characters, \
                 and {} were given",
                expected.len()
            ),
        ));
    }
    Ok(fingerprint(certificate_pem)? == expected)
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Lowercase, and always two characters. `{:x}` alone drops the leading
        // zero of a byte below sixteen and shortens the whole value.
        out.push_str(&format!("{byte:02x}"));
    }
    out
}
