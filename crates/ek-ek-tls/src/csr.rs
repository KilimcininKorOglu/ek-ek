// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The certificate signing request an order is finalised with.
//!
//! A fresh private key per order, never the account key. The account key
//! identifies the account to the server; a certificate key is served to
//! clients. Using one for both would mean that anybody who obtained the
//! server's key could also act as the account and revoke everything it holds.

use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::stack::Stack;
use openssl::x509::extension::SubjectAlternativeName;
use openssl::x509::{X509Name, X509Req};

use crate::error::{Failure, Reason};
use crate::jws::{CURVE, base64url};

/// A signing request and the key it belongs to.
///
/// Its `Debug` prints neither half. The request is public, but printing it
/// beside a redacted key invites somebody to relax the rule for the other
/// field too.
pub struct Request {
    /// The key the certificate will be issued against.
    pub key: PKey<Private>,
    /// The request itself, in DER.
    pub der: Vec<u8>,
}

impl Request {
    /// The request as ACME carries it: base64url, no padding.
    #[must_use]
    pub fn encoded(&self) -> String {
        base64url(&self.der)
    }

    /// The key in PEM, which is what the store keeps and the traffic path
    /// loads.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Crypto`] when the key cannot be written out.
    pub fn key_pem(&self) -> Result<Vec<u8>, Failure> {
        self.key.private_key_to_pem_pkcs8().map_err(|error| {
            Failure::new(Reason::Crypto, format!("the key does not write: {error}"))
        })
    }
}

impl std::fmt::Debug for Request {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Request").finish_non_exhaustive()
    }
}

/// Builds a signing request covering every name, with a fresh key.
///
/// The names go into the subject alternative name extension. A common name is
/// set as well, because some servers still read it, but it carries no
/// authority: a client has ignored it since RFC 2818 was replaced.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when no name was asked for, and
/// [`Reason::Crypto`] when the request cannot be built or signed.
pub fn request(names: &[String]) -> Result<Request, Failure> {
    request_with(names, generate()?)
}

/// Generates one certificate key.
///
/// Separate from [`request`] because a replicated order stores the key before
/// it places anything, so whichever node finishes the order holds the key the
/// certificate is issued against (ADR-0086).
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the key cannot be generated.
pub fn generate() -> Result<PKey<Private>, Failure> {
    let group = EcGroup::from_curve_name(CURVE)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no P-256 group: {error}")))?;
    let generated = EcKey::generate(&group)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no key: {error}")))?;
    PKey::from_ec_key(generated)
        .map_err(|error| Failure::new(Reason::Crypto, format!("the key does not wrap: {error}")))
}

/// Reads a stored certificate key back.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the key does not open.
pub fn key_from_pem(pem: &[u8]) -> Result<PKey<Private>, Failure> {
    // No passphrase rather than a prompt: this runs with no terminal, and the
    // default callback would wait forever on a question nobody sees.
    PKey::private_key_from_pem_callback(pem, |_| Ok(0)).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the stored certificate key does not open: {error}"),
        )
    })
}

/// Writes a certificate key out for the store to seal.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the key cannot be written.
pub fn key_to_pem(key: &PKey<Private>) -> Result<Vec<u8>, Failure> {
    key.private_key_to_pem_pkcs8()
        .map_err(|error| Failure::new(Reason::Crypto, format!("the key does not write: {error}")))
}

/// Builds a signing request against a key the caller already holds.
///
/// # Errors
///
/// The same as [`request`].
pub fn request_with(names: &[String], key: PKey<Private>) -> Result<Request, Failure> {
    let first = names.first().ok_or_else(|| {
        Failure::new(
            Reason::Configuration,
            "a certificate covering no name was asked for".to_owned(),
        )
    })?;

    let mut subject = X509Name::builder()
        .map_err(|error| Failure::new(Reason::Crypto, format!("no name builder: {error}")))?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, first)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no common name: {error}")))?;
    let subject = subject.build();

    let mut builder = X509Req::builder()
        .map_err(|error| Failure::new(Reason::Crypto, format!("no request builder: {error}")))?;
    builder
        .set_version(0)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no version: {error}")))?;
    builder
        .set_subject_name(&subject)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no subject: {error}")))?;
    builder
        .set_pubkey(&key)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no public key: {error}")))?;

    let mut alternatives = SubjectAlternativeName::new();
    for name in names {
        alternatives.dns(name);
    }
    let extension = alternatives
        .build(&builder.x509v3_context(None))
        .map_err(|error| Failure::new(Reason::Crypto, format!("no alternative names: {error}")))?;
    let mut extensions = Stack::new()
        .map_err(|error| Failure::new(Reason::Crypto, format!("no extension stack: {error}")))?;
    extensions
        .push(extension)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no extension: {error}")))?;
    builder
        .add_extensions(&extensions)
        .map_err(|error| Failure::new(Reason::Crypto, format!("no extensions: {error}")))?;

    builder
        .sign(&key, MessageDigest::sha256())
        .map_err(|error| {
            Failure::new(
                Reason::Crypto,
                format!("the request does not sign: {error}"),
            )
        })?;
    let request = builder.build();
    let der = request.to_der().map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the request does not write: {error}"),
        )
    })?;

    Ok(Request { key, der })
}
