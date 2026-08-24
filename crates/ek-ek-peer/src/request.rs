// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Asking the cluster for a certificate without handing over a key.
//!
//! A joining node makes its own key, sends a signing request, and gets a
//! certificate back. The private key never leaves the machine that made it,
//! which is what closes the gap the enrolment file left open (R-33,
//! ADR-0084).
//!
//! # What the cluster takes from a request and what it refuses to take
//!
//! Only the public key. The name and the addresses come from the join, not
//! from the request: a node that could name itself in its own request would
//! be choosing its own identity, and the whole point of a join token is that
//! the cluster decides who is admitted.
//!
//! The signature on the request is checked all the same. It proves the sender
//! holds the private key that goes with the public one, so nobody can have a
//! certificate issued against somebody else's key.

use std::net::IpAddr;

use ek_ek_config::NodeId;
use ek_ek_store::Secret;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private, Public};
use openssl::x509::{X509Name, X509Req};

use crate::authority::{Authority, Signed, generate_key, sign_for};
use crate::error::{Failure, Reason, crypto};

/// The name a request carries in its subject.
///
/// Fixed rather than the node's own name, because the cluster ignores it. A
/// name here that looked meaningful would invite somebody to read it as the
/// identity being granted.
pub const REQUEST_COMMON_NAME: &str = "ek-ek join request";

/// A signing request and the key it was made with.
pub struct Requested {
    /// The request, in PEM, to send to the cluster.
    pub request_pem: String,
    /// The private key, which stays here.
    pub key_pem: Secret,
}

impl std::fmt::Debug for Requested {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Requested").finish_non_exhaustive()
    }
}

/// Makes a key and a request to have it certified.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the key or the request cannot be built.
pub fn request() -> Result<Requested, Failure> {
    let key = generate_key()?;

    let mut subject = X509Name::builder().map_err(crypto("the request name could not be built"))?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, REQUEST_COMMON_NAME)
        .map_err(crypto("the request name could not be set"))?;
    let subject = subject.build();

    let mut builder = X509Req::builder().map_err(crypto("no request builder"))?;
    builder
        .set_version(0)
        .map_err(crypto("the request version could not be set"))?;
    builder
        .set_subject_name(&subject)
        .map_err(crypto("the request subject could not be set"))?;
    builder
        .set_pubkey(&key)
        .map_err(crypto("the request public key could not be set"))?;
    // Signed with the key it carries. That signature is what proves the sender
    // holds the private half, and it is checked before anything is issued.
    builder
        .sign(&key, MessageDigest::sha256())
        .map_err(crypto("the request could not be signed"))?;

    let request = builder.build();
    Ok(Requested {
        request_pem: String::from_utf8(
            request
                .to_pem()
                .map_err(crypto("the request could not be written out"))?,
        )
        .map_err(|error| {
            Failure::new(Reason::Crypto, format!("the request is not text: {error}"))
        })?,
        key_pem: Secret::new(
            key.private_key_to_pem_pkcs8()
                .map_err(crypto("the request key could not be written out"))?,
        ),
    })
}

/// Reads the public key out of a request, after checking it was really signed
/// with the matching private one.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the request does not read back, and
/// [`Reason::Rejected`] when its signature does not check out.
pub fn public_key(request_pem: &str) -> Result<PKey<Public>, Failure> {
    let request = X509Req::from_pem(request_pem.as_bytes())
        .map_err(crypto("the signing request does not read back"))?;

    let key = request
        .public_key()
        .map_err(crypto("the signing request carries no public key"))?;

    // A request whose signature does not check out is one whose sender does
    // not hold the key. Issuing against it would certify a public key to
    // somebody who cannot use it, and hand that somebody an identity.
    let held = request
        .verify(&key)
        .map_err(crypto("the signing request signature could not be checked"))?;
    if !held {
        return Err(Failure::new(
            Reason::Rejected,
            "the signing request was not signed with the key it carries".to_owned(),
        ));
    }

    Ok(key)
}

/// Signs a request into a node certificate.
///
/// The name and the addresses are the caller's, never the request's. A node
/// that named itself would be choosing its own identity.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the node has no identity,
/// [`Reason::Rejected`] when the request does not check out, and
/// [`Reason::Crypto`] when the certificate cannot be signed.
pub fn certify(
    authority: &Authority,
    request_pem: &str,
    node: &NodeId,
    addresses: &[IpAddr],
    now_unix: i64,
) -> Result<Signed, Failure> {
    let key = public_key(request_pem)?;
    sign_for(authority, node, addresses, now_unix, &key)
}

/// The key a request was made with, read back from its PEM.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the key does not read back.
pub fn key_of(key_pem: &Secret) -> Result<PKey<Private>, Failure> {
    PKey::private_key_from_pem(key_pem.expose())
        .map_err(crypto("the request key does not read back"))
}
