// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The cluster's own certificate authority, and the node certificates it
//! signs.
//!
//! This authority signs nothing a browser will ever see. It exists so that two
//! nodes can prove to each other which node they are, over a channel nobody
//! else can read (ADR-0008). It is not the authority behind the certificates
//! an operator uploads, and the two are never mixed.
//!
//! # Why every function takes the moment it works against
//!
//! No clock is read here. A certificate that expired last week and one that
//! expires in ten years are then both a parameter away, so the rules about
//! windows months wide are measured in microseconds.

use std::net::IpAddr;

use ek_ek_config::NodeId;
use ek_ek_store::Secret;
use openssl::asn1::Asn1Time;
use openssl::bn::BigNum;
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{HasPublic, PKey, PKeyRef, Private};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Name, X509NameRef};

use crate::error::{Failure, Reason, crypto};

/// The curve every key here is generated on.
///
/// P-256: what the ACME path already uses, what every TLS library supports,
/// and small enough that signing costs nothing on the hardware this product
/// runs on.
const CURVE: Nid = Nid::X9_62_PRIME256V1;

/// How long the cluster authority is valid, in days.
///
/// Ten years. The authority expiring invalidates every node certificate at
/// once and there is no recovery flow for that, so the window is set well past
/// the point where the question has to be answered (ADR-0082).
pub const AUTHORITY_LIFETIME_DAYS: i64 = 3650;

/// How long a node certificate is valid, in days.
///
/// Ninety, the same as a public certificate. Short enough that a node removed
/// from the cluster loses its way back on its own, long enough that renewal is
/// not a daily event.
pub const NODE_LIFETIME_DAYS: i64 = 90;

/// How far back a certificate starts, in seconds.
///
/// Five minutes. Two nodes never have exactly the same clock, and a
/// certificate issued on one and presented to the other a moment later would
/// otherwise be refused as not yet valid.
pub const CLOCK_SKEW_ALLOWANCE_SECONDS: i64 = 300;

/// The subject the cluster authority carries.
pub const AUTHORITY_COMMON_NAME: &str = "ek-ek cluster CA";

/// Seconds in a day.
const DAY: i64 = 86_400;

/// How many bytes of randomness a serial number carries.
const SERIAL_BYTES: i32 = 128;

/// The cluster authority: its certificate and the key that signs with it.
///
/// Its `Debug` prints neither half. The certificate is public, but printing it
/// beside a redacted key invites somebody to relax the rule for the other
/// field too.
#[derive(Clone, PartialEq, Eq)]
pub struct Authority {
    /// The authority certificate, in PEM. Every node trusts this and no other.
    pub certificate_pem: String,
    /// The key that signs node certificates.
    pub key_pem: Secret,
}

impl std::fmt::Debug for Authority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Authority").finish_non_exhaustive()
    }
}

/// One node's certificate, without the key it belongs to.
///
/// This is what the cluster hands back when a node made its own key and asked
/// for it to be certified: the signer never sees the private half, so it has
/// nothing else to give (ADR-0084).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signed {
    /// The node certificate, in PEM.
    pub certificate_pem: String,
    /// When the certificate starts being valid.
    pub not_before_unix: i64,
    /// When it stops.
    pub not_after_unix: i64,
}

/// One node's certificate and the key it belongs to.
#[derive(Clone, PartialEq, Eq)]
pub struct Issued {
    /// The node certificate, in PEM.
    pub certificate_pem: String,
    /// The key the certificate was issued against.
    pub key_pem: Secret,
    /// When the certificate starts being valid.
    pub not_before_unix: i64,
    /// When it stops.
    pub not_after_unix: i64,
}

impl std::fmt::Debug for Issued {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Issued")
            .field("not_before_unix", &self.not_before_unix)
            .field("not_after_unix", &self.not_after_unix)
            .finish_non_exhaustive()
    }
}

/// Builds a fresh cluster authority.
///
/// Self-signed, because there is nothing above it: the whole point is that the
/// cluster is its own root and trusts nobody else for peer traffic.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when a key, a name or a certificate cannot be
/// produced.
pub fn create(now_unix: i64) -> Result<Authority, Failure> {
    let key = generate_key()?;

    let mut subject =
        X509Name::builder().map_err(crypto("the authority name could not be built"))?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, AUTHORITY_COMMON_NAME)
        .map_err(crypto("the authority name could not be set"))?;
    let subject = subject.build();

    let serial = serial()?;
    let mut builder = X509::builder().map_err(crypto("no certificate builder"))?;
    // Version 2 in the encoding is X.509 v3. Anything below it carries no
    // extension field at all, so the constraints below would have nowhere to
    // live. Written out rather than left to the library: measured, OpenSSL
    // promotes a certificate to v3 by itself as soon as one extension is
    // added, so this line changes nothing today and states the requirement
    // for the day a certificate here carries none.
    builder
        .set_version(2)
        .map_err(crypto("the version could not be set"))?;
    builder
        .set_serial_number(&serial)
        .map_err(crypto("the serial number could not be set"))?;
    builder
        .set_subject_name(&subject)
        .map_err(crypto("the subject could not be set"))?;
    builder
        .set_issuer_name(&subject)
        .map_err(crypto("the issuer could not be set"))?;
    builder
        .set_pubkey(&key)
        .map_err(crypto("the public key could not be set"))?;
    set_window(&mut builder, now_unix, AUTHORITY_LIFETIME_DAYS)?;

    // Critical on purpose. A verifier that does not understand the constraint
    // has to refuse the certificate rather than treat it as an end entity.
    let constraints = BasicConstraints::new()
        .critical()
        .ca()
        // Zero: this authority signs node certificates and never another
        // authority. A second level would be a way to issue node identities
        // without holding this key.
        .pathlen(0)
        .build()
        .map_err(crypto("the constraints could not be built"))?;
    builder
        .append_extension(constraints)
        .map_err(crypto("the constraints could not be added"))?;

    let usage = KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()
        .map_err(crypto("the key usage could not be built"))?;
    builder
        .append_extension(usage)
        .map_err(crypto("the key usage could not be added"))?;

    let identifier = {
        let context = builder.x509v3_context(None, None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(crypto("the subject key identifier could not be built"))?
    };
    builder
        .append_extension(identifier)
        .map_err(crypto("the subject key identifier could not be added"))?;

    builder
        .sign(&key, MessageDigest::sha256())
        .map_err(crypto("the authority could not be signed"))?;
    let certificate = builder.build();

    Ok(Authority {
        certificate_pem: pem_of(&certificate)?,
        key_pem: Secret::new(
            key.private_key_to_pem_pkcs8()
                .map_err(crypto("the authority key could not be written out"))?,
        ),
    })
}

/// Signs a certificate for one node.
///
/// The identity is the node's, in the common name and in the subject
/// alternative names. Its addresses go in beside it, but nothing verifies
/// against them: a node keeps its identity when its address changes, which is
/// why the config model references nodes by identity in the first place
/// (ADR-0082).
///
/// The certificate is issued for both ends of a peer connection, because a
/// node dials its peers and is dialled by them with the same identity.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the node has no identity to carry,
/// and [`Reason::Crypto`] when the authority does not read back or the
/// certificate cannot be signed.
pub fn issue(
    authority: &Authority,
    node: &NodeId,
    addresses: &[IpAddr],
    now_unix: i64,
) -> Result<Issued, Failure> {
    let key = generate_key()?;
    let signed = sign_for(authority, node, addresses, now_unix, &key)?;

    Ok(Issued {
        certificate_pem: signed.certificate_pem,
        key_pem: Secret::new(
            key.private_key_to_pem_pkcs8()
                .map_err(crypto("the node key could not be written out"))?,
        ),
        not_before_unix: signed.not_before_unix,
        not_after_unix: signed.not_after_unix,
    })
}

/// Signs a certificate for one node against a public key that already exists.
///
/// The key is a parameter because a joining node makes its own and sends only
/// the public half. Everything else about the certificate is decided here, by
/// the cluster: a node does not name itself (ADR-0084).
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the node has no identity to carry,
/// and [`Reason::Crypto`] when the authority does not read back or the
/// certificate cannot be signed.
pub fn sign_for<T>(
    authority: &Authority,
    node: &NodeId,
    addresses: &[IpAddr],
    now_unix: i64,
    key: &PKeyRef<T>,
) -> Result<Signed, Failure>
where
    T: HasPublic,
{
    if node.as_str().is_empty() {
        return Err(Failure::new(
            Reason::Configuration,
            "a certificate for a node with no identity was asked for".to_owned(),
        ));
    }

    let signer = authority_key(authority)?;
    let issuer = authority_certificate(authority)?;

    let mut subject = X509Name::builder().map_err(crypto("the node name could not be built"))?;
    subject
        .append_entry_by_nid(Nid::COMMONNAME, node.as_str())
        .map_err(crypto("the node name could not be set"))?;
    let subject = subject.build();

    let serial = serial()?;
    let mut builder = X509::builder().map_err(crypto("no certificate builder"))?;
    builder
        .set_version(2)
        .map_err(crypto("the version could not be set"))?;
    builder
        .set_serial_number(&serial)
        .map_err(crypto("the serial number could not be set"))?;
    builder
        .set_subject_name(&subject)
        .map_err(crypto("the subject could not be set"))?;
    builder
        .set_issuer_name(issuer.subject_name())
        .map_err(crypto("the issuer could not be set"))?;
    builder
        .set_pubkey(key)
        .map_err(crypto("the public key could not be set"))?;
    let (not_before_unix, not_after_unix) = set_window(&mut builder, now_unix, NODE_LIFETIME_DAYS)?;

    let constraints = BasicConstraints::new()
        .critical()
        .build()
        .map_err(crypto("the constraints could not be built"))?;
    builder
        .append_extension(constraints)
        .map_err(crypto("the constraints could not be added"))?;

    let usage = KeyUsage::new()
        .critical()
        .digital_signature()
        .key_encipherment()
        .build()
        .map_err(crypto("the key usage could not be built"))?;
    builder
        .append_extension(usage)
        .map_err(crypto("the key usage could not be added"))?;

    // Both ends. A peer is a server to whoever dials it and a client to
    // whoever it dials, and one certificate carries it in both directions.
    let purpose = ExtendedKeyUsage::new()
        .server_auth()
        .client_auth()
        .build()
        .map_err(crypto("the extended key usage could not be built"))?;
    builder
        .append_extension(purpose)
        .map_err(crypto("the extended key usage could not be added"))?;

    let alternatives = {
        let context = builder.x509v3_context(Some(&issuer), None);
        let mut names = SubjectAlternativeName::new();
        names.dns(node.as_str());
        for address in addresses {
            names.ip(&address.to_string());
        }
        names
            .build(&context)
            .map_err(crypto("the alternative names could not be built"))?
    };
    builder
        .append_extension(alternatives)
        .map_err(crypto("the alternative names could not be added"))?;

    let identifier = {
        let context = builder.x509v3_context(Some(&issuer), None);
        SubjectKeyIdentifier::new()
            .build(&context)
            .map_err(crypto("the subject key identifier could not be built"))?
    };
    builder
        .append_extension(identifier)
        .map_err(crypto("the subject key identifier could not be added"))?;

    let authority_identifier = {
        let context = builder.x509v3_context(Some(&issuer), None);
        AuthorityKeyIdentifier::new()
            .keyid(false)
            .build(&context)
            .map_err(crypto("the authority key identifier could not be built"))?
    };
    builder
        .append_extension(authority_identifier)
        .map_err(crypto("the authority key identifier could not be added"))?;

    builder
        .sign(&signer, MessageDigest::sha256())
        .map_err(crypto("the node certificate could not be signed"))?;
    let certificate = builder.build();

    Ok(Signed {
        certificate_pem: pem_of(&certificate)?,
        not_before_unix,
        not_after_unix,
    })
}

/// Whether an authority signed a certificate.
///
/// What a joining node asks about the certificate it was served, once the
/// exchange hands it the authority the token's fingerprint names. Without this
/// second half the fingerprint proves only that somebody knows a public value
/// (ADR-0084).
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the authority does not read back or the
/// signature cannot be checked.
pub fn signed_by(certificate: &X509, authority_pem: &str) -> Result<bool, Failure> {
    let authority = X509::from_pem(authority_pem.as_bytes())
        .map_err(crypto("the cluster authority does not read back"))?;
    let key = authority
        .public_key()
        .map_err(crypto("the cluster authority carries no public key"))?;
    certificate
        .verify(&key)
        .map_err(crypto("the certificate signature could not be checked"))
}

/// Reads the node identity out of a certificate's subject.
///
/// This is what a peer answers "who called?" with. The address the connection
/// came from says nothing: anybody can dial from anywhere, and only the
/// certificate was signed by the authority.
///
/// # Errors
///
/// Returns [`Reason::Protocol`] when the certificate carries no common name.
pub fn identity_of(certificate: &X509) -> Result<NodeId, Failure> {
    common_name(certificate.subject_name()).map(NodeId::new)
}

/// Parses the authority certificate.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the stored PEM is not a certificate.
pub fn authority_certificate(authority: &Authority) -> Result<X509, Failure> {
    X509::from_pem(authority.certificate_pem.as_bytes()).map_err(crypto(
        "the stored authority certificate does not read back",
    ))
}

/// Parses the authority key.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the stored PEM is not a private key.
pub fn authority_key(authority: &Authority) -> Result<PKey<Private>, Failure> {
    PKey::private_key_from_pem(authority.key_pem.expose())
        .map_err(crypto("the stored authority key does not read back"))
}

fn common_name(name: &X509NameRef) -> Result<String, Failure> {
    let entry = name.entries_by_nid(Nid::COMMONNAME).next().ok_or_else(|| {
        Failure::new(
            Reason::Protocol,
            "a peer presented a certificate with no common name".to_owned(),
        )
    })?;
    entry
        .data()
        .as_utf8()
        .map(|value| value.to_string())
        .map_err(crypto("a common name could not be read"))
}

pub(crate) fn generate_key() -> Result<PKey<Private>, Failure> {
    let group = EcGroup::from_curve_name(CURVE).map_err(crypto("no P-256 group"))?;
    let generated = EcKey::generate(&group).map_err(crypto("no key"))?;
    PKey::from_ec_key(generated).map_err(crypto("the key does not wrap"))
}

/// Draws a serial number.
///
/// Random rather than counted. A counter would have to be stored and agreed
/// on, and two nodes issuing the same number would be two certificates a
/// verifier cannot tell apart.
fn serial() -> Result<openssl::asn1::Asn1Integer, Failure> {
    let mut number = BigNum::new().map_err(crypto("no serial number"))?;
    number
        .rand(SERIAL_BYTES, openssl::bn::MsbOption::MAYBE_ZERO, false)
        .map_err(crypto("the serial number could not be drawn"))?;
    number
        .to_asn1_integer()
        .map_err(crypto("the serial number could not be encoded"))
}

/// Sets the validity window and returns it.
fn set_window(
    builder: &mut openssl::x509::X509Builder,
    now_unix: i64,
    days: i64,
) -> Result<(i64, i64), Failure> {
    let not_before_unix = now_unix.saturating_sub(CLOCK_SKEW_ALLOWANCE_SECONDS);
    let not_after_unix = now_unix.saturating_add(days.saturating_mul(DAY));

    let not_before = Asn1Time::from_unix(not_before_unix)
        .map_err(crypto("the start of the window could not be built"))?;
    let not_after = Asn1Time::from_unix(not_after_unix)
        .map_err(crypto("the end of the window could not be built"))?;
    builder
        .set_not_before(&not_before)
        .map_err(crypto("the start of the window could not be set"))?;
    builder
        .set_not_after(&not_after)
        .map_err(crypto("the end of the window could not be set"))?;

    Ok((not_before_unix, not_after_unix))
}

fn pem_of(certificate: &X509) -> Result<String, Failure> {
    let bytes = certificate
        .to_pem()
        .map_err(crypto("the certificate could not be written out"))?;
    String::from_utf8(bytes).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the certificate did not write as text: {error}"),
        )
    })
}
