// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificates built at run time for the measurements to work on.
//!
//! Nothing here is a literal PEM block. A key written into a tracked file is
//! a key in the repository's history, whatever the comment above it says, and
//! the secret scan is right to refuse one. These are built with the same
//! library the product uses, so what the measurements feed it is what an
//! operator's own tools produce.

#![allow(clippy::expect_used, clippy::unwrap_used, dead_code)]

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::extension::{
    BasicConstraints, KeyUsage, SubjectAlternativeName, SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509Name, X509NameRef};

/// One certificate and the key that belongs to it.
pub struct Pair {
    pub certificate: X509,
    pub key: PKey<Private>,
}

impl Pair {
    /// The certificate in PEM.
    pub fn chain_pem(&self) -> Vec<u8> {
        self.certificate.to_pem().expect("a certificate writes out")
    }

    /// The key in PEM, with no passphrase.
    pub fn key_pem(&self) -> Vec<u8> {
        self.key
            .private_key_to_pem_pkcs8()
            .expect("a key writes out")
    }

    /// The key in PEM, behind a passphrase.
    pub fn key_pem_encrypted(&self, passphrase: &str) -> Vec<u8> {
        self.key
            .private_key_to_pem_pkcs8_passphrase(
                openssl::symm::Cipher::aes_256_cbc(),
                passphrase.as_bytes(),
            )
            .expect("a key writes out encrypted")
    }
}

/// A key of the kind this product's own certificates use.
fn key() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("P-256 exists");
    let key = EcKey::generate(&group).expect("a key is generated");
    PKey::from_ec_key(key).expect("the key wraps")
}

/// A name with one common name in it.
fn named(common_name: &str) -> X509Name {
    let mut builder = X509Name::builder().expect("a name builder");
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common_name)
        .expect("a common name is appended");
    builder.build()
}

/// A serial number, because two certificates from one issuer need different
/// ones.
fn serial() -> openssl::asn1::Asn1Integer {
    let mut number = BigNum::new().expect("a number");
    number
        .rand(96, MsbOption::MAYBE_ZERO, false)
        .expect("a random serial");
    number.to_asn1_integer().expect("the serial converts")
}

/// A self-signed certificate authority.
pub fn authority(common_name: &str) -> Pair {
    let key = key();
    let name = named(common_name);

    let mut builder = X509::builder().expect("a certificate builder");
    builder.set_version(2).expect("version 3");
    builder.set_serial_number(&serial()).expect("a serial");
    builder.set_subject_name(&name).expect("a subject");
    builder.set_issuer_name(&name).expect("an issuer");
    builder.set_pubkey(&key).expect("a public key");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("a start"))
        .expect("the start is set");
    builder
        .set_not_after(&Asn1Time::days_from_now(3650).expect("an end"))
        .expect("the end is set");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("basic constraints"),
        )
        .expect("the extension is appended");
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("key usage"),
        )
        .expect("the extension is appended");
    builder
        .sign(&key, MessageDigest::sha256())
        .expect("the certificate is signed");

    Pair {
        certificate: builder.build(),
        key,
    }
}

/// An intermediate signed by an authority.
pub fn intermediate(common_name: &str, issuer: &Pair) -> Pair {
    let key = key();
    let mut builder = X509::builder().expect("a certificate builder");
    builder.set_version(2).expect("version 3");
    builder.set_serial_number(&serial()).expect("a serial");
    builder
        .set_subject_name(&named(common_name))
        .expect("a subject");
    builder
        .set_issuer_name(issuer.certificate.subject_name())
        .expect("an issuer");
    builder.set_pubkey(&key).expect("a public key");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("a start"))
        .expect("the start is set");
    builder
        .set_not_after(&Asn1Time::days_from_now(1825).expect("an end"))
        .expect("the end is set");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .pathlen(0)
                .build()
                .expect("basic constraints"),
        )
        .expect("the extension is appended");
    builder
        .sign(&issuer.key, MessageDigest::sha256())
        .expect("the certificate is signed");

    Pair {
        certificate: builder.build(),
        key,
    }
}

/// A server certificate, signed by whoever is given.
///
/// The days are relative to now, so a measurement can build one that expired
/// last week without waiting for anything.
pub fn leaf(
    common_name: &str,
    alternatives: &[&str],
    issuer: &Pair,
    from_days: i64,
    to_days: i64,
) -> Pair {
    let key = key();
    let mut builder = X509::builder().expect("a certificate builder");
    builder.set_version(2).expect("version 3");
    builder.set_serial_number(&serial()).expect("a serial");
    builder
        .set_subject_name(&named(common_name))
        .expect("a subject");
    builder
        .set_issuer_name(issuer.certificate.subject_name())
        .expect("an issuer");
    builder.set_pubkey(&key).expect("a public key");
    builder
        .set_not_before(&from(from_days))
        .expect("the start is set");
    builder
        .set_not_after(&from(to_days))
        .expect("the end is set");
    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .build()
                .expect("basic constraints"),
        )
        .expect("the extension is appended");
    builder
        .append_extension(
            SubjectKeyIdentifier::new()
                .build(&builder.x509v3_context(Some(&issuer.certificate), None))
                .expect("a subject key identifier"),
        )
        .expect("the extension is appended");

    if !alternatives.is_empty() {
        let mut names = SubjectAlternativeName::new();
        for name in alternatives {
            names.dns(name);
        }
        builder
            .append_extension(
                names
                    .build(&builder.x509v3_context(Some(&issuer.certificate), None))
                    .expect("subject alternative names"),
            )
            .expect("the extension is appended");
    }

    builder
        .sign(&issuer.key, MessageDigest::sha256())
        .expect("the certificate is signed");

    Pair {
        certificate: builder.build(),
        key,
    }
}

/// A time this many days from now, forwards or backwards.
fn from(days: i64) -> Asn1Time {
    if days >= 0 {
        let days = u32::try_from(days).expect("a day count fits");
        Asn1Time::days_from_now(days).expect("a time")
    } else {
        let days = u32::try_from(-days).expect("a day count fits");
        let seconds = i64::from(days) * 86_400;
        Asn1Time::from_unix(now() - seconds).expect("a time")
    }
}

/// Seconds since the epoch, as the measurements read them.
pub fn now() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is past the epoch")
            .as_secs(),
    )
    .expect("the epoch fits")
}

/// Several certificates in one file, in the order given.
pub fn joined(certificates: &[&X509]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for certificate in certificates {
        bytes.extend_from_slice(&certificate.to_pem().expect("a certificate writes out"));
    }
    bytes
}

/// A name as text, for a measurement that checks which issuer was named.
pub fn text_of(name: &X509NameRef) -> String {
    name.entries()
        .filter_map(|entry| {
            let value = entry.data().as_utf8().ok()?;
            Some(format!(
                "{}={value}",
                entry.object().nid().short_name().unwrap_or("?")
            ))
        })
        .collect::<Vec<String>>()
        .join(",")
}
