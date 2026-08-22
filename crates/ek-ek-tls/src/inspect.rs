// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Reading what an operator uploaded, and refusing what cannot be served.
//!
//! A wrong upload breaks TLS silently: the handshake fails for every client
//! and nothing in the configuration looks wrong. So the material is parsed
//! here, before it is stored, and every fault is named with a stable code the
//! interface layer translates (ADR-0015).
//!
//! # What this never does
//!
//! No error and no warning carries the material it was given. A message ends
//! up in a log eventually, and a private key must never arrive there
//! (ADR-0018). The types below carry the key inside [`Secret`], whose `Debug`
//! redacts it.

use ek_ek_config::{
    CertificateValidity, ErrorCode, FieldPath, ValidationError, ValidationErrors,
    ValidationWarning, WarningCode,
};
use ek_ek_store::Secret;
use openssl::asn1::Asn1TimeRef;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::x509::X509;

/// What an upload turned out to be.
///
/// Returned only when the material can actually be served. Anything that
/// cannot is an error, and anything an operator should know about but that
/// still works is a warning.
#[derive(Debug)]
pub struct Upload {
    /// Names the handshake's SNI is matched against, in the order they were
    /// read: the subject's common name first, then the subject alternative
    /// names.
    pub sni_names: Vec<String>,
    /// The window the leaf certificate is usable in.
    pub validity: CertificateValidity,
    /// The chain as it will be stored, leaf first, in PEM.
    ///
    /// Written back out rather than kept as it arrived, so what is stored is
    /// what was parsed. A file with a comment above the first `BEGIN` line,
    /// or with the wrong line endings, is then stored in one shape.
    pub chain: Secret,
    /// The private key as it will be stored, in PEM and with no passphrase.
    ///
    /// The passphrase protects the file on its way here. Keeping it would
    /// mean keeping the passphrase too, and the material is sealed with the
    /// node's master key once it is stored (ADR-0018).
    pub key: Secret,
    /// Worth telling the operator, but not a reason to refuse.
    pub warnings: Vec<ValidationWarning>,
}

/// How many certificates the chain holds.
///
/// A chain longer than this is not a chain anybody serves; it is a file that
/// was concatenated by accident. The bound stops an upload from turning into
/// unbounded work.
pub const MOST_CERTIFICATES: usize = 16;

/// Reads an uploaded certificate and its key.
///
/// The passphrase is only used when the key is encrypted. Passing one for a
/// key that is not encrypted is not an error: an operator who types their
/// passphrase for the wrong file should get their certificate installed, not
/// a lecture.
///
/// # Errors
///
/// Returns every fault at once, each with a stable code and the field it
/// blames, so an interface can show them together rather than one per
/// attempt.
pub fn inspect(
    chain_pem: &[u8],
    key_pem: &[u8],
    passphrase: Option<&str>,
    now_unix: i64,
) -> Result<Upload, ValidationErrors> {
    let chain = read_chain(chain_pem)?;
    let key = read_key(key_pem, passphrase)?;

    // The leaf is what the key has to belong to and what the names come from.
    // A chain that parsed always holds one, which `read_chain` has checked.
    let Some(leaf) = chain.first() else {
        return Err(one_error(ErrorCode::CertificateChainEmpty, "chain"));
    };

    if !leaf.public_key().is_ok_and(|public| public.public_eq(&key)) {
        return Err(one_error(ErrorCode::CertificateKeyMismatch, "private_key"));
    }

    let validity = window(leaf)?;
    let mut warnings = Vec::new();
    if validity.not_after_unix <= now_unix {
        warnings.push(
            ValidationWarning::new(
                WarningCode::CertificateExpired,
                FieldPath::root().field("chain"),
            )
            .with_number("not_after_unix", validity.not_after_unix),
        );
    }
    if let Some(missing) = incomplete(&chain) {
        warnings.push(
            ValidationWarning::new(
                WarningCode::CertificateChainIncomplete,
                FieldPath::root().field("chain"),
            )
            .with_id("issuer", &missing),
        );
    }

    let chain_pem = written(&chain)?;
    let key_pem = key
        .private_key_to_pem_pkcs8()
        .map_err(|_| one_error(ErrorCode::CertificateKeyUnreadable, "private_key"))?;

    Ok(Upload {
        sni_names: names(leaf),
        validity,
        chain: Secret::new(chain_pem),
        key: Secret::new(key_pem),
        warnings,
    })
}

/// Reads the chain, leaf first.
fn read_chain(pem: &[u8]) -> Result<Vec<X509>, ValidationErrors> {
    let chain = X509::stack_from_pem(pem)
        .map_err(|_| one_error(ErrorCode::CertificateChainUnreadable, "chain"))?;
    if chain.is_empty() {
        return Err(one_error(ErrorCode::CertificateChainEmpty, "chain"));
    }
    if chain.len() > MOST_CERTIFICATES {
        return Err(ValidationErrors::from_errors(vec![
            ValidationError::new(
                ErrorCode::CertificateChainTooLong,
                FieldPath::root().field("chain"),
            )
            .with_number(
                "certificate_count",
                i64::try_from(chain.len()).unwrap_or(i64::MAX),
            )
            .with_number(
                "limit",
                i64::try_from(MOST_CERTIFICATES).unwrap_or(i64::MAX),
            ),
        ]));
    }
    Ok(chain)
}

/// Reads the private key, opening it with the passphrase when it needs one.
///
/// The two passphrase faults are told apart, because they need different
/// things from the operator: one is a prompt, the other is a correction.
fn read_key(pem: &[u8], passphrase: Option<&str>) -> Result<PKey<Private>, ValidationErrors> {
    // An empty passphrase is the same as none. An interface that sends the
    // field it always sends would otherwise turn "no passphrase" into "the
    // passphrase is the empty string", which no key was ever built with.
    let passphrase = passphrase.filter(|word| !word.is_empty());

    if let Some(word) = passphrase {
        if let Ok(key) = PKey::private_key_from_pem_passphrase(pem, word.as_bytes()) {
            return Ok(key);
        }
        // A key that opens without one was never encrypted, so the passphrase
        // was simply not needed. The certificate goes in.
        if let Ok(key) = unlocked(pem) {
            return Ok(key);
        }
        return Err(if encrypted(pem) {
            one_error(ErrorCode::CertificateKeyPassphraseWrong, "passphrase")
        } else {
            one_error(ErrorCode::CertificateKeyUnreadable, "private_key")
        });
    }

    unlocked(pem).map_err(|_| {
        if encrypted(pem) {
            one_error(ErrorCode::CertificateKeyPassphraseRequired, "passphrase")
        } else {
            one_error(ErrorCode::CertificateKeyUnreadable, "private_key")
        }
    })
}

/// Reads a key that is expected to need no passphrase.
///
/// The callback is what stops OpenSSL from asking for one. Its default reads
/// from the terminal, and a control plane has none: the process would hang
/// waiting for somebody to type into a tty nobody is watching.
fn unlocked(pem: &[u8]) -> Result<PKey<Private>, openssl::error::ErrorStack> {
    // No passphrase, which is what a length of zero says.
    PKey::private_key_from_pem_callback(pem, |_| Ok(0))
}

/// Whether a key file says it is encrypted.
///
/// Read from the file rather than from the failure, because OpenSSL reports a
/// missing passphrase and a broken file the same way, and an operator who is
/// asked for a passphrase they do not have learns nothing.
fn encrypted(pem: &[u8]) -> bool {
    let text = String::from_utf8_lossy(pem);
    // PKCS#8, which is what modern tools write, and the older PEM header that
    // OpenSSL's own `-traditional` output still carries.
    text.contains("BEGIN ENCRYPTED PRIVATE KEY") || text.contains("Proc-Type: 4,ENCRYPTED")
}

/// The names a handshake is matched against.
///
/// The common name first, then every DNS subject alternative name that is not
/// already there. RFC 6125 has deprecated the common name for years, and
/// certificates that carry only one are still in use inside companies, which
/// is exactly where this product runs.
fn names(leaf: &X509) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();

    for entry in leaf.subject_name().entries_by_nid(Nid::COMMONNAME) {
        if let Ok(text) = entry.data().as_utf8() {
            found.push(text.to_string());
        }
    }
    if let Some(alternatives) = leaf.subject_alt_names() {
        for name in alternatives {
            if let Some(text) = name.dnsname() {
                found.push(text.to_owned());
            }
        }
    }

    found.retain(|name| !name.is_empty());
    let mut seen = Vec::with_capacity(found.len());
    found.retain(|name| {
        if seen.contains(name) {
            return false;
        }
        seen.push(name.clone());
        true
    });
    found
}

/// The window the leaf is usable in.
fn window(leaf: &X509) -> Result<CertificateValidity, ValidationErrors> {
    let not_before_unix = unix(leaf.not_before())
        .ok_or_else(|| one_error(ErrorCode::CertificateChainUnreadable, "chain"))?;
    let not_after_unix = unix(leaf.not_after())
        .ok_or_else(|| one_error(ErrorCode::CertificateChainUnreadable, "chain"))?;
    Ok(CertificateValidity {
        not_before_unix,
        not_after_unix,
    })
}

/// An ASN.1 time as seconds since the epoch.
///
/// OpenSSL offers no reading of the value itself, only a difference against
/// another time, so the difference is taken against the epoch.
fn unix(time: &Asn1TimeRef) -> Option<i64> {
    let epoch = openssl::asn1::Asn1Time::from_unix(0).ok()?;
    let difference = epoch.diff(time).ok()?;
    let days = i64::from(difference.days);
    let seconds = i64::from(difference.secs);
    Some(days * 86_400 + seconds)
}

/// The issuer the chain stops at, when it stops short of a root.
///
/// Walked link by link: each certificate's issuer has to be the next one's
/// subject, and the last one has to be self-signed. Nothing is checked
/// against the machine's trust store, because a certificate from a company's
/// own CA is the normal case here and that CA is often not installed on the
/// load balancer itself.
fn incomplete(chain: &[X509]) -> Option<String> {
    for pair in chain.windows(2) {
        let (lower, higher) = (&pair[0], &pair[1]);
        // A file whose certificates are not in order is not a chain that can
        // be served, and saying which issuer is missing is more use than
        // saying the order is wrong.
        if !issued_by(lower, higher) {
            return Some(text_of(lower.issuer_name()));
        }
    }

    let last = chain.last()?;
    if issued_by(last, last) {
        return None;
    }
    Some(text_of(last.issuer_name()))
}

/// Whether one certificate was issued by another.
fn issued_by(certificate: &X509, issuer: &X509) -> bool {
    text_of(certificate.issuer_name()) == text_of(issuer.subject_name())
}

/// A name as one comparable string.
fn text_of(name: &openssl::x509::X509NameRef) -> String {
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

/// The chain written back out as PEM, leaf first.
fn written(chain: &[X509]) -> Result<Vec<u8>, ValidationErrors> {
    let mut bytes = Vec::new();
    for certificate in chain {
        let one = certificate
            .to_pem()
            .map_err(|_| one_error(ErrorCode::CertificateChainUnreadable, "chain"))?;
        bytes.extend_from_slice(&one);
    }
    Ok(bytes)
}

/// One error, as the only thing that went wrong.
fn one_error(code: ErrorCode, field: &str) -> ValidationErrors {
    ValidationErrors::from_errors(vec![ValidationError::new(
        code,
        FieldPath::root().field(field),
    )])
}
