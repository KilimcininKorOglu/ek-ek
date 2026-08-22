// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Building certificates and speaking TLS from the client side.
//!
//! Certificates are produced here rather than committed, because a PEM block
//! in a tracked file is a key in the repository whatever it protects.
//!
//! The chain has three levels, root then intermediate then leaf, because that
//! is what a real deployment has: the server sends the leaf and the
//! intermediate, and the client already trusts the root. A two level chain
//! would leave the intermediate path untested.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509NameBuilder};

/// One certificate and the key that goes with it.
pub struct Issued {
    /// The certificate itself.
    pub certificate: X509,
    /// Its private key.
    pub key: PKey<Private>,
}

impl Issued {
    /// The certificate as PEM.
    #[must_use]
    pub fn pem(&self) -> String {
        String::from_utf8(
            self.certificate
                .to_pem()
                .expect("a certificate must render as PEM"),
        )
        .expect("PEM is text")
    }

    /// The private key as PEM.
    #[must_use]
    pub fn key_pem(&self) -> String {
        String::from_utf8(
            self.key
                .private_key_to_pem_pkcs8()
                .expect("a key must render as PEM"),
        )
        .expect("PEM is text")
    }
}

/// A test certificate authority: a root, an intermediate, and leaves.
pub struct Authority {
    root: Issued,
    intermediate: Issued,
}

impl Default for Authority {
    fn default() -> Self {
        Self::new()
    }
}

impl Authority {
    /// Builds a fresh authority. Every test gets its own.
    #[must_use]
    pub fn new() -> Self {
        let root = issue_authority("ek-ek test root", None);
        let intermediate = issue_authority("ek-ek test intermediate", Some(&root));
        Self { root, intermediate }
    }

    /// Issues a leaf covering the names given.
    ///
    /// The first name becomes the subject common name, which is what a test
    /// reads back to say which certificate was served.
    #[must_use]
    pub fn issue(&self, names: &[&str]) -> Issued {
        let key = key_pair();
        let mut builder = X509::builder().expect("a builder must open");
        builder.set_version(2).expect("x509v3");
        builder
            .set_serial_number(&serial())
            .expect("a serial must be set");
        builder
            .set_subject_name(&name_for(names[0]))
            .expect("a subject must be set");
        builder
            .set_issuer_name(self.intermediate.certificate.subject_name())
            .expect("an issuer must be set");
        builder.set_pubkey(&key).expect("a public key must be set");
        builder
            .set_not_before(&Asn1Time::days_from_now(0).expect("a start"))
            .expect("a start must be set");
        builder
            .set_not_after(&Asn1Time::days_from_now(30).expect("an end"))
            .expect("an end must be set");

        builder
            .append_extension(
                BasicConstraints::new()
                    .build()
                    .expect("basic constraints must build"),
            )
            .expect("basic constraints must append");
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .expect("key usage must build"),
            )
            .expect("key usage must append");

        let mut alternative = SubjectAlternativeName::new();
        for name in names {
            alternative.dns(name);
        }
        let context = builder.x509v3_context(Some(&self.intermediate.certificate), None);
        let alternative = alternative
            .build(&context)
            .expect("subject alternative names must build");
        builder
            .append_extension(alternative)
            .expect("subject alternative names must append");

        builder
            .sign(&self.intermediate.key, MessageDigest::sha256())
            .expect("a leaf must sign");
        Issued {
            certificate: builder.build(),
            key,
        }
    }

    /// The chain a server sends: the leaf, then the intermediate.
    ///
    /// The root is left out on purpose, because a server that sent its root
    /// would hide the case where the client cannot build the path.
    #[must_use]
    pub fn chain_pem(&self, leaf: &Issued) -> String {
        format!("{}{}", leaf.pem(), self.intermediate.pem())
    }

    /// The root, which is what a client has to trust.
    #[must_use]
    pub fn root_pem(&self) -> String {
        self.root.pem()
    }
}

/// What a TLS handshake produced.
#[derive(Debug)]
pub struct Handshake {
    /// Common name of the certificate the server presented.
    pub served: String,
    /// The protocol agreed with ALPN, if any.
    pub alpn: Option<String>,
    /// How many certificates the server sent.
    pub chain_length: usize,
    /// Whether the client could build a path to the root it trusts.
    pub verified: bool,
}

/// Connects to a port, speaks TLS, and reports what came back.
///
/// # Errors
///
/// Returns the reason the handshake did not complete, which is what a test
/// measuring a refusal reads.
pub fn handshake(
    port: u16,
    server_name: Option<&str>,
    trusted_root: Option<&str>,
    alpn: &[&str],
) -> Result<Handshake, String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;

    // Verification is asked for only when a test says which root to trust.
    // Elsewhere the point is which certificate was served, not whether the
    // client would accept it.
    match trusted_root {
        Some(pem) => {
            let root = X509::from_pem(pem.as_bytes()).map_err(|error| error.to_string())?;
            builder
                .cert_store_mut()
                .add_cert(root)
                .map_err(|error| error.to_string())?;
            builder.set_verify(SslVerifyMode::PEER);
        }
        None => builder.set_verify(SslVerifyMode::NONE),
    }

    if !alpn.is_empty() {
        let mut wire = Vec::new();
        for protocol in alpn {
            wire.push(u8::try_from(protocol.len()).map_err(|_| "alpn too long".to_owned())?);
            wire.extend_from_slice(protocol.as_bytes());
        }
        builder
            .set_alpn_protos(&wire)
            .map_err(|error| error.to_string())?;
    }

    let connector = builder.build();
    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|error| error.to_string())?;

    let mut configured = connector
        .configure()
        .map_err(|error| error.to_string())?
        .verify_hostname(false);
    // A client with no name to send is exactly the case ADR-0070 defines a
    // behaviour for, so the harness has to be able to produce it.
    configured.set_use_server_name_indication(server_name.is_some());
    let name = server_name.unwrap_or("");

    let stream = configured
        .connect(name, stream)
        .map_err(|error| error.to_string())?;

    let session = stream.ssl();
    let served = session
        .peer_certificate()
        .ok_or_else(|| "the server presented no certificate".to_owned())?;
    let chain_length = session
        .peer_cert_chain()
        .map_or(1, |chain| chain.iter().count());

    Ok(Handshake {
        served: common_name(&served),
        alpn: session
            .selected_alpn_protocol()
            .map(|wire| String::from_utf8_lossy(wire).into_owned()),
        chain_length,
        verified: session.verify_result() == openssl::x509::X509VerifyResult::OK,
    })
}

/// A TLS connection held open across more than one request.
pub type Held = openssl::ssl::SslStream<TcpStream>;

/// Opens a connection and completes the handshake, keeping it open.
///
/// # Errors
///
/// Returns the reason the connection or the handshake did not complete.
pub fn open(port: u16, server_name: &str) -> Result<Held, String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;
    builder.set_verify(SslVerifyMode::NONE);
    // HTTP/1.1 on purpose: the point is one connection carrying two requests,
    // and h2 would put the reader on the wrong side of a frame parser.
    builder
        .set_alpn_protos(b"\x08http/1.1")
        .map_err(|error| error.to_string())?;
    let connector = builder.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    connector
        .configure()
        .map_err(|error| error.to_string())?
        .verify_hostname(false)
        .connect(server_name, stream)
        .map_err(|error| error.to_string())
}

/// Sends one request on a connection already open and reads the answer.
///
/// # Errors
///
/// Returns the reason the exchange did not complete, which is what a test
/// measuring a cut connection reads.
pub fn exchange(held: &mut Held, request: &str) -> Result<String, String> {
    held.write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    held.flush().map_err(|error| error.to_string())?;

    let mut answer = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match held.read(&mut buffer) {
            Ok(0) => return Err("the connection was closed".to_owned()),
            Ok(read) => {
                answer.extend_from_slice(&buffer[..read]);
                if complete(&answer) {
                    return Ok(String::from_utf8_lossy(&answer).into_owned());
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
}

/// Sends one HTTP request over TLS and returns the whole answer.
///
/// # Errors
///
/// Returns the reason the handshake or the exchange did not complete.
pub fn request(port: u16, server_name: &str, request: &str) -> Result<String, String> {
    let mut builder =
        SslConnector::builder(SslMethod::tls_client()).map_err(|error| error.to_string())?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();

    let stream = TcpStream::connect(("127.0.0.1", port)).map_err(|error| error.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|error| error.to_string())?;
    let mut stream = connector
        .configure()
        .map_err(|error| error.to_string())?
        .verify_hostname(false)
        .connect(server_name, stream)
        .map_err(|error| error.to_string())?;

    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;

    let mut answer = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                answer.extend_from_slice(&buffer[..read]);
                if complete(&answer) {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    Ok(String::from_utf8_lossy(&answer).into_owned())
}

/// Whether an answer holds its whole body, so the reader can stop.
fn complete(answer: &[u8]) -> bool {
    let text = String::from_utf8_lossy(answer);
    let Some((head, body)) = text.split_once("\r\n\r\n") else {
        return false;
    };
    let declared = head
        .lines()
        .find_map(|line| line.strip_prefix("Content-Length: "))
        .and_then(|value| value.trim().parse::<usize>().ok());
    declared.is_some_and(|length| body.len() >= length)
}

/// The common name of a certificate, which names it in a test.
fn common_name(certificate: &X509) -> String {
    certificate
        .subject_name()
        .entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|entry| entry.data().as_utf8().ok())
        .map_or_else(String::new, |name| name.to_string())
}

/// A P-256 key pair. Faster to make than RSA, which matters in a test that
/// issues several certificates.
fn key_pair() -> PKey<Private> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("a curve must exist");
    let key = EcKey::generate(&group).expect("a key must generate");
    PKey::from_ec_key(key).expect("a key must convert")
}

/// A random serial, because two certificates from one authority must differ.
fn serial() -> openssl::asn1::Asn1Integer {
    let mut number = BigNum::new().expect("a number must open");
    number
        .rand(159, MsbOption::MAYBE_ZERO, false)
        .expect("a number must fill");
    number.to_asn1_integer().expect("a serial must convert")
}

/// A subject holding one common name.
fn name_for(common: &str) -> openssl::x509::X509Name {
    let mut builder = X509NameBuilder::new().expect("a name must open");
    builder
        .append_entry_by_nid(Nid::COMMONNAME, common)
        .expect("a common name must append");
    builder.build()
}

/// Issues a certificate that may sign others.
///
/// With no parent it signs itself and becomes a root.
fn issue_authority(common: &str, parent: Option<&Issued>) -> Issued {
    let key = key_pair();
    let own = name_for(common);
    let mut builder = X509::builder().expect("a builder must open");
    builder.set_version(2).expect("x509v3");
    builder
        .set_serial_number(&serial())
        .expect("a serial must be set");
    builder
        .set_subject_name(&own)
        .expect("a subject must be set");
    builder
        .set_issuer_name(parent.map_or(&own, |parent| parent.certificate.subject_name()))
        .expect("an issuer must be set");
    builder.set_pubkey(&key).expect("a public key must be set");
    builder
        .set_not_before(&Asn1Time::days_from_now(0).expect("a start"))
        .expect("a start must be set");
    builder
        .set_not_after(&Asn1Time::days_from_now(365).expect("an end"))
        .expect("an end must be set");

    builder
        .append_extension(
            BasicConstraints::new()
                .critical()
                .ca()
                .build()
                .expect("basic constraints must build"),
        )
        .expect("basic constraints must append");
    builder
        .append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()
                .expect("key usage must build"),
        )
        .expect("key usage must append");

    let context = builder.x509v3_context(parent.map(|parent| parent.certificate.as_ref()), None);
    let subject_id = SubjectKeyIdentifier::new()
        .build(&context)
        .expect("a subject key id must build");
    // Only where there is an issuer to point at. A self-signed root has no
    // other certificate to name, and asking for one fails outright.
    let authority_id = parent.map(|_| {
        AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&context)
            .expect("an authority key id must build")
    });
    builder
        .append_extension(subject_id)
        .expect("a subject key id must append");
    if let Some(authority_id) = authority_id {
        builder
            .append_extension(authority_id)
            .expect("an authority key id must append");
    }

    let signing = parent.map_or(&key, |parent| &parent.key);
    builder
        .sign(signing, MessageDigest::sha256())
        .expect("an authority must sign");
    Issued {
        certificate: builder.build(),
        key,
    }
}
