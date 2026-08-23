// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The signed envelope every ACME request travels in.
//!
//! The values here are checked against RFC 7515, RFC 7638 and RFC 8555 rather
//! than against what this code happens to produce, because a server that is
//! not ours is the one reading them. A signature in the wrong shape is
//! answered as a bad signature, which reads like a wrong key and sends an
//! operator looking in the wrong place.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_tls::{Identify, account_from_pem, account_key, account_to_pem, base64url, jwk, sign};
use openssl::hash::{MessageDigest, hash};

/// Reads one field out of a compact JSON object.
fn field(document: &str, name: &str) -> String {
    let value: serde_json::Value = serde_json::from_str(document).expect("valid JSON");
    value
        .get(name)
        .and_then(|held| held.as_str())
        .unwrap_or_else(|| panic!("{document} carries no {name}"))
        .to_owned()
}

/// Decodes base64url without padding.
fn decode(text: &str) -> Vec<u8> {
    let mut standard = text.replace('-', "+").replace('_', "/");
    while !standard.len().is_multiple_of(4) {
        standard.push('=');
    }
    openssl::base64::decode_block(&standard).expect("it was written by base64url")
}

#[test]
fn base64url_uses_the_url_alphabet_and_no_padding() {
    // A value chosen so the standard alphabet would produce both `+` and `/`.
    let bytes = [0xfb_u8, 0xff, 0xbe];
    let written = base64url(&bytes);
    assert!(
        !written.contains('+') && !written.contains('/') && !written.contains('='),
        "{written} is not URL safe"
    );
    assert_eq!(decode(&written), bytes, "it does not decode back");

    // The other side: the standard encoding of the same bytes does carry them,
    // so the test is measuring the change rather than an input with no `+` in
    // it to start with.
    let standard = openssl::base64::encode_block(&bytes);
    assert!(standard.contains('+') || standard.contains('/'));
}

#[test]
fn a_jwk_is_written_in_the_one_order_a_thumbprint_is_taken_over() {
    let key = account_key().expect("a key");
    let written = jwk(&key).expect("a JWK");

    // RFC 7638 takes the digest over the required fields, lexicographically
    // ordered, with no whitespace. Any other bytes hash to something the
    // server never computes.
    assert!(
        written.starts_with(r#"{"crv":"P-256","kty":"EC","x":""#),
        "{written} is not in the canonical order"
    );
    assert!(!written.contains(' '), "{written} carries whitespace");

    let x = field(&written, "x");
    let y = field(&written, "y");
    assert_eq!(decode(&x).len(), 32, "a P-256 coordinate is 32 bytes");
    assert_eq!(decode(&y).len(), 32, "a P-256 coordinate is 32 bytes");
}

#[test]
fn a_thumbprint_is_the_digest_of_that_exact_document() {
    let key = account_key().expect("a key");
    let written = jwk(&key).expect("a JWK");
    let expected = base64url(&hash(MessageDigest::sha256(), written.as_bytes()).expect("a digest"));
    assert_eq!(
        ek_ek_tls::thumbprint(&key).expect("a thumbprint"),
        expected,
        "the thumbprint is not taken over the JWK that is sent"
    );

    // Two keys produce two thumbprints, so the value identifies the account.
    let other = account_key().expect("another key");
    assert_ne!(
        ek_ek_tls::thumbprint(&key).unwrap(),
        ek_ek_tls::thumbprint(&other).unwrap()
    );
}

#[test]
fn a_challenge_answer_ties_the_token_to_the_account() {
    assert_eq!(
        ek_ek_tls::key_authorization("tok", "thumb"),
        "tok.thumb",
        "the answer is the token and the thumbprint, separated by a dot"
    );
}

#[test]
fn the_account_creating_request_carries_the_key_and_the_rest_carry_the_account() {
    let key = account_key().expect("a key");

    let with_key = sign(
        &key,
        Identify::Key,
        None,
        "https://acme.example.org/new-account",
        "nonce-1",
        Some(r#"{"termsOfServiceAgreed":true}"#),
    )
    .expect("a signed envelope");
    let protected = String::from_utf8(decode(&field(&with_key, "protected"))).expect("text");
    assert!(protected.contains(r#""alg":"ES256""#));
    assert!(protected.contains(r#""jwk":"#));
    assert!(!protected.contains(r#""kid":"#), "both would be a fault");
    assert!(protected.contains(r#""nonce":"nonce-1""#));
    assert!(protected.contains(r#""url":"https://acme.example.org/new-account""#));

    let with_account = sign(
        &key,
        Identify::Account,
        Some("https://acme.example.org/account/7"),
        "https://acme.example.org/order/1",
        "nonce-2",
        None,
    )
    .expect("a signed envelope");
    let protected = String::from_utf8(decode(&field(&with_account, "protected"))).expect("text");
    assert!(protected.contains(r#""kid":"https://acme.example.org/account/7""#));
    assert!(!protected.contains(r#""jwk":"#));
}

#[test]
fn signing_as_an_account_the_server_never_named_is_refused() {
    let key = account_key().expect("a key");
    let failure = sign(
        &key,
        Identify::Account,
        None,
        "https://acme.example.org/order/1",
        "nonce",
        None,
    )
    .expect_err("there is no account to name");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Protocol);
}

#[test]
fn a_read_only_request_signs_over_an_empty_payload() {
    let key = account_key().expect("a key");
    let envelope = sign(
        &key,
        Identify::Account,
        Some("https://acme.example.org/account/7"),
        "https://acme.example.org/order/1",
        "nonce",
        None,
    )
    .expect("a signed envelope");

    // RFC 8555 section 6.3: the payload field is present and empty, not
    // absent. A server reading an absent field refuses the request.
    let value: serde_json::Value = serde_json::from_str(&envelope).expect("valid JSON");
    assert_eq!(value.get("payload").and_then(|p| p.as_str()), Some(""));
}

#[test]
fn the_signature_is_the_two_numbers_and_not_the_der_structure() {
    let key = account_key().expect("a key");
    let envelope = sign(
        &key,
        Identify::Key,
        None,
        "https://acme.example.org/new-account",
        "nonce",
        Some("{}"),
    )
    .expect("a signed envelope");

    let signature = decode(&field(&envelope, "signature"));
    assert_eq!(
        signature.len(),
        64,
        "ES256 is two 32 byte numbers; a DER structure would be a different length"
    );
    // A DER signature starts with the SEQUENCE tag. The raw form does not,
    // except by coincidence in one value out of 256, so this is checked as
    // well as the length.
    assert!(
        !(signature[0] == 0x30 && usize::from(signature[1]) + 2 == signature.len()),
        "the signature is still wrapped in DER"
    );
}

#[test]
fn the_signature_verifies_against_the_key_that_made_it() {
    let key = account_key().expect("a key");
    let envelope = sign(
        &key,
        Identify::Key,
        None,
        "https://acme.example.org/new-account",
        "nonce",
        Some("{}"),
    )
    .expect("a signed envelope");

    let protected = field(&envelope, "protected");
    let payload = field(&envelope, "payload");
    let signature = decode(&field(&envelope, "signature"));
    let digest = hash(
        MessageDigest::sha256(),
        format!("{protected}.{payload}").as_bytes(),
    )
    .expect("a digest");

    let r = openssl::bn::BigNum::from_slice(&signature[..32]).expect("a number");
    let s = openssl::bn::BigNum::from_slice(&signature[32..]).expect("a number");
    let rebuilt = openssl::ecdsa::EcdsaSig::from_private_components(r, s).expect("a signature");
    assert!(
        rebuilt
            .verify(&digest, &key.ec_key().expect("an EC key"))
            .expect("the check runs"),
        "the signature does not verify against its own key"
    );

    // The other side: a different key does not verify it, so the check above
    // is measuring the signature rather than always saying yes.
    let other = account_key().expect("another key");
    assert!(
        !rebuilt
            .verify(&digest, &other.ec_key().expect("an EC key"))
            .expect("the check runs")
    );
}

#[test]
fn a_url_carrying_a_quote_cannot_write_extra_fields_into_the_header() {
    let key = account_key().expect("a key");
    let envelope = sign(
        &key,
        Identify::Account,
        Some(r#"https://evil.example.org/a","alg":"none"#),
        "https://acme.example.org/order/1",
        "nonce",
        None,
    )
    .expect("a signed envelope");

    let protected = String::from_utf8(decode(&field(&envelope, "protected"))).expect("text");
    // It still parses as one object, and the algorithm is the one this client
    // chose rather than the one the value tried to name.
    let value: serde_json::Value = serde_json::from_str(&protected).expect("one JSON object");
    assert_eq!(value.get("alg").and_then(|a| a.as_str()), Some("ES256"));
}

#[test]
fn an_account_key_survives_being_stored_and_read_back() {
    let key = account_key().expect("a key");
    let pem = account_to_pem(&key).expect("it writes out");
    let read = account_from_pem(&pem).expect("it reads back");

    assert_eq!(
        ek_ek_tls::thumbprint(&key).unwrap(),
        ek_ek_tls::thumbprint(&read).unwrap(),
        "the stored key is not the same account"
    );

    // The other side: material that is not a key is refused rather than
    // producing a key nobody can use.
    let failure = account_from_pem(b"not a key at all").expect_err("this is not a key");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Crypto);
}

#[test]
fn a_signing_request_covers_every_name_and_carries_its_own_key() {
    let names = vec!["www.example.org".to_owned(), "posta.example.org".to_owned()];
    let request = ek_ek_tls::request(&names).expect("a signing request");

    let parsed = openssl::x509::X509Req::from_der(&request.der).expect("it reads as a request");
    assert!(
        parsed
            .verify(&parsed.public_key().expect("a public key"))
            .expect("the check runs"),
        "the request is not signed by the key it carries"
    );

    let text = String::from_utf8(parsed.to_text().expect("it renders")).expect("text");
    for name in &names {
        assert!(text.contains(name.as_str()), "{name} is not in the request");
    }

    // The key it carries is not the account key, and it comes back as PEM for
    // the store to seal.
    let pem = request.key_pem().expect("the key writes out");
    assert!(String::from_utf8_lossy(&pem).contains("BEGIN PRIVATE KEY"));

    // And the encoded form is what ACME carries: base64url, no padding.
    let encoded = request.encoded();
    assert!(!encoded.contains('+') && !encoded.contains('/') && !encoded.contains('='));
    assert_eq!(decode(&encoded), request.der);
}

#[test]
fn a_request_covering_no_name_is_refused() {
    let failure = ek_ek_tls::request(&[]).expect_err("a certificate needs a name");
    assert_eq!(failure.reason(), ek_ek_tls::Reason::Configuration);
}
