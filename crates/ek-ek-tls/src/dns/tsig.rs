// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transaction signatures for DNS messages (RFC 8945).
//!
//! An update that is not signed is an update anybody on the path can send, so
//! nothing here builds an unsigned one: [`sign`] is the only way a message
//! leaves this module, and it always appends the signature.
//!
//! The answer is checked too. A forged `NOERROR` would tell the order the
//! challenge record is in place when nothing was written, and the certificate
//! authority would then read an empty name and refuse the identifier for good.

use ek_ek_config::TsigAlgorithm;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer;

use crate::dns::wire::{self, CLASS_ANY, Case, TYPE_TSIG};
use crate::error::{Failure, Reason};

/// How far apart the two clocks may be, in seconds.
///
/// The value RFC 8945 recommends. A wider window would accept a replayed
/// message for longer; a narrower one would refuse a signature over a clock
/// difference an ordinary network has.
pub const FUDGE: u16 = 300;

/// A signed message and the signature that went into it.
///
/// The signature is kept, because the answer's own signature is computed over
/// it: that is what ties one answer to one request.
#[derive(Clone, Debug)]
pub struct Signed {
    /// The message, signature appended.
    pub message: Vec<u8>,
    /// The signature itself.
    pub mac: Vec<u8>,
}

/// The name of the algorithm as it is written on the wire.
#[must_use]
pub const fn algorithm_name(algorithm: TsigAlgorithm) -> &'static str {
    match algorithm {
        TsigAlgorithm::HmacSha256 => "hmac-sha256",
        TsigAlgorithm::HmacSha512 => "hmac-sha512",
    }
}

const fn digest_of(algorithm: TsigAlgorithm) -> fn() -> MessageDigest {
    match algorithm {
        TsigAlgorithm::HmacSha256 => MessageDigest::sha256,
        TsigAlgorithm::HmacSha512 => MessageDigest::sha512,
    }
}

/// Signs a message and appends the signature record.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the key cannot be used, and
/// [`Reason::Protocol`] when the key name cannot be encoded.
pub fn sign(
    message: &[u8],
    key_name: &str,
    algorithm: TsigAlgorithm,
    secret: &[u8],
    signed_at: u64,
) -> Result<Signed, Failure> {
    let variables = variables(key_name, algorithm, signed_at, 0, &[])?;

    let mut digested = Vec::with_capacity(message.len() + variables.len());
    digested.extend_from_slice(message);
    digested.extend_from_slice(&variables);
    let mac = hmac(algorithm, secret, &digested)?;

    let id = wire::header(message)?.id;
    let mut out = message.to_vec();
    append(&mut out, key_name, algorithm, signed_at, &mac, id)?;
    Ok(Signed { message: out, mac })
}

/// Checks the signature on an answer against the request it answers.
///
/// # Errors
///
/// Returns [`Reason::Crypto`] when the answer carries no signature, carries
/// one this key does not produce, or was signed too long ago.
pub fn verify(
    response: &[u8],
    key_name: &str,
    algorithm: TsigAlgorithm,
    secret: &[u8],
    request_mac: &[u8],
    now: u64,
) -> Result<(), Failure> {
    let at = last_record(response)?.ok_or_else(missing)?;
    let (name, after) = wire::read_name(response, at)?;
    let kind = u16::from_be_bytes([
        *response.get(after).ok_or_else(missing)?,
        *response.get(after + 1).ok_or_else(missing)?,
    ]);
    if kind != TYPE_TSIG {
        return Err(missing());
    }
    if !name.eq_ignore_ascii_case(key_name.trim_end_matches('.')) {
        return Err(Failure::new(
            Reason::Crypto,
            format!("the name server signed its answer as {name}, not as {key_name}"),
        ));
    }

    let length = usize::from(u16::from_be_bytes([
        *response.get(after + 8).ok_or_else(missing)?,
        *response.get(after + 9).ok_or_else(missing)?,
    ]));
    let start = after + 10;
    let data = response
        .get(start..start + length)
        .ok_or_else(|| Failure::new(Reason::Crypto, "the signature record ends too early"))?;

    let held = read_rdata(data)?;
    if !held
        .algorithm
        .eq_ignore_ascii_case(algorithm_name(algorithm))
    {
        return Err(Failure::new(
            Reason::Crypto,
            format!(
                "the name server signed its answer with {}, not with {}",
                held.algorithm,
                algorithm_name(algorithm)
            ),
        ));
    }
    // The name server saying the signature is wrong is not a fault in the
    // signing here: it is the two sides holding different keys, or clocks too
    // far apart. Both are things an operator changes, and neither is worth
    // another attempt (RFC 8945 section 4.3).
    if held.error != 0 {
        return Err(Failure::new(
            Reason::Configuration,
            match held.error {
                16 => "the name server does not hold the key this update was signed with; \
                       the shared key stored here and the one in its configuration differ"
                    .to_owned(),
                17 => "the name server knows no key by this name".to_owned(),
                18 => "the name server and this machine disagree about the time by more \
                       than the signature allows"
                    .to_owned(),
                other => format!("the name server refused the signature with code {other}"),
            },
        ));
    }
    if now.abs_diff(held.signed_at) > u64::from(held.fudge) {
        return Err(Failure::new(
            Reason::Crypto,
            format!(
                "the answer was signed {}s away from this clock, more than the {}s allowed",
                now.abs_diff(held.signed_at),
                held.fudge
            ),
        ));
    }

    // The message the signature covers is the answer without its own
    // signature record, and with the count that record was added to put back.
    let mut stripped = response[..at].to_vec();
    let additional = u16::from_be_bytes([stripped[10], stripped[11]]);
    let without = additional.checked_sub(1).ok_or_else(|| {
        Failure::new(
            Reason::Crypto,
            "the answer carries a signature it does not count".to_owned(),
        )
    })?;
    stripped[10..12].copy_from_slice(&without.to_be_bytes());

    let variables = variables(key_name, algorithm, held.signed_at, held.error, &held.other)?;

    let mut digested = Vec::new();
    let request_length = u16::try_from(request_mac.len())
        .map_err(|_| Failure::new(Reason::Crypto, "the request signature is not a signature"))?;
    digested.extend_from_slice(&request_length.to_be_bytes());
    digested.extend_from_slice(request_mac);
    digested.extend_from_slice(&stripped);
    digested.extend_from_slice(&variables);

    let expected = hmac(algorithm, secret, &digested)?;
    if expected.len() != held.mac.len() || !openssl::memcmp::eq(&expected, &held.mac) {
        return Err(Failure::new(
            Reason::Crypto,
            "the answer's signature does not match the key this update was signed with".to_owned(),
        ));
    }
    Ok(())
}

/// The fields of a signature record.
struct Rdata {
    algorithm: String,
    signed_at: u64,
    fudge: u16,
    mac: Vec<u8>,
    error: u16,
    other: Vec<u8>,
}

fn read_rdata(data: &[u8]) -> Result<Rdata, Failure> {
    let (algorithm, at) = wire::read_name(data, 0)?;
    let field = |from: usize, length: usize| {
        data.get(from..from + length)
            .ok_or_else(|| Failure::new(Reason::Crypto, "the signature record ends too early"))
    };

    let time = field(at, 6)?;
    let signed_at = time
        .iter()
        .fold(0_u64, |carried, byte| (carried << 8) | u64::from(*byte));
    let fudge = u16::from_be_bytes([field(at + 6, 2)?[0], field(at + 6, 2)?[1]]);
    let mac_size = usize::from(u16::from_be_bytes([
        field(at + 8, 2)?[0],
        field(at + 8, 2)?[1],
    ]));
    let mac = field(at + 10, mac_size)?.to_vec();
    let rest = at + 10 + mac_size;
    let error = u16::from_be_bytes([field(rest + 2, 2)?[0], field(rest + 2, 2)?[1]]);
    let other_size = usize::from(u16::from_be_bytes([
        field(rest + 4, 2)?[0],
        field(rest + 4, 2)?[1],
    ]));
    let other = field(rest + 6, other_size)?.to_vec();

    Ok(Rdata {
        algorithm,
        signed_at,
        fudge,
        mac,
        error,
        other,
    })
}

/// The part of a signature record the signature itself covers.
///
/// Names go in canonical form, which is lowercase and never compressed. The
/// two sides compute this the same way or they never agree.
fn variables(
    key_name: &str,
    algorithm: TsigAlgorithm,
    signed_at: u64,
    error: u16,
    other: &[u8],
) -> Result<Vec<u8>, Failure> {
    let mut out = Vec::new();
    wire::write_name(key_name, Case::Canonical, &mut out)?;
    out.extend_from_slice(&CLASS_ANY.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    wire::write_name(algorithm_name(algorithm), Case::Canonical, &mut out)?;
    out.extend_from_slice(&signed_at.to_be_bytes()[2..]);
    out.extend_from_slice(&FUDGE.to_be_bytes());
    out.extend_from_slice(&error.to_be_bytes());
    let other_length = u16::try_from(other.len()).map_err(|_| {
        Failure::new(
            Reason::Crypto,
            "a signature carries more trailing data than one record holds".to_owned(),
        )
    })?;
    out.extend_from_slice(&other_length.to_be_bytes());
    out.extend_from_slice(other);
    Ok(out)
}

/// Appends the signature record and counts it.
fn append(
    message: &mut Vec<u8>,
    key_name: &str,
    algorithm: TsigAlgorithm,
    signed_at: u64,
    mac: &[u8],
    id: u16,
) -> Result<(), Failure> {
    let mut data = Vec::new();
    wire::write_name(algorithm_name(algorithm), Case::AsGiven, &mut data)?;
    data.extend_from_slice(&signed_at.to_be_bytes()[2..]);
    data.extend_from_slice(&FUDGE.to_be_bytes());
    let mac_length = u16::try_from(mac.len())
        .map_err(|_| Failure::new(Reason::Crypto, "the signature is not a signature"))?;
    data.extend_from_slice(&mac_length.to_be_bytes());
    data.extend_from_slice(mac);
    data.extend_from_slice(&id.to_be_bytes());
    // No error and no trailing data: this is a request being signed.
    data.extend_from_slice(&0_u16.to_be_bytes());
    data.extend_from_slice(&0_u16.to_be_bytes());

    wire::write_name(key_name, Case::AsGiven, message)?;
    message.extend_from_slice(&TYPE_TSIG.to_be_bytes());
    message.extend_from_slice(&CLASS_ANY.to_be_bytes());
    message.extend_from_slice(&0_u32.to_be_bytes());
    let length = u16::try_from(data.len())
        .map_err(|_| Failure::new(Reason::Crypto, "the signature record does not fit"))?;
    message.extend_from_slice(&length.to_be_bytes());
    message.extend_from_slice(&data);

    let additional = u16::from_be_bytes([message[10], message[11]]);
    let counted = additional.checked_add(1).ok_or_else(|| {
        Failure::new(
            Reason::Crypto,
            "the message already carries as many records as it can".to_owned(),
        )
    })?;
    message[10..12].copy_from_slice(&counted.to_be_bytes());
    Ok(())
}

/// Where the last record of a message starts, if it has one.
///
/// The signature is always the last record, so this is where verification
/// begins and where the covered part of the message ends.
fn last_record(bytes: &[u8]) -> Result<Option<usize>, Failure> {
    let head = wire::header(bytes)?;
    let mut at = 12;

    for _ in 0..head.counts[0] {
        let (_, next) = wire::read_name(bytes, at)?;
        at = next + 4;
    }

    let records = u32::from(head.counts[1]) + u32::from(head.counts[2]) + u32::from(head.counts[3]);
    if records == 0 {
        return Ok(None);
    }

    let mut start = at;
    for _ in 0..records {
        start = at;
        let (_, next) = wire::read_name(bytes, at)?;
        let length = usize::from(u16::from_be_bytes([
            *bytes.get(next + 8).ok_or_else(missing)?,
            *bytes.get(next + 9).ok_or_else(missing)?,
        ]));
        at = next + 10 + length;
    }
    Ok(Some(start))
}

fn hmac(algorithm: TsigAlgorithm, secret: &[u8], over: &[u8]) -> Result<Vec<u8>, Failure> {
    let key = PKey::hmac(secret).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the shared key could not be used: {error}"),
        )
    })?;
    let mut signer = Signer::new(digest_of(algorithm)(), &key).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the signature could not be started: {error}"),
        )
    })?;
    signer.update(over).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the signature could not be computed: {error}"),
        )
    })?;
    signer.sign_to_vec().map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("the signature could not be finished: {error}"),
        )
    })
}

fn missing() -> Failure {
    Failure::new(
        Reason::Crypto,
        "the name server answered without signing, and an unsigned answer proves nothing"
            .to_owned(),
    )
}
