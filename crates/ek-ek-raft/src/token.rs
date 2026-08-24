// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one word an operator carries from a running cluster to a new node.
//!
//! `ekek1.<id>.<secret>.<fingerprint>`
//!
//! No spaces, so it survives being copied. The leading `ekek1` is the format
//! version: a later format is refused by name rather than misread. The
//! fingerprint rides along because a joining node has nothing else to check
//! the far end against, and a join that trusts whatever answers is the attack
//! the token exists to stop (ADR-0031, ADR-0084).
//!
//! # What the cluster keeps
//!
//! The digest of the secret, never the secret. The secret is shown once, at
//! the moment it is minted, and a leaked backup hands over nothing that can be
//! presented.

use ek_ek_peer::fingerprint::{FINGERPRINT_CHARACTERS, well_formed};
use ek_ek_store::TokenId;
use sha2::{Digest, Sha256};

use crate::error::{Failure, Reason};

/// The word every token starts with.
pub const FORMAT: &str = "ekek1";

/// How many characters the public half is.
///
/// Eight bytes of randomness, two hex characters each. It names a record and
/// grants nothing, so it is short enough to read out over a telephone.
pub const ID_CHARACTERS: usize = 16;

/// How many characters the secret half is.
///
/// Thirty-two bytes of randomness, two hex characters each. This is the half
/// that lets a node in, so it is sized like a key and not like a name.
pub const SECRET_CHARACTERS: usize = 64;

/// How long a token is usable for by default, in seconds.
///
/// One hour. Long enough to walk to the second machine, short enough that a
/// token left in a terminal history is worth nothing by the end of the day
/// (ADR-0031).
pub const LIFETIME_SECONDS: i64 = 3_600;

/// A join token, taken apart.
#[derive(Clone, PartialEq, Eq)]
pub struct Token {
    /// The public half, which names the record.
    pub id: TokenId,
    /// The secret half, which is what a join presents.
    pub secret: String,
    /// The fingerprint of the cluster authority the token was minted by.
    pub fingerprint: String,
}

impl Token {
    /// The one word, ready to be carried.
    #[must_use]
    pub fn word(&self) -> String {
        format!("{FORMAT}.{}.{}.{}", self.id, self.secret, self.fingerprint)
    }

    /// Takes a token apart, refusing anything that is not one.
    ///
    /// # Errors
    ///
    /// Returns [`Reason::Configuration`] when the word is not a token of this
    /// format.
    pub fn read(word: &str) -> Result<Self, Failure> {
        let parts: Vec<&str> = word.trim().split('.').collect();
        let [format, id, secret, fingerprint] = parts.as_slice() else {
            return Err(malformed(&format!(
                "a join token is four parts separated by dots, and {} were given",
                parts.len()
            )));
        };

        // Named rather than guessed at. A cluster one release older has to be
        // able to say "this is a token I do not read" instead of "this token
        // is wrong".
        if *format != FORMAT {
            return Err(malformed(&format!(
                "this release reads {FORMAT} join tokens and the token says {format}"
            )));
        }
        if !hex_of_length(id, ID_CHARACTERS) {
            return Err(malformed(&format!(
                "a join token identity is {ID_CHARACTERS} lowercase hex characters"
            )));
        }
        if !hex_of_length(secret, SECRET_CHARACTERS) {
            return Err(malformed(&format!(
                "a join token secret is {SECRET_CHARACTERS} lowercase hex characters"
            )));
        }
        if !well_formed(fingerprint) {
            return Err(malformed(&format!(
                "a join token carries a fingerprint of {FINGERPRINT_CHARACTERS} \
                 lowercase hex characters"
            )));
        }

        Ok(Self {
            id: TokenId::new(*id),
            secret: (*secret).to_owned(),
            fingerprint: (*fingerprint).to_owned(),
        })
    }
}

/// Prints nothing. The secret is half of this structure, and a token in a log
/// line is a token anybody reading the log can use.
impl std::fmt::Debug for Token {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Token")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// Mints a fresh token against one authority.
///
/// # Errors
///
/// Returns [`Reason::Configuration`] when the fingerprint is not one, and
/// [`Reason::Crypto`] when randomness cannot be had.
pub fn mint(fingerprint: &str) -> Result<Token, Failure> {
    if !well_formed(fingerprint) {
        return Err(malformed(&format!(
            "a join token carries a fingerprint of {FINGERPRINT_CHARACTERS} \
             lowercase hex characters"
        )));
    }

    Ok(Token {
        id: TokenId::new(random_hex(ID_CHARACTERS / 2)?),
        secret: random_hex(SECRET_CHARACTERS / 2)?,
        fingerprint: fingerprint.to_owned(),
    })
}

/// The digest a cluster stores instead of the secret.
#[must_use]
pub fn digest(secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Whether a presented secret is the one a stored digest was taken from.
///
/// The comparison runs over every byte rather than stopping at the first
/// difference, so how long it takes says nothing about how much of the secret
/// was right.
#[must_use]
pub fn presented(secret: &str, stored_digest: &str) -> bool {
    let taken = digest(secret);
    if taken.len() != stored_digest.len() {
        return false;
    }
    taken
        .bytes()
        .zip(stored_digest.bytes())
        .fold(0_u8, |differences, (left, right)| {
            differences | (left ^ right)
        })
        == 0
}

fn random_hex(bytes: usize) -> Result<String, Failure> {
    let mut buffer = vec![0_u8; bytes];
    getrandom::fill(&mut buffer).map_err(|error| {
        Failure::new(
            Reason::Crypto,
            format!("a join token could not be made random: {error}"),
        )
    })?;
    Ok(buffer.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn hex_of_length(value: &str, characters: usize) -> bool {
    value.len() == characters
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn malformed(detail: &str) -> Failure {
    Failure::new(Reason::Configuration, detail.to_owned())
}
