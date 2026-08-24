// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the one word an operator carries must hold true.
//!
//! A token is typed or pasted by a person, so every rule here is about a token
//! that arrived wrong: split by a line wrap, from an older release, or from
//! another cluster. Each one has to be refused by name, because "this token is
//! wrong" and "this token is not one I read" are different problems for the
//! person holding it (ADR-0031, ADR-0084).

#![allow(clippy::expect_used, clippy::unwrap_used)]

use ek_ek_raft::token::{self, FORMAT, ID_CHARACTERS, LIFETIME_SECONDS, SECRET_CHARACTERS, Token};
use ek_ek_raft::{Reason, digest, presented};
use ek_ek_store::{JoinRecord, TokenId};

/// A fingerprint that is well formed and belongs to nothing.
const PRINT: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn a_token_is_one_word_and_reads_back_whole() {
    let minted = token::mint(PRINT).expect("a token is minted");
    let word = minted.word();

    assert!(
        word.starts_with(&format!("{FORMAT}.")),
        "a token does not say what format it is: {word}"
    );
    assert_eq!(
        word.split('.').count(),
        4,
        "a token is four parts and this one is not: {word}"
    );
    assert!(
        !word.contains(char::is_whitespace),
        "a token with a space in it does not survive being copied: {word}"
    );

    let read = Token::read(&word).expect("the word reads back");
    assert_eq!(read.id, minted.id);
    assert_eq!(read.secret, minted.secret);
    assert_eq!(read.fingerprint, minted.fingerprint);

    // And whitespace around it, which is what a paste brings with it, does not
    // stop it being read.
    let padded = Token::read(&format!("  {word}\n")).expect("a pasted token reads back");
    assert_eq!(padded.id, minted.id);
}

#[test]
fn two_tokens_are_never_the_same() {
    // A token that repeated would be one an attacker could guess from another.
    let first = token::mint(PRINT).expect("a token");
    let second = token::mint(PRINT).expect("a second token");

    assert_ne!(first.id, second.id, "two tokens share an identity");
    assert_ne!(first.secret, second.secret, "two tokens share a secret");
    assert_eq!(
        first.secret.len(),
        SECRET_CHARACTERS,
        "the secret is not the length it is documented as"
    );
    assert_eq!(first.id.as_str().len(), ID_CHARACTERS);
}

#[test]
fn a_token_from_another_format_is_refused_by_name() {
    // The reason the format version is in there at all. A release that cannot
    // read a token has to say so rather than say the token is wrong.
    let word = token::mint(PRINT).expect("a token").word();
    let older = word.replacen(FORMAT, "ekek0", 1);

    let refused = Token::read(&older).expect_err("another format is not read");
    assert_eq!(refused.reason(), Reason::Configuration, "{refused}");
    assert!(
        refused.detail().contains(FORMAT) && refused.detail().contains("ekek0"),
        "the refusal names neither format: {refused}"
    );
}

#[test]
fn a_token_that_arrived_broken_is_refused() {
    let minted = token::mint(PRINT).expect("a token");
    let word = minted.word();

    for (broken, what) in [
        (word.replace('.', " "), "split by spaces"),
        (
            word.split('.').take(3).collect::<Vec<_>>().join("."),
            "missing its fingerprint",
        ),
        (format!("{word}.extra"), "carrying a fifth part"),
        (
            word.replacen("ekek1.", "ekek1.ZZ", 1),
            "with a bad identity",
        ),
        (word.to_uppercase(), "in the wrong case"),
        (String::new(), "empty"),
        // The secret half, damaged on its own. The parts above are refused
        // before the secret is even looked at, so without these two a check
        // that never read the secret would still pass.
        (
            word.replacen(&minted.secret, &minted.secret.replacen('0', "Z", 1), 1),
            "with a secret that is not hex",
        ),
        (
            word.replacen(&minted.secret, &minted.secret[1..], 1),
            "with a secret one character short",
        ),
        // And the fingerprint half.
        (
            word.replacen(PRINT, &PRINT.replacen('0', "Z", 1), 1),
            "with a fingerprint that is not hex",
        ),
        (
            word.replacen(PRINT, &PRINT[1..], 1),
            "with a fingerprint one character short",
        ),
    ] {
        let refused = Token::read(&broken).expect_err(what);
        assert_eq!(
            refused.reason(),
            Reason::Configuration,
            "a token {what} was refused for the wrong reason: {refused}"
        );
    }

    // And the unbroken one is read, so the checks above are about the damage
    // and not about refusing every token.
    Token::read(&word).expect("an unbroken token reads back");
}

#[test]
fn a_token_carries_a_fingerprint_and_refuses_anything_else() {
    let refused = token::mint("not a fingerprint").expect_err("a fingerprint is checked");
    assert_eq!(refused.reason(), Reason::Configuration, "{refused}");

    token::mint(PRINT).expect("a well formed fingerprint is taken");
}

#[test]
fn what_is_kept_is_the_digest_and_never_the_secret() {
    let minted = token::mint(PRINT).expect("a token");
    let kept = digest(&minted.secret);

    assert_ne!(kept, minted.secret, "the secret itself was kept");
    assert!(
        presented(&minted.secret, &kept),
        "the digest does not answer to the secret it was taken from"
    );
    assert!(
        !presented("something else entirely", &kept),
        "the digest answers to a secret it was not taken from"
    );
    // The same secret always digests to the same value, which is what makes
    // the comparison work at all across two nodes.
    assert_eq!(kept, digest(&minted.secret));

    // A stored value of the wrong length answers to nothing. It cannot arrive
    // from a token this release minted, so the only way to see one is a store
    // that was damaged or written by hand, and neither may be treated as a
    // match.
    assert!(
        !presented(&minted.secret, ""),
        "an empty stored digest answered to a secret"
    );
    assert!(
        !presented(&minted.secret, &kept[1..]),
        "a stored digest one character short answered to a secret"
    );
}

#[test]
fn a_token_prints_nothing_it_holds() {
    // A token in a log line is a token whoever reads the log can use.
    let minted = token::mint(PRINT).expect("a token");
    let printed = format!("{minted:?}");

    assert!(
        !printed.contains(&minted.secret),
        "the secret is in the debug output: {printed}"
    );
    assert!(
        printed.contains(minted.id.as_str()),
        "the debug output does not even say which token it is: {printed}"
    );
}

#[test]
fn a_record_is_usable_until_the_second_it_runs_out() {
    let record = JoinRecord {
        secret_digest: digest("a secret"),
        expires_at_unix: 1_000 + LIFETIME_SECONDS,
        used_by: None,
        issued_by: "admin".to_owned(),
        issued_at_unix: 1_000,
    };

    assert!(
        record.usable(1_000),
        "a token is not usable when it is made"
    );
    assert!(
        record.usable(1_000 + LIFETIME_SECONDS - 1),
        "a token is not usable one second before it runs out"
    );
    assert!(
        !record.usable(1_000 + LIFETIME_SECONDS),
        "a token is still usable the second it runs out"
    );
    assert!(record.expired(1_000 + LIFETIME_SECONDS));
    assert!(!record.expired(1_000 + LIFETIME_SECONDS - 1));

    // And a token that was used is not usable however early it is.
    let used = JoinRecord {
        used_by: Some(ek_ek_config::NodeId::new("node-b")),
        ..record
    };
    assert!(!used.usable(1_000), "a used token is still usable");
}

#[test]
fn an_identity_names_a_record_and_nothing_else() {
    // The public half is public on purpose. Knowing it finds the record and
    // opens nothing, because the secret beside it is what a join is checked
    // against.
    let minted = token::mint(PRINT).expect("a token");
    let id = TokenId::new(minted.id.as_str());

    assert_eq!(id, minted.id);
    assert_eq!(id.to_string(), minted.id.as_str());
    assert!(
        !minted.secret.contains(minted.id.as_str()),
        "the identity gives away part of the secret"
    );
}
