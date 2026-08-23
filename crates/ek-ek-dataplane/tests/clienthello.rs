// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::indexing_slicing)]

//! What the parser makes of a ClientHello, and of everything that is not one.
//!
//! The bytes are written here rather than produced by a TLS library, so the
//! measurement covers the shapes an attacker sends as well as the ones a
//! client does.

#[path = "common/hello.rs"]
mod hello;

use ek_ek_dataplane::clienthello::{MOST_NAME_BYTES, Outcome, read};
use hello::{Hello, entries_extension, entry_extension, server_name_extension};

/// Where the name's own bytes start inside a whole ClientHello.
fn name_starts_at(bytes: &[u8], name: &str) -> usize {
    bytes
        .windows(name.len())
        .position(|window| window == name.as_bytes())
        .expect("the name is in there")
}

#[test]
fn a_client_hello_asking_for_a_name_gives_that_name() {
    let bytes = Hello::named("posta.ornek.com").bytes();

    assert_eq!(read(&bytes), Outcome::Named("posta.ornek.com".to_owned()));
}

#[test]
fn a_client_hello_with_no_server_name_extension_is_nameless() {
    // An old client and a monitoring tool connecting by address both send
    // this. It is a case of its own, not a fault (ADR-0070).
    let bytes = Hello::nameless().bytes();

    assert_eq!(read(&bytes), Outcome::Nameless);
}

#[test]
fn a_client_hello_with_no_extensions_at_all_is_nameless() {
    let bytes = Hello {
        extensions: false,
        ..Hello::default()
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::Nameless);
}

#[test]
fn the_name_is_found_after_extensions_that_come_before_it() {
    // A real client sends a dozen extensions and the server name is rarely
    // first. Each one has to be walked past by its own length.
    let bytes = Hello::named("posta.ornek.com")
        .after(0x000B, vec![0x01, 0x02, 0x03])
        .after(0x000A, vec![0xAA; 40])
        .after(0x0010, vec![0x08; 12])
        .bytes();

    assert_eq!(read(&bytes), Outcome::Named("posta.ornek.com".to_owned()));
}

#[test]
fn the_name_is_found_after_another_name_type_in_the_same_list() {
    // The list may hold entries the RFC never defined. They are walked past,
    // because a host name may still follow.
    let list = entries_extension(&[(9, b"something else"), (0, b"posta.ornek.com")]);

    let bytes = Hello {
        server_name: Some(list),
        ..Hello::default()
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::Named("posta.ornek.com".to_owned()));
}

#[test]
fn a_hello_that_has_only_partly_arrived_asks_for_more() {
    // The ClientHello crosses several TCP segments regularly. Every prefix of
    // a good one has to say "read again" rather than "this is broken".
    let whole = Hello::named("posta.ornek.com").bytes();

    for keep in 0..whole.len() {
        let outcome = read(&whole[..keep]);
        assert_eq!(
            outcome,
            Outcome::More,
            "{keep} of {} bytes was judged {outcome:?}",
            whole.len()
        );
    }
    assert_eq!(read(&whole), Outcome::Named("posta.ornek.com".to_owned()));
}

#[test]
fn bytes_that_are_not_a_handshake_are_refused() {
    // An HTTP request on a passthrough port, which is what somebody typing
    // the address into a browser sends.
    assert_eq!(
        read(b"GET / HTTP/1.1\r\nHost: ornek.com\r\n\r\n"),
        Outcome::NotAHandshake
    );
    // A TLS alert record rather than a handshake one.
    assert_eq!(read(&[21, 3, 1, 0, 2, 1, 0]), Outcome::NotAHandshake);
}

#[test]
fn a_handshake_that_is_not_a_client_hello_is_refused() {
    // Nothing else may legitimately be the first message on a fresh
    // connection.
    let bytes = Hello {
        message_type: 2,
        ..Hello::named("posta.ornek.com")
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::NotAHandshake);
}

#[test]
fn nothing_at_all_asks_for_more() {
    // An accepted connection that has sent no byte yet.
    assert_eq!(read(&[]), Outcome::More);
}

#[test]
fn a_record_that_claims_no_body_is_refused() {
    assert_eq!(read(&[22, 3, 1, 0, 0]), Outcome::NotAHandshake);
}

#[test]
fn a_name_longer_than_the_rfc_allows_is_not_read() {
    // Checked before the bytes are taken, so a length claiming more than any
    // name may be costs nothing. The connection still goes somewhere: the
    // default pool takes it.
    let long = "a".repeat(MOST_NAME_BYTES + 1);
    let bytes = Hello {
        server_name: Some(server_name_extension(&long)),
        ..Hello::default()
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::Nameless);
}

#[test]
fn a_name_exactly_as_long_as_the_rfc_allows_is_read() {
    // The other side of the limit, or the check above would pass against a
    // parser that refused every name.
    //
    // Written as the number rather than as the constant: a length taken from
    // the constant follows it wherever it moves, and the measurement would
    // then say nothing about where the limit actually is.
    assert_eq!(MOST_NAME_BYTES, 255, "RFC 6066 caps a server name here");
    let name = format!("{}.ornek.com", "a".repeat(245));
    assert_eq!(name.len(), 255);
    let bytes = Hello {
        server_name: Some(server_name_extension(&name)),
        ..Hello::default()
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::Named(name));
}

#[test]
fn a_name_that_is_not_text_is_not_read() {
    let bytes = Hello {
        server_name: Some(entry_extension(0, &[0xFF, 0xFE, 0xFD])),
        ..Hello::default()
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::Nameless);
}

#[test]
fn an_empty_name_is_not_a_name() {
    let bytes = Hello {
        server_name: Some(entry_extension(0, b"")),
        ..Hello::default()
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::Nameless);
}

#[test]
fn a_session_id_claiming_more_than_the_record_holds_asks_for_more() {
    // The session id is walked past rather than read, and a length nobody
    // checked walks the cursor straight past the end of the buffer. The
    // record's own length is honest here, so only the inner check can catch
    // it.
    let bytes = Hello {
        session_id: 4,
        session_id_claims: Some(200),
        ..Hello::named("posta.ornek.com")
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::More);
}

#[test]
fn a_cipher_list_claiming_more_than_the_record_holds_asks_for_more() {
    // The same lie on the vector whose length is two bytes rather than one.
    let bytes = Hello {
        ciphers: 4,
        ciphers_claim: Some(2000),
        ..Hello::named("posta.ornek.com")
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::More);
}

#[test]
fn a_compression_list_claiming_more_than_the_record_holds_asks_for_more() {
    // The last vector before the extensions, and the one where an unchecked
    // skip is invisible: what follows it is the extension block's length, and
    // a cursor sitting past the end reads that as "there are no extensions"
    // rather than as "there is not enough here".
    let bytes = Hello {
        compression: 1,
        compression_claims: Some(200),
        ..Hello::named("posta.ornek.com")
    }
    .bytes();

    assert_eq!(read(&bytes), Outcome::More);
}

#[test]
fn an_extension_that_claims_more_than_it_carries_is_refused() {
    // The length is the field a careless parser trusts and then reads past
    // the end of its buffer on.
    let mut bytes = Hello::named("posta.ornek.com").bytes();
    // Back from the name: entry length (2), entry type (1), list length (2),
    // then the extension's own length.
    let length_at = name_starts_at(&bytes, "posta.ornek.com") - 7;
    bytes[length_at] = 0x7F;
    bytes[length_at + 1] = 0xFF;

    assert_eq!(read(&bytes), Outcome::NotAHandshake);
}

#[test]
fn a_name_list_that_claims_more_than_it_carries_is_refused() {
    // The same lie one level in, where the parser has already slid into the
    // extension's own block.
    let mut bytes = Hello::named("posta.ornek.com").bytes();
    let length_at = name_starts_at(&bytes, "posta.ornek.com") - 5;
    bytes[length_at] = 0x7F;
    bytes[length_at + 1] = 0xFF;

    assert_eq!(read(&bytes), Outcome::NotAHandshake);
}

#[test]
fn a_name_that_claims_more_than_it_carries_is_refused() {
    // And one level further in still, on the field that says how long the
    // name itself is.
    let mut bytes = Hello::named("posta.ornek.com").bytes();
    let length_at = name_starts_at(&bytes, "posta.ornek.com") - 2;
    // Under the RFC's cap, so the length check does not take this first.
    bytes[length_at] = 0;
    bytes[length_at + 1] = 200;

    assert_eq!(read(&bytes), Outcome::NotAHandshake);
}

#[test]
fn a_hello_the_record_says_is_longer_than_it_is_asks_for_more() {
    // A record header stating more than has arrived is the ordinary case of a
    // handshake split across segments.
    let mut bytes = Hello::named("posta.ornek.com").bytes();
    bytes[3] = 0x7F;
    bytes[4] = 0xFF;

    assert_eq!(read(&bytes), Outcome::More);
}

#[test]
fn bytes_after_the_record_do_not_disturb_the_name() {
    // The client may already have sent the next record. Those bytes belong to
    // it, not to this handshake.
    let mut bytes = Hello::named("posta.ornek.com").bytes();
    bytes.extend_from_slice(&[22, 3, 3, 0xFF, 0xFF, 0x01, 0x02]);

    assert_eq!(read(&bytes), Outcome::Named("posta.ornek.com".to_owned()));
}
