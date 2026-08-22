// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Taking the secrets out of a message before it is written.
//!
//! Our own records are built from named fields and carry no header value, no
//! cookie and no body. The libraries underneath us are not: pingora writes the
//! whole request header and the whole response body at `debug` and `trace`, so
//! an operator raising the level to find a fault would put every password and
//! every session cookie into a log that journald then keeps and ships
//! (ADR-0037).
//!
//! # What is masked
//!
//! The value of a header known to carry credentials, the value of anything
//! called a body, and any PEM private key block. The name stays, so a reader
//! still sees that the header was there; only what it held is replaced.
//!
//! # Why a scan and not a level cap
//!
//! Capping the level of other crates would throw away the record entirely,
//! and with it the reason the operator raised the level. Masking keeps the
//! record and removes only the value.

/// What a masked value is replaced with.
const MASK: &str = "***";

/// Field names whose value never reaches the log.
///
/// Matched without case, because the same header is written `Cookie` by one
/// library and `"cookie"` by another.
const SECRET: [&str; 8] = [
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "password",
    "body",
];

/// The message with every secret value replaced.
///
/// Returns the message unchanged when there is nothing to mask, so the common
/// case allocates nothing beyond the message itself.
#[must_use]
pub fn message(message: &str) -> String {
    let mut out = String::with_capacity(message.len());
    let bytes = message.as_bytes();
    let lower = message.to_ascii_lowercase();
    let mut at = 0;

    while at < bytes.len() {
        if let Some(name) = secret_at(&lower, at)
            && let Some((from, to)) = value_span(bytes, at + name.len())
        {
            out.push_str(&message[at..from]);
            out.push_str(MASK);
            at = to;
            continue;
        }
        if let Some(end) = pem_key_at(&lower, at) {
            out.push_str(MASK);
            at = end;
            continue;
        }
        // Whole characters, because a message is text and slicing it mid
        // character would produce something that is not.
        let step = char_len(bytes[at]);
        let end = (at + step).min(message.len());
        out.push_str(&message[at..end]);
        at = end;
    }
    out
}

/// The secret name starting exactly here, if any.
///
/// A name only counts on a boundary, so `cookie` matches and the `cookie` in
/// `cookiejar_size` does not.
fn secret_at(lower: &str, at: usize) -> Option<&'static str> {
    if !boundary_before(lower.as_bytes(), at) {
        return None;
    }
    SECRET.iter().copied().find(|name| {
        lower[at..].starts_with(name)
            && lower.as_bytes().get(at + name.len()).is_none_or(|after| {
                !after.is_ascii_alphanumeric() && *after != b'_' && *after != b'-'
            })
    })
}

/// Whether the byte before this position ends whatever came before it.
///
/// An escape sequence counts as a boundary: a header written into a debug byte
/// string is preceded by the two characters `\` and `n`, and reading that `n`
/// as part of a word would leave the header unmasked.
fn boundary_before(bytes: &[u8], at: usize) -> bool {
    if at == 0 {
        return true;
    }
    let before = bytes[at - 1];
    if matches!(before, b'n' | b'r' | b't') && at >= 2 && bytes[at - 2] == b'\\' {
        return true;
    }
    !before.is_ascii_alphanumeric() && before != b'_'
}

/// The stretch of a message that holds a value, wrappers and all.
///
/// Returns nothing when the name introduces no value, so a sentence merely
/// mentioning a cookie keeps its words.
fn value_span(bytes: &[u8], mut at: usize) -> Option<(usize, usize)> {
    // A name written inside quotes, as a JSON-ish debug format does.
    if bytes.get(at) == Some(&b'"') {
        at += 1;
    }
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }
    // The separator. Without one the name was just a word in a sentence.
    if !matches!(bytes.get(at), Some(b':' | b'=')) {
        return None;
    }
    at += 1;
    while bytes.get(at).is_some_and(u8::is_ascii_whitespace) {
        at += 1;
    }

    let from = at;
    // The wrappers a debug format puts round a value. Masked along with the
    // value, so what is written stays balanced.
    let mut quoted = false;
    for wrapper in ["Some(", "b", "\\\"", "\""] {
        if bytes[at..].starts_with(wrapper.as_bytes()) {
            at += wrapper.len();
            quoted |= wrapper.ends_with('"');
        }
    }

    let mut to = at;
    while to < bytes.len() {
        if bytes[to..].starts_with(b"\\r") || bytes[to..].starts_with(b"\\n") {
            break;
        }
        if matches!(bytes[to], b'"' | b'\r' | b'\n' | b',' | b'}' | b')') {
            // The closing quote belongs to the value it wrapped.
            if quoted && bytes[to] == b'"' {
                to += 1;
            }
            break;
        }
        to += 1;
    }
    Some((from, to))
}

/// The end of a PEM private key block starting here, if one does.
///
/// Matched as a block rather than by its name, because a key printed without
/// its banner is still a key and a key printed with one is unmistakable.
fn pem_key_at(lower: &str, at: usize) -> Option<usize> {
    const OPEN: &str = "-----begin";
    const CLOSE: &str = "-----";
    if !lower[at..].starts_with(OPEN) {
        return None;
    }
    let head_end = lower[at + OPEN.len()..].find(CLOSE)? + at + OPEN.len();
    if !lower[at..head_end].contains("private key") {
        return None;
    }
    // Everything up to and including the closing banner.
    let tail = lower[head_end..].find("-----end")? + head_end;
    let end = lower[tail + CLOSE.len()..].find(CLOSE)? + tail + CLOSE.len() + CLOSE.len();
    Some(end.min(lower.len()))
}

/// How many bytes the character starting with this byte takes.
const fn char_len(first: u8) -> usize {
    match first {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}
