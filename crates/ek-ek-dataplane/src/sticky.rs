// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Session stickiness: keeping one client on one member.
//!
//! An application that holds session state in memory needs the same client
//! to come back to the same server. The proxy sets its own cookie rather
//! than learning the application's, because a cookie name configured wrong
//! breaks quietly (ADR-0024).
//!
//! # What the cookie carries
//!
//! Nothing readable. The value is the first bytes of
//! `HMAC-SHA256(key, pool + "\0" + member)`, as hex (ADR-0065). Reading it
//! back means computing the same digest for every eligible member and
//! looking for a match, so:
//!
//! - a member that was removed matches nothing, and its cookies stop working
//!   without any invalidation step;
//! - a member that was renumbered still matches, because the digest is over
//!   the member's identity and not its address;
//! - a forged value matches nothing without the key.
//!
//! Comparison is constant time. A comparison that stopped at the first
//! differing byte would let an attacker learn a valid value one byte at a
//! time.

use ek_ek_config::{Backend, BackendMember, SameSitePolicy, SessionStickiness};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// How many digest bytes the cookie carries.
///
/// Sixteen bytes is 32 hex characters, small enough to keep the header
/// short and far past what a forger can search.
const DIGEST_BYTES: usize = 16;

/// Signs and recognises cookie values for one key.
///
/// The key is accepted once, when the signer is built, so no later call has
/// an error to handle or a bad key to fall back from.
#[derive(Clone)]
pub struct Signer(Hmac<Sha256>);

impl Signer {
    /// Builds a signer, or `None` when the key cannot be used.
    ///
    /// Returning `None` turns stickiness off for that configuration rather
    /// than signing with something nobody configured.
    #[must_use]
    pub fn new(key: &[u8]) -> Option<Self> {
        <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .ok()
            .map(Self)
    }

    /// Builds a signer from the hex key a configuration carries.
    #[must_use]
    pub fn from_hex(key: &str) -> Option<Self> {
        Self::new(&key_bytes(key)?)
    }

    /// Computes the opaque value naming one member.
    ///
    /// The pool goes into the digest as well as the member, so the same
    /// member identity in two pools does not produce one value that would
    /// let a cookie written for one pool select in the other.
    #[must_use]
    pub fn token(&self, pool: &str, member: &str) -> String {
        let mut mac = self.0.clone();
        mac.update(pool.as_bytes());
        mac.update(b"\0");
        mac.update(member.as_bytes());

        let digest = mac.finalize().into_bytes();
        let mut value = String::with_capacity(DIGEST_BYTES * 2);
        for byte in digest.iter().take(DIGEST_BYTES) {
            use std::fmt::Write;
            // Writing into a String cannot fail. The result is discarded
            // rather than unwrapped so no path here can panic.
            let _ = write!(value, "{byte:02x}");
        }
        value
    }

    /// Finds which of these members a cookie value names.
    ///
    /// Members that cannot take traffic are not offered: a cookie pointing
    /// at a member that is out of service has to be redistributed, and
    /// matching it first would only send the request somewhere it cannot go.
    #[must_use]
    pub fn member_for<'a>(
        &self,
        pool: &str,
        eligible: &[&'a BackendMember],
        value: &str,
    ) -> Option<&'a BackendMember> {
        // Every member is tried even after a match, so the work does not
        // depend on where in the pool the answer sits.
        let mut found = None;
        for member in eligible {
            if same(&self.token(pool, member.id.as_str()), value) {
                found = Some(*member);
            }
        }
        found
    }
}

impl std::fmt::Debug for Signer {
    /// Prints nothing about the key. A signer that logged its own key would
    /// put it in every diagnostic that formats the structure holding it.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("Signer")
    }
}

/// Compares two values without stopping at the first difference.
#[must_use]
fn same(left: &str, right: &str) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

/// Reads the stickiness settings of a pool, or `None` when it has none.
#[must_use]
pub fn settings(pool: &Backend) -> Option<(&str, SameSitePolicy)> {
    match &pool.stickiness {
        SessionStickiness::Disabled => None,
        SessionStickiness::SignedCookie {
            cookie_name,
            same_site,
        } => Some((cookie_name.as_str(), *same_site)),
    }
}

/// Finds the value a named cookie carries in a `Cookie` header.
///
/// A client may send several `Cookie` headers, and each may carry several
/// pairs, so every header line is walked rather than only the first.
#[must_use]
pub fn read<'a>(headers: impl Iterator<Item = &'a str>, name: &str) -> Option<String> {
    for line in headers {
        for pair in line.split(';') {
            let pair = pair.trim();
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            if key.trim() == name {
                return Some(value.trim().to_owned());
            }
        }
    }
    None
}

/// Builds the `Set-Cookie` value that pins a client to a member.
///
/// No `Max-Age` and no `Expires`: this is a session cookie, so stickiness
/// ends with the browser session rather than outliving the member it names
/// (ADR-0065).
#[must_use]
pub fn set_cookie(name: &str, value: &str, same_site: SameSitePolicy, secure: bool) -> String {
    let policy = match same_site {
        SameSitePolicy::Strict => "Strict",
        SameSitePolicy::Lax => "Lax",
        SameSitePolicy::None => "None",
    };

    let mut cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite={policy}");
    // A cookie a client sends back over plaintext is a cookie an observer
    // on the path has read.
    if secure || same_site == SameSitePolicy::None {
        // SameSite=None without Secure is rejected by every current browser,
        // so the pair is written together rather than left to produce a
        // cookie nothing stores.
        cookie.push_str("; Secure");
    }
    cookie
}

/// Reads a hex key into bytes.
///
/// Returns `None` for anything that is not hex, so a misconfigured key
/// turns stickiness off rather than signing with a key nobody meant.
#[must_use]
pub fn key_bytes(key: &str) -> Option<Vec<u8>> {
    if key.is_empty() || !key.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(key.len() / 2);
    let digits = key.as_bytes();
    for pair in digits.chunks_exact(2) {
        let high = char::from(*pair.first()?).to_digit(16)?;
        let low = char::from(*pair.get(1)?).to_digit(16)?;
        let byte = u8::try_from(high * 16 + low).ok()?;
        bytes.push(byte);
    }
    Some(bytes)
}
