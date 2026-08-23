// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What each TLS policy level means, as a table rather than as code.
//!
//! An operator picks a level and never a cipher suite list, because a
//! hand-written list is how a configuration silently becomes insecure
//! (ADR-0028). The three levels are defined here and nowhere else.
//!
//! # Why this is a pure function
//!
//! It returns a value and touches no `SslAcceptorBuilder`. That is what lets
//! the contents of a cipher list be measured directly: a handshake shows only
//! the one suite that was chosen, so a list read back from a connection says
//! almost nothing about the list that was offered (ADR-0081).
//!
//! # Why the lists are written out here
//!
//! `mozilla_intermediate_v5` moves with the `openssl` crate. Taking it as it
//! comes would let the meaning of `dengeli` change with a dependency bump and
//! with nothing in this repository to show it. A security setting that shifts
//! quietly is worse than the setting itself.
//!
//! # Ageing
//!
//! Cipher suite lists go stale. Review all three at every major release. That
//! is a rule of the product, not of this file (ADR-0028).

use std::fmt::Write as _;

use ek_ek_config::{Config, TlsPolicyLevel};
use pingora::tls::ssl::SslVersion;

/// The lowest protocol version a level accepts.
///
/// Named rather than taken from the TLS library, because this table is what
/// the levels mean and a test has to be able to read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Version {
    /// TLS 1.0.
    Tls1_0,
    /// TLS 1.2.
    Tls1_2,
    /// TLS 1.3.
    Tls1_3,
}

/// What one level asks of the TLS library.
///
/// No upper bound is carried on purpose. Accepting an old client must not pull
/// a modern one down with it, so every level runs up to the newest version the
/// library speaks (ADR-0081).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policy {
    /// The oldest protocol version this level accepts.
    pub least_version: Version,
    /// Cipher suites for TLS 1.2 and below, in OpenSSL's list syntax.
    ///
    /// Empty when the level accepts no version below TLS 1.3, because there is
    /// then nothing for this list to describe.
    pub cipher_list: &'static str,
    /// Cipher suites for TLS 1.3, which OpenSSL keeps in a separate list.
    pub ciphersuites: &'static str,
    /// Whether the level lowers OpenSSL's security level to zero.
    ///
    /// Measured: without it a TLS 1.0 handshake never completes on OpenSSL 3,
    /// because the default security level refuses SHA-1 signatures and the
    /// cipher suites of that era.
    pub relaxes_security_level: bool,
}

/// TLS 1.3 suites. The same three at every level, because TLS 1.3 defines no
/// weak ones to leave out.
const TLS13_SUITES: &str =
    "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256";

/// TLS 1.2 suites for `dengeli`: forward secrecy and an AEAD mode, nothing
/// else. No RSA key exchange, no CBC, no SHA-1.
const BALANCED_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384";

/// Suites for `eski-uyumlu`: everything above, then what a TLS 1.0 client can
/// actually do.
///
/// `@SECLEVEL=0` is what makes the old half reachable at all on OpenSSL 3. The
/// suites `dengeli` offers stay first in the list, so a modern client on this
/// frontend still gets a modern suite.
///
/// The old half names both an ECDSA and an RSA suite for every shape. A leaf
/// can be either, and a list carrying only the RSA half leaves a frontend with
/// an ECDSA certificate unable to complete a TLS 1.0 handshake at all: the
/// AEAD suites its key can use were defined for TLS 1.2 and are not offered
/// below it.
const LEGACY_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:\
DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-SHA:\
ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:\
AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA:\
!aNULL:!eNULL:!EXPORT:!MD5:!RC4:!DES:!3DES:@SECLEVEL=0";

/// What a level asks of the TLS library.
#[must_use]
pub const fn settings(level: TlsPolicyLevel) -> Policy {
    match level {
        TlsPolicyLevel::Modern => Policy {
            least_version: Version::Tls1_3,
            // Nothing below TLS 1.3 is accepted, so no list of older suites
            // can be reached. Left empty rather than filled with suites that
            // would never be offered.
            cipher_list: "",
            ciphersuites: TLS13_SUITES,
            relaxes_security_level: false,
        },
        TlsPolicyLevel::Balanced => Policy {
            least_version: Version::Tls1_2,
            cipher_list: BALANCED_CIPHERS,
            ciphersuites: TLS13_SUITES,
            relaxes_security_level: false,
        },
        TlsPolicyLevel::LegacyCompatible => Policy {
            least_version: Version::Tls1_0,
            cipher_list: LEGACY_CIPHERS,
            ciphersuites: TLS13_SUITES,
            // The deliberate concession. It is confined to this level, because
            // there is no reason for the other two to share it.
            relaxes_security_level: true,
        },
    }
}

/// The oldest version a level accepts, in the TLS library's own spelling.
///
/// Kept here rather than at the listener, so the translation is measurable
/// without a handshake. Two of the three levels cannot be told apart on the
/// wire: the cipher list of `dengeli` already excludes everything below TLS
/// 1.2, so a floor set one version too low would change nothing a client
/// could see and nothing a measurement could catch.
#[must_use]
pub fn least_openssl_version(level: TlsPolicyLevel) -> SslVersion {
    match settings(level).least_version {
        Version::Tls1_0 => SslVersion::TLS1,
        Version::Tls1_2 => SslVersion::TLS1_2,
        Version::Tls1_3 => SslVersion::TLS1_3,
    }
}

/// The metric name carrying which policy each frontend runs.
pub const POLICY_METRIC: &str = "ek_ek_frontend_tls_policy";

/// The name a level goes into a metric and a log line under.
///
/// The configuration's own spelling, so an operator reading a dashboard sees
/// what they wrote in the document.
#[must_use]
pub const fn name_of(level: TlsPolicyLevel) -> &'static str {
    match level {
        TlsPolicyLevel::Modern => "modern",
        TlsPolicyLevel::Balanced => "dengeli",
        TlsPolicyLevel::LegacyCompatible => "eski-uyumlu",
    }
}

/// Prometheus lines saying which policy every TLS frontend runs.
///
/// One line per frontend that terminates TLS. A frontend that does not is left
/// out entirely rather than written with a zero: it has no policy, and a zero
/// would read as one that is turned off.
///
/// The value is always 1, because the reading is which level is in force and
/// the level is a label. That is the shape Prometheus expects for a state.
#[must_use]
pub fn exposition(config: &Config) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "# HELP {POLICY_METRIC} Which TLS policy level a frontend runs."
    );
    let _ = writeln!(out, "# TYPE {POLICY_METRIC} gauge");

    for frontend in &config.frontends {
        // Only a frontend that opens the handshake has a policy, and TLS
        // settings are the one thing that says it does. A passthrough or a raw
        // frontend cannot carry them: validation refuses both by their own
        // code, so this one check covers all three cases.
        let Some(tls) = &frontend.tls else {
            continue;
        };
        let _ = writeln!(
            out,
            "{POLICY_METRIC}{{frontend=\"{}\",level=\"{}\"}} 1",
            escape(frontend.id.as_str()),
            name_of(tls.policy)
        );
    }
    out
}

/// Makes a value safe to put inside a Prometheus label.
///
/// A frontend identity is written by an operator. A quote or a backslash in it
/// would close the label set early and make every line after it unreadable.
fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
