// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Choosing which rule a request falls under.
//!
//! Nothing here touches the network or the configuration store, so every rule
//! is measurable directly. That matters more than usual: path matching is
//! what a path-based split rests on, and a normalisation gap turns into a way
//! around it (ADR-0071).

use ek_ek_config::{Frontend, PathCase, RoutingRule, RuleAction};

/// What is done with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision<'a> {
    /// Forward it to this pool, with this many seconds to finish in.
    ///
    /// Zero seconds means no limit, which is what an ActiveSync push or an
    /// IMAP IDLE request needs (ADR-0058).
    Pool {
        /// Which pool takes it.
        name: &'a str,
        /// How long it may take, in seconds.
        request_timeout_seconds: u32,
    },
    /// Answer it with this redirect status.
    Redirect(u16),
    /// Nowhere to send it.
    Nowhere,
}

/// Picks the rule a request falls under and says what happens to it.
///
/// The list is ordered and the first match wins; nothing after it is tried.
/// With no rule matching, the frontend's default pool takes the request, and
/// with no default the request goes nowhere (ADR-0071).
#[must_use]
pub fn decide<'a>(frontend: &'a Frontend, host: Option<&str>, path: &str) -> Decision<'a> {
    let path = normalise(path);
    let host = host.map(strip_port);

    for rule in &frontend.routing_rules {
        if !matches(rule, host.as_deref(), &path) {
            continue;
        }
        return match &rule.action {
            RuleAction::Proxy { backend } => Decision::Pool {
                name: backend.as_str(),
                request_timeout_seconds: rule
                    .request_timeout_seconds
                    .unwrap_or(frontend.request_timeout_seconds),
            },
            RuleAction::Redirect { status } => Decision::Redirect(status.code()),
        };
    }

    frontend
        .default_backend
        .as_ref()
        .map_or(Decision::Nowhere, |backend| Decision::Pool {
            name: backend.as_str(),
            request_timeout_seconds: frontend.request_timeout_seconds,
        })
}

/// Whether a rule takes this request.
///
/// A rule naming both a host and a path takes only requests matching both.
/// A rule naming neither takes everything, which is what a redirect listener
/// is made of (ADR-0057).
#[must_use]
pub fn matches(rule: &RoutingRule, host: Option<&str>, normalised_path: &str) -> bool {
    let host_ok = match rule.host_pattern.as_deref() {
        None => true,
        Some(pattern) => host.is_some_and(|host| host_matches(pattern, host)),
    };
    if !host_ok {
        return false;
    }

    match rule.path_prefix.as_deref() {
        None => true,
        Some(prefix) => path_matches(prefix, normalised_path, rule.path_case),
    }
}

/// Whether a host pattern covers a host.
///
/// Matching is case insensitive, because DNS names are. A leading `*.` stands
/// for exactly one label: `*.ornek.com` covers `posta.ornek.com` and neither
/// `a.posta.ornek.com` nor `ornek.com` (ADR-0071).
#[must_use]
pub fn host_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let host = host.to_lowercase();

    if let Some(suffix) = pattern.strip_prefix("*.") {
        return host
            .split_once('.')
            .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix);
    }
    pattern == host
}

/// Whether a path prefix covers a path.
///
/// The path is expected to be normalised already. The prefix matches on a
/// component boundary, so `/owa` covers `/owa` and `/owa/auth` but not
/// `/owanot` (ADR-0071).
#[must_use]
pub fn path_matches(prefix: &str, normalised_path: &str, case: PathCase) -> bool {
    let (prefix, path) = match case {
        PathCase::Insensitive => (prefix.to_lowercase(), normalised_path.to_lowercase()),
        PathCase::Sensitive => (prefix.to_owned(), normalised_path.to_owned()),
    };

    if path == prefix {
        return true;
    }
    // A prefix that already ends in `/` names the boundary itself, so the
    // rest may start with anything.
    path.strip_prefix(&prefix)
        .is_some_and(|rest| prefix.ends_with('/') || rest.starts_with('/'))
}

/// Puts a path into the one form matching is done against.
///
/// The query string is dropped, percent encoding is decoded once, `.` is
/// removed, `..` climbs one level and stops at the root, and repeated
/// separators count as one. Without this, `/owa/../admin` would slip past an
/// `/owa` rule (ADR-0071).
#[must_use]
pub fn normalise(path: &str) -> String {
    // Everything from the first `?` or `#` belongs to the query or the
    // fragment and is not part of the path.
    let path = path
        .split_once(['?', '#'])
        .map_or(path, |(before, _)| before);
    // Decoded once, never twice. Decoding twice would turn `%252e%252e` into
    // `..` and hand back the way around that normalising exists to close.
    let path = percent_decode(path);

    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            // An empty part is a repeated separator, and `.` is the path it
            // is already on. Neither moves anywhere.
            "" | "." => {}
            ".." => {
                // At the root there is nowhere above to climb to.
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    let mut out = String::with_capacity(path.len() + 1);
    for part in &parts {
        out.push('/');
        out.push_str(part);
    }
    if out.is_empty() {
        out.push('/');
    } else if path.ends_with('/') {
        // A trailing separator is kept, because `/owa/` and `/owa` are the
        // same resource to a rule but not to a backend.
        out.push('/');
    }
    out
}

/// Decodes percent escapes once, leaving anything malformed as it stands.
fn percent_decode(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut at = 0;

    while at < bytes.len() {
        if bytes[at] == b'%'
            && at + 2 < bytes.len()
            && let Some(high) = (bytes[at + 1] as char).to_digit(16)
            && let Some(low) = (bytes[at + 2] as char).to_digit(16)
        {
            // Both digits are hex, so the product fits a byte.
            out.push(u8::try_from(high * 16 + low).unwrap_or(b'%'));
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }

    // A sequence that is not valid text is left as it arrived rather than
    // replaced, because replacing bytes changes what is being matched.
    String::from_utf8(out).unwrap_or_else(|_| path.to_owned())
}

/// Drops the port a `Host` header may carry.
///
/// A client writing `ornek.com:8080` asked for the same host as one writing
/// `ornek.com`, so both fall under the same rule.
fn strip_port(host: &str) -> String {
    // An IPv6 literal is bracketed, and the colons inside it are not a port.
    if let Some(rest) = host.strip_prefix('[') {
        return rest
            .split_once(']')
            .map_or_else(|| host.to_owned(), |(inside, _)| format!("[{inside}]"));
    }
    host.split_once(':')
        .map_or_else(|| host.to_owned(), |(name, _)| name.to_owned())
}
