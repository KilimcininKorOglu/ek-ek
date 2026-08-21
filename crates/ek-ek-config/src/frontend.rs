// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Frontends, the listening ends clients connect to.
//!
//! A frontend binds exactly one VIP, one port and one transport protocol
//! (ADR-0016). That triple is what makes a frontend unique, which is why a
//! TCP and a UDP frontend can share an address and a port: they are separate
//! sockets. DNS needs precisely that.
//!
//! Combinations that make no sense, such as TLS settings on a frontend that
//! does not terminate TLS, are representable here on purpose. The model
//! records what an operator asked for and the validation layer judges it, so
//! a mistake produces an error naming the field rather than a silently
//! dropped setting.

use serde::{Deserialize, Serialize};

use crate::id::{BackendId, CertificateId, FrontendId, VipId};

/// A listening endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Frontend {
    /// Identity used to reference this frontend.
    pub id: FrontendId,
    /// The single VIP this frontend listens on.
    pub vip: VipId,
    /// The single port this frontend listens on.
    pub port: u16,
    /// The single transport protocol this frontend listens with.
    pub transport: TransportProtocol,
    /// What the frontend does with the bytes it receives.
    pub application: ApplicationProtocol,
    /// TLS termination settings, set only where TLS is terminated.
    pub tls: Option<TlsSettings>,
    /// Whether the client address is forwarded with a PROXY protocol header.
    #[serde(default)]
    pub proxy_protocol: ProxyProtocol,
    /// Ordered host and path rules, applied first match wins (ADR-0044).
    ///
    /// Order is part of the configuration, so it is preserved exactly as the
    /// operator wrote it and never sorted.
    #[serde(default)]
    pub routing_rules: Vec<RoutingRule>,
    /// Ordered SNI rules for TLS passthrough, applied first match wins
    /// (ADR-0027).
    #[serde(default)]
    pub sni_rules: Vec<SniRule>,
    /// Pool used when no rule matches.
    ///
    /// With no default set, a request that matches no rule is rejected and a
    /// passthrough connection is closed.
    pub default_backend: Option<BackendId>,
    /// Whether cleartext HTTP/2 is accepted alongside HTTP/1.1 (ADR-0059).
    #[serde(default)]
    pub http2: Http2,
    /// How long the proxy waits for a backend to accept a connection, in
    /// seconds.
    ///
    /// This is separate from the request limit because the two are on
    /// different scales: an unreachable member is known in seconds, while a
    /// legitimate request may run for hours.
    pub connect_timeout_seconds: u32,
    /// How long a request may take before the client is told it timed out, in
    /// seconds (ADR-0058).
    ///
    /// A routing rule carrying its own value overrides this one. Zero means
    /// no limit, which is a deliberate choice rather than an unset field:
    /// ActiveSync push and IMAP IDLE hold a request open for an hour or more,
    /// and some deployments want no ceiling at all.
    pub request_timeout_seconds: u32,
    /// How long a connection may sit with no byte moving in either direction,
    /// in seconds (ADR-0060).
    ///
    /// The counter resets on traffic in either direction, because a
    /// connection that sent a slow query and is waiting for its answer is
    /// working, not idle. Only the L4 path reads this: on an HTTP frontend
    /// the request limit already covers it.
    ///
    /// Zero means no limit on TCP. On UDP it means the default instead
    /// (ADR-0066): a session table with no idle limit empties only through
    /// eviction, so dead sessions would push live ones out.
    pub idle_timeout_seconds: u32,
    /// How long the frontend waits before it cuts what is left, in seconds.
    ///
    /// On TCP this is the time open connections get to finish. On UDP there
    /// are no connections to finish, so it is the time the session table gets
    /// to empty before its remaining entries are dropped.
    pub drain_timeout_seconds: u32,
    /// How many UDP sessions this frontend keeps at once.
    ///
    /// Each session holds its own socket to the backend, so this bounds file
    /// descriptors as well as memory (ADR-0066). Reaching it evicts the least
    /// recently used session rather than refusing the new one: the table is
    /// an accelerator, not the source of truth, so an evicted client lands
    /// back on the same member (ADR-0025).
    ///
    /// Zero means the default. It sits per frontend because a DNS service and
    /// a syslog service see very different numbers of clients.
    #[serde(default)]
    pub udp_session_limit: u32,
}

/// Transport layer a frontend listens with.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    /// Connection-oriented transport.
    Tcp,
    /// Datagram transport, carried by the hand-written path rather than by
    /// pingora (ADR-0017).
    Udp,
}

/// What a frontend does with the traffic it accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplicationProtocol {
    /// Parses HTTP and routes on host and path.
    Http,
    /// Reads the SNI from the ClientHello and forwards the handshake
    /// untouched. No certificate is held for this frontend.
    TlsPassthrough,
    /// Forwards bytes without interpreting them.
    Raw,
}

/// TLS termination settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsSettings {
    /// Certificates offered, selected per handshake by SNI.
    pub certificates: Vec<CertificateId>,
    /// Protocol versions and cipher suites, chosen as a level rather than as
    /// a list (ADR-0028).
    #[serde(default)]
    pub policy: TlsPolicyLevel,
}

/// A named TLS policy.
///
/// Operators pick a level. They never enter a cipher suite list, because a
/// hand-written list is how a configuration silently becomes insecure.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum TlsPolicyLevel {
    /// TLS 1.3 only.
    #[serde(rename = "modern")]
    Modern,
    /// TLS 1.2 and 1.3 with safe cipher suites. This is the default.
    #[default]
    #[serde(rename = "dengeli")]
    Balanced,
    /// TLS 1.0 and above, for backends that cannot be upgraded.
    #[serde(rename = "eski-uyumlu")]
    LegacyCompatible,
}

/// Whether a PROXY protocol header is sent to the backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    /// No header is sent. This is the default, because a backend that does
    /// not expect the header rejects the connection (ADR-0043).
    #[default]
    Disabled,
    /// Human-readable header.
    V1,
    /// Binary header.
    V2,
}

/// Whether a frontend accepts cleartext HTTP/2 (ADR-0059).
///
/// The setting exists per frontend because turning it off is sometimes the
/// only way to keep a backend working, and an operator must be able to do that
/// on one published service without touching the rest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Http2 {
    /// Accepts HTTP/2 when the client asks for it and HTTP/1.1 otherwise. This
    /// is the default: the two are told apart by the connection preface, so an
    /// HTTP/1.1 client is unaffected.
    #[default]
    Enabled,
    /// Answers only HTTP/1.1, whatever the client asks for.
    Disabled,
}

impl Http2 {
    /// Returns whether cleartext HTTP/2 is accepted.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        matches!(self, Self::Enabled)
    }
}

/// One host and path rule.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRule {
    /// Host the request must match, with `*` allowed as the leading label.
    ///
    /// Leaving both this and `path_prefix` unset makes the rule match
    /// everything, which validation rejects unless it is the last rule.
    pub host_pattern: Option<String>,
    /// Path the request must start with, matched after normalisation so that
    /// `/owa/../admin` cannot slip past an `/owa` rule.
    pub path_prefix: Option<String>,
    /// What happens to a request this rule matches.
    pub action: RuleAction,
    /// Time a matching request may take, in seconds.
    ///
    /// Unset falls back to the frontend's own limit. ActiveSync push and
    /// IMAP IDLE need values of an hour or more here.
    pub request_timeout_seconds: Option<u32>,
}

/// What a matched request is done with (ADR-0057).
///
/// A rule either forwards the request or answers it with a redirect. It never
/// does anything else: there is no header rewriting, no body change and no
/// scripting. Widening this beyond the two variants needs a new decision.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum RuleAction {
    /// Forwards the request to a pool.
    Proxy {
        /// Pool the request is sent to.
        backend: BackendId,
    },
    /// Answers with a redirect to HTTPS on the same host.
    ///
    /// A site with a certificate has to answer on port 80 as well, or the
    /// address someone typed into a browser reaches nothing. The answer is
    /// produced here rather than by a backend, so no plaintext request ever
    /// leaves the load balancer.
    Redirect {
        /// Which permanent redirect to send.
        status: RedirectStatus,
    },
}

/// Which redirect status a rule answers with.
///
/// The path and the query string are carried over either way. There is no
/// setting to drop them, because a redirect that loses the path takes the
/// visitor away from the page they asked for.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedirectStatus {
    /// Answers with `301`. A browser following it rewrites a POST into a GET,
    /// which loses the request body.
    MovedPermanently,
    /// Answers with `308`, keeping the method and the body, so an API
    /// published this way keeps working. That is why it is the default.
    #[default]
    Permanent,
}

impl RedirectStatus {
    /// Returns the HTTP status code to answer with.
    #[must_use]
    pub const fn code(self) -> u16 {
        match self {
            Self::MovedPermanently => 301,
            Self::Permanent => 308,
        }
    }
}

/// One SNI rule for a passthrough frontend.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SniRule {
    /// Server name the ClientHello must match, with `*` allowed as the
    /// leading label.
    pub sni_pattern: String,
    /// Pool matching connections are sent to.
    pub backend: BackendId,
}
