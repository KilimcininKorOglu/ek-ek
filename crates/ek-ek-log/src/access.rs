// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What one request or one connection did.
//!
//! Three transports share one record type, because an operator asking "where
//! did this client go" should not have to know which of three shapes to look
//! for. Fields that do not apply to a transport are left out rather than
//! written as null, and each transport's field set is pinned by a test
//! (ADR-0037).
//!
//! Nothing here carries a header value, a cookie or a body. What a client sent
//! is exactly where a secret ends up in a log, so the record is built from
//! named fields and never from whatever arrived.

use serde::Serialize;

/// Which listener carried the traffic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// Parsed as HTTP and routed on host and path.
    Http,
    /// Forwarded byte for byte over TCP.
    Tcp,
    /// Forwarded datagram for datagram.
    Udp,
}

impl Protocol {
    /// The name written into the `protocol` field.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

/// One finished request or connection.
///
/// Built with [`Access::new`] and then filled in, so a caller cannot forget
/// the fields every transport shares.
#[derive(Clone, Debug, Serialize)]
pub struct Access {
    /// Which listener carried it.
    pub protocol: Protocol,
    /// Which frontend it arrived on.
    pub frontend: String,
    /// Where it came from, address and port.
    pub client: String,
    /// How long it took, in milliseconds.
    pub duration_ms: f64,
    /// The identity every record of this request shares.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    /// The pool it was sent to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_pool: Option<String>,
    /// The member inside that pool.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backend_member: Option<String>,
    /// HTTP only: the method.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// HTTP only: the path, after normalising.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// HTTP only: the status that went back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// TCP only: bytes that went to the backend.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_to_backend: Option<u64>,
    /// TCP only: bytes that came back.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_from_backend: Option<u64>,
    /// UDP only: which session table entry was opened for it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

impl Access {
    /// A record with what every transport carries, and nothing else yet.
    #[must_use]
    pub fn new(protocol: Protocol, frontend: &str, client: &str, duration_ms: f64) -> Self {
        Self {
            protocol,
            frontend: frontend.to_owned(),
            client: client.to_owned(),
            duration_ms,
            request_id: None,
            backend_pool: None,
            backend_member: None,
            method: None,
            path: None,
            status: None,
            bytes_to_backend: None,
            bytes_from_backend: None,
            session: None,
        }
    }

    /// Names where the traffic was sent.
    #[must_use]
    pub fn to_backend(mut self, pool: &str, member: &str) -> Self {
        self.backend_pool = Some(pool.to_owned());
        self.backend_member = Some(member.to_owned());
        self
    }

    /// Names the identity shared by every record of this request.
    #[must_use]
    pub fn with_request_id(mut self, request_id: &str) -> Self {
        self.request_id = Some(request_id.to_owned());
        self
    }

    /// Adds what only an HTTP request has.
    #[must_use]
    pub fn http(mut self, method: &str, path: &str, status: u16) -> Self {
        self.method = Some(method.to_owned());
        self.path = Some(path.to_owned());
        self.status = Some(status);
        self
    }

    /// Adds what only a TCP connection has.
    #[must_use]
    pub const fn tcp(mut self, to_backend: u64, from_backend: u64) -> Self {
        self.bytes_to_backend = Some(to_backend);
        self.bytes_from_backend = Some(from_backend);
        self
    }

    /// Adds what only a UDP session has.
    ///
    /// One record per session rather than per datagram: a session is what a
    /// UDP frontend actually routes, and a record per datagram would drown a
    /// DNS frontend's log in a second.
    #[must_use]
    pub fn udp(mut self, session: &str) -> Self {
        self.session = Some(session.to_owned());
        self
    }
}
