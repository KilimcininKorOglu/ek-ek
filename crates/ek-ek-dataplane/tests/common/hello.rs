// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Building a ClientHello byte by byte.
//!
//! Written out here rather than produced by a TLS library on purpose. What is
//! measured is a parser against bytes on a wire, and a library would only ever
//! hand it the shapes that library happens to produce. This builder makes the
//! shapes an attacker sends too: a length that lies, a name that is not text,
//! an extension list that stops in the middle.

#![allow(dead_code)]

/// The record type that carries a handshake.
pub const HANDSHAKE: u8 = 22;

/// What goes into one ClientHello.
pub struct Hello {
    /// The server name extension's contents, when it carries one.
    pub server_name: Option<Vec<u8>>,
    /// Extensions written before the server name one.
    pub before: Vec<(u16, Vec<u8>)>,
    /// Whether the extension block is written at all.
    pub extensions: bool,
    /// Bytes of session id, which the parser walks past.
    pub session_id: usize,
    /// What the session id says its length is, when that is a lie.
    pub session_id_claims: Option<usize>,
    /// Bytes of cipher suites, which the parser walks past.
    pub ciphers: usize,
    /// What the cipher list says its length is, when that is a lie.
    pub ciphers_claim: Option<usize>,
    /// Bytes of compression methods, the last vector before the extensions.
    pub compression: usize,
    /// What that list says its length is, when that is a lie.
    pub compression_claims: Option<usize>,
    /// The record type byte, so a caller can make it something else.
    pub record_type: u8,
    /// The handshake message type, for the same reason.
    pub message_type: u8,
}

impl Default for Hello {
    fn default() -> Self {
        Self {
            server_name: None,
            before: Vec::new(),
            extensions: true,
            session_id: 32,
            session_id_claims: None,
            ciphers: 4,
            ciphers_claim: None,
            compression: 1,
            compression_claims: None,
            record_type: HANDSHAKE,
            message_type: 1,
        }
    }
}

impl Hello {
    /// A ClientHello asking for one name.
    #[must_use]
    pub fn named(name: &str) -> Self {
        Self {
            server_name: Some(server_name_extension(name)),
            ..Self::default()
        }
    }

    /// A ClientHello with no server name extension at all.
    #[must_use]
    pub fn nameless() -> Self {
        Self::default()
    }

    /// Puts an extension in front of the server name one.
    #[must_use]
    pub fn after(mut self, kind: u16, body: Vec<u8>) -> Self {
        self.before.push((kind, body));
        self
    }

    /// The bytes, record header and all.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        let mut body = Vec::new();
        body.push(self.message_type);
        let hello = self.handshake_body();
        // Three byte length.
        body.push(0);
        body.extend_from_slice(&u16::try_from(hello.len()).unwrap_or(u16::MAX).to_be_bytes());
        body.extend_from_slice(&hello);

        let mut out = Vec::new();
        out.push(self.record_type);
        // Version, which the parser walks past.
        out.extend_from_slice(&[3, 1]);
        out.extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Everything after the handshake header.
    fn handshake_body(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // The client's version, then thirty two bytes of randomness.
        out.extend_from_slice(&[3, 3]);
        out.extend_from_slice(&[0x5A; 32]);
        // Session id. The stated length and the bytes written may differ,
        // because a length nobody checked is what a parser reads past the end
        // of its buffer on.
        let claimed = self.session_id_claims.unwrap_or(self.session_id);
        out.push(u8::try_from(claimed).unwrap_or(u8::MAX));
        out.extend(std::iter::repeat_n(0x11, self.session_id));
        // Cipher suites, on the same terms.
        let claimed = self.ciphers_claim.unwrap_or(self.ciphers);
        out.extend_from_slice(&u16::try_from(claimed).unwrap_or(u16::MAX).to_be_bytes());
        out.extend(std::iter::repeat_n(0x13, self.ciphers));
        // Compression methods: the null one, unless a test asks otherwise.
        let claimed = self.compression_claims.unwrap_or(self.compression);
        out.push(u8::try_from(claimed).unwrap_or(u8::MAX));
        out.extend(std::iter::repeat_n(0, self.compression));

        if !self.extensions {
            return out;
        }

        let mut extensions = Vec::new();
        for (kind, body) in &self.before {
            extensions.extend_from_slice(&kind.to_be_bytes());
            extensions
                .extend_from_slice(&u16::try_from(body.len()).unwrap_or(u16::MAX).to_be_bytes());
            extensions.extend_from_slice(body);
        }
        if let Some(name) = &self.server_name {
            extensions.extend_from_slice(&0_u16.to_be_bytes());
            extensions
                .extend_from_slice(&u16::try_from(name.len()).unwrap_or(u16::MAX).to_be_bytes());
            extensions.extend_from_slice(name);
        }
        out.extend_from_slice(
            &u16::try_from(extensions.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        out.extend_from_slice(&extensions);
        out
    }
}

/// The body of a server name extension carrying one host name.
#[must_use]
pub fn server_name_extension(name: &str) -> Vec<u8> {
    entry_extension(0, name.as_bytes())
}

/// The body of a server name extension with one entry of the type given.
#[must_use]
pub fn entry_extension(kind: u8, value: &[u8]) -> Vec<u8> {
    entries_extension(&[(kind, value)])
}

/// The body of a server name extension with a list of entries.
#[must_use]
pub fn entries_extension(entries: &[(u8, &[u8])]) -> Vec<u8> {
    let mut list = Vec::new();
    for (kind, value) in entries {
        list.push(*kind);
        list.extend_from_slice(&u16::try_from(value.len()).unwrap_or(u16::MAX).to_be_bytes());
        list.extend_from_slice(value);
    }

    let mut out = Vec::new();
    out.extend_from_slice(&u16::try_from(list.len()).unwrap_or(u16::MAX).to_be_bytes());
    out.extend_from_slice(&list);
    out
}
