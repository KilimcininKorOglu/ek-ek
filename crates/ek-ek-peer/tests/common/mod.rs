// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What every peer measurement needs: an authority, a node, and the clock.

#![allow(dead_code)]

use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use ek_ek_config::NodeId;
use ek_ek_peer::{Authority, Credentials, Issued};

/// The moment the system is at.
///
/// A live handshake is checked against the real clock by the TLS library, so a
/// certificate meant to be accepted has to be issued around now. The rules
/// that need no socket take their moment as a parameter instead.
pub fn now() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_secs(),
    )
    .expect("the clock fits in a timestamp")
}

/// Seconds in a day.
pub const DAY: i64 = 86_400;

/// An authority to sign with.
pub fn authority() -> Authority {
    ek_ek_peer::create(now()).expect("an authority is created")
}

/// One node's certificate, issued now.
pub fn issue(authority: &Authority, node: &str) -> Issued {
    issue_at(authority, node, now())
}

/// One node's certificate, issued at a given moment.
pub fn issue_at(authority: &Authority, node: &str, at: i64) -> Issued {
    let address: IpAddr = "127.0.0.1".parse().expect("an address");
    ek_ek_peer::issue(authority, &NodeId::new(node), &[address], at)
        .expect("a certificate is signed")
}

/// What one node presents and what it trusts.
pub fn credentials(trusting: &Authority, issued: &Issued) -> Credentials {
    Credentials {
        authority_pem: trusting.certificate_pem.clone(),
        certificate_pem: issued.certificate_pem.clone(),
        key_pem: issued.key_pem.clone(),
    }
}
