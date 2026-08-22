// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the stickiness cookie is made of.
//!
//! The behaviour a client sees is measured over a socket in `ek-ek`. What
//! cannot be measured there is the arithmetic: what goes into the digest,
//! what a wrong key produces, and what a cookie header is read out of.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};

use ek_ek_config::{
    AdminState, Backend, BackendId, BackendMember, ConnectionPooling, LoadBalancingAlgorithm,
    MemberId, SameSitePolicy, SessionStickiness,
};
use ek_ek_dataplane::sticky::{self, Signer};

/// A key that is not a secret: it exists so two runs produce the same digest.
const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";
/// A different key of the same length.
const OTHER: &[u8] = b"fedcba9876543210fedcba9876543210";

fn member(name: &str, last: u8) -> BackendMember {
    BackendMember {
        id: MemberId::new(name),
        address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
        port: 8080,
        weight: 1,
        admin_state: AdminState::Enabled,
    }
}

fn pool(id: &str, stickiness: SessionStickiness, members: Vec<BackendMember>) -> Backend {
    Backend {
        id: BackendId::new(id),
        members,
        algorithm: LoadBalancingAlgorithm::RoundRobin,
        health_check: None,
        stickiness,
        connection_pooling: ConnectionPooling::Enabled,
        connection_pool_size: Backend::default_pool_size(),
        connection_lifetime_seconds: Backend::default_connection_lifetime_seconds(),
    }
}

fn signer() -> Signer {
    Signer::new(KEY).expect("the key must be accepted")
}

#[test]
fn the_value_names_neither_the_member_nor_its_address() {
    let value = signer().token("web", "app-server-1");

    assert!(
        !value.contains("app-server-1"),
        "the member identity is readable in {value}"
    );
    assert!(
        !value.contains("10.0.0"),
        "an address is readable in {value}"
    );
    assert!(
        value.chars().all(|character| character.is_ascii_hexdigit()),
        "the value is not a digest: {value}"
    );
    assert_eq!(value.len(), 32, "the value changed length: {value}");
}

#[test]
fn the_same_member_gets_the_same_value_every_time() {
    assert_eq!(signer().token("web", "one"), signer().token("web", "one"));
}

#[test]
fn two_members_get_different_values() {
    assert_ne!(signer().token("web", "one"), signer().token("web", "two"));
}

#[test]
fn the_same_member_identity_in_two_pools_gets_different_values() {
    // Without the pool in the digest, a cookie written by one pool would
    // select a member in another pool that happens to use the same names.
    assert_ne!(signer().token("web", "one"), signer().token("mail", "one"));
}

#[test]
fn another_key_produces_another_value() {
    let mine = signer().token("web", "one");
    let theirs = Signer::new(OTHER)
        .expect("the other key must be accepted")
        .token("web", "one");

    assert_ne!(mine, theirs, "the key does not change the value");
}

#[test]
fn a_member_that_changed_address_keeps_its_value() {
    // The digest is over identity. A renumbered server keeps its clients.
    let before = member("one", 5);
    let after = member("one", 200);
    assert_ne!(before.address, after.address, "the address did not change");

    let signer = signer();
    assert_eq!(
        signer.token("web", before.id.as_str()),
        signer.token("web", after.id.as_str())
    );
}

#[test]
fn a_value_matches_the_member_it_was_made_for() {
    let one = member("one", 1);
    let two = member("two", 2);
    let eligible = vec![&one, &two];
    let signer = signer();

    let value = signer.token("web", "two");
    let found = signer
        .member_for("web", &eligible, &value)
        .expect("the value must name a member");

    assert_eq!(found.id.as_str(), "two");
}

#[test]
fn a_value_for_a_member_that_is_not_offered_matches_nobody() {
    // This is what makes a cookie for an unhealthy or removed member fall
    // through to the algorithm: the member is simply not in the list.
    let one = member("one", 1);
    let eligible = vec![&one];
    let signer = signer();

    let value = signer.token("web", "two");

    assert!(signer.member_for("web", &eligible, &value).is_none());
}

#[test]
fn a_value_with_one_digit_changed_matches_nobody() {
    let one = member("one", 1);
    let eligible = vec![&one];
    let signer = signer();

    let mut broken = signer.token("web", "one");
    let last = broken.pop().unwrap_or('0');
    broken.push(if last == '0' { '1' } else { '0' });

    assert!(signer.member_for("web", &eligible, &broken).is_none());
}

#[test]
fn a_value_of_the_wrong_length_matches_nobody() {
    let one = member("one", 1);
    let eligible = vec![&one];
    let signer = signer();

    let value = signer.token("web", "one");
    assert!(signer.member_for("web", &eligible, &value[..8]).is_none());
    assert!(
        signer
            .member_for("web", &eligible, &format!("{value}00"))
            .is_none()
    );
    assert!(signer.member_for("web", &eligible, "").is_none());
}

#[test]
fn a_signer_prints_nothing_about_its_key() {
    let printed = format!("{:?}", signer());

    assert!(
        !printed.contains("0123456789"),
        "the key is in the debug output: {printed}"
    );
}

#[test]
fn only_hex_of_at_least_one_byte_is_accepted_as_a_key() {
    assert!(Signer::from_hex("00112233").is_some());
    assert!(Signer::from_hex("").is_none(), "an empty key was accepted");
    assert!(
        Signer::from_hex("001122334").is_none(),
        "an odd number of digits was accepted"
    );
    assert!(
        Signer::from_hex("zzzz").is_none(),
        "something that is not hex was accepted"
    );
}

#[test]
fn a_hex_key_names_the_bytes_it_spells() {
    // A key read as its digits rather than as its bytes would still work,
    // and would silently be a different key from the one on the other node.
    let by_hex = Signer::from_hex("00ff").expect("the key must be accepted");
    let by_bytes = Signer::new(&[0x00, 0xff]).expect("the key must be accepted");

    assert_eq!(by_hex.token("web", "one"), by_bytes.token("web", "one"));
}

#[test]
fn a_cookie_is_found_wherever_it_sits_in_the_header() {
    let alone = ["EKEK=abc"];
    let first = ["EKEK=abc; theme=dark"];
    let middle = ["theme=dark; EKEK=abc; lang=tr"];
    let last = ["theme=dark; EKEK=abc"];
    let split = ["theme=dark", "EKEK=abc"];

    for lines in [&alone[..], &first[..], &middle[..], &last[..], &split[..]] {
        assert_eq!(
            sticky::read(lines.iter().copied(), "EKEK"),
            Some("abc".to_owned()),
            "the cookie was not found in {lines:?}"
        );
    }
}

#[test]
fn a_cookie_that_is_not_there_is_not_invented() {
    assert_eq!(sticky::read(["theme=dark"].into_iter(), "EKEK"), None);
    assert_eq!(sticky::read([].into_iter(), "EKEK"), None);
    // A name that only ends the same way is a different cookie.
    assert_eq!(sticky::read(["MYEKEK=abc"].into_iter(), "EKEK"), None);
}

#[test]
fn a_set_cookie_line_carries_the_flags_that_were_asked_for() {
    let plain = sticky::set_cookie("EKEK", "abc", SameSitePolicy::Lax, false);
    assert!(plain.starts_with("EKEK=abc;"), "{plain}");
    assert!(plain.contains("HttpOnly"), "{plain}");
    assert!(plain.contains("Path=/"), "{plain}");
    assert!(plain.contains("SameSite=Lax"), "{plain}");
    assert!(!plain.contains("Secure"), "{plain}");
    assert!(!plain.to_ascii_lowercase().contains("max-age"), "{plain}");

    let secure = sticky::set_cookie("EKEK", "abc", SameSitePolicy::Strict, true);
    assert!(secure.contains("Secure"), "{secure}");
    assert!(secure.contains("SameSite=Strict"), "{secure}");

    // `SameSite=None` is refused by browsers without `Secure`, so the pair
    // is written together even on a plaintext listener.
    let cross = sticky::set_cookie("EKEK", "abc", SameSitePolicy::None, false);
    assert!(cross.contains("SameSite=None"), "{cross}");
    assert!(cross.contains("Secure"), "{cross}");
}

#[test]
fn a_pool_reports_the_stickiness_it_was_configured_with() {
    let off = pool("web", SessionStickiness::Disabled, vec![member("one", 1)]);
    assert!(sticky::settings(&off).is_none());

    let on = pool(
        "web",
        SessionStickiness::SignedCookie {
            cookie_name: "MYAPP".to_owned(),
            same_site: SameSitePolicy::Strict,
        },
        vec![member("one", 1)],
    );
    assert_eq!(
        sticky::settings(&on),
        Some(("MYAPP", SameSitePolicy::Strict))
    );
}
