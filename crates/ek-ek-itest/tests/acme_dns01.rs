// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Certificates obtained by writing a record into a real name server.
//!
//! BIND is what the update goes to, and it is what refuses an update that is
//! not signed with the key it holds. Pebble is what looks the record up: it is
//! pointed at the same BIND, so a certificate coming back means the update
//! message, the signature, the propagation wait and the cleanup all worked
//! against software nobody here wrote.
//!
//! The Cloudflare side stands its endpoint in, because no measurement may
//! reach the real API. What the stand-in does with a change is not stood in
//! for: it applies it with BIND's own client, so the record the authority
//! reads is a real one.
//!
//! Every reading comes from outside the product: the name server's own log,
//! `dig`, the certificate authority's log and the bytes on the disk.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::time::Duration;

use ek_ek_itest::{
    Background, Cluster, LAB_NAME, LAB_TSIG_KEY, LAB_WILDCARD, LAB_ZONE, Node, PEBBLE_DIRECTORY,
};

/// The configuration the order works from.
const CONFIG: &str = "/tmp/ek-ek-dns01.json";
/// Where the order would write an HTTP-01 answer. Nothing writes it here.
const CHALLENGE_FILE: &str = "/tmp/ek-ek-dns01-challenges.json";
/// Where a credential is handed to the product, and then removed.
const CREDENTIAL_FILE: &str = "/tmp/ek-ek-credential";
/// The identity the configuration refers to the provider's credential by.
const CREDENTIAL: &str = "dns-provider-credential";
/// The certificate these measurements order.
const CERTIFICATE: &str = "cert-lab-dns";
/// The provider the certificate names.
const PROVIDER: &str = "dns-lab";
/// The record one name's challenge is answered at.
///
/// A wildcard is proven at the name it stands for, so `*.ek-ek.test` and
/// `ek-ek.test` are both answered at `_acme-challenge.ek-ek.test`.
fn record_for(name: &str) -> String {
    format!(
        "_acme-challenge.{}",
        name.strip_prefix("*.").unwrap_or(name)
    )
}

/// The zone identity the stand-in API answers for.
const CLOUDFLARE_ZONE: &str = "labzone0123456789";
/// The token the stand-in API accepts, and the product is given.
const CLOUDFLARE_TOKEN: &str = "a-token-only-this-lab-holds";
/// Where the stand-in writes the certificate it serves.
const CLOUDFLARE_CERT: &str = "/var/lib/ek-ek/cloudflare.pem";
/// Where the stand-in's token sits on the node that runs it.
const CLOUDFLARE_TOKEN_FILE: &str = "/tmp/ek-ek-cloudflare-token";
/// Where the shared key sits on a node.
const TSIG_FILE: &str = "/tmp/ek-ek-tsig";
/// The node the stand-in API runs on, and the port it answers on.
const API_HOST: &str = "node2";
const API_PORT: u16 = 8443;

/// Puts a value into a JSON string.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            other => out.push(other),
        }
    }
    out
}

/// How the certificate's provider is reached.
enum Reach {
    /// A dynamic update signed with the shared key.
    Update { server: Ipv4Addr },
    /// The stand-in API.
    Api,
}

/// The configuration the order works from.
///
/// No listener and no backend: a DNS-01 order needs nothing to be reachable
/// from outside, which is the whole reason it exists (ADR-0026).
fn document(node: &Node, names: &[&str], reach: &Reach, root: &str, timeout: u32) -> String {
    let listed: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
    let connection = match reach {
        Reach::Update { server } => format!(
            r#"{{"type":"rfc2136","server":"{server}","port":53,"zone":"{LAB_ZONE}","tsig_key_name":"{LAB_TSIG_KEY}","tsig_algorithm":"hmac-sha256","tsig_secret":"{CREDENTIAL}"}}"#
        ),
        Reach::Api => format!(
            r#"{{"type":"cloudflare","zone_id":"{CLOUDFLARE_ZONE}","api_token":"{CREDENTIAL}","api_base":"https://{API_HOST}:{API_PORT}/client/v4"}}"#
        ),
    };

    format!(
        r#"{{
  "schema_version": 1,
  "nodes": [{{"id":"{name}","address":"{address}","roles":["control_plane","data_plane"]}}],
  "vips": [],
  "frontends": [],
  "backends": [],
  "certificates": [{{
    "id": "{CERTIFICATE}",
    "sni_names": [{names}],
    "source": {{"type":"acme_dns01","provider":"{PROVIDER}"}},
    "validity": null,
    "chain": null,
    "private_key": null
  }}],
  "dns_providers": [{{
    "id": "{PROVIDER}",
    "connection": {connection},
    "propagation_timeout_secs": {timeout}
  }}],
  "acme": {{
    "directory_url": "{PEBBLE_DIRECTORY}",
    "contact_email": "yonetici@ek-ek.test",
    "accepted_terms": true,
    "trusted_root_pem": "{root}"
  }}
}}"#,
        name = node.name(),
        address = node.address(),
        names = listed.join(","),
        root = quoted(root),
    )
}

/// The same document on one line, for a file a shell writes.
fn one_line(document: &str) -> String {
    document.lines().map(str::trim).collect::<String>()
}

/// Writes a file inside a node.
fn write(node: &Node, path: &str, contents: &str) {
    let written = node
        .shell(&format!(
            "cat > {path} <<'ENDOFFILE'\n{contents}\nENDOFFILE"
        ))
        .expect("the file should be writable");
    assert!(written.ok(), "{path} was not written: {}", written.stderr);
}

/// Everything a node has to forget before a measurement starts.
fn clean(node: &Node) {
    let _ = node.kill_matching("ek-ek-standin-cloudflare");
    let cleared = node
        .shell(&format!(
            "rm -f {CONFIG} {CHALLENGE_FILE} {CREDENTIAL_FILE} {TSIG_FILE} \
             {CLOUDFLARE_TOKEN_FILE} {CLOUDFLARE_CERT} {CLOUDFLARE_CERT}.key.conf \
             /var/lib/ek-ek/config.db* /var/lib/ek-ek/master.key \
             /usr/local/share/ca-certificates/ek-ek-lab.crt; \
             update-ca-certificates --fresh >/dev/null 2>&1 || true"
        ))
        .expect("the node should be reachable");
    assert!(cleared.ok(), "the node was not cleared: {}", cleared.stderr);
}

/// Takes every challenge record out of the zone.
///
/// A measurement that failed halfway leaves one behind, and the next run would
/// read that leftover as its own result.
fn clear_zone(node: &Node, server: Ipv4Addr, secret: &str) {
    write(node, TSIG_FILE, &key_file(secret));
    for name in [LAB_NAME, LAB_ZONE] {
        let record = record_for(name);
        let _ = node.shell(&format!(
            "printf 'server {server}\\nzone {LAB_ZONE}\\nupdate delete {record}. TXT\\nsend\\n' \
             | nsupdate -k {TSIG_FILE}"
        ));
    }
}

/// The shared key in the form BIND's own client reads.
fn key_file(secret: &str) -> String {
    format!("key \"{LAB_TSIG_KEY}\" {{\n    algorithm hmac-sha256;\n    secret \"{secret}\";\n}};")
}

/// What the zone answers at the challenge name, read with `dig`.
///
/// The name server is asked directly, so what comes back is what it holds
/// rather than what anything between here and it remembers.
fn records_in_zone(node: &Node, server: Ipv4Addr, name: &str) -> Vec<String> {
    let answer = node
        .run(&[
            "dig",
            "+short",
            &format!("@{server}"),
            "TXT",
            &format!("{}.", record_for(name)),
        ])
        .expect("dig should run");
    answer
        .stdout
        .lines()
        .map(|line| line.trim().trim_matches('"').to_owned())
        .filter(|line| !line.is_empty())
        .collect()
}

/// Puts one credential into the store.
fn store_credential(node: &Node, product: &str, value: &str) {
    write(node, CREDENTIAL_FILE, value);
    let stored = node
        .run(&[
            product,
            "secret",
            "set",
            "--data-dir",
            "/var/lib/ek-ek",
            "--id",
            CREDENTIAL,
            "--from-file",
            CREDENTIAL_FILE,
            "--config",
            CONFIG,
        ])
        .expect("the store command should run");
    assert!(
        stored.ok(),
        "the credential was not stored: {}\n{}",
        stored.stdout,
        stored.stderr
    );
    assert!(
        !stored.stdout.contains(value),
        "the credential itself was written to standard output: {}",
        stored.stdout
    );
    // The file is the operator's, not the product's. Leaving it behind would
    // leave a credential in a world readable place.
    let _ = node.run(&["rm", "-f", CREDENTIAL_FILE]);
}

/// Runs one order and returns what the product said.
fn order(node: &Node, product: &str) -> ek_ek_itest::Output {
    node.run(&[
        product,
        "acme",
        "--config",
        CONFIG,
        "--data-dir",
        "/var/lib/ek-ek",
        "--certificate",
        CERTIFICATE,
        "--challenges",
        CHALLENGE_FILE,
    ])
    .expect("the order command should run")
}

#[test]
fn a_certificate_is_obtained_by_writing_a_signed_dynamic_update() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let node = cluster.node("node1").expect("node1 is in the cluster");
    clean(node);

    let server = cluster.bind_address();
    let secret = cluster
        .tsig_secret()
        .expect("the name server wrote its key");
    clear_zone(node, server, &secret);

    let root = cluster
        .pebble_root()
        .expect("the ACME server's own authority should be readable");
    write(
        node,
        CONFIG,
        &one_line(&document(
            node,
            &[LAB_NAME],
            &Reach::Update { server },
            &root,
            60,
        )),
    );
    store_credential(node, &product, &secret);

    assert!(
        records_in_zone(node, server, LAB_NAME).is_empty(),
        "the zone already held a challenge record, so nothing below measures anything"
    );

    let ordered = order(node, &product);
    let report = format!(
        "stdout:\n{}\nstderr:\n{}\nbind:\n{}\npebble:\n{}",
        ordered.stdout,
        ordered.stderr,
        cluster.bind_log(40).unwrap_or_default(),
        cluster.pebble_log(60).unwrap_or_default()
    );
    assert!(ordered.ok(), "the order did not complete\n{report}");

    for event in [
        r#""event":"ordering""#,
        r#""challenge":"dns-01""#,
        r#""event":"published""#,
        r#""event":"withdrawn""#,
        r#""event":"obtained""#,
        r#""event":"stored""#,
        r#""event":"usable""#,
    ] {
        assert!(
            ordered.stdout.contains(event),
            "{event} is missing from the record\n{report}"
        );
    }
    assert!(
        ordered.stdout.contains(&record_for(LAB_NAME)),
        "the order never named the record it wrote\n{report}"
    );

    // What the certificate authority says it did. This is the reading that
    // comes from outside: it looked the record up and was satisfied.
    let served = cluster.pebble_log(200).unwrap_or_default();
    assert!(
        served.contains(LAB_NAME),
        "the ACME server never mentions the name\n{served}"
    );

    // And the zone is as it was. A record left behind is one that accumulates
    // order after order until somebody notices the zone is full of them.
    assert!(
        records_in_zone(node, server, LAB_NAME).is_empty(),
        "the challenge record is still in the zone after the order\n{report}"
    );

    // The material on the disk is sealed (ADR-0018).
    let readable = node
        .shell("grep -c 'BEGIN PRIVATE KEY' /var/lib/ek-ek/config.db* 2>/dev/null | tr '\\n' ' '")
        .expect("the node should be readable");
    assert!(
        !readable.stdout.contains(":1") && !readable.stdout.trim_end().ends_with('1'),
        "a private key is readable in the store: {}",
        readable.stdout
    );
    // And so is the shared key, which is a credential like any other.
    let leaked = node
        .shell(&format!(
            "grep -c '{}' /var/lib/ek-ek/config.db 2>/dev/null | tr -d '\\n'",
            secret.trim()
        ))
        .expect("the node should be readable");
    assert_eq!(
        leaked.stdout.trim(),
        "0",
        "the shared key is readable in the store"
    );
}

#[test]
fn a_wildcard_certificate_is_obtained_with_both_names_at_one_record() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let node = cluster.node("node1").expect("node1 is in the cluster");
    clean(node);

    let server = cluster.bind_address();
    let secret = cluster
        .tsig_secret()
        .expect("the name server wrote its key");
    clear_zone(node, server, &secret);

    let root = cluster.pebble_root().expect("the authority is readable");
    write(
        node,
        CONFIG,
        &one_line(&document(
            node,
            &[LAB_ZONE, LAB_WILDCARD],
            &Reach::Update { server },
            &root,
            60,
        )),
    );
    store_credential(node, &product, &secret);

    let ordered = order(node, &product);
    let report = format!(
        "stdout:\n{}\nstderr:\n{}\nbind:\n{}\npebble:\n{}",
        ordered.stdout,
        ordered.stderr,
        cluster.bind_log(40).unwrap_or_default(),
        cluster.pebble_log(80).unwrap_or_default()
    );
    assert!(
        ordered.ok(),
        "a wildcard certificate is what DNS-01 exists for\n{report}"
    );
    assert!(ordered.stdout.contains(r#""event":"usable""#), "{report}");
    assert!(
        ordered.stdout.contains(LAB_WILDCARD),
        "the certificate does not cover the wildcard it was ordered for\n{report}"
    );

    // Both names are proven at one record, so the order publishes to the same
    // name twice: once for the apex and once for the wildcard.
    let published = ordered
        .stdout
        .lines()
        .filter(|line| line.contains(r#""event":"published""#))
        .count();
    assert_eq!(
        published, 2,
        "an apex and its wildcard are two authorizations at one name\n{report}"
    );
    assert!(
        ordered.stdout.contains(&record_for(LAB_ZONE)),
        "the order never named the record it wrote\n{report}"
    );
    assert!(
        records_in_zone(node, server, LAB_ZONE).is_empty(),
        "the challenge records are still in the zone\n{report}"
    );
}

#[test]
fn an_update_signed_with_the_wrong_key_is_refused_and_named() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let node = cluster.node("node3").expect("node3 is in the cluster");
    clean(node);

    let server = cluster.bind_address();
    let root = cluster.pebble_root().expect("the authority is readable");
    write(
        node,
        CONFIG,
        &one_line(&document(
            node,
            &[LAB_NAME],
            &Reach::Update { server },
            &root,
            5,
        )),
    );
    // A key of the right shape and the wrong value, which is what a mistyped
    // or rotated key looks like.
    store_credential(node, &product, "bm90LXRoZS1rZXktdGhpcy1zZXJ2ZXItaG9sZHM=");

    let ordered = order(node, &product);
    let report = format!(
        "stdout:\n{}\nstderr:\n{}\nbind:\n{}",
        ordered.stdout,
        ordered.stderr,
        cluster.bind_log(40).unwrap_or_default()
    );
    assert!(
        !ordered.ok(),
        "an update the name server refused was reported as success\n{report}"
    );
    assert!(
        ordered.stdout.contains(r#""event":"failed""#),
        "the failure was not reported\n{report}"
    );
    assert!(
        ordered.stdout.contains(r#""reason":"acme.configuration""#),
        "a wrong key is not a fault that passes, so it must not be retried\n{report}"
    );
    assert!(
        !ordered.stdout.contains(r#""event":"obtained""#),
        "a certificate came back from an order that could not write its record\n{report}"
    );

    // The name server's own account of it.
    let said = cluster.bind_log(60).unwrap_or_default();
    assert!(
        said.contains("tsig") || said.contains("TSIG") || said.contains("denied"),
        "the name server does not say it refused the update\n{said}"
    );
}

#[test]
fn a_record_that_never_becomes_visible_ends_the_order_and_leaves_nothing_behind() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let standin = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-cloudflare")
        .expect("the stand-in should build");

    let node = cluster.node("node1").expect("node1 is in the cluster");
    let host = cluster
        .node(API_HOST)
        .expect("the API host is in the cluster");
    clean(node);
    clean(host);

    let server = cluster.bind_address();
    let secret = cluster
        .tsig_secret()
        .expect("the name server wrote its key");
    clear_zone(node, server, &secret);

    // The API takes every change and applies none of it, which is a zone that
    // has not caught up. Nothing is ever visible, so the wait has to end.
    let api = start_api(host, &standin, server, &secret, true);
    trust(node, host);

    let root = cluster.pebble_root().expect("the authority is readable");
    write(
        node,
        CONFIG,
        &one_line(&document(node, &[LAB_NAME], &Reach::Api, &root, 4)),
    );
    store_credential(node, &product, CLOUDFLARE_TOKEN);

    let ordered = order(node, &product);
    let report = format!(
        "stdout:\n{}\nstderr:\n{}\napi:\n{}",
        ordered.stdout,
        ordered.stderr,
        api.stdout()
    );
    assert!(
        !ordered.ok(),
        "an order whose record never appeared was reported as success\n{report}"
    );
    assert!(
        ordered.stdout.contains(r#""reason":"acme.challenge""#),
        "the timeout was not reported as a challenge that cannot be answered\n{report}"
    );
    assert!(
        ordered.stdout.contains("propagation timeout"),
        "the message does not say what an operator can change\n{report}"
    );

    // What the API was told, in order. The record went in and came out again,
    // even though the order failed.
    let said = api.stdout();
    assert!(said.contains("wrote"), "nothing was ever written\n{report}");
    assert!(
        said.contains("deleted"),
        "a failed order left its record behind\n{report}"
    );
}

#[test]
fn a_certificate_is_obtained_through_the_api_and_the_record_is_cleared() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let standin = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-cloudflare")
        .expect("the stand-in should build");

    let node = cluster.node("node1").expect("node1 is in the cluster");
    let host = cluster
        .node(API_HOST)
        .expect("the API host is in the cluster");
    clean(node);
    clean(host);

    let server = cluster.bind_address();
    let secret = cluster
        .tsig_secret()
        .expect("the name server wrote its key");
    clear_zone(node, server, &secret);

    let api = start_api(host, &standin, server, &secret, false);
    trust(node, host);

    let root = cluster.pebble_root().expect("the authority is readable");
    write(
        node,
        CONFIG,
        &one_line(&document(node, &[LAB_NAME], &Reach::Api, &root, 60)),
    );
    store_credential(node, &product, CLOUDFLARE_TOKEN);

    let ordered = order(node, &product);
    let report = format!(
        "stdout:\n{}\nstderr:\n{}\napi:\n{}\npebble:\n{}",
        ordered.stdout,
        ordered.stderr,
        api.stdout(),
        cluster.pebble_log(60).unwrap_or_default()
    );
    assert!(ordered.ok(), "the order did not complete\n{report}");
    assert!(ordered.stdout.contains(r#""event":"usable""#), "{report}");
    assert!(
        records_in_zone(node, server, LAB_NAME).is_empty(),
        "the challenge record is still in the zone\n{report}"
    );
    assert!(
        api.stdout().contains("deleted"),
        "the API still holds the record\n{report}"
    );
}

#[test]
fn a_token_the_api_refuses_stops_the_order_with_the_reason_it_gave() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let standin = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-cloudflare")
        .expect("the stand-in should build");

    let node = cluster.node("node1").expect("node1 is in the cluster");
    let host = cluster
        .node(API_HOST)
        .expect("the API host is in the cluster");
    clean(node);
    clean(host);

    let server = cluster.bind_address();
    let secret = cluster
        .tsig_secret()
        .expect("the name server wrote its key");
    let api = start_api(host, &standin, server, &secret, false);
    trust(node, host);

    let root = cluster.pebble_root().expect("the authority is readable");
    write(
        node,
        CONFIG,
        &one_line(&document(node, &[LAB_NAME], &Reach::Api, &root, 10)),
    );
    store_credential(node, &product, "a-token-that-was-rotated-away");

    let ordered = order(node, &product);
    let report = format!(
        "stdout:\n{}\nstderr:\n{}\napi:\n{}",
        ordered.stdout,
        ordered.stderr,
        api.stdout()
    );
    assert!(
        !ordered.ok(),
        "a refused token was reported as success\n{report}"
    );
    assert!(
        ordered.stdout.contains(r#""reason":"acme.configuration""#),
        "a refused token is not a fault that passes\n{report}"
    );
    assert!(
        ordered.stdout.contains("9109"),
        "the API's own code is missing, and that is what its documentation is indexed by\n{report}"
    );
    assert!(
        !ordered.stdout.contains("a-token-that-was-rotated-away"),
        "the token itself was written to standard output\n{report}"
    );
}

/// Starts the stand-in API and waits until it is listening.
fn start_api(
    host: &Node,
    binary: &str,
    server: Ipv4Addr,
    secret: &str,
    no_dns: bool,
) -> Background {
    write(host, TSIG_FILE, secret);
    write(host, CLOUDFLARE_TOKEN_FILE, CLOUDFLARE_TOKEN);

    let listen = format!("0.0.0.0:{API_PORT}");
    let server = server.to_string();
    let address = host.address().to_string();
    let mut arguments = vec![
        binary,
        "--listen",
        &listen,
        "--zone-id",
        CLOUDFLARE_ZONE,
        "--token-file",
        CLOUDFLARE_TOKEN_FILE,
        "--dns-server",
        &server,
        "--dns-zone",
        LAB_ZONE,
        "--tsig-key",
        LAB_TSIG_KEY,
        "--tsig-secret-file",
        TSIG_FILE,
        "--cert-out",
        CLOUDFLARE_CERT,
        "--name",
        API_HOST,
        "--address",
        &address,
    ];
    if no_dns {
        arguments.push("--no-dns");
    }

    let api = host.spawn(&arguments).expect("the stand-in should start");
    api.wait_for_stdout("listening on", Duration::from_secs(20))
        .expect("the stand-in should bind its port");
    api
}

/// Puts the stand-in's certificate into a node's trust store.
///
/// Nothing trusts a certificate a server signed for itself, and the product
/// must not be given a way to skip that check. So the certificate is
/// installed the way an operator installs their own authority.
fn trust(node: &Node, host: &Node) {
    let pem = host
        .run_ok(&["cat", CLOUDFLARE_CERT])
        .expect("the stand-in wrote its certificate");
    write(node, "/usr/local/share/ca-certificates/ek-ek-lab.crt", &pem);
    let installed = node
        .shell("update-ca-certificates >/dev/null 2>&1 && echo installed")
        .expect("the node should be reachable");
    assert!(
        installed.stdout.contains("installed"),
        "the lab authority was not installed: {}",
        installed.stderr
    );
}
