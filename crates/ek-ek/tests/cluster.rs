// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `cluster` commands, run as the binary.
//!
//! What the library does is measured in `ek-ek-peer`. What is measured here is
//! the operator's side of it: that bootstrapping happens once, that the
//! fingerprint comes back in the form a join token needs, that the key written
//! to disk is readable by nobody else, and that nothing secret reaches
//! standard output.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};

/// Seconds in a day.
const DAY: i64 = 86_400;

/// A fixed moment, so a renewal decision can be asked for without waiting.
const ISSUED: i64 = 1_800_000_000;

/// The smallest configuration a store will start from.
const CONFIG: &str = r#"{
  "schema_version": 1,
  "nodes": [],
  "vips": [],
  "frontends": [],
  "backends": [],
  "certificates": [],
  "dns_providers": [],
  "acme": null
}"#;

fn run(argv: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ek-ek"))
        .arg("cluster")
        .args(argv)
        .output()
        .expect("the binary should run")
}

fn said(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Creates a store with an authority in it, and returns the directory.
fn bootstrapped() -> tempfile::TempDir {
    let home = tempfile::tempdir().expect("a directory");
    let config = home.path().join("config.json");
    std::fs::write(&config, CONFIG).expect("the document is writable");

    let output = run(&[
        "init",
        "--data-dir",
        home.path().to_str().expect("a path"),
        "--config",
        config.to_str().expect("a path"),
    ]);
    assert!(output.status.success(), "{}", said(&output));
    home
}

#[test]
fn bootstrapping_creates_an_authority_and_prints_its_fingerprint() {
    let home = bootstrapped();
    let output = run(&["fingerprint", "--data-dir", home.path().to_str().unwrap()]);
    let text = said(&output);
    assert!(output.status.success(), "{text}");

    let printed: serde_json::Value =
        serde_json::from_str(text.trim()).expect("the line is a record");
    let mark = printed["fingerprint"].as_str().expect("a fingerprint");
    assert_eq!(mark.len(), 64, "the fingerprint is not join token shaped");
    assert!(
        mark.chars()
            .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)),
        "the fingerprint is not lowercase hex: {mark}"
    );
}

#[test]
fn a_second_bootstrap_is_refused() {
    // A second authority would leave every certificate the first one signed
    // unable to connect, and there would be nothing on either node to say why.
    let home = bootstrapped();
    let output = run(&["init", "--data-dir", home.path().to_str().unwrap()]);
    let text = said(&output);
    assert!(!output.status.success(), "a second authority was created");
    assert!(text.contains("already holds"), "{text}");
}

#[test]
fn the_fingerprint_is_the_one_openssl_prints() {
    // The value an operator can check against a tool this project did not
    // write. If the two disagree, the join token is worthless.
    let home = bootstrapped();
    let out_dir = home.path().join("material");
    let enrolled = run(&[
        "enroll",
        "--data-dir",
        home.path().to_str().unwrap(),
        "--node",
        "node-1",
        "--address",
        "127.0.0.1",
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    assert!(enrolled.status.success(), "{}", said(&enrolled));

    let printed = run(&["fingerprint", "--data-dir", home.path().to_str().unwrap()]);
    let record: serde_json::Value = serde_json::from_str(said(&printed).trim()).expect("a record");
    let mark = record["fingerprint"].as_str().expect("a fingerprint");

    let authority = out_dir.join("cluster-ca.crt");
    let openssl = Command::new("openssl")
        .args(["x509", "-in"])
        .arg(&authority)
        .args(["-noout", "-fingerprint", "-sha256"])
        .output()
        .expect("openssl runs");
    assert!(openssl.status.success());
    let independent = String::from_utf8_lossy(&openssl.stdout)
        .split('=')
        .nth(1)
        .expect("a value")
        .trim()
        .replace(':', "")
        .to_lowercase();

    assert_eq!(mark, independent);
}

#[test]
fn an_enrolled_key_is_readable_by_its_owner_alone() {
    // The material is on disk because the join flow does not exist yet
    // (ADR-0082). A key another user on the machine can read is the same as no
    // key at all.
    let home = bootstrapped();
    let out_dir = home.path().join("material");
    let output = run(&[
        "enroll",
        "--data-dir",
        home.path().to_str().unwrap(),
        "--node",
        "node-1",
        "--address",
        "127.0.0.1",
        "--out-dir",
        out_dir.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{}", said(&output));

    let mode = std::fs::metadata(out_dir.join("node-1.key"))
        .expect("the key was written")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the key is readable by somebody else");
}

#[test]
fn nothing_the_commands_print_carries_key_material() {
    // Standard output goes to a log, a terminal recording or a support
    // bundle. A key that reaches any of them is a key that has left the node
    // (T-036).
    // Bootstrapped here rather than by the helper, because the line that says
    // an authority was created is only written by the run that creates one. A
    // second `init` on a store that already holds one is refused before it
    // reaches that line, and the search below would then be looking at output
    // the command never produced.
    let home = tempfile::tempdir().expect("a directory");
    let config = home.path().join("config.json");
    std::fs::write(&config, CONFIG).expect("the document is writable");
    let out_dir = home.path().join("material");

    let mut printed = String::new();
    printed.push_str(&said(&run(&[
        "init",
        "--data-dir",
        home.path().to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
    ])));
    assert!(
        printed.contains(r#""event":"created""#),
        "the authority was not created here, so nothing it prints is being read: {printed}"
    );
    printed.push_str(&said(&run(&[
        "fingerprint",
        "--data-dir",
        home.path().to_str().unwrap(),
    ])));
    printed.push_str(&said(&run(&[
        "enroll",
        "--data-dir",
        home.path().to_str().unwrap(),
        "--node",
        "node-1",
        "--address",
        "127.0.0.1",
        "--out-dir",
        out_dir.to_str().unwrap(),
    ])));

    assert!(!printed.is_empty(), "the commands said nothing at all");
    assert!(
        !printed.contains("PRIVATE KEY"),
        "a key reached standard output: {printed}"
    );
    assert!(
        !printed.contains("BEGIN"),
        "something PEM shaped reached standard output: {printed}"
    );

    // And the key really was produced, so the search above is not looking for
    // something that never existed.
    let key = std::fs::read_to_string(out_dir.join("node-1.key")).expect("the key was written");
    assert!(key.contains("PRIVATE KEY"));
}

#[test]
fn a_certificate_with_most_of_its_life_left_is_kept() {
    let home = bootstrapped();
    let out_dir = home.path().join("material");
    let enroll = |at: i64| {
        run(&[
            "enroll",
            "--data-dir",
            home.path().to_str().unwrap(),
            "--node",
            "node-1",
            "--address",
            "127.0.0.1",
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--now",
            &at.to_string(),
        ])
    };

    let first = enroll(ISSUED);
    assert!(
        said(&first).contains(r#""event":"enrolled""#),
        "{}",
        said(&first)
    );
    let held = std::fs::read(out_dir.join("node-1.crt")).expect("a certificate");

    let again = enroll(ISSUED + 30 * DAY);
    let text = said(&again);
    assert!(again.status.success(), "{text}");
    assert!(text.contains(r#""event":"kept""#), "{text}");
    assert_eq!(
        std::fs::read(out_dir.join("node-1.crt")).expect("a certificate"),
        held,
        "a certificate with most of its life left was replaced"
    );
}

#[test]
fn a_certificate_running_out_is_signed_again_before_it_expires() {
    // The other side. Sixty-one days into a ninety day certificate, less than
    // a third is left and a new one is signed, while the old one still works.
    let home = bootstrapped();
    let out_dir = home.path().join("material");
    let enroll = |at: i64| {
        run(&[
            "enroll",
            "--data-dir",
            home.path().to_str().unwrap(),
            "--node",
            "node-1",
            "--address",
            "127.0.0.1",
            "--out-dir",
            out_dir.to_str().unwrap(),
            "--now",
            &at.to_string(),
        ])
    };

    assert!(enroll(ISSUED).status.success());
    let held = std::fs::read(out_dir.join("node-1.crt")).expect("a certificate");

    let renewed = enroll(ISSUED + 61 * DAY);
    let text = said(&renewed);
    assert!(renewed.status.success(), "{text}");
    assert!(text.contains(r#""event":"enrolled""#), "{text}");

    let now = std::fs::read(out_dir.join("node-1.crt")).expect("a certificate");
    assert_ne!(now, held, "the certificate was not replaced");

    let record: serde_json::Value = serde_json::from_str(text.trim()).expect("a record");
    let ends = record["not_after"].as_i64().expect("an end");
    assert!(
        ends > ISSUED + 90 * DAY,
        "the new certificate runs out no later than the old one"
    );
}

#[test]
fn two_nodes_of_one_cluster_speak_over_the_peer_channel() {
    // The channel, through the binary, with two certificates from the same
    // authority. What is proved here is that the commands wire the material
    // together the way the library expects.
    let home = bootstrapped();
    let first = home.path().join("node-1");
    let second = home.path().join("node-2");

    for (node, out) in [("node-1", &first), ("node-2", &second)] {
        let output = run(&[
            "enroll",
            "--data-dir",
            home.path().to_str().unwrap(),
            "--node",
            node,
            "--address",
            "127.0.0.1",
            "--out-dir",
            out.to_str().unwrap(),
        ]);
        assert!(output.status.success(), "{}", said(&output));
    }

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut serving = Command::new(env!("CARGO_BIN_EXE_ek-ek"))
        .args(["cluster", "serve", "--listen"])
        .arg(&listen)
        .args(["--node", "node-1", "--material"])
        .arg(&first)
        .args(["--connections", "1"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the listener starts");

    wait_until_listening(&mut serving);

    let asked = Command::new(env!("CARGO_BIN_EXE_ek-ek"))
        .args(["cluster", "ping", "--to"])
        .arg(&listen)
        .args(["--expect", "node-1", "--node", "node-2", "--material"])
        .arg(&second)
        .output()
        .expect("the ping runs");
    let text = String::from_utf8_lossy(&asked.stdout).into_owned();
    assert!(asked.status.success(), "{text}");
    assert!(text.contains(r#""node":"node-1""#), "{text}");

    let finished = serving.wait().expect("the listener stops");
    assert!(finished.success());
}

#[test]
fn a_node_of_another_cluster_is_refused_over_the_peer_channel() {
    // The other side. Everything is the same except which authority signed the
    // caller's certificate.
    let ours = bootstrapped();
    let theirs = bootstrapped();
    let server = ours.path().join("node-1");
    let stranger = theirs.path().join("node-2");

    for (home, node, out) in [(&ours, "node-1", &server), (&theirs, "node-2", &stranger)] {
        let output = run(&[
            "enroll",
            "--data-dir",
            home.path().to_str().unwrap(),
            "--node",
            node,
            "--address",
            "127.0.0.1",
            "--out-dir",
            out.to_str().unwrap(),
        ]);
        assert!(output.status.success(), "{}", said(&output));
    }

    // The stranger has to trust our authority, or it refuses the listener
    // before the listener gets a chance to refuse it, and the measurement
    // would be of the wrong end.
    std::fs::copy(
        server.join("cluster-ca.crt"),
        stranger.join("cluster-ca.crt"),
    )
    .expect("the authority is copied");

    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let mut serving = Command::new(env!("CARGO_BIN_EXE_ek-ek"))
        .args(["cluster", "serve", "--listen"])
        .arg(&listen)
        .args(["--node", "node-1", "--material"])
        .arg(&server)
        .args(["--connections", "1"])
        .stdout(std::process::Stdio::piped())
        .spawn()
        .expect("the listener starts");

    wait_until_listening(&mut serving);

    let asked = Command::new(env!("CARGO_BIN_EXE_ek-ek"))
        .args(["cluster", "ping", "--to"])
        .arg(&listen)
        .args(["--expect", "node-1", "--node", "node-2", "--material"])
        .arg(&stranger)
        .output()
        .expect("the ping runs");
    assert!(
        !asked.status.success(),
        "a node of another cluster was served: {}",
        String::from_utf8_lossy(&asked.stdout)
    );

    let finished = serving.wait().expect("the listener stops");
    assert!(finished.success());
}

/// A port nothing is listening on.
fn free_port() -> u16 {
    let socket = std::net::TcpListener::bind("127.0.0.1:0").expect("a port");
    socket.local_addr().expect("readable").port()
}

/// Waits until the listener says it is up.
///
/// Read out of the process rather than probed with a connection: a probe would
/// take the one connection the listener was told to answer, and a ping sent
/// before the port was bound fails for the wrong reason.
fn wait_until_listening(child: &mut std::process::Child) {
    let stdout = child
        .stdout
        .as_mut()
        .expect("the listener writes to a pipe");
    let mut line = String::new();
    std::io::BufRead::read_line(&mut std::io::BufReader::new(stdout), &mut line)
        .expect("the listener says something");
    assert!(
        line.contains(r#""event":"listening""#),
        "the listener never came up: {line}"
    );
}
