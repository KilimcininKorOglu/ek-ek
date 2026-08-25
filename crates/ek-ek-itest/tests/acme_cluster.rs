// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A certificate ordered by a cluster, against a real ACME server.
//!
//! Three nodes carry real consensus over the real peer channel, one of them
//! places the order, and Pebble decides whether the challenge was answered.
//! Nothing here is simulated: the certificate authority is Let's Encrypt's own
//! test server, it connects to port 80 and reads what a traffic path answers,
//! and the answer it reads was written on a different node from the one that
//! placed the order (ADR-0032, ADR-0086).
//!
//! # Why the node the name resolves to is never the leader
//!
//! `node1.ek-ek.test` is a network alias on node1, so the certificate
//! authority always connects to node1. The measurements below make sure node1
//! is a follower, which is the only arrangement where "the answer replicated"
//! and "the node that ordered answered its own challenge" are different
//! statements.
//!
//! # Why each node's traffic path binds its own address
//!
//! The replicated document names one virtual address, and in production VRRP
//! puts it on one node. Nothing here measures where the address sits, so each
//! node's own agent is given a document naming that node's address instead.
//! What is measured is where the challenge answer comes from, and that is the
//! replicated state either way.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ek_ek_itest::{Background, Cluster, LAB_NAME, Node, PEBBLE_DIRECTORY};

/// Where the consensus store lives inside a node.
const STORE: &str = "/var/lib/ek-ek/acme-store";
/// Where the peer certificates live inside a node.
const MATERIAL: &str = "/var/lib/ek-ek/acme-material";
/// The configuration the node process watches and puts through consensus.
const APPLY: &str = "/var/lib/ek-ek/acme-apply.json";
/// The configuration this node's own traffic path is given.
const SERVING: &str = "/var/lib/ek-ek/acme-serving.json";
/// Where the node process writes the answers it holds, for its agent to read.
const CHALLENGES: &str = "/var/lib/ek-ek/acme-challenges.json";
/// The socket the traffic path takes its configuration from.
const SOCKET: &str = "/var/lib/ek-ek/acme-agent.sock";

/// Port the consensus members answer each other on.
const PEER_PORT: u16 = 7391;
/// Port the certificate authority connects to, which is the one it always uses.
const HTTP_PORT: u16 = 80;
/// The prefix length the lab network uses.
const PREFIX: u8 = 24;

/// The certificate the cluster orders.
const CERTIFICATE: &str = "cert-cluster";

/// The three nodes, in the order the cluster is built from.
const NAMES: [&str; 3] = ["node1", "node2", "node3"];

/// The node the certificate's name resolves to, and never the one that orders.
const ANSWERING: &str = "node1";

/// The node that brings the cluster into being, and so the first leader.
///
/// Deliberately not the node above. `initialize` makes the calling node the
/// leader of the first term, which is what puts the node the certificate
/// authority connects to on the receiving end of the replication rather than
/// on the sending end (ADR-0086).
const FOUNDER: &str = "node2";

/// How long anything in the lab is given to reach a state.
const PATIENCE: Duration = Duration::from_secs(90);

/// The smallest document a store will start from.
const SEED: &str = r#"{"schema_version":1,"nodes":[],"vips":[],"frontends":[],"backends":[],"certificates":[],"dns_providers":[],"acme":null}"#;

/// Clears everything an earlier measurement left on a node.
fn clean(node: &Node) {
    node.kill_matching("/var/lib/ek-ek/ek-ek").ok();
    node.kill_matching("ek-ek-standin-agent").ok();
    node.shell(&format!(
        "rm -rf {STORE} {MATERIAL} {APPLY} {SERVING} {SOCKET} {CHALLENGES}"
    ))
    .expect("the node should be cleanable");
}

/// Writes a file inside a node.
fn put(node: &Node, path: &str, content: &str) {
    node.shell(&format!("cat > {path} <<'CONTENT'\n{content}\nCONTENT"))
        .expect("the file should be writable");
}

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

/// The document every node agrees on and orders from.
///
/// The virtual address is node1's, because that is where the name resolves and
/// where the certificate authority will knock. Whoever leads reads this same
/// document and waits for that address to answer, which is a wait across the
/// lab network whenever the leader is not node1.
fn agreed(root: &str, backend: Ipv4Addr, answering: Ipv4Addr) -> String {
    one_line(&format!(
        r#"{{
  "schema_version": 1,
  "nodes": [
    {{"id":"node1","address":"172.28.0.11","roles":["control_plane","data_plane"]}},
    {{"id":"node2","address":"172.28.0.12","roles":["control_plane","data_plane"]}},
    {{"id":"node3","address":"172.28.0.13","roles":["control_plane","data_plane"]}}
  ],
  "vips": [{{"id":"vip-acme","address":"{answering}","prefix_length":{PREFIX},"interface":"eth0","preferred_node":"node1"}}],
  "frontends": [{{
    "id": "web",
    "vip": "vip-acme",
    "port": {HTTP_PORT},
    "transport": "tcp",
    "application": "http",
    "tls": null,
    "proxy_protocol": "disabled",
    "routing_rules": [],
    "sni_rules": [],
    "default_backend": "pool",
    "http2": "disabled",
    "connect_timeout_seconds": 5,
    "request_timeout_seconds": 30,
    "idle_timeout_seconds": 0,
    "drain_timeout_seconds": 5,
    "udp_session_limit": 0
  }}],
  "backends": [{{
    "id": "pool",
    "algorithm": "round_robin",
    "members": [{{"id":"one","address":"{backend}","port":80,"weight":1,"admin_state":"enabled"}}],
    "health_check": null,
    "stickiness": {{"mode":"disabled"}},
    "connection_pooling": "disabled",
    "connection_pool_size": 0,
    "connection_lifetime_seconds": 0
  }}],
  "certificates": [{{
    "id": "{CERTIFICATE}",
    "sni_names": ["{LAB_NAME}"],
    "source": {{"type":"acme_http01"}},
    "validity": null,
    "chain": null,
    "private_key": null
  }}],
  "dns_providers": [],
  "acme": {{
    "directory_url": "{PEBBLE_DIRECTORY}",
    "contact_email": "yonetici@ek-ek.test",
    "accepted_terms": true,
    "trusted_root_pem": "{root}"
  }}
}}"#,
        root = quoted(root)
    ))
}

/// The document one node's own traffic path is given.
///
/// The same as the agreed one, except that the virtual address is this node's
/// own. Every node then binds an address it actually holds, so a challenge can
/// be asked for at any of the three.
fn serving(root: &str, backend: Ipv4Addr, mine: Ipv4Addr) -> String {
    agreed(root, backend, mine)
}

/// The same document on one line.
///
/// The agent delivers one JSON object per line (ADR-0010), so a document with
/// real newlines in it arrives cut in half.
fn one_line(document: &str) -> String {
    document.lines().map(str::trim).collect::<String>()
}

/// Creates the authority on the first node.
fn found(node: &Node, product: &str) {
    node.shell(&format!("mkdir -p {STORE}"))
        .expect("the directory should be creatable");
    put(node, "/var/lib/ek-ek/acme-seed.json", SEED);
    node.run_ok(&[
        product,
        "cluster",
        "init",
        "--data-dir",
        STORE,
        "--config",
        "/var/lib/ek-ek/acme-seed.json",
    ])
    .expect("the authority should be created");
}

/// Signs a certificate for one node and returns the directory it landed in.
fn enrol(node: &Node, product: &str, name: &str, address: Ipv4Addr) -> String {
    let out = format!("{MATERIAL}/{name}");
    node.run_ok(&[
        product,
        "cluster",
        "enroll",
        "--data-dir",
        STORE,
        "--node",
        name,
        "--address",
        &address.to_string(),
        "--out-dir",
        &out,
    ])
    .expect("the certificate should be signed");
    out
}

/// Copies one node's certificate, key and authority to another node.
fn hand_over(from: &Node, to: &Node, directory: &str, name: &str) {
    to.shell(&format!("mkdir -p {directory}"))
        .expect("the directory should be creatable");
    for file in [
        format!("{name}.crt"),
        format!("{name}.key"),
        "cluster-ca.crt".to_owned(),
    ] {
        let content = from
            .run_ok(&["cat", &format!("{directory}/{file}")])
            .expect("the file should be readable");
        put(to, &format!("{directory}/{file}"), content.trim_end());
    }
    to.shell(&format!("chmod 600 {directory}/{name}.key"))
        .expect("the key should be restrictable");
}

/// Starts one consensus member that also orders certificates when it leads.
fn start_member(node: &Node, product: &str, initialise: Option<&str>) -> Background {
    let listen = format!("0.0.0.0:{PEER_PORT}");
    let material = format!("{MATERIAL}/{}", node.name());
    let mut argv: Vec<String> = vec![
        product.to_owned(),
        "cluster".to_owned(),
        "node".to_owned(),
        "--data-dir".to_owned(),
        STORE.to_owned(),
        "--node".to_owned(),
        node.name().to_owned(),
        "--material".to_owned(),
        material,
        "--listen".to_owned(),
        listen,
        "--apply".to_owned(),
        APPLY.to_owned(),
        "--challenges".to_owned(),
        CHALLENGES.to_owned(),
        "--acme".to_owned(),
    ];
    if let Some(membership) = initialise {
        argv.push("--initialise".to_owned());
        argv.push(membership.to_owned());
    }

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let member = node
        .spawn(&borrowed)
        .unwrap_or_else(|error| panic!("{} must start its member: {error}", node.name()));
    member
        .wait_for_stdout(r#""event":"listening""#, PATIENCE)
        .unwrap_or_else(|error| panic!("{} never opened its peer port: {error}", node.name()));
    member
}

/// Stops one node's member without touching its traffic path.
fn stop_member(node: &Node) {
    node.kill_matching("cluster node --data-dir")
        .expect("the member should be stoppable");
}

/// The `name=address` list one node initialises the cluster with.
fn membership(cluster: &Cluster) -> String {
    NAMES
        .iter()
        .map(|name| {
            let node = cluster.node(name).expect("the node is in the cluster");
            format!("{name}={}:{PEER_PORT}", node.address())
        })
        .collect::<Vec<String>>()
        .join(",")
}

/// Starts the stand-in agent and the traffic path on one node.
fn start_plane(node: &Node, agent_binary: &str, product: &str) -> (Background, Background) {
    let agent = node
        .spawn(&[
            agent_binary,
            "--socket",
            SOCKET,
            "--config",
            SERVING,
            "--challenges",
            CHALLENGES,
        ])
        .expect("the stand-in agent should start");
    agent
        .wait_for_stdout("listening on", PATIENCE)
        .expect("the stand-in agent should bind its socket");

    let plane = node
        .spawn(&[product, "data-plane", "--agent-socket", SOCKET])
        .expect("the traffic path should start");
    wait_until_listening(node, &plane);
    (agent, plane)
}

/// Asks one node's own listener for a challenge path.
///
/// A refused connection comes back as `000`, which is what curl writes when it
/// never got a status.
fn ask(node: &Node, token: &str) -> (String, String) {
    let answer = node
        .run(&[
            "curl",
            "-s",
            "-o",
            "/tmp/ek-ek-cluster-body",
            "-w",
            "%{http_code}",
            "--max-time",
            "5",
            &format!(
                "http://{}:{HTTP_PORT}/.well-known/acme-challenge/{token}",
                node.address()
            ),
        ])
        .expect("curl should run");
    let body = node
        .run_ok(&["cat", "/tmp/ek-ek-cluster-body"])
        .unwrap_or_default();
    (answer.stdout.trim().to_owned(), body)
}

/// Waits until a node's traffic path answers at all.
fn wait_until_listening(node: &Node, plane: &Background) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ask(node, "nothing-is-live").0 == "404" {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "{} never started answering on port {HTTP_PORT}\nstdout:\n{}\nstderr:\n{}",
        node.name(),
        plane.stdout(),
        plane.stderr()
    );
}

/// What one node holds in its challenge file, as written text.
fn answers(node: &Node) -> String {
    node.run_ok(&["sh", "-c", &format!("cat {CHALLENGES} 2>/dev/null || true")])
        .unwrap_or_default()
        .trim()
        .to_owned()
}

/// Tells the watcher threads to stop, whether the measurement passed or not.
///
/// The watchers spin until this flag is set, and `thread::scope` joins them
/// before it returns. A failed assertion inside the scope unwinds past the
/// line that would have set the flag, so without this the scope waits for
/// threads that never finish and the measurement hangs instead of reporting
/// what it found. `Drop` runs while unwinding, so the flag is set either way.
struct Stop<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Stop<'_> {
    fn drop(&mut self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Waits until a record has appeared at least this many times.
fn wait_for(background: &Background, needle: &str, at_least: usize, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if background.stdout().matches(needle).count() >= at_least {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!(
        "{what}: {needle} appeared {} time(s), not {at_least}\n{}",
        background.stdout().matches(needle).count(),
        background.stdout()
    );
}

/// Waits until the answer the given predicate wants is true, or gives up.
fn wait_while(what: &str, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if ready() {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("{what}");
}

/// The three members, by the name each runs under.
struct Cohort {
    members: Vec<Background>,
}

impl Cohort {
    fn named(&self, name: &str) -> &Background {
        let at = NAMES
            .iter()
            .position(|held| *held == name)
            .unwrap_or_else(|| panic!("no member named {name}"));
        &self.members[at]
    }

    /// Which node every member agrees is the leader.
    fn leader(&self) -> Option<String> {
        let named: Vec<Option<String>> = NAMES
            .iter()
            .map(|name| last_leader(self.named(name)))
            .collect();
        let first = named.first().cloned().flatten()?;
        named
            .iter()
            .all(|held| held.as_deref() == Some(first.as_str()))
            .then_some(first)
    }
}

/// The node named in the most recent leader record a member wrote.
fn last_leader(member: &Background) -> Option<String> {
    member
        .stdout()
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|record| record.get("event").and_then(serde_json::Value::as_str) == Some("leader"))
        .filter_map(|record| {
            record
                .get("node")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .next_back()
}

/// Builds the authority, hands the certificates out and starts three members.
fn found_cluster(cluster: &Cluster, product: &str) -> Cohort {
    let first = cluster.node("node1").expect("node1 is in the cluster");
    found(first, product);
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        let directory = enrol(first, product, name, node.address());
        if name != "node1" {
            hand_over(first, node, &directory, name);
        }
    }

    let membership = membership(cluster);
    let members: Vec<Background> = NAMES
        .iter()
        .map(|name| {
            let node = cluster.node(name).expect("the node is in the cluster");
            let initialise = (*name == FOUNDER).then_some(membership.as_str());
            start_member(node, product, initialise)
        })
        .collect();

    let cohort = Cohort { members };
    for name in NAMES {
        wait_for(
            cohort.named(name),
            r#""event":"quorum","reachable":true"#,
            1,
            &format!("{name} never reached a quorum"),
        );
    }
    cohort
}

/// The node every member agrees leads, once one is agreed on.
///
/// It must not be the node the certificate's name resolves to. The whole point
/// of replicating the answer is that the node answering the certificate
/// authority need not be the node that ordered, and a run where they are the
/// same node measures nothing about that. The cluster is founded on another
/// node for exactly this reason, so a leader here that is the answering node
/// is a fault rather than a run to work around.
fn leading(cohort: &Cohort) -> String {
    wait_while("no leader was ever agreed on", || cohort.leader().is_some());
    let named = cohort.leader().expect("a leader is agreed on");
    assert_ne!(
        named, ANSWERING,
        "the node the certificate authority connects to is the one that leads, \
         so nothing here would measure the answer replicating"
    );
    named
}

/// Whether one node's store holds the material of the certificate.
///
/// Both halves, by the identities `install` files them under. A chain without
/// its key is a frontend that answers no handshake, and a measurement that
/// looked for one of the two would call that a certificate.
///
/// Read out of the database files rather than from the process that wrote it.
/// A certificate that only ever lived in the leader's memory would pass a
/// measurement that asked the leader. The glob matters: SQLite runs in
/// write-ahead mode, so a commit sits in `config.db-wal` until a checkpoint
/// moves it, and a node that has not checkpointed yet still holds it.
fn holds_certificate(node: &Node, product: &str) -> bool {
    // Read through the product's own reader rather than out of the store file.
    // SQLite leaves the bytes of deleted rows in the file and keeps older ones
    // in the write ahead log, so a file that once held a certificate matches a
    // search for it for ever: a check written that way passes whatever the
    // node holds, which is no check at all.
    let Ok(said) = node.run_ok(&[product, "cluster", "status", "--data-dir", STORE]) else {
        return false;
    };
    let Some(line) = said.lines().find(|line| line.contains(r#""event":"status""#)) else {
        return false;
    };
    let held: serde_json::Value =
        serde_json::from_str(line).expect("the status record should be JSON");
    held["certificates"]
        .as_array()
        .expect("the status record should name the certificates held")
        .iter()
        .any(|id| id.as_str() == Some(CERTIFICATE))
}

/// The token in a challenge file, when there is exactly one.
fn only_token(document: &str) -> Option<String> {
    let held: std::collections::BTreeMap<String, String> = serde_json::from_str(document).ok()?;
    let mut keys = held.into_keys();
    let first = keys.next()?;
    keys.next().is_none().then_some(first)
}

#[test]
fn one_node_orders_and_every_node_answers_the_certificate_authority() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let agent_binary = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-agent")
        .expect("the stand-in agent should build");

    for name in NAMES {
        clean(cluster.node(name).expect("the node is in the cluster"));
    }

    let root = cluster
        .pebble_root()
        .expect("the ACME server's own authority should be readable");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    let answering = cluster
        .node(ANSWERING)
        .expect("the node is in the cluster")
        .address();

    let cohort = found_cluster(&cluster, &product);
    let leading = leading(&cohort);

    // Every node's own traffic path. All three are up before the order, so the
    // certificate authority finds an answer wherever it knocks and the order
    // goes through on its first attempt: a failed one waits an hour before the
    // next (ADR-0077), which is longer than any measurement can sit for.
    let mut planes: Vec<(Background, Background)> = Vec::new();
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        put(node, SERVING, &serving(&root, backend, node.address()));
        planes.push(start_plane(node, &agent_binary, &product));
    }

    // Nothing answers a challenge before an order, on any node.
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        // Empty rather than absent: the node process writes the closed path
        // out explicitly, so a file that is only ever added to cannot leave a
        // token answerable (ADR-0086).
        let held = answers(node);
        assert!(
            held.is_empty() || held == "{}",
            "{name} held a challenge answer before any order was placed: {held}"
        );
        assert_eq!(
            ask(node, "nothing-is-live").0,
            "404",
            "{name} answered a challenge path before any order was placed"
        );
    }

    // The answer is live only while the server is checking it, which is a
    // window of seconds. These read each node throughout the order and keep
    // what they saw, because a reading taken after it is a reading of a path
    // that has correctly closed.
    let stop = std::sync::atomic::AtomicBool::new(false);
    let seen = std::thread::scope(|scope| {
        let _stop = Stop(&stop);
        let watchers: Vec<_> = NAMES
            .iter()
            .map(|name| {
                let stop = &stop;
                let cluster = &cluster;
                scope.spawn(move || {
                    let node = cluster.node(name).expect("the node is in the cluster");
                    let mut held: Option<String> = None;
                    let mut answered: Option<(String, String)> = None;
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        if let Some(token) = only_token(&answers(node)) {
                            if answered.is_none() {
                                let (status, body) = ask(node, &token);
                                if status == "200" {
                                    answered = Some((token.clone(), body));
                                }
                            }
                            held = Some(token);
                        }
                    }
                    (held, answered)
                })
            })
            .collect();

        // The document goes in through consensus. Every node offers it; only
        // the leader's write lands.
        for name in NAMES {
            let node = cluster.node(name).expect("the node is in the cluster");
            put(node, APPLY, &agreed(&root, backend, answering));
        }
        wait_for(
            cohort.named(&leading),
            r#""event":"applied""#,
            1,
            "the configuration never went through consensus",
        );
        wait_for(
            cohort.named(&leading),
            r#""event":"ordering""#,
            1,
            "the leader never started an order",
        );
        wait_for(
            cohort.named(&leading),
            r#""event":"ordered""#,
            1,
            "the order never completed",
        );

        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        watchers
            .into_iter()
            .map(|watcher| watcher.join().expect("the watcher finishes"))
            .collect::<Vec<(Option<String>, Option<(String, String)>)>>()
    });

    // Only one node ordered. Three orders would spend the server's allowance
    // three times over for one certificate (ADR-0032).
    for name in NAMES.iter().filter(|name| **name != leading) {
        assert_eq!(
            cohort
                .named(name)
                .stdout()
                .matches(r#""event":"ordering""#)
                .count(),
            0,
            "{name} placed an order as well as {leading}\n{}",
            cohort.named(name).stdout()
        );
    }

    // Every node held the same answer, the two that did not order included.
    let token = seen
        .iter()
        .find_map(|(held, _)| held.clone())
        .expect("no node ever held a challenge answer");
    for (name, (held, _)) in NAMES.iter().zip(seen.iter()) {
        assert_eq!(
            held.as_deref(),
            Some(token.as_str()),
            "{name} never held the answer the order published, so the \
             certificate authority would get a 404 from it"
        );
    }

    // And every node answered a request for it. The virtual address in the
    // agreed document belongs to one node, so the other two are answering a
    // challenge for an address they do not hold (ADR-0032).
    for (name, (_, answered)) in NAMES.iter().zip(seen.iter()) {
        let (asked, body) = answered
            .as_ref()
            .unwrap_or_else(|| panic!("{name} never answered a request for the challenge"));
        assert_eq!(asked, &token);
        assert!(
            body.starts_with(&token),
            "{name} answered something that is not the key authorization"
        );
    }

    // What the certificate authority says it did, which is the reading that
    // comes from outside this project.
    let served = cluster.pebble_log(200).unwrap_or_default();
    assert!(
        served.contains(LAB_NAME),
        "the ACME server never mentions the name it was asked about\n{served}"
    );

    // The certificate is usable on every node, not only on the one that
    // ordered it. A virtual address that moves must not move a certificate.
    wait_while("the certificate never reached every node", || {
        NAMES
            .iter()
            .all(|name| holds_certificate(
                cluster.node(name).expect("the node is in the cluster"),
                &product,
            ))
    });

    // And the path is closed again, everywhere. A token left answerable is an
    // endpoint on a name nobody is watching.
    wait_while("a node kept answering after the order finished", || {
        NAMES.iter().all(|name| {
            let node = cluster.node(name).expect("the node is in the cluster");
            answers(node) == "{}" || answers(node).is_empty()
        })
    });
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        let (status, body) = ask(node, &token);
        assert_eq!(
            status, "404",
            "{name} still answers the challenge path after the order: {body}"
        );
    }

    // A configuration written after the order must not take the certificate
    // with it. Only the state has ever held the material, and a document
    // applied as written would replace the certificate record with the one an
    // operator typed, which carries nothing (ADR-0079).
    let changed = agreed(&root, backend, answering)
        .replace("yonetici@ek-ek.test", "baska-yonetici@ek-ek.test");
    assert_ne!(
        changed,
        agreed(&root, backend, answering),
        "the second document is the same as the first, so nothing is applied twice"
    );
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        put(node, APPLY, &changed);
    }
    wait_for(
        cohort.named(&leading),
        r#""event":"applied""#,
        2,
        "the second configuration never went through consensus",
    );
    for name in NAMES {
        assert!(
            holds_certificate(
                cluster.node(name).expect("the node is in the cluster"),
                &product,
            ),
            "{name} lost the certificate when a configuration was applied after the order"
        );
    }

    drop(planes);
}

#[test]
fn an_order_whose_leader_stopped_is_taken_over_rather_than_lost() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let agent_binary = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-agent")
        .expect("the stand-in agent should build");

    for name in NAMES {
        clean(cluster.node(name).expect("the node is in the cluster"));
    }

    let root = cluster
        .pebble_root()
        .expect("the ACME server's own authority should be readable");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    let answering = cluster
        .node(ANSWERING)
        .expect("the node is in the cluster")
        .address();

    let cohort = found_cluster(&cluster, &product);
    let leading = leading(&cohort);

    // The node the certificate authority connects to holds no traffic path
    // yet. The leader's order then stops at the wait for its own answer to
    // become reachable, which is the window this measurement needs.
    for name in NAMES {
        let node = cluster.node(name).expect("the node is in the cluster");
        put(node, SERVING, &serving(&root, backend, node.address()));
        put(node, APPLY, &agreed(&root, backend, answering));
    }
    wait_for(
        cohort.named(&leading),
        r#""event":"applied""#,
        1,
        "the configuration never went through consensus",
    );
    wait_for(
        cohort.named(&leading),
        r#""event":"ordering""#,
        1,
        "the leader never started an order",
    );

    // The order has been placed with the certificate authority once every node
    // is holding an answer for it: the URL is written before the answer is
    // (ADR-0086), so this is the point where there is something to take over.
    wait_while(
        "the order never reached the point of being taken over",
        || {
            NAMES.iter().all(|name| {
                let node = cluster.node(name).expect("the node is in the cluster");
                only_token(&answers(node)).is_some()
            })
        },
    );

    // The node driving the order disappears, exactly as a stopped machine
    // would. Its record stays in the state, because nothing closed it.
    stop_member(cluster.node(&leading).expect("the node is in the cluster"));

    // And the answer can now be reached, so whoever takes the order over can
    // finish it.
    let node = cluster.node(ANSWERING).expect("the node is in the cluster");
    let _plane = start_plane(node, &agent_binary, &product);

    let survivor = NAMES
        .iter()
        .find(|name| **name != leading && **name != ANSWERING)
        .map_or(ANSWERING, |name| *name);

    // Whichever of the two left leads now says it is taking the order over,
    // and says the certificate authority had already named it. A record with
    // no URL would be a fresh order wearing the same name.
    wait_while("no node ever took the order over", || {
        [survivor, ANSWERING].iter().any(|name| {
            cohort
                .named(name)
                .stdout()
                .contains(r#""event":"taking_over""#)
        })
    });
    let took_over = [survivor, ANSWERING]
        .iter()
        .find(|name| {
            cohort
                .named(name)
                .stdout()
                .contains(r#""event":"taking_over""#)
        })
        .map(|name| (*name).to_owned())
        .expect("one of the two took the order over");
    assert_ne!(
        took_over, leading,
        "the node that stopped is the one that reported taking the order over"
    );
    assert!(
        cohort
            .named(&took_over)
            .stdout()
            .contains(r#""event":"taking_over","certificate":"cert-cluster","placed":true"#),
        "the order was restarted rather than taken over, \
         so the allowance spent on the first one was wasted\n{}",
        cohort.named(&took_over).stdout()
    );

    wait_for(
        cohort.named(&took_over),
        r#""event":"ordered""#,
        1,
        "the order that was taken over never finished",
    );

    // The certificate lands on the nodes that are still running. The one that
    // stopped is not asked: a node that is down holds whatever it held.
    wait_while(
        "the taken over certificate never reached the running nodes",
        || {
            [survivor, ANSWERING].iter().all(|name| {
                holds_certificate(
                cluster.node(name).expect("the node is in the cluster"),
                &product,
            )
            })
        },
    );
}
