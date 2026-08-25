// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Supervising the traffic path, measured on real processes.
//!
//! `node-agent` starts `data-plane`, watches it and gives this node's virtual
//! address up the moment it stops serving (ADR-0033). Nothing here is
//! simulated: the processes are the shipped ones, the address moves over
//! netlink, and which node answered is read off the payload a real backend
//! returns rather than off anything the product said about itself.
//!
//! # Why two nodes point at different backends
//!
//! Both nodes proxy the same virtual address, so a request that succeeds says
//! nothing about which one answered it. Pointing each node at its own backend
//! makes the answer name the node: `backend1` means node1 served it and
//! `backend2` means node2 did.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use ek_ek_itest::{Background, Cluster, Node};

/// The configuration the agent delivers to the traffic path.
const SERVING: &str = "/var/lib/ek-ek/supervise-serving.json";
/// The socket the traffic path takes its configuration from.
const SOCKET: &str = "/var/lib/ek-ek/supervise-agent.sock";
/// A stand-in traffic path a measurement can make crash on purpose.
const CRASHER: &str = "/var/lib/ek-ek/supervise-crasher.sh";
/// Where the crasher counts its own starts.
const STARTS: &str = "/var/lib/ek-ek/supervise-starts";
/// A wrapper the agent starts instead of the traffic path directly.
///
/// It `exec`s the shipped binary, so the process the agent supervises is the
/// real one under the real process id. Rewriting the file decides whether the
/// next start succeeds, which is what lets a measurement hold the traffic
/// path down for as long as it needs rather than race the restart.
const WRAPPER: &str = "/var/lib/ek-ek/supervise-data-plane.sh";

/// Port the HTTP frontend listens on.
const HTTP_PORT: u16 = 8081;
/// The prefix length the lab network uses.
const PREFIX: u8 = 24;
/// The virtual router number these measurements use.
const VRID: u8 = 71;

/// How long anything in the lab is given to reach a state.
const PATIENCE: Duration = Duration::from_secs(30);

/// What ADR-0033 promises: the claim comes down inside a second.
const WITHIN: Duration = Duration::from_secs(1);

/// Clears everything an earlier measurement left on a node.
fn clean(node: &Node) {
    node.kill_matching("/var/lib/ek-ek/ek-ek").ok();
    node.kill_matching("supervise-crasher").ok();
    node.shell(&format!(
        "rm -rf {SERVING} {SOCKET} {CRASHER} {STARTS} {WRAPPER}"
    ))
    .expect("the node should be cleanable");
}

/// Writes a file inside a node.
fn put(node: &Node, path: &str, content: &str) {
    node.shell(&format!("cat > {path} <<'CONTENT'\n{content}\nCONTENT"))
        .expect("the file should be writable");
}

/// The document one node's traffic path serves.
fn serving(vip: Ipv4Addr, backend: Ipv4Addr) -> String {
    one_line(&format!(
        r#"{{
  "schema_version": 1,
  "nodes": [{{"id":"node1","address":"172.28.0.11","roles":["control_plane","data_plane"]}}],
  "vips": [{{"id":"vip-supervise","address":"{vip}","prefix_length":{PREFIX},"interface":"eth0","preferred_node":"node1"}}],
  "frontends": [{{
    "id": "web",
    "vip": "vip-supervise",
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
  "certificates": [],
  "dns_providers": [],
  "acme": null
}}"#
    ))
}

/// A wrapper that starts the shipped traffic path.
///
/// `exec` rather than a plain call, so the process the agent supervises is the
/// traffic path itself under the process id the agent recorded.
fn starts(product: &str) -> String {
    format!("#!/bin/sh\nexec {product} \"$@\"\n")
}

/// The same document on one line.
fn one_line(document: &str) -> String {
    document.lines().map(str::trim).collect::<String>()
}

/// Starts `node-agent` on one node, with a virtual router.
fn start_agent(
    node: &Node,
    product: &str,
    traffic_path: &str,
    priority: u8,
    peers: &[Ipv4Addr],
    vip: Ipv4Addr,
) -> Background {
    let mut argv: Vec<String> = vec![
        product.to_owned(),
        "node-agent".to_owned(),
        "--socket".to_owned(),
        SOCKET.to_owned(),
        "--config".to_owned(),
        SERVING.to_owned(),
        "--data-plane".to_owned(),
        traffic_path.to_owned(),
        "--address".to_owned(),
        node.address().to_string(),
        "--interface".to_owned(),
        "eth0".to_owned(),
        "--virtual-address".to_owned(),
        format!("{vip}/{PREFIX}"),
        "--vrid".to_owned(),
        VRID.to_string(),
        "--priority".to_owned(),
        priority.to_string(),
        // Short, so a measurement waits on the product rather than on a
        // timer this task chose for production.
        "--asking-ms".to_owned(),
        "200".to_owned(),
        "--patience".to_owned(),
        "3".to_owned(),
    ];
    for peer in peers {
        argv.push("--peer".to_owned());
        argv.push(peer.to_string());
    }

    let borrowed: Vec<&str> = argv.iter().map(String::as_str).collect();
    let agent = node
        .spawn(&borrowed)
        .unwrap_or_else(|error| panic!("{} must start its agent: {error}", node.name()));
    agent
        .wait_for_stdout(r#""event":"listening""#, PATIENCE)
        .unwrap_or_else(|error| panic!("{} never opened its socket: {error}", node.name()));
    agent
}

/// Starts `node-agent` with a stand-in traffic path and no virtual router.
///
/// The stand-in is a shell script, so a measurement decides exactly when it
/// crashes. Everything about the supervision is the same: the process is
/// started, watched and restarted by the shipped code.
fn start_agent_over(node: &Node, product: &str, script: &str) -> Background {
    put(node, CRASHER, script);
    node.run_ok(&["chmod", "+x", CRASHER])
        .expect("the stand-in should be runnable");

    let agent = node
        .spawn(&[
            product,
            "node-agent",
            "--socket",
            SOCKET,
            "--config",
            SERVING,
            "--data-plane",
            CRASHER,
            "--asking-ms",
            "200",
            "--patience",
            "3",
        ])
        .expect("the agent must start");
    agent
        .wait_for_stdout(r#""event":"listening""#, PATIENCE)
        .expect("the agent never opened its socket");
    agent
}

/// Waits until a record has appeared at least this many times.
fn wait_for(background: &Background, needle: &str, at_least: usize, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    while Instant::now() < deadline {
        if background.stdout().matches(needle).count() >= at_least {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "{what}: {needle} appeared {} time(s), not {at_least}\n{}",
        background.stdout().matches(needle).count(),
        background.stdout()
    );
}

/// Waits until the predicate holds, or gives up.
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

/// The `ts` field of the first record matching a needle.
fn stamp(written: &str, needle: &str) -> Option<u128> {
    let line = written.lines().find(|line| line.contains(needle))?;
    let rest = line.split(r#""ts":"#).nth(1)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

/// Every `ts` of the records matching a needle, in order.
fn stamps(written: &str, needle: &str) -> Vec<u128> {
    written
        .lines()
        .filter(|line| line.contains(needle))
        .filter_map(|line| {
            let rest = line.split(r#""ts":"#).nth(1)?;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

/// Which process ids the traffic path has run under, in order.
fn started_pids(written: &str) -> Vec<u32> {
    written
        .lines()
        .filter(|line| line.contains(r#""event":"data_plane_started""#))
        .filter_map(|line| {
            let rest = line.split(r#""pid":"#).nth(1)?;
            let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
            digits.parse().ok()
        })
        .collect()
}

/// Whether a process with this identifier is still in the table.
fn alive(node: &Node, pid: u32) -> bool {
    node.shell(&format!("kill -0 {pid} 2>/dev/null && echo yes || echo no"))
        .map(|out| out.stdout.trim() == "yes")
        .unwrap_or(false)
}

/// Asks the virtual address for a page and says which backend answered.
fn ask(node: &Node, vip: Ipv4Addr) -> String {
    node.run(&[
        "curl",
        "-s",
        "--max-time",
        "5",
        &format!("http://{vip}:{HTTP_PORT}/"),
    ])
    .map(|out| out.stdout.trim().to_owned())
    .unwrap_or_default()
}

/// Waits until the virtual address is answered by this backend.
///
/// It names what did answer when it gives up. "The traffic never followed"
/// says nothing about whether the other node answered, whether the old one
/// still did, or whether nothing answered at all, and those are three
/// different defects.
fn wait_for_answer(from: &Node, holders: &[&Node], vip: Ipv4Addr, backend: &str, what: &str) {
    let deadline = Instant::now() + PATIENCE;
    let mut answer = String::new();
    while Instant::now() < deadline {
        answer = ask(from, vip);
        if answer == backend {
            return;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let holding: Vec<&str> = holders
        .iter()
        .filter(|node| node.has_address(vip).unwrap_or(false))
        .map(|node| node.name())
        .collect();
    panic!(
        "{what}: {vip} answered {answer:?} rather than {backend:?}, and the \
         address is on {holding:?}"
    );
}

#[test]
fn the_agent_starts_the_traffic_path_and_gives_the_address_up_when_it_dies() {
    let cluster = Cluster::start().expect("cluster should start");
    cluster.reset().expect("the cluster should start clean");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");

    let node1 = cluster.node("node1").expect("node1 is in the cluster");
    let node2 = cluster.node("node2").expect("node2 is in the cluster");
    let node3 = cluster.node("node3").expect("node3 is in the cluster");
    clean(node1);
    clean(node2);
    clean(node3);

    let vip = cluster.vip(7).expect("vip 7 is inside the reserved range");
    let first = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    let second = cluster
        .backend_address("backend2")
        .expect("backend2 is in the cluster");

    // Each node's traffic path points at its own backend, so what answers the
    // virtual address names the node that answered.
    put(node1, SERVING, &serving(vip, first));
    put(node2, SERVING, &serving(vip, second));

    // node1 starts the shipped traffic path through a wrapper this
    // measurement rewrites; node2 starts it directly.
    put(node1, WRAPPER, &starts(&product));
    node1
        .run_ok(&["chmod", "+x", WRAPPER])
        .expect("the wrapper should be runnable");

    let stronger = start_agent(node1, &product, WRAPPER, 200, &[node2.address()], vip);
    let weaker = start_agent(node2, &product, &product, 100, &[node1.address()], vip);

    // The agent started the traffic path, and the traffic path answered.
    wait_for(
        &stronger,
        r#""event":"data_plane_started""#,
        1,
        "node1's agent never started a traffic path",
    );
    wait_for(
        &stronger,
        r#""standing":"serving""#,
        1,
        "node1's traffic path never answered the agent",
    );
    wait_while("node1 never took the virtual address", || {
        node1.has_address(vip).unwrap_or(false)
    });
    wait_for_answer(
        node3,
        &[node1, node2],
        vip,
        "backend1",
        "the stronger node never answered at the address",
    );

    // Now take the traffic path away, and hold it away. The agent restarts it
    // within a tenth of a second, which is short enough that a measurement
    // reading the network afterwards would be racing the restart rather than
    // measuring the failover. The wrapper is rewritten first, so every restart
    // until it is put back fails immediately.
    put(node1, WRAPPER, "#!/bin/sh\nexit 1\n");

    // Nothing else about the node changes: it is still on the network, still
    // answering its peer, and nothing the protocol can see says it cannot
    // serve (ADR-0033).
    let pid = *started_pids(&stronger.stdout())
        .first()
        .expect("the traffic path has a process id");
    node1
        .run_ok(&["kill", "-9", &pid.to_string()])
        .expect("the traffic path should be killable");
    let killed_at = Instant::now();

    wait_for(
        &stronger,
        r#""event":"claim_lowered""#,
        1,
        "node1 kept its claim after its traffic path was killed",
    );
    let noticed = killed_at.elapsed();
    assert!(
        noticed < WITHIN,
        "the claim came down {noticed:?} after the traffic path died, and \
         ADR-0033 asks for it inside {WITHIN:?}"
    );

    // The address moves, and the traffic follows it. What says so is the
    // payload: backend2 is only reachable through node2's traffic path.
    wait_while("the address never reached node2", || {
        node2.has_address(vip).unwrap_or(false)
    });
    wait_for_answer(
        node3,
        &[node1, node2],
        vip,
        "backend2",
        "the traffic never followed the address to node2",
    );

    // The claim stays down for as long as the traffic path cannot serve, and
    // the agent keeps trying: it restarted a process that failed at once.
    wait_for(
        &stronger,
        r#""event":"data_plane_started""#,
        2,
        "node1's agent never restarted the traffic path",
    );
    assert!(
        !stronger.stdout().contains(r#""event":"claim_restored""#),
        "node1 put its claim back while its traffic path could not even \
         start:\n{}",
        stronger.stdout()
    );

    // And the claim goes back up once the traffic path answers again, without
    // anything asking the agent to try: it is still restarting on its own.
    put(node1, WRAPPER, &starts(&product));
    wait_for(
        &stronger,
        r#""event":"claim_restored""#,
        1,
        "node1 never put its claim back after the traffic path came back",
    );
    wait_while("node1 never took the address back", || {
        node1.has_address(vip).unwrap_or(false)
    });
    wait_for_answer(
        node3,
        &[node1, node2],
        vip,
        "backend1",
        "the traffic never came back to node1",
    );

    // The restart is a different process, not the one that was killed.
    let pids = started_pids(&stronger.stdout());
    assert_ne!(
        pids[0], pids[1],
        "the agent reported a restart with the process id of the one that died"
    );
    assert!(!alive(node1, pids[0]), "the killed process is still there");

    drop(weaker);
    drop(stronger);
    clean(node1);
    clean(node2);
}

#[test]
fn a_traffic_path_that_keeps_crashing_is_restarted_for_ever_and_raises_an_alarm() {
    let cluster = Cluster::start().expect("cluster should start");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let node = cluster.node("node3").expect("node3 is in the cluster");
    clean(node);

    let vip = cluster.vip(8).expect("vip 8 is inside the reserved range");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    put(node, SERVING, &serving(vip, backend));

    // Crashes at once, every time, and counts its own starts so the restarts
    // are read from something the product did not write.
    let agent = start_agent_over(
        node,
        &product,
        &format!("#!/bin/sh\necho x >> {STARTS}\nexit 1\n"),
    );

    wait_for(
        &agent,
        r#""event":"crash_loop""#,
        1,
        "a traffic path that never starts raised no alarm",
    );
    assert!(
        agent.stdout().contains(r#""alarming":true"#),
        "the alarm was said once and never held, so a reader that connected \
         afterwards could not learn it was still on:\n{}",
        agent.stdout()
    );

    // Past the alarm on purpose. What ADR-0033 asks for is that the restarts
    // carry on regardless, so the measurement has to see restarts the alarm
    // did not stop.
    wait_for(
        &agent,
        r#""event":"data_plane_started""#,
        7,
        "the agent stopped restarting a traffic path that keeps crashing",
    );

    // The waits grow. Read as differences between the restarts the agent
    // recorded, so what is measured is when it actually started them.
    let written = agent.stdout();
    let started = stamps(&written, r#""event":"data_plane_started""#);
    let gaps: Vec<u128> = started.windows(2).map(|two| two[1] - two[0]).collect();
    assert!(
        gaps.len() >= 5,
        "not enough restarts to see the waits grow: {started:?}"
    );
    assert!(
        gaps.last().expect("there is a gap") > gaps.first().expect("there is a gap"),
        "the waits between restarts never grew: {gaps:?}"
    );
    // Growing, not merely different. A wait that jumped once and then stayed
    // put would pass a comparison of the two ends.
    assert!(
        gaps[gaps.len() - 1] > gaps[gaps.len() - 2],
        "the waits stopped growing before the cap: {gaps:?}"
    );

    // And the process really is being started again, counted by the process
    // itself rather than by the records the agent wrote about it.
    let counted = node
        .shell(&format!("wc -l < {STARTS} 2>/dev/null || echo 0"))
        .expect("the count should be readable")
        .stdout
        .trim()
        .parse::<usize>()
        .unwrap_or(0);
    assert!(
        counted >= started.len(),
        "the agent recorded {} starts and the process counted {counted}",
        started.len()
    );

    drop(agent);
    clean(node);
}

#[test]
fn a_traffic_path_that_stops_answering_is_treated_as_one_that_crashed() {
    let cluster = Cluster::start().expect("cluster should start");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let node = cluster.node("node3").expect("node3 is in the cluster");
    clean(node);

    let vip = cluster.vip(8).expect("vip 8 is inside the reserved range");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    put(node, SERVING, &serving(vip, backend));

    // Connects, greets, and then says nothing at all. The process is in the
    // table and its socket is open, so nothing short of asking it a question
    // can tell it from one that is serving (ADR-0087).
    let agent = start_agent_over(
        node,
        &product,
        &format!(
            "#!/bin/sh\n\
             echo x >> {STARTS}\n\
             python3 -c \"\n\
             import socket,time\n\
             s=socket.socket(socket.AF_UNIX)\n\
             s.connect('{SOCKET}')\n\
             s.sendall(b'{{\\\"message\\\":\\\"hello\\\",\\\"pid\\\":1,\\\"version\\\":\\\"x\\\",\\\"generation\\\":null}}\\n')\n\
             time.sleep(600)\n\
             \"\n"
        ),
    );

    wait_for(
        &agent,
        r#""event":"greeted""#,
        1,
        "the stand-in never introduced itself, so it was never up to be silent",
    );
    wait_for(
        &agent,
        r#""event":"data_plane_silent""#,
        1,
        "a process that answered nothing was left running",
    );
    wait_for(
        &agent,
        r#""event":"data_plane_started""#,
        2,
        "a process that stopped answering was not restarted",
    );

    // The same path as a crash: the claim comes down and a restart follows.
    let written = agent.stdout();
    assert!(
        written.contains(r#""event":"claim_lowered""#),
        "a process that stopped answering kept this node's claim:\n{written}"
    );
    let silent = stamp(&written, r#""event":"data_plane_silent""#)
        .expect("the moment it was noticed is recorded");
    let lowered = stamp(&written, r#""event":"claim_lowered""#)
        .expect("the moment the claim came down is recorded");
    assert!(
        lowered >= silent && lowered - silent < WITHIN.as_millis() * 2,
        "the claim came down {}ms after the process was found silent",
        lowered.saturating_sub(silent)
    );

    drop(agent);
    clean(node);
}

#[test]
fn an_agent_that_goes_takes_the_traffic_path_with_it() {
    let cluster = Cluster::start().expect("cluster should start");
    let product = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let node = cluster.node("node3").expect("node3 is in the cluster");
    clean(node);

    let vip = cluster.vip(8).expect("vip 8 is inside the reserved range");
    let backend = cluster
        .backend_address("backend1")
        .expect("backend1 is in the cluster");
    put(node, SERVING, &serving(vip, backend));

    // Asked to stop first. The traffic path must end with it, or a node keeps
    // listeners nobody supervises.
    let agent = start_agent_over(
        node,
        &product,
        &format!("#!/bin/sh\necho x >> {STARTS}\nexec sleep 600\n"),
    );
    wait_for(
        &agent,
        r#""event":"data_plane_started""#,
        1,
        "the agent never started a traffic path",
    );
    let asked_pid = *started_pids(&agent.stdout())
        .first()
        .expect("the traffic path has a process id");

    // Asked, not killed. SIGTERM is what an operator sends and what systemd
    // sends, and the difference is this half's whole point: the agent is
    // still running and gets to stop its traffic path itself. The bracket
    // keeps the pattern from matching the shell that carries it.
    node.shell("pkill -f '[e]k-ek node-agent'")
        .expect("the agent should be stoppable");
    wait_while(
        "the traffic path outlived an agent that was asked to stop",
        || !alive(node, asked_pid),
    );
    // The agent stopped it, rather than leaving the kernel to do it. Both end
    // the process, but only one of them waits for it to go and escalates to a
    // kill when it will not, and a stop that does not wait leaves the next
    // process starting while the last one still holds the sockets (ADR-0087).
    wait_for(
        &agent,
        r#""event":"data_plane_stopped""#,
        1,
        "the agent left without stopping its traffic path, so what ended it \
         was the kernel rather than the supervision",
    );
    drop(agent);

    // And killed outright, which is the case nothing in userspace can handle:
    // the agent is not running any more, so only the kernel can end the child
    // (ADR-0087).
    let agent = start_agent_over(
        node,
        &product,
        &format!("#!/bin/sh\necho x >> {STARTS}\nexec sleep 600\n"),
    );
    wait_for(
        &agent,
        r#""event":"data_plane_started""#,
        1,
        "the agent never started a traffic path",
    );
    let killed_pid = *started_pids(&agent.stdout())
        .first()
        .expect("the traffic path has a process id");
    assert!(alive(node, killed_pid), "the traffic path is not running");

    node.shell("pkill -9 -f '[e]k-ek node-agent'")
        .expect("the agent should be killable");
    wait_while("the traffic path outlived an agent that was killed", || {
        !alive(node, killed_pid)
    });

    drop(agent);
    clean(node);
}

#[test]
fn the_supervision_runs_under_systemd_as_a_user_with_no_privileges_of_its_own() {
    // The one question the rest of the lab cannot answer. Everywhere else the
    // processes run as root, because Docker grants added capabilities to root
    // only (ADR-0012). Here systemd is PID 1, the unit names a non-root user,
    // and the capability is granted ambiently the way a real installation
    // grants it.
    let cluster = Cluster::start().expect("cluster should start");
    let product = cluster
        .install_binary_for_systemd("ek-ek", "ek-ek")
        .expect("the product binary should build");
    let host = cluster.systemd();

    host.run_ok(&["systemctl", "is-system-running", "--wait"])
        .ok();
    let running = host
        .run(&["systemctl", "is-system-running"])
        .expect("systemd should answer");
    assert!(
        running.stdout.trim() == "running" || running.stdout.trim() == "degraded",
        "systemd is not up in the container: {}",
        running.stdout
    );

    let serving_document = serving(
        cluster.vip(9).expect("vip 9 is inside the reserved range"),
        cluster
            .backend_address("backend1")
            .expect("backend1 is in the cluster"),
    );
    host.shell("mkdir -p /var/lib/ek-ek && chown ek-ek:ek-ek /var/lib/ek-ek")
        .expect("the service directory should be creatable");
    put(&host, "/var/lib/ek-ek/serving.json", &serving_document);
    host.run_ok(&["chown", "ek-ek:ek-ek", "/var/lib/ek-ek/serving.json"])
        .expect("the document should be readable by the service user");

    // The unit as an installation would have it: a non-root user, and the one
    // capability the traffic path needs granted ambiently rather than
    // inherited from root.
    put(
        &host,
        "/etc/systemd/system/ek-ek-node-agent.service",
        &format!(
            "[Unit]\n\
             Description=ek-ek node agent\n\n\
             [Service]\n\
             Type=simple\n\
             User=ek-ek\n\
             Group=ek-ek\n\
             AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n\
             CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE\n\
             NoNewPrivileges=yes\n\
             RuntimeDirectory=ek-ek\n\
             ExecStart={product} node-agent --socket /run/ek-ek/agent.sock \
             --config /var/lib/ek-ek/serving.json --asking-ms 200\n\
             Restart=no\n\n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        ),
    );
    host.run_ok(&["systemctl", "daemon-reload"])
        .expect("the unit should be readable");
    // Whatever an earlier run left. Without this the unit could already be up
    // and `start` would be a no-op on a process started with another binary.
    host.run(&["systemctl", "stop", "ek-ek-node-agent.service"])
        .ok();
    host.run_ok(&["systemctl", "start", "ek-ek-node-agent.service"])
        .expect("the unit should start");

    // Running, and running as the service user rather than as root.
    let deadline = Instant::now() + PATIENCE;
    let mut active = String::new();
    while Instant::now() < deadline {
        active = host
            .run(&["systemctl", "is-active", "ek-ek-node-agent.service"])
            .expect("systemd should answer")
            .stdout
            .trim()
            .to_owned();
        if active == "active" {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let journal = host
        .run(&["journalctl", "-u", "ek-ek-node-agent.service", "--no-pager"])
        .map(|out| out.stdout)
        .unwrap_or_default();
    assert_eq!(active, "active", "the unit did not stay up:\n{journal}");

    let main_pid = host
        .shell("systemctl show -p MainPID --value ek-ek-node-agent.service")
        .expect("systemd should answer")
        .stdout
        .trim()
        .to_owned();
    let owner = host
        .shell(&format!("ps -o user= -p {main_pid}"))
        .expect("the process should be listed")
        .stdout
        .trim()
        .to_owned();
    assert_eq!(
        owner, "ek-ek",
        "the agent runs as {owner} rather than as the service user, so nothing \
         here measured a non-root installation"
    );

    // And the capability is actually there, granted ambiently rather than
    // inherited: a non-root process with an empty ambient set could not move
    // an address, and the whole unit would be untested.
    let ambient = host
        .shell(&format!(
            "grep -E '^CapAmb|^CapEff' /proc/{main_pid}/status | tr -s ' ' | tr '\\n' ' '"
        ))
        .expect("the process should have a status file")
        .stdout;
    let effective = ambient
        .split_whitespace()
        .skip_while(|word| *word != "CapEff:")
        .nth(1)
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .expect("the effective set is readable");
    // CAP_NET_ADMIN is bit 12, CAP_NET_RAW is bit 13.
    assert!(
        effective & (1 << 12) != 0,
        "the service user has no CAP_NET_ADMIN, so it could not move a virtual \
         address: {ambient}"
    );
    assert!(
        effective & (1 << 13) != 0,
        "the service user has no CAP_NET_RAW, so it could not send an \
         advertisement: {ambient}"
    );

    // The supervision itself works here too: the traffic path is started, and
    // stopping the unit takes it away rather than leaving it behind.
    assert!(
        journal.contains(r#""event":"data_plane_started""#)
            || host
                .run(&["journalctl", "-u", "ek-ek-node-agent.service", "--no-pager"])
                .map(|out| out.stdout.contains(r#""event":"data_plane_started""#))
                .unwrap_or(false),
        "the unit came up and never started a traffic path:\n{journal}"
    );

    // Read by process id rather than by matching a command line. A pattern
    // wide enough to find the traffic path also finds the shell that was
    // given the pattern, so the count would never reach zero.
    let started = started_pids(
        &host
            .run(&["journalctl", "-u", "ek-ek-node-agent.service", "--no-pager"])
            .map(|out| out.stdout)
            .unwrap_or_default(),
    );
    // The last one, not the first. The journal outlives a run of this
    // measurement, so the first record can name a process from a previous one
    // that has long since gone.
    let running = *started
        .last()
        .expect("the unit recorded which process it started");
    assert!(
        alive(&host, running),
        "the traffic path the unit started is not there to be stopped"
    );

    host.run_ok(&["systemctl", "stop", "ek-ek-node-agent.service"])
        .expect("the unit should stop");
    wait_while(
        "stopping the unit left a traffic path behind with nobody supervising it",
        || !alive(&host, running),
    );

    host.run_ok(&["systemctl", "disable", "--now", "ek-ek-node-agent.service"])
        .ok();
}
