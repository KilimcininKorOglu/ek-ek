// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The PROXY header, read by a real SMTP server.
//!
//! Everything else about this feature is measured against bytes this project
//! wrote and this project reads back. That proves the two halves agree, and
//! nothing more. Here the reader is Postfix: it parses the header itself, and
//! the address it names on its connect line is the only reading of the header
//! that comes from outside the project (ADR-0043).
//!
//! The whole path runs: the real traffic path binary on node1, a real client
//! on node2, and the mail container as the backend.

// Test code may panic on a broken precondition. Product code may not.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::time::Duration;

use ek_ek_itest::{Background, Cluster, MAIL_PLAIN_PORT, MAIL_PROXIED_PORT, Node};

/// Port the frontend under test listens on.
const FRONTEND_PORT: u16 = 2525;

/// How long the traffic path gets to bind before a test gives up on it.
const STARTUP: Duration = Duration::from_secs(20);

/// How much of the mail log is read back. Large enough that a whole run fits,
/// so a mark taken early is still inside the window later.
const LOG_TAIL: usize = 2000;

/// A traffic path running on a node, with the agent that feeds it.
///
/// Both are held so neither is reaped while the test is still measuring, and
/// both are stopped from inside the container on the way out.
struct Serving<'a> {
    node: &'a Node,
    _agent: Background,
    _data_plane: Background,
}

impl Drop for Serving<'_> {
    fn drop(&mut self) {
        let _ = self.node.kill_matching("/var/lib/ek-ek/ek-ek");
    }
}

/// Starts the traffic path on a node, serving one raw TCP frontend.
fn serve<'a>(cluster: &Cluster, node: &'a Node, backend_port: u16, format: &str) -> Serving<'a> {
    let agent_binary = cluster
        .install_binary("ek-ek-itest", "ek-ek-standin-agent")
        .expect("the stand-in agent should build and install");
    let binary = cluster
        .install_binary("ek-ek", "ek-ek")
        .expect("the traffic path should build and install");

    let document = document(
        node,
        cluster.mail_address().to_string().as_str(),
        backend_port,
        format,
    );
    node.shell(&format!(
        "cat > /var/lib/ek-ek/config.json <<'DOCUMENT'\n{document}\nDOCUMENT"
    ))
    .expect("the configuration should be written");

    let socket = "/var/lib/ek-ek/agent.sock";
    let agent = node
        .spawn(&[
            &agent_binary,
            "--socket",
            socket,
            "--config",
            "/var/lib/ek-ek/config.json",
        ])
        .expect("the stand-in agent should start");
    agent
        .wait_for_stdout("listening on", STARTUP)
        .expect("the stand-in agent should say it is listening");

    let data_plane = node
        .spawn(&[&binary, "data-plane", "--agent-socket", socket])
        .expect("the traffic path should start");

    let serving = Serving {
        node,
        _agent: agent,
        _data_plane: data_plane,
    };
    wait_until_listening(node, FRONTEND_PORT);
    serving
}

/// Waits until something answers on the frontend port.
fn wait_until_listening(node: &Node, port: u16) {
    let start = std::time::Instant::now();
    loop {
        let probe = node
            .shell(&format!(
                "python3 -c \"import socket,sys; s=socket.create_connection(('{}',{port}),1); s.close()\"",
                node.address()
            ))
            .expect("the probe should run");
        if probe.ok() {
            return;
        }
        assert!(
            start.elapsed() <= STARTUP,
            "the traffic path never listened on {}:{port}",
            node.address()
        );
        std::thread::sleep(Duration::from_millis(300));
    }
}

/// How many lines the mail server has logged so far.
///
/// Sessions before this one, the readiness probe included, are what a naive
/// reading of the whole log would pick up: the probe is a real connection from
/// the proxy node and is logged as such.
fn mail_log_mark(cluster: &Cluster) -> usize {
    cluster
        .mail_log(LOG_TAIL)
        .expect("the mail log should be readable")
        .lines()
        .count()
}

/// Everything the mail server logged after a mark.
fn mail_log_since(cluster: &Cluster, mark: usize) -> String {
    cluster
        .mail_log(LOG_TAIL)
        .expect("the mail log should be readable")
        .lines()
        .skip(mark)
        .collect::<Vec<_>>()
        .join("\n")
}

/// One SMTP session, driven from a node, reported as everything it heard.
///
/// Whatever the server has already said is drained before each command is
/// sent. A server that ends the session off the header alone answers and hangs
/// up without waiting, and reading only after the next send would lose those
/// answers to the reset that the send provokes.
fn smtp_session(from: &Node, host: &str, port: u16) -> String {
    let script = format!(
        r"import socket
seen = []
try:
    s = socket.create_connection(('{host}', {port}), 10)
except Exception as error:
    print('CONNECT-FAILED: %s' % error)
    raise SystemExit(0)
s.settimeout(1.5)

def drain():
    while True:
        try:
            piece = s.recv(4096)
        except Exception:
            return
        if not piece:
            return
        seen.append(piece.decode('utf-8', 'replace'))

def say(line):
    try:
        s.sendall(line)
    except Exception as error:
        seen.append('SEND-FAILED: %s\n' % error)

drain()
say(b'EHLO probe.lab.test\r\n')
drain()
say(b'QUIT\r\n')
drain()
try:
    s.close()
except Exception:
    pass
print(''.join(seen))
"
    );
    from.shell(&format!(
        "cat > /tmp/smtp-session.py <<'SCRIPT'\n{script}\nSCRIPT\npython3 /tmp/smtp-session.py"
    ))
    .expect("the session should run")
    .stdout
}

/// The configuration document the traffic path is given.
fn document(node: &Node, backend_host: &str, backend_port: u16, format: &str) -> String {
    format!(
        r#"{{"schema_version":1,
"nodes":[{{"id":"node1","address":"{listen}","roles":["control_plane","data_plane"]}}],
"vips":[{{"id":"vip-smtp","address":"{listen}","prefix_length":24,"interface":"eth0","preferred_node":"node1"}}],
"frontends":[{{"id":"smtp","vip":"vip-smtp","port":{FRONTEND_PORT},"transport":"tcp","application":"raw","tls":null,"proxy_protocol":"{format}","routing_rules":[],"sni_rules":[],"default_backend":"mail","http2":"disabled","connect_timeout_seconds":5,"request_timeout_seconds":30,"idle_timeout_seconds":0,"drain_timeout_seconds":5,"udp_session_limit":0}}],
"backends":[{{"id":"mail","members":[{{"id":"mail1","address":"{backend_host}","port":{backend_port},"weight":1,"admin_state":"enabled"}}],"algorithm":"round_robin","health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"enabled"}}],
"certificates":[],
"dns_providers":[],
"stickiness_key":""}}"#,
        listen = node.address(),
    )
    .replace('\n', "")
}

#[test]
fn a_real_smtp_server_reads_the_client_address_out_of_a_v2_header() {
    let cluster = Cluster::start().expect("cluster should start");
    let proxy = cluster.node("node1").expect("node1 exists");
    let client = cluster.node("node2").expect("node2 exists");

    let _serving = serve(&cluster, proxy, MAIL_PROXIED_PORT, "v2");
    let mark = mail_log_mark(&cluster);
    let session = smtp_session(client, &proxy.address().to_string(), FRONTEND_PORT);

    assert!(
        session.contains("220 ") && session.contains("250-"),
        "the session did not complete through the proxy:\n{session}"
    );

    // Postfix parsed the header itself and named the client on its connect
    // line. That address is the measurement.
    let log = mail_log_since(&cluster, mark);
    let expected = format!("connect from unknown[{}]", client.address());
    assert!(
        log.contains(&expected),
        "the mail server did not see the real client; it logged:\n{log}"
    );
    assert!(
        !log.contains(&format!("connect from unknown[{}]", proxy.address())),
        "the mail server saw the load balancer instead of the client:\n{log}"
    );
}

#[test]
fn a_real_smtp_server_reads_the_client_address_out_of_a_v1_header() {
    // Both formats exist so an operator is not forced onto one (ADR-0043).
    // Producing v1 bytes nobody else accepts would make that choice useless.
    let cluster = Cluster::start().expect("cluster should start");
    let proxy = cluster.node("node1").expect("node1 exists");
    let client = cluster.node("node3").expect("node3 exists");

    let _serving = serve(&cluster, proxy, MAIL_PROXIED_PORT, "v1");
    let mark = mail_log_mark(&cluster);
    let session = smtp_session(client, &proxy.address().to_string(), FRONTEND_PORT);

    assert!(
        session.contains("250-"),
        "the session did not complete through the proxy:\n{session}"
    );

    let log = mail_log_since(&cluster, mark);
    assert!(
        log.contains(&format!("connect from unknown[{}]", client.address())),
        "the mail server did not see the real client; it logged:\n{log}"
    );
    assert!(
        !log.contains(&format!("connect from unknown[{}]", proxy.address())),
        "the mail server saw the load balancer instead of the client:\n{log}"
    );
}

#[test]
fn a_server_that_does_not_expect_a_v2_header_loses_the_session_to_it() {
    // Pinned because this is what an operator must be warned about, and the
    // shape of the failure decides what the warning has to say. The TCP
    // connection is established; what dies is the SMTP session, and it dies
    // before the client's first command reaches the server.
    let cluster = Cluster::start().expect("cluster should start");
    let proxy = cluster.node("node1").expect("node1 exists");
    let client = cluster.node("node2").expect("node2 exists");

    // Same server, same client, only the listener differs: this one was never
    // told to expect a header.
    let serving = serve(&cluster, proxy, MAIL_PLAIN_PORT, "v2");
    let refused = smtp_session(client, &proxy.address().to_string(), FRONTEND_PORT);
    drop(serving);

    assert!(
        refused.contains("500 "),
        "the server must reject the header it did not expect:\n{refused}"
    );
    assert!(
        !refused.contains("250-"),
        "the client's own command must never be answered:\n{refused}"
    );
    // The binary signature ends in the bytes `QUIT\n`, which this server reads
    // as a command of its own and acts on. The session is therefore over
    // before the client has said anything.
    assert!(
        refused.contains("221 "),
        "the server must have ended the session off the header alone:\n{refused}"
    );

    // The same pair works once the header is not sent, so the failure above is
    // the header rather than a broken backend.
    let _serving = serve(&cluster, proxy, MAIL_PLAIN_PORT, "disabled");
    let accepted = smtp_session(client, &proxy.address().to_string(), FRONTEND_PORT);
    assert!(
        accepted.contains("250-"),
        "the same backend must serve a session with no header in front of it:\n{accepted}"
    );
}

#[test]
fn a_server_that_does_not_expect_a_v1_header_answers_it_with_an_error() {
    // The other half of the warning. A text header is one bad command rather
    // than a session ender, so the session survives it, every client sees a
    // 500 it did not ask for, and the address the server logs is the load
    // balancer's. Silent wrongness, which is worse to diagnose than a break.
    let cluster = Cluster::start().expect("cluster should start");
    let proxy = cluster.node("node1").expect("node1 exists");
    let client = cluster.node("node2").expect("node2 exists");

    let _serving = serve(&cluster, proxy, MAIL_PLAIN_PORT, "v1");
    let mark = mail_log_mark(&cluster);
    let session = smtp_session(client, &proxy.address().to_string(), FRONTEND_PORT);

    assert!(
        session.contains("500 "),
        "the server must reject the header it did not expect:\n{session}"
    );
    assert!(
        session.contains("250-"),
        "the session survives a text header, unlike a binary one:\n{session}"
    );

    let log = mail_log_since(&cluster, mark);
    assert!(
        log.contains(&format!("connect from unknown[{}]", proxy.address())),
        "an unconfigured server still sees the load balancer; it logged:\n{log}"
    );
    assert!(
        !log.contains(&format!("connect from unknown[{}]", client.address())),
        "the address the header states counts for nothing here; it logged:\n{log}"
    );
}
