// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a configuration change must not do to traffic already in flight.
//!
//! The other data plane rules are measured against the link on its own. This
//! one cannot be: it is about sockets a client is holding open, so it needs
//! the real binary, a real pingora server and connections that stay up across
//! the change (ADR-0009).
//!
//! The agent here is a stand-in that speaks the line protocol directly and
//! builds its configuration as text. Nothing in this file uses the crates the
//! binary is built from, so a change that quietly alters the wire format or
//! the configuration document is a failure here rather than a rename that
//! compiles.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpStream, UnixListener};
use tokio::sync::broadcast;

/// How long a worker keeps asking before giving up on seeing the last change.
const PATIENCE: Duration = Duration::from_secs(20);

/// How many connections hold traffic open across the change.
const WORKERS: usize = 4;

/// A configuration document, written as text rather than built from the
/// crate's own types.
fn config_document(port: u16, members: u16) -> String {
    let members: Vec<String> = (1..=members)
        .map(|number| {
            format!(
                r#"{{"id":"web-{number}","address":"127.0.0.{number}","port":{member_port},"weight":1,"admin_state":"enabled"}}"#,
                member_port = 9000 + number
            )
        })
        .collect();

    format!(
        r#"{{"schema_version":1,
"nodes":[{{"id":"node1","address":"127.0.0.1","roles":["control_plane","data_plane"]}}],
"vips":[{{"id":"vip-web","address":"127.0.0.1","prefix_length":8,"interface":"lo","preferred_node":"node1"}}],
"frontends":[{{"id":"web","vip":"vip-web","port":{port},"transport":"tcp","application":"http","tls":null,"proxy_protocol":"disabled","routing_rules":[],"sni_rules":[],"default_backend":"web","drain_timeout_seconds":5}}],
"backends":[{{"id":"web","members":[{members}],"algorithm":"round_robin","health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"enabled"}}],
"certificates":[],
"dns_providers":[]}}"#,
        members = members.join(",")
    )
    .replace('\n', "")
}

/// One delivery, as the agent puts it on the wire.
fn delivery(generation: u64, port: u16, members: u16) -> String {
    format!(
        r#"{{"message":"config","generation":{generation},"config":{}}}"#,
        config_document(port, members)
    ) + "\n"
}

/// A stand-in `node-agent`: it greets with one delivery and can push more.
struct Agent {
    pushes: broadcast::Sender<String>,
    /// Set once the long lived link is connected. The short connection that
    /// collects the first configuration is not it, and pushing to that one
    /// would push to a socket about to close.
    linked: Arc<AtomicBool>,
    accept: tokio::task::JoinHandle<()>,
}

impl Agent {
    async fn start(socket: &Path, greeting: String) -> Self {
        let listener = UnixListener::bind(socket).expect("the socket must bind");
        let (pushes, _) = broadcast::channel::<String>(16);
        let sender = pushes.clone();
        let linked = Arc::new(AtomicBool::new(false));
        let connected = Arc::clone(&linked);

        let accept = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let greeting = greeting.clone();
                let mut pushed = sender.subscribe();
                let connected = Arc::clone(&connected);

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();

                    // The traffic path greets first and says what it already
                    // holds. Only a connection holding nothing needs the
                    // configuration sent to it.
                    let Ok(Some(hello)) = lines.next_line().await else {
                        return;
                    };
                    if hello.contains(r#""generation":null"#) {
                        if writer.write_all(greeting.as_bytes()).await.is_err() {
                            return;
                        }
                    } else {
                        connected.store(true, Ordering::SeqCst);
                    }

                    loop {
                        tokio::select! {
                            line = lines.next_line() => {
                                if !matches!(line, Ok(Some(_))) {
                                    return;
                                }
                            }
                            push = pushed.recv() => {
                                let Ok(push) = push else { return };
                                if writer.write_all(push.as_bytes()).await.is_err() {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        Self {
            pushes,
            linked,
            accept,
        }
    }

    /// Waits until the traffic path's own link is connected, so a push is not
    /// sent to nobody.
    async fn wait_linked(&self) {
        for _ in 0..400 {
            if self.linked.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the traffic path never opened its link to the agent");
    }

    fn push(&self, delivery: &str) {
        assert!(
            self.pushes.send(delivery.to_owned()).is_ok(),
            "the traffic path must be connected, or the push measures nothing"
        );
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// The running binary, stopped when the test ends however it ends.
struct DataPlane(Child);

impl DataPlane {
    fn start(socket: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_ek-ek"))
            .arg("data-plane")
            .arg("--agent-socket")
            .arg(socket)
            .spawn()
            .expect("the binary under test must start");
        Self(child)
    }
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A port nothing is listening on, released before the binary takes it.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port must be free");
    let port = listener
        .local_addr()
        .expect("the listener must have an address")
        .port();
    drop(listener);
    port
}

/// Connects once the binary is listening.
async fn connect(port: u16) -> TcpStream {
    for _ in 0..400 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("the traffic path never started listening on port {port}");
}

/// Sends one request on a connection that is already open and returns the
/// generation that answered it.
async fn ask(io: &mut BufReader<TcpStream>) -> std::io::Result<u64> {
    io.get_mut()
        .write_all(b"GET / HTTP/1.1\r\nHost: ek-ek.test\r\n\r\n")
        .await?;

    let mut length: Option<usize> = None;
    loop {
        let mut line = String::new();
        if io.read_line(&mut line).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the connection was closed while the answer was being read",
            ));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some(value) = line
            .to_ascii_lowercase()
            .strip_prefix("content-length:")
            .map(str::trim)
            .and_then(|value| value.parse::<usize>().ok())
        {
            length = Some(value);
        }
    }

    let length = length.ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the answer carried no length, so the connection cannot be reused",
        )
    })?;
    let mut body = vec![0_u8; length];
    io.read_exact(&mut body).await?;
    let body = String::from_utf8_lossy(&body).into_owned();

    body.lines()
        .find_map(|line| line.strip_prefix("generation="))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the answer did not say which generation served it: {body:?}"),
            )
        })
}

/// What one connection saw over its lifetime.
struct Seen {
    address: SocketAddr,
    requests: usize,
    generations: BTreeSet<u64>,
    failure: Option<String>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_change_does_not_cut_connections_that_are_already_open() {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    let socket: PathBuf = directory.path().join("agent.sock");
    let port = free_port();

    let agent = Agent::start(&socket, delivery(1, port, 1)).await;
    let _data_plane = DataPlane::start(&socket);

    // Every worker holds one connection open for the whole test and never
    // opens a second one. A cut connection therefore shows up as a failure
    // rather than as a reconnection nobody notices.
    let mut workers = Vec::new();
    for _ in 0..WORKERS {
        let stream = connect(port).await;
        let address = stream
            .local_addr()
            .expect("an open connection must have an address");

        workers.push(tokio::spawn(async move {
            let mut io = BufReader::new(stream);
            let mut seen = Seen {
                address,
                requests: 0,
                generations: BTreeSet::new(),
                failure: None,
            };
            let start = tokio::time::Instant::now();

            loop {
                match ask(&mut io).await {
                    Ok(generation) => {
                        seen.requests += 1;
                        seen.generations.insert(generation);
                        // Stop on the last change, so the test is not paced by
                        // a fixed sleep.
                        if generation >= 3 {
                            break;
                        }
                    }
                    Err(error) => {
                        seen.failure = Some(format!("after {} requests: {error}", seen.requests));
                        break;
                    }
                }
                if start.elapsed() > PATIENCE {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(2)).await;
            }

            // Reading the address again from the same socket: a closed
            // connection cannot answer this.
            let still_open = io
                .get_ref()
                .local_addr()
                .map(|later| later == seen.address)
                .unwrap_or(false);
            (seen, still_open)
        }));
    }

    // Traffic is flowing. Change the configuration underneath it, twice.
    agent.wait_linked().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    agent.push(&delivery(2, port, 3));
    tokio::time::sleep(Duration::from_millis(200)).await;
    agent.push(&delivery(3, port, 2));

    for (number, worker) in workers.into_iter().enumerate() {
        let (seen, still_open) = worker.await.expect("a worker must finish");

        assert!(
            seen.failure.is_none(),
            "connection {number} was cut during a configuration change: {}",
            seen.failure.unwrap_or_default()
        );
        assert!(
            seen.generations.contains(&1),
            "connection {number} must have been open before the first change, saw {:?}",
            seen.generations
        );
        assert!(
            seen.generations.contains(&3),
            "connection {number} must have been open after the last change, saw {:?}",
            seen.generations
        );
        assert!(
            seen.requests > 10,
            "connection {number} answered only {} requests, which measures nothing",
            seen.requests
        );
        assert!(
            still_open,
            "connection {number} is no longer the socket it started as"
        );
    }
}
