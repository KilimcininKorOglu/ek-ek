// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the traffic path tests run against: a stand-in agent, real backend
//! servers and the real binary.
//!
//! Nothing here uses the crates the binary is built from. The configuration is
//! written as text and the line protocol is spoken directly, so a change that
//! quietly alters either is a failure in these tests rather than a rename that
//! compiles.

#![allow(dead_code, clippy::expect_used, clippy::unwrap_used)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::broadcast;

/// How long a test waits for the binary to start listening.
const STARTUP_PATIENCE: Duration = Duration::from_secs(20);

/// How long one request may take before the test calls it a failure.
///
/// Without this a proxy that answers nothing would hang the test run instead
/// of failing it, and "the connection is never left silent" would be a rule
/// nothing measures.
const ANSWER_PATIENCE: Duration = Duration::from_secs(15);

/// A port nothing is listening on, released before somebody takes it.
#[must_use]
pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a port must be free");
    let port = listener
        .local_addr()
        .expect("the listener must have an address")
        .port();
    drop(listener);
    port
}

/// How a stand-in backend behaves.
#[derive(Clone, Copy, Debug, Default)]
pub enum Behaviour {
    /// Answers immediately.
    #[default]
    Prompt,
    /// Answers after a delay, which is how a slow member is measured.
    Slow(Duration),
    /// Accepts the connection and never answers, which is what a timeout
    /// needs: a refused connection would be a different fault.
    Silent,
}

/// A stand-in backend member.
///
/// Speaks just enough HTTP/1.1 to be proxied to, and reports what it saw so a
/// test can measure the proxy rather than the backend.
pub struct Member {
    /// Identity used in the configuration and echoed in every answer.
    pub name: String,
    /// Port it listens on.
    pub port: u16,
    /// How many requests it has answered.
    hits: Arc<AtomicU64>,
    accept: tokio::task::JoinHandle<()>,
}

impl Member {
    /// Starts a member that answers immediately.
    pub async fn start(name: &str) -> Self {
        Self::with_behaviour(name, Behaviour::Prompt).await
    }

    /// Starts a member behaving as asked.
    pub async fn with_behaviour(name: &str, behaviour: Behaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a backend port must be free");
        let port = listener
            .local_addr()
            .expect("the backend must have an address")
            .port();

        let hits = Arc::new(AtomicU64::new(0));
        let counted = Arc::clone(&hits);
        let identity = name.to_owned();

        let accept = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let identity = identity.clone();
                let counted = Arc::clone(&counted);

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();

                    loop {
                        // Read one request. The headers are what a test
                        // measures, so they are collected rather than skipped.
                        let mut forwarded_for = String::new();
                        let mut forwarded_proto = String::new();
                        let mut saw_request = false;

                        loop {
                            let Ok(Some(line)) = lines.next_line().await else {
                                return;
                            };
                            if line.is_empty() {
                                break;
                            }
                            saw_request = true;
                            let lowered = line.to_ascii_lowercase();
                            if let Some(value) = lowered.strip_prefix("x-forwarded-for:") {
                                // Every occurrence is collected, not just the
                                // last one. A proxy that appends rather than
                                // overwrites sends two of these, and reading
                                // only one would hide exactly that.
                                if !forwarded_for.is_empty() {
                                    forwarded_for.push_str(", ");
                                }
                                forwarded_for.push_str(value.trim());
                            }
                            if let Some(value) = lowered.strip_prefix("x-forwarded-proto:") {
                                forwarded_proto = value.trim().to_owned();
                            }
                        }
                        if !saw_request {
                            return;
                        }

                        match behaviour {
                            Behaviour::Prompt => {}
                            Behaviour::Slow(delay) => tokio::time::sleep(delay).await,
                            Behaviour::Silent => {
                                // Hold the connection open and answer nothing.
                                // Dropping it would be a closed connection,
                                // not a timeout.
                                tokio::time::sleep(Duration::from_secs(3600)).await;
                                return;
                            }
                        }

                        counted.fetch_add(1, Ordering::SeqCst);
                        let body = format!(
                            "member={identity}\nforwarded_for={forwarded_for}\nforwarded_proto={forwarded_proto}\n"
                        );
                        let answer = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
                            body.len()
                        );
                        if writer.write_all(answer.as_bytes()).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });

        Self {
            name: name.to_owned(),
            port,
            hits,
            accept,
        }
    }

    /// How many requests this member has answered.
    #[must_use]
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::SeqCst)
    }

    /// Forgets the count, so one test can measure two rounds separately.
    pub fn reset(&self) {
        self.hits.store(0, Ordering::SeqCst);
    }

    /// How this member is written into a configuration.
    #[must_use]
    pub fn entry(&self, weight: u16, admin_state: &str) -> String {
        format!(
            r#"{{"id":"{}","address":"127.0.0.1","port":{},"weight":{weight},"admin_state":"{admin_state}"}}"#,
            self.name, self.port
        )
    }
}

impl Drop for Member {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// A configuration document, written as text.
pub struct Document {
    /// Port the frontend listens on.
    pub port: u16,
    /// Members, already rendered.
    pub members: Vec<String>,
    /// How a member is chosen.
    pub algorithm: String,
    /// Seconds the proxy waits for a backend connection.
    pub connect_timeout_seconds: u32,
    /// Seconds a request may take.
    pub request_timeout_seconds: u32,
    /// Whether cleartext HTTP/2 is accepted.
    pub http2: String,
    /// Rules, already rendered.
    pub routing_rules: Vec<String>,
    /// Pool used when no rule matches, or nothing.
    pub default_backend: String,
}

impl Document {
    /// A document with one pool, round robin, and prompt timeouts.
    #[must_use]
    pub fn new(port: u16, members: Vec<String>) -> Self {
        Self {
            port,
            members,
            algorithm: "round_robin".to_owned(),
            connect_timeout_seconds: 2,
            request_timeout_seconds: 5,
            http2: "enabled".to_owned(),
            routing_rules: Vec::new(),
            default_backend: r#""web""#.to_owned(),
        }
    }

    /// Chooses the algorithm.
    #[must_use]
    pub fn algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = algorithm.to_owned();
        self
    }

    /// Sets how long a request may take.
    #[must_use]
    pub fn request_timeout(mut self, seconds: u32) -> Self {
        self.request_timeout_seconds = seconds;
        self
    }

    /// Sets how long a backend connection may take to open.
    #[must_use]
    pub fn connect_timeout(mut self, seconds: u32) -> Self {
        self.connect_timeout_seconds = seconds;
        self
    }

    /// Turns cleartext HTTP/2 off.
    #[must_use]
    pub fn without_http2(mut self) -> Self {
        self.http2 = "disabled".to_owned();
        self
    }

    /// Renders the document.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            r#"{{"schema_version":1,
"nodes":[{{"id":"node1","address":"127.0.0.1","roles":["control_plane","data_plane"]}}],
"vips":[{{"id":"vip-web","address":"127.0.0.1","prefix_length":8,"interface":"lo","preferred_node":"node1"}}],
"frontends":[{{"id":"web","vip":"vip-web","port":{port},"transport":"tcp","application":"http","tls":null,"proxy_protocol":"disabled","routing_rules":[{rules}],"sni_rules":[],"default_backend":{default_backend},"http2":"{http2}","connect_timeout_seconds":{connect},"request_timeout_seconds":{request},"drain_timeout_seconds":5}}],
"backends":[{{"id":"web","members":[{members}],"algorithm":"{algorithm}","health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"enabled"}}],
"certificates":[],
"dns_providers":[]}}"#,
            port = self.port,
            rules = self.routing_rules.join(","),
            default_backend = self.default_backend,
            http2 = self.http2,
            connect = self.connect_timeout_seconds,
            request = self.request_timeout_seconds,
            members = self.members.join(","),
            algorithm = self.algorithm,
        )
        .replace('\n', "")
    }

    /// Renders one delivery, as the agent puts it on the wire.
    #[must_use]
    pub fn delivery(&self, generation: u64) -> String {
        format!(
            r#"{{"message":"config","generation":{generation},"config":{}}}"#,
            self.render()
        ) + "\n"
    }
}

/// A stand-in `node-agent`: it greets with one delivery and can push more.
pub struct Agent {
    pushes: broadcast::Sender<String>,
    /// Set once the long lived link is connected. The short connection that
    /// collects the first configuration is not it, and pushing to that one
    /// would push to a socket about to close.
    linked: Arc<AtomicBool>,
    accept: tokio::task::JoinHandle<()>,
}

impl Agent {
    /// Starts an agent on a socket, greeting with one delivery.
    pub async fn start(socket: &Path, greeting: String) -> Self {
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
                                match push {
                                    Ok(push) => {
                                        if writer.write_all(push.as_bytes()).await.is_err() {
                                            return;
                                        }
                                    }
                                    // Falling behind is not a reason to drop
                                    // the link. A test that pushes faster
                                    // than the socket drains would otherwise
                                    // lose its agent halfway through.
                                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                                    Err(broadcast::error::RecvError::Closed) => return,
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
    pub async fn wait_linked(&self) {
        for _ in 0..400 {
            if self.linked.load(Ordering::SeqCst) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the traffic path never opened its link to the agent");
    }

    /// Pushes one delivery to the connected traffic path.
    pub fn push(&self, delivery: &str) {
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
pub struct DataPlane(Child);

impl DataPlane {
    /// Starts the binary against an agent socket.
    #[must_use]
    pub fn start(socket: &Path) -> Self {
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

/// A running traffic path with its agent and its temporary directory.
///
/// Held together so a test drops all three at once and nothing outlives the
/// socket it needs.
pub struct Running {
    /// The stand-in agent, kept so deliveries can be pushed.
    pub agent: Agent,
    /// The port the frontend listens on.
    pub port: u16,
    data_plane: DataPlane,
    directory: tempfile::TempDir,
}

impl Running {
    /// Starts the binary serving one document and waits until it listens.
    pub async fn start(document: &Document) -> Self {
        let directory = tempfile::tempdir().expect("a temporary directory must be available");
        let socket: PathBuf = directory.path().join("agent.sock");
        let agent = Agent::start(&socket, document.delivery(1)).await;
        let data_plane = DataPlane::start(&socket);

        let running = Self {
            agent,
            port: document.port,
            data_plane,
            directory,
        };
        drop(connect(running.port).await);
        running
    }
}

/// Connects once the binary is listening.
pub async fn connect(port: u16) -> TcpStream {
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        assert!(
            start.elapsed() <= STARTUP_PATIENCE,
            "the traffic path never started listening on port {port}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// One answer, as a test reads it.
#[derive(Clone, Debug)]
pub struct Answer {
    /// The status code.
    pub status: u16,
    /// The headers, keyed by lower case name.
    pub headers: std::collections::BTreeMap<String, String>,
    /// The body, empty when there is none.
    pub body: String,
}

impl Answer {
    /// One header, or an empty string when it is absent.
    #[must_use]
    pub fn header(&self, name: &str) -> String {
        self.headers.get(name).cloned().unwrap_or_default()
    }
}

impl Answer {
    /// The member named in the body, or an empty string.
    #[must_use]
    pub fn member(&self) -> String {
        self.field("member")
    }

    /// One `name=value` line of the body.
    #[must_use]
    pub fn field(&self, name: &str) -> String {
        self.body
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{name}=")))
            .unwrap_or_default()
            .to_owned()
    }
}

/// Sends one request on a connection that is already open and reads the
/// answer.
///
/// # Errors
///
/// Fails when the connection is cut or the answer cannot be read to its end,
/// which is what makes a cut connection a test failure rather than a silent
/// retry.
pub async fn ask(io: &mut BufReader<TcpStream>, request: &str) -> std::io::Result<Answer> {
    io.get_mut().write_all(request.as_bytes()).await?;
    tokio::time::timeout(ANSWER_PATIENCE, read_answer(io))
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "no answer arrived and the connection was not closed either",
            )
        })?
}

/// Reads one answer from a connection.
async fn read_answer(io: &mut BufReader<TcpStream>) -> std::io::Result<Answer> {
    let mut status_line = String::new();
    if io.read_line(&mut status_line).await? == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "the connection was closed before an answer arrived",
        ));
    }
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("the answer had no status: {status_line:?}"),
            )
        })?;

    let mut length: Option<usize> = None;
    let mut headers = std::collections::BTreeMap::new();
    loop {
        let mut line = String::new();
        if io.read_line(&mut line).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the connection was closed while the headers were being read",
            ));
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_ascii_lowercase(), value.trim().to_owned());
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

    Ok(Answer {
        status,
        headers,
        body: String::from_utf8_lossy(&body).into_owned(),
    })
}

/// A plain request a keep-alive connection can carry.
#[must_use]
pub fn plain_request() -> String {
    "GET / HTTP/1.1\r\nHost: ek-ek.test\r\n\r\n".to_owned()
}

/// Opens a connection, sends one request and reads the answer.
///
/// # Errors
///
/// Fails when the answer cannot be read.
pub async fn ask_once(port: u16, request: &str) -> std::io::Result<Answer> {
    let stream = TcpStream::connect(("127.0.0.1", port)).await?;
    let mut io = BufReader::new(stream);
    ask(&mut io, request).await
}
