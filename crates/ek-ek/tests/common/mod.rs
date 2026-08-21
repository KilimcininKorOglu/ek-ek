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
    /// What the frontend does with the bytes it accepts.
    pub application: String,
    /// Seconds a connection may sit with no byte moving.
    pub idle_timeout_seconds: u32,
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
            application: "http".to_owned(),
            idle_timeout_seconds: 0,
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

    /// Makes the frontend an L4 listener that forwards bytes untouched.
    #[must_use]
    pub fn raw(mut self) -> Self {
        self.application = "raw".to_owned();
        self
    }

    /// Sets how long a connection may sit with no byte moving.
    #[must_use]
    pub fn idle_timeout(mut self, seconds: u32) -> Self {
        self.idle_timeout_seconds = seconds;
        self
    }

    /// Renders the document.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            r#"{{"schema_version":1,
"nodes":[{{"id":"node1","address":"127.0.0.1","roles":["control_plane","data_plane"]}}],
"vips":[{{"id":"vip-web","address":"127.0.0.1","prefix_length":8,"interface":"lo","preferred_node":"node1"}}],
"frontends":[{{"id":"web","vip":"vip-web","port":{port},"transport":"tcp","application":"{application}","tls":null,"proxy_protocol":"disabled","routing_rules":[{rules}],"sni_rules":[],"default_backend":{default_backend},"http2":"{http2}","connect_timeout_seconds":{connect},"request_timeout_seconds":{request},"idle_timeout_seconds":{idle},"drain_timeout_seconds":5}}],
"backends":[{{"id":"web","members":[{members}],"algorithm":"{algorithm}","health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"enabled"}}],
"certificates":[],
"dns_providers":[]}}"#,
            port = self.port,
            application = self.application,
            idle = self.idle_timeout_seconds,
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
    /// The last status report the traffic path sent, as raw JSON.
    ///
    /// Kept as text rather than parsed into a workspace type, so a change to
    /// the wire format fails a test rather than compiling.
    reports: Arc<std::sync::Mutex<Option<String>>>,
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
        let reports: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));
        let collected = Arc::clone(&reports);

        let accept = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let greeting = greeting.clone();
                let mut pushed = sender.subscribe();
                let connected = Arc::clone(&connected);
                let collected = Arc::clone(&collected);

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
                                let Ok(Some(line)) = line else { return };
                                if line.contains(r#""message":"status""#)
                                    && let Ok(mut store) = collected.lock()
                                {
                                    *store = Some(line);
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
            reports,
            linked,
            accept,
        }
    }

    /// Returns the last status report, waiting for one to arrive.
    pub async fn last_report(&self) -> Option<Report> {
        for _ in 0..600 {
            if let Ok(store) = self.reports.lock()
                && let Some(line) = store.as_ref()
            {
                return Some(Report::parse(line));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    /// Waits until a named counter reaches at least `least`.
    pub async fn wait_for_counter(&self, name: &str, least: u64) -> Option<u64> {
        for _ in 0..600 {
            let line = self
                .reports
                .lock()
                .ok()
                .and_then(|store| store.as_ref().cloned());
            if let Some(line) = line
                && let Some(value) = field(&line, name).and_then(|value| value.parse::<u64>().ok())
                && value >= least
            {
                return Some(value);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    /// Waits until the reported open connections add up to `total`.
    ///
    /// Returns them so a test can check the breakdown, not just the total.
    pub async fn wait_for_open_connections(&self, total: u64) -> Option<Vec<Open>> {
        for _ in 0..600 {
            let line = self
                .reports
                .lock()
                .ok()
                .and_then(|store| store.as_ref().cloned());
            if let Some(line) = line {
                let open = Report::parse(&line).open_connections;
                if open.iter().map(|entry| entry.count).sum::<u64>() == total {
                    return Some(open);
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
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

    /// Starts an L4 frontend and forgets what the readiness check cost.
    ///
    /// Proving the listener is up means opening a connection to it, and on an
    /// L4 frontend that connection reaches a backend like any other. Counting
    /// it would put every share and every total one out.
    pub async fn start_l4(document: &Document, members: &[&RawMember]) -> Self {
        let running = Self::start(document).await;
        for member in members {
            member.settle().await;
        }
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

/// A stand-in backend that speaks no protocol at all.
///
/// Used by the L4 tests: it echoes what it receives, greets first when asked
/// to, or accepts and stays silent. None of that is HTTP, which is the point.
pub struct RawMember {
    /// Identity used in the configuration.
    pub name: String,
    /// Port it listens on.
    pub port: u16,
    /// How many connections it has accepted.
    accepted: Arc<AtomicU64>,
    /// How many of those it has seen closed by the client.
    closed: Arc<AtomicU64>,
    /// Every byte it received, in order, per connection.
    received: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
    accept: tokio::task::JoinHandle<()>,
}

/// How a raw backend behaves once a connection arrives.
#[derive(Clone, Debug)]
pub enum RawBehaviour {
    /// Sends back everything it receives.
    Echo,
    /// Writes these bytes before the client has said anything, the way SMTP
    /// and PostgreSQL both do.
    GreetFirst(Vec<u8>),
    /// Accepts and never writes.
    Silent,
    /// Accepts, waits, then closes without the client having asked.
    CloseAfter(Duration),
}

impl RawMember {
    /// Starts a raw backend behaving as asked.
    pub async fn start(name: &str, behaviour: RawBehaviour) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a backend port must be free");
        let port = listener
            .local_addr()
            .expect("the backend must have an address")
            .port();

        let accepted = Arc::new(AtomicU64::new(0));
        let closed = Arc::new(AtomicU64::new(0));
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));

        let counted = Arc::clone(&accepted);
        let hung_up = Arc::clone(&closed);
        let collected = Arc::clone(&received);

        let accept = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                let behaviour = behaviour.clone();
                let hung_up = Arc::clone(&hung_up);
                let collected = Arc::clone(&collected);

                tokio::spawn(async move {
                    let mut seen: Vec<u8> = Vec::new();
                    if let RawBehaviour::GreetFirst(greeting) = &behaviour
                        && stream.write_all(greeting).await.is_err()
                    {
                        return;
                    }
                    if let RawBehaviour::CloseAfter(delay) = &behaviour {
                        tokio::time::sleep(*delay).await;
                        drop(stream);
                        return;
                    }

                    let mut buffer = vec![0_u8; 16 * 1024];
                    loop {
                        match stream.read(&mut buffer).await {
                            Ok(0) | Err(_) => {
                                // The client went away. Recording it is how a
                                // test proves the proxy passed the close on
                                // rather than holding the socket.
                                hung_up.fetch_add(1, Ordering::SeqCst);
                                if let Ok(mut store) = collected.lock() {
                                    store.push(seen);
                                }
                                return;
                            }
                            Ok(read) => {
                                seen.extend_from_slice(&buffer[..read]);
                                if matches!(behaviour, RawBehaviour::Echo)
                                    && stream.write_all(&buffer[..read]).await.is_err()
                                {
                                    return;
                                }
                            }
                        }
                    }
                });
            }
        });

        Self {
            name: name.to_owned(),
            port,
            accepted,
            closed,
            received,
            accept,
        }
    }

    /// How many connections have arrived.
    #[must_use]
    pub fn accepted(&self) -> u64 {
        self.accepted.load(Ordering::SeqCst)
    }

    /// Waits for the readiness connection to land, then forgets everything
    /// counted so far.
    ///
    /// Without the wait the probe could still be in flight and land after the
    /// reset, which would put the count one out in the other direction.
    pub async fn settle(&self) {
        let start = tokio::time::Instant::now();
        while self.accepted.load(Ordering::SeqCst) == 0 {
            if start.elapsed() > Duration::from_secs(5) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        self.accepted.store(0, Ordering::SeqCst);
        self.closed.store(0, Ordering::SeqCst);
        if let Ok(mut store) = self.received.lock() {
            store.clear();
        }
    }

    /// How many connections the client end has closed.
    #[must_use]
    pub fn closed(&self) -> u64 {
        self.closed.load(Ordering::SeqCst)
    }

    /// Everything received, per finished connection.
    #[must_use]
    pub fn received(&self) -> Vec<Vec<u8>> {
        self.received
            .lock()
            .map(|store| store.clone())
            .unwrap_or_default()
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

impl Drop for RawMember {
    fn drop(&mut self) {
        self.accept.abort();
    }
}

/// FNV-1a over a byte slice, for proving a payload crossed unchanged.
///
/// Written out rather than taken from the standard library, so a test failure
/// means the bytes differ rather than that the hasher changed.
#[must_use]
pub fn checksum(bytes: &[u8]) -> u64 {
    let mut value: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        value ^= u64::from(*byte);
        value = value.wrapping_mul(0x0000_0100_0000_01b3);
    }
    value
}

/// A payload of the given size, with no repeating block a buggy copy could
/// hide inside.
#[must_use]
pub fn payload(size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size);
    let mut value: u64 = 0x2545_F491_4F6C_DD1D;
    while bytes.len() < size {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.truncate(size);
    bytes
}

/// One entry of a status report's open connection list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Open {
    /// The frontend the connections arrived on.
    pub frontend: String,
    /// The pool they went to.
    pub pool: String,
    /// The member inside that pool.
    pub member: String,
    /// How many are open.
    pub count: u64,
}

/// A status report, read out of the wire format by hand.
///
/// Parsed with string scanning rather than with the crate's own types, so a
/// rename that keeps compiling still fails here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    /// What the process says it is doing.
    pub state: String,
    /// The generation being served.
    pub generation: u64,
    /// Open connections, per frontend, pool and member.
    pub open_connections: Vec<Open>,
}

impl Report {
    /// Reads a report out of one protocol line.
    #[must_use]
    pub fn parse(line: &str) -> Self {
        Self {
            state: field(line, "state").unwrap_or_default(),
            generation: field(line, "generation")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            open_connections: open_connections(line),
        }
    }
}

/// Reads one scalar field out of a JSON line.
fn field(line: &str, name: &str) -> Option<String> {
    let at = line.find(&format!(r#""{name}":"#))? + name.len() + 3;
    let rest = &line[at..];
    if let Some(text) = rest.strip_prefix('"') {
        text.find('"').map(|end| text[..end].to_owned())
    } else {
        let end = rest
            .find(|character: char| !character.is_ascii_digit())
            .unwrap_or(rest.len());
        Some(rest[..end].to_owned())
    }
}

/// Reads the open connection list out of a JSON line.
fn open_connections(line: &str) -> Vec<Open> {
    let Some(at) = line.find(r#""open_connections":["#) else {
        return Vec::new();
    };
    let rest = &line[at + r#""open_connections":["#.len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };

    rest[..end]
        .split("},")
        .filter(|part| part.contains("\"member\""))
        .map(|part| Open {
            frontend: field(part, "frontend").unwrap_or_default(),
            pool: field(part, "pool").unwrap_or_default(),
            member: field(part, "member").unwrap_or_default(),
            count: field(part, "count")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
        .collect()
}
