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

pub mod tls;

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::broadcast;

/// How long a test waits for the binary to start listening.
const STARTUP_PATIENCE: Duration = Duration::from_secs(30);

/// How many copies of the binary may be starting at once.
///
/// Each one brings up a pingora server with its own worker threads. Letting
/// every test in a file start one at the same moment makes them all slow
/// enough to miss the startup window, which then reads as a product fault
/// rather than as a loaded machine.
static AT_ONCE: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

/// How long one request may take before the test calls it a failure.
///
/// Without this a proxy that answers nothing would hang the test run instead
/// of failing it, and "the connection is never left silent" would be a rule
/// nothing measures.
const ANSWER_PATIENCE: Duration = Duration::from_secs(15);

/// Where this test binary's own port range starts.
///
/// Derived from the process id so two test binaries running at once do not
/// hand out the same numbers.
static NEXT_PORT: AtomicU64 = AtomicU64::new(0);

/// A port nothing is listening on.
///
/// Walks a range of its own rather than asking the kernel for any free port.
/// The kernel's answer has to be released before the binary under test can
/// bind it, and in that gap a parallel test takes it: the binary then fails
/// to bind, exits, and the test reads it as a product fault.
#[must_use]
pub fn free_port() -> u16 {
    let base = 20_000 + u64::from(std::process::id() % 400) * 100;
    loop {
        let at = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
        let port = u16::try_from(base + at % 100).unwrap_or(20_000);
        // Bound and released only to prove nothing else holds it. Two callers
        // never get the same number, so the gap that matters does not exist.
        if std::net::TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
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
    /// How many health probes it has answered.
    probes: Arc<AtomicU64>,
    /// Whether it is still answering at all.
    alive: Arc<AtomicBool>,
    accept: tokio::task::JoinHandle<()>,
}

impl Member {
    /// Starts a member that answers immediately.
    pub async fn start(name: &str) -> Self {
        Self::with_behaviour(name, Behaviour::Prompt).await
    }

    /// Starts a member that sets a cookie of its own on every answer.
    pub async fn setting_cookie(name: &str, cookie: &str) -> Self {
        Self::build(name, Behaviour::Prompt, Some(cookie.to_owned())).await
    }

    /// Starts a member behaving as asked.
    pub async fn with_behaviour(name: &str, behaviour: Behaviour) -> Self {
        Self::build(name, behaviour, None).await
    }

    async fn build(name: &str, behaviour: Behaviour, own_cookie: Option<String>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a backend port must be free");
        let port = listener
            .local_addr()
            .expect("the backend must have an address")
            .port();

        let hits = Arc::new(AtomicU64::new(0));
        let probes = Arc::new(AtomicU64::new(0));
        let alive = Arc::new(AtomicBool::new(true));
        let counted = Arc::clone(&hits);
        let probed = Arc::clone(&probes);
        let answering = Arc::clone(&alive);
        let identity = name.to_owned();

        let accept = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let identity = identity.clone();
                let counted = Arc::clone(&counted);
                let probed = Arc::clone(&probed);
                let answering = Arc::clone(&answering);
                let own_cookie = own_cookie.clone();

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();

                    loop {
                        // Read one request. The headers are what a test
                        // measures, so they are collected rather than skipped.
                        let mut forwarded_for = String::new();
                        let mut forwarded_proto = String::new();
                        let mut cookie = String::new();
                        let mut saw_request = false;
                        let mut is_probe = false;

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
                            if let Some(value) = lowered.strip_prefix("cookie:") {
                                if !cookie.is_empty() {
                                    cookie.push_str("; ");
                                }
                                cookie.push_str(value.trim());
                            }
                            // Health traffic names itself, which is the only
                            // reason a backend can tell it from a real
                            // request in its own log.
                            if lowered.starts_with("user-agent:")
                                && lowered.contains("ek-ek-health/")
                            {
                                is_probe = true;
                            }
                        }
                        if !saw_request {
                            return;
                        }

                        // A member that has been stopped accepts and says
                        // nothing, which is what a hung service looks like.
                        if !answering.load(Ordering::SeqCst) {
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

                        if is_probe {
                            probed.fetch_add(1, Ordering::SeqCst);
                        } else {
                            counted.fetch_add(1, Ordering::SeqCst);
                        }
                        let body = format!(
                            "member={identity}\nforwarded_for={forwarded_for}\nforwarded_proto={forwarded_proto}\ncookie={cookie}\n"
                        );
                        // An application that sets its own cookies is what
                        // proves the proxy adds to them rather than replacing
                        // the header they arrive in.
                        let own = own_cookie
                            .as_ref()
                            .map(|line| format!("Set-Cookie: {line}\r\n"))
                            .unwrap_or_default();
                        let answer = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n{own}Content-Length: {}\r\n\r\n{body}",
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
            probes,
            alive,
            accept,
        }
    }

    /// How many health probes this member has answered.
    #[must_use]
    pub fn probes(&self) -> u64 {
        self.probes.load(Ordering::SeqCst)
    }

    /// Stops answering, without closing the listening socket.
    ///
    /// This is what a hung service looks like: the connection is accepted and
    /// then nothing comes back, which a TCP connect probe cannot see but an
    /// HTTP probe can.
    pub fn stop_answering(&self) {
        self.alive.store(false, Ordering::SeqCst);
    }

    /// Starts answering again.
    pub fn answer_again(&self) {
        self.alive.store(true, Ordering::SeqCst);
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

/// The key the stickiness cookie is signed with in tests.
///
/// Not a secret: it exists so a document that turns stickiness on is valid,
/// and so a test can sign a value the way the product would.
pub const STICKINESS_KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

/// Renders a string as a JSON string.
///
/// Written out rather than taken from a JSON library, because the harness
/// speaks the wire format by hand on purpose: that is what proves the format
/// is a protocol and not a shared type.
fn quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other if (other as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", other as u32));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
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
    /// Which transport the frontend carries.
    pub transport: String,
    /// The most UDP sessions the frontend keeps, or zero for the default.
    pub udp_session_limit: u32,
    /// Seconds the frontend gets to drain.
    pub drain_timeout_seconds: u32,
    /// Seconds a connection may sit with no byte moving.
    pub idle_timeout_seconds: u32,
    /// The pool's health check, already rendered, or `null`.
    pub health_check: String,
    /// Rules, already rendered.
    pub routing_rules: Vec<String>,
    /// Extra backend pools beyond `web`, already rendered.
    pub extra_pools: Vec<String>,
    /// Pool used when no rule matches, or nothing.
    pub default_backend: String,
    /// The pool's stickiness, already rendered.
    pub stickiness: String,
    /// The frontend's TLS settings, already rendered, or `null`.
    pub tls: String,
    /// Certificates, already rendered.
    pub certificates: String,
    /// Chain and key of each certificate, keyed by identity.
    ///
    /// Carried here rather than beside the document, so a delivery always
    /// names the material for the certificates it references (ADR-0069).
    pub material: Vec<(String, String, String)>,
    /// Key the stickiness cookie is signed with, as hex.
    pub stickiness_key: String,
    /// Which PROXY header the frontend opens a backend connection with.
    ///
    /// Nothing means the document does not name the setting at all, which is
    /// how the default is measured rather than assumed.
    pub proxy_protocol: Option<String>,
    /// Address the VIP carries, and so the address the frontend listens on.
    pub vip_address: String,
    /// Prefix length the VIP is written with.
    pub prefix_length: u8,
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
            transport: "tcp".to_owned(),
            udp_session_limit: 0,
            drain_timeout_seconds: 5,
            idle_timeout_seconds: 0,
            health_check: "null".to_owned(),
            routing_rules: Vec::new(),
            extra_pools: Vec::new(),
            default_backend: r#""web""#.to_owned(),
            stickiness: r#"{"mode":"disabled"}"#.to_owned(),
            tls: "null".to_owned(),
            certificates: String::new(),
            material: Vec::new(),
            stickiness_key: String::new(),
            proxy_protocol: Some("disabled".to_owned()),
            vip_address: "127.0.0.1".to_owned(),
            prefix_length: 8,
        }
    }

    /// Turns the PROXY protocol on for the frontend, in the named format.
    #[must_use]
    pub fn proxy_protocol(mut self, format: &str) -> Self {
        self.proxy_protocol = Some(format.to_owned());
        self
    }

    /// Leaves the setting out of the document entirely.
    ///
    /// A frontend written without it is what an operator who never touched
    /// the setting has, so this is how the default is measured.
    #[must_use]
    pub fn without_proxy_protocol_named(mut self) -> Self {
        self.proxy_protocol = None;
        self
    }

    /// Puts the VIP, and so the listener, on this address.
    #[must_use]
    pub fn on_address(mut self, address: &str, prefix_length: u8) -> Self {
        self.vip_address = address.to_owned();
        self.prefix_length = prefix_length;
        self
    }

    /// Turns cookie stickiness on for the pool.
    #[must_use]
    pub fn sticky(mut self, cookie_name: &str, same_site: &str) -> Self {
        self.stickiness = format!(
            r#"{{"mode":"signed_cookie","cookie_name":"{cookie_name}","same_site":"{same_site}"}}"#
        );
        if self.stickiness_key.is_empty() {
            self.stickiness_key = STICKINESS_KEY.to_owned();
        }
        self
    }

    /// Adds a certificate the frontend can serve, with its material.
    ///
    /// The names are what a handshake is matched against, and a name of the
    /// form `*.example.test` is a wildcard (ADR-0070).
    #[must_use]
    pub fn certificate(mut self, id: &str, names: &[&str], chain_pem: &str, key_pem: &str) -> Self {
        let names = names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let rendered = format!(
            r#"{{"id":"{id}","sni_names":[{names}],"source":{{"type":"manual_upload"}},"validity":null,"chain":"chain-{id}","private_key":"key-{id}"}}"#
        );
        if self.certificates.is_empty() {
            self.certificates = rendered;
        } else {
            self.certificates.push(',');
            self.certificates.push_str(&rendered);
        }
        self.material
            .push((id.to_owned(), chain_pem.to_owned(), key_pem.to_owned()));
        self
    }

    /// Adds a certificate the configuration references but nothing delivers.
    ///
    /// This is what a frontend looks like when a certificate was configured
    /// and its material never arrived.
    #[must_use]
    pub fn certificate_without_material(mut self, id: &str, names: &[&str]) -> Self {
        let names = names
            .iter()
            .map(|name| format!("\"{name}\""))
            .collect::<Vec<_>>()
            .join(",");
        let rendered = format!(
            r#"{{"id":"{id}","sni_names":[{names}],"source":{{"type":"manual_upload"}},"validity":null,"chain":null,"private_key":null}}"#
        );
        if self.certificates.is_empty() {
            self.certificates = rendered;
        } else {
            self.certificates.push(',');
            self.certificates.push_str(&rendered);
        }
        self
    }

    /// Says the frontend terminates TLS with the certificates named.
    ///
    /// `default` is served when the SNI name matches nothing and when the
    /// client sends no name; left out, both are refused (ADR-0070).
    #[must_use]
    pub fn terminating_tls(mut self, certificates: &[&str], default: Option<&str>) -> Self {
        let listed = certificates
            .iter()
            .map(|id| format!("\"{id}\""))
            .collect::<Vec<_>>()
            .join(",");
        let default = default.map_or_else(|| "null".to_owned(), |id| format!("\"{id}\""));
        self.tls = format!(
            r#"{{"certificates":[{listed}],"default_certificate":{default},"policy":"dengeli"}}"#
        );
        self
    }

    /// Adds a backend pool beyond the default `web` one.
    #[must_use]
    pub fn pool(mut self, id: &str, members: Vec<String>) -> Self {
        self.extra_pools.push(format!(
            r#"{{"id":"{id}","members":[{}],"algorithm":"round_robin","health_check":null,"stickiness":{{"mode":"disabled"}},"connection_pooling":"enabled"}}"#,
            members.join(",")
        ));
        self
    }

    /// Adds a routing rule to the end of the list.
    ///
    /// `host` and `path` are each optional, and a rule naming neither takes
    /// every request. `seconds` overrides the frontend's request limit.
    #[must_use]
    pub fn rule(
        mut self,
        host: Option<&str>,
        path: Option<&str>,
        backend: &str,
        seconds: Option<u32>,
    ) -> Self {
        self.routing_rules.push(format!(
            r#"{{"host_pattern":{},"path_prefix":{},"path_case":"insensitive","action":{{"type":"proxy","backend":"{backend}"}},"request_timeout_seconds":{}}}"#,
            quoted_or_null(host),
            quoted_or_null(path),
            seconds.map_or_else(|| "null".to_owned(), |value| value.to_string()),
        ));
        self
    }

    /// Adds a routing rule that matches its path case sensitively.
    #[must_use]
    pub fn case_sensitive_rule(mut self, path: &str, backend: &str) -> Self {
        self.routing_rules.push(format!(
            r#"{{"host_pattern":null,"path_prefix":"{path}","path_case":"sensitive","action":{{"type":"proxy","backend":"{backend}"}},"request_timeout_seconds":null}}"#
        ));
        self
    }

    /// Drops the default pool, so a request no rule takes has nowhere to go.
    #[must_use]
    pub fn without_default_backend(mut self) -> Self {
        self.default_backend = "null".to_owned();
        self
    }

    /// Signs the stickiness cookie with a different key.
    #[must_use]
    pub fn stickiness_key(mut self, key: &str) -> Self {
        self.stickiness_key = key.to_owned();
        self
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

    /// Makes the frontend a UDP listener.
    #[must_use]
    pub fn udp(mut self) -> Self {
        self.application = "raw".to_owned();
        self.transport = "udp".to_owned();
        self
    }

    /// Sets how long the frontend gets to drain before it is cut.
    #[must_use]
    pub fn drain_timeout(mut self, seconds: u32) -> Self {
        self.drain_timeout_seconds = seconds;
        self
    }

    /// Sets the most UDP sessions the frontend keeps.
    #[must_use]
    pub fn udp_session_limit(mut self, limit: u32) -> Self {
        self.udp_session_limit = limit;
        self
    }

    /// Sets how long a connection may sit with no byte moving.
    #[must_use]
    pub fn idle_timeout(mut self, seconds: u32) -> Self {
        self.idle_timeout_seconds = seconds;
        self
    }

    /// Gives the pool a TCP connect health check.
    #[must_use]
    pub fn tcp_health_check(
        mut self,
        interval_ms: u32,
        timeout_ms: u32,
        healthy: u8,
        unhealthy: u8,
    ) -> Self {
        self.health_check = format!(
            r#"{{"probe":{{"type":"tcp_connect"}},"interval_ms":{interval_ms},"timeout_ms":{timeout_ms},"healthy_threshold":{healthy},"unhealthy_threshold":{unhealthy}}}"#
        );
        self
    }

    /// Gives the pool an HTTP health check.
    #[must_use]
    pub fn http_health_check(mut self, path: &str, status: u16, interval_ms: u32) -> Self {
        self.health_check = format!(
            r#"{{"probe":{{"type":"http","path":"{path}","expected_status":[{status}],"expected_body":null,"host_header":null}},"interval_ms":{interval_ms},"timeout_ms":{},"healthy_threshold":1,"unhealthy_threshold":1}}"#,
            interval_ms / 2
        );
        self
    }

    /// Renders the document.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            r#"{{"schema_version":1,
"nodes":[{{"id":"node1","address":"127.0.0.1","roles":["control_plane","data_plane"]}}],
"vips":[{{"id":"vip-web","address":"{vip_address}","prefix_length":{prefix_length},"interface":"lo","preferred_node":"node1"}}],
"frontends":[{{"id":"web","vip":"vip-web","port":{port},"transport":"{transport}","application":"{application}","tls":{tls},{proxy_protocol}"routing_rules":[{rules}],"sni_rules":[],"default_backend":{default_backend},"http2":"{http2}","connect_timeout_seconds":{connect},"request_timeout_seconds":{request},"idle_timeout_seconds":{idle},"drain_timeout_seconds":{drain},"udp_session_limit":{udp_limit}}}],
"backends":[{{"id":"web","members":[{members}],"algorithm":"{algorithm}","health_check":{health_check},"stickiness":{stickiness},"connection_pooling":"enabled"}}{extra_pools}],
"certificates":[{certificates}],
"dns_providers":[],
"stickiness_key":"{stickiness_key}"}}"#,
            port = self.port,
            vip_address = self.vip_address,
            prefix_length = self.prefix_length,
            proxy_protocol = self
                .proxy_protocol
                .as_ref()
                .map_or_else(String::new, |format| {
                    format!(r#""proxy_protocol":"{format}","#)
                }),
            application = self.application,
            transport = self.transport,
            udp_limit = self.udp_session_limit,
            drain = self.drain_timeout_seconds,
            idle = self.idle_timeout_seconds,
            rules = self.routing_rules.join(","),
            extra_pools = self
                .extra_pools
                .iter()
                .map(|pool| format!(",{pool}"))
                .collect::<String>(),
            default_backend = self.default_backend,
            http2 = self.http2,
            connect = self.connect_timeout_seconds,
            request = self.request_timeout_seconds,
            members = self.members.join(","),
            algorithm = self.algorithm,
            health_check = self.health_check,
            stickiness = self.stickiness,
            tls = self.tls,
            certificates = self.certificates,
            stickiness_key = self.stickiness_key,
        )
        .replace('\n', "")
    }

    /// Renders the certificate material, as the agent puts it on the wire.
    #[must_use]
    pub fn material(&self) -> String {
        self.material
            .iter()
            .map(|(id, chain, key)| {
                format!(
                    r#""{id}":{{"chain_pem":{},"key_pem":{}}}"#,
                    quoted(chain),
                    quoted(key)
                )
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Renders one delivery, as the agent puts it on the wire.
    #[must_use]
    pub fn delivery(&self, generation: u64) -> String {
        format!(
            r#"{{"message":"config","generation":{generation},"config":{},"certificates":{{{}}}}}"#,
            self.render(),
            self.material()
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

    /// Waits until a member is reported with the health asked for.
    ///
    /// Returns how many transitions it had by then, so a test can tell a
    /// member that settled from one that keeps flapping.
    pub async fn wait_for_health(&self, member: &str, healthy: bool) -> Option<u64> {
        for _ in 0..600 {
            let line = self
                .reports
                .lock()
                .ok()
                .and_then(|store| store.as_ref().cloned());
            if let Some(line) = line
                && let Some(entry) = member_health(&line)
                    .into_iter()
                    .find(|entry| entry.member == member)
                && entry.healthy == healthy
            {
                return Some(entry.transitions);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    /// Waits until the report says at least `least` handshakes were refused.
    ///
    /// Reports arrive on a timer, so a test that read once would measure how
    /// fast it ran rather than what the traffic path counted.
    pub async fn wait_for_refused_handshakes(&self, least: u64) -> u64 {
        let mut seen = 0;
        for _ in 0..600 {
            let line = self
                .reports
                .lock()
                .ok()
                .and_then(|store| store.as_ref().cloned());
            if let Some(line) = line {
                seen = Report::parse(&line).tls_handshakes_refused;
                if seen >= least {
                    return seen;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        seen
    }

    /// Returns the health entries of the last report.
    pub async fn health_now(&self) -> Vec<MemberHealthLine> {
        self.reports
            .lock()
            .ok()
            .and_then(|store| store.as_ref().cloned())
            .map(|line| member_health(&line))
            .unwrap_or_default()
    }

    /// What a UDP frontend's session table looks like in the last report.
    pub async fn udp_sessions_now(&self, frontend: &str) -> Option<UdpSessionLine> {
        let line = self
            .reports
            .lock()
            .ok()
            .and_then(|store| store.as_ref().cloned())?;
        udp_sessions(&line)
            .into_iter()
            .find(|entry| entry.frontend == frontend)
    }

    /// Waits until a UDP frontend reports at least `least` sessions.
    pub async fn wait_for_udp_sessions(
        &self,
        frontend: &str,
        least: u64,
    ) -> Option<UdpSessionLine> {
        for _ in 0..600 {
            if let Some(entry) = self.udp_sessions_now(frontend).await
                && entry.count >= least
            {
                return Some(entry);
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

    /// Whether the traffic path has opened its link to this agent.
    #[must_use]
    pub fn is_linked(&self) -> bool {
        self.linked.load(Ordering::SeqCst)
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

/// A stand-in UDP backend.
///
/// Answers every datagram with its own name and what it received, counts
/// what it saw, and remembers which source addresses it saw them from. The
/// source it sees is the proxy's own socket, not the client's, which is what
/// makes "one socket per session" observable from the backend side.
pub struct UdpMember {
    /// Identity used in the configuration.
    pub name: String,
    /// Port it listens on.
    pub port: u16,
    /// How many datagrams it has answered.
    seen: Arc<AtomicU64>,
    /// The distinct source addresses it has been reached from.
    sources: Arc<std::sync::Mutex<std::collections::BTreeSet<std::net::SocketAddr>>>,
    /// Every payload it received, in order.
    payloads: Arc<std::sync::Mutex<Vec<String>>>,
    accept: tokio::task::JoinHandle<()>,
    /// The TCP listener a connect probe reaches, when this member has one.
    tcp: Option<tokio::task::JoinHandle<()>>,
}

impl UdpMember {
    /// Starts a member on a free port.
    pub async fn start(name: &str) -> Self {
        Self::build(name, false).await
    }

    /// Starts a member that also accepts TCP on the same port.
    ///
    /// A TCP connect health check against a member that speaks only UDP
    /// fails, which is how a test marks one member unhealthy without
    /// breaking it. The member that must stay healthy needs something for
    /// that probe to connect to.
    pub async fn also_answering_tcp(name: &str) -> Self {
        Self::build(name, true).await
    }

    async fn build(name: &str, with_tcp: bool) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a backend port must be free");
        let port = socket
            .local_addr()
            .expect("the backend must have an address")
            .port();

        let seen = Arc::new(AtomicU64::new(0));
        let sources = Arc::new(std::sync::Mutex::new(std::collections::BTreeSet::new()));
        let payloads = Arc::new(std::sync::Mutex::new(Vec::new()));
        let counted = Arc::clone(&seen);
        let noted = Arc::clone(&sources);
        let kept = Arc::clone(&payloads);
        let identity = name.to_owned();

        let accept = tokio::spawn(async move {
            let mut buffer = vec![0_u8; 4096];
            loop {
                let Ok((read, from)) = socket.recv_from(&mut buffer).await else {
                    return;
                };
                counted.fetch_add(1, Ordering::SeqCst);
                if let Ok(mut store) = noted.lock() {
                    store.insert(from);
                }
                let payload = String::from_utf8_lossy(&buffer[..read]).into_owned();
                if let Ok(mut store) = kept.lock() {
                    store.push(payload.clone());
                }
                let answer = format!("{identity}:{payload}");
                let _ = socket.send_to(answer.as_bytes(), from).await;
            }
        });

        let tcp = if with_tcp {
            let listener = TcpListener::bind(("127.0.0.1", port))
                .await
                .expect("the same port must be free for tcp");
            Some(tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    // Accepted and closed, which is all a connect probe asks
                    // for.
                    drop(stream);
                }
            }))
        } else {
            None
        };

        Self {
            name: name.to_owned(),
            port,
            seen,
            sources,
            payloads,
            accept,
            tcp,
        }
    }

    /// How many datagrams this member has answered.
    #[must_use]
    pub fn seen(&self) -> u64 {
        self.seen.load(Ordering::SeqCst)
    }

    /// How many distinct source addresses have reached it.
    #[must_use]
    pub fn sources(&self) -> usize {
        self.sources.lock().map(|store| store.len()).unwrap_or(0)
    }

    /// Every payload it received.
    #[must_use]
    pub fn payloads(&self) -> Vec<String> {
        self.payloads
            .lock()
            .map(|store| store.clone())
            .unwrap_or_default()
    }

    /// Forgets everything it has seen.
    pub fn reset(&self) {
        self.seen.store(0, Ordering::SeqCst);
        if let Ok(mut store) = self.sources.lock() {
            store.clear();
        }
        if let Ok(mut store) = self.payloads.lock() {
            store.clear();
        }
    }

    /// Renders this member as a configuration entry.
    #[must_use]
    pub fn entry(&self, weight: u16, admin_state: &str) -> String {
        format!(
            r#"{{"id":"{}","address":"127.0.0.1","port":{},"weight":{weight},"admin_state":"{admin_state}"}}"#,
            self.name, self.port
        )
    }
}

impl Drop for UdpMember {
    fn drop(&mut self) {
        self.accept.abort();
        if let Some(tcp) = self.tcp.take() {
            tcp.abort();
        }
    }
}

/// One client, holding its own socket so its source port stays the same.
///
/// A UDP session is keyed on the client's address and port, so a test that
/// opened a new socket for every datagram would be a new client every time.
pub struct UdpClient {
    socket: tokio::net::UdpSocket,
    target: std::net::SocketAddr,
}

impl UdpClient {
    /// Opens a client pointed at a frontend.
    pub async fn open(port: u16) -> Self {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a client port must be free");
        Self {
            socket,
            target: std::net::SocketAddr::from(([127, 0, 0, 1], port)),
        }
    }

    /// Sends one datagram and waits for the answer.
    ///
    /// # Errors
    ///
    /// Fails when nothing answers within the patience window. UDP loses
    /// datagrams, so a test that waited forever would hang rather than fail.
    pub async fn ask(&self, payload: &str) -> std::io::Result<String> {
        self.socket.send_to(payload.as_bytes(), self.target).await?;
        let mut buffer = vec![0_u8; 4096];
        let read = tokio::time::timeout(ANSWER_PATIENCE, self.socket.recv(&mut buffer))
            .await
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "nothing answered the datagram",
                )
            })??;
        Ok(String::from_utf8_lossy(&buffer[..read]).into_owned())
    }

    /// Sends one datagram and does not wait.
    pub async fn tell(&self, payload: &str) {
        let _ = self.socket.send_to(payload.as_bytes(), self.target).await;
    }

    /// Which member answered, from an answer of the form `member:payload`.
    #[must_use]
    pub fn member_of(answer: &str) -> String {
        answer.split(':').next().unwrap_or_default().to_owned()
    }
}

/// The running binary, stopped when the test ends however it ends.
pub struct DataPlane {
    child: Child,
    /// Where the binary's own diagnostics go, so a test that fails can say
    /// what the binary said rather than only that nothing happened.
    complaints: PathBuf,
}

impl DataPlane {
    /// Starts the binary against an agent socket.
    #[must_use]
    pub fn start(socket: &Path) -> Self {
        // Numbered, because an upgrade runs two processes against one agent
        // socket and they must not write over each other's diagnostics.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let at = NEXT.fetch_add(1, Ordering::SeqCst);
        let complaints = socket.with_extension(format!("stderr.{at}"));
        let errors = std::fs::File::create(&complaints).expect("a log file must be creatable");
        let child = Command::new(env!("CARGO_BIN_EXE_ek-ek"))
            .arg("data-plane")
            .arg("--agent-socket")
            .arg(socket)
            .stderr(errors)
            .spawn()
            .expect("the binary under test must start");
        Self { child, complaints }
    }

    /// What the binary has written to its error output so far.
    #[must_use]
    pub fn complaints(&self) -> String {
        std::fs::read_to_string(&self.complaints).unwrap_or_default()
    }

    /// The process id, which is what a signal and `ps` both need.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Asks the process to shut down gracefully.
    ///
    /// `SIGQUIT` is pingora's upgrade signal: it hands over listening sockets
    /// and drains rather than cutting what is in flight.
    pub fn ask_to_drain(&self) {
        let _ = Command::new("kill")
            .arg("-QUIT")
            .arg(self.pid().to_string())
            .status();
    }

    /// Waits for the process to end on its own, returning how long it took.
    ///
    /// Returns `None` when it is still running at the end of the wait, so a
    /// test can say "it never stopped" rather than hang.
    pub async fn wait_for_exit(&mut self, patience: Duration) -> Option<Duration> {
        let start = tokio::time::Instant::now();
        loop {
            if self.exited().is_some() {
                return Some(start.elapsed());
            }
            if start.elapsed() > patience {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// How the binary exited, when it already has.
    ///
    /// A binary that refused its configuration or failed to bind is gone
    /// within a moment. Without this a test waits out the whole startup
    /// window and then reports that nothing started listening, which says
    /// nothing about why.
    pub fn exited(&mut self) -> Option<String> {
        match self.child.try_wait() {
            Ok(Some(status)) => Some(format!("{status}")),
            _ => None,
        }
    }
}

impl Drop for DataPlane {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Whether the operating system still knows this process id.
///
/// Read from `ps` rather than from the `Child`, so a process that ended
/// without being reaped is still visible: that is what a zombie is.
#[must_use]
pub fn process_state(pid: u32) -> String {
    let output = Command::new("ps")
        .arg("-o")
        .arg("stat=")
        .arg("-p")
        .arg(pid.to_string())
        .output();
    output
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .unwrap_or_default()
}

/// How many processes hold a UDP port open.
///
/// Read from `lsof`, so the answer comes from the operating system rather
/// than from what the test believes it started.
#[must_use]
pub fn udp_listeners(port: u16) -> usize {
    let output = Command::new("lsof")
        .arg("-nP")
        .arg(format!("-iUDP:{port}"))
        .output();
    let Ok(output) = output else {
        return 0;
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .skip(1)
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect::<std::collections::BTreeSet<_>>()
        .len()
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
    /// The address the frontend listens on, which is the VIP's.
    pub address: String,
    data_plane: DataPlane,
    directory: tempfile::TempDir,
    /// Held for as long as the binary runs, so only a few run at once.
    _slot: tokio::sync::SemaphorePermit<'static>,
}

impl Running {
    /// Starts the binary serving one document and waits until it listens.
    pub async fn start(document: &Document) -> Self {
        let slot = AT_ONCE
            .acquire()
            .await
            .expect("the semaphore is never closed");
        let directory = tempfile::tempdir().expect("a temporary directory must be available");
        let socket: PathBuf = directory.path().join("agent.sock");
        let agent = Agent::start(&socket, document.delivery(1)).await;
        let data_plane = DataPlane::start(&socket);

        let mut running = Self {
            agent,
            port: document.port,
            address: document.vip_address.clone(),
            data_plane,
            directory,
            _slot: slot,
        };
        running.wait_until_listening().await;
        running
    }

    /// Waits for the frontend to accept a connection, or says why it never
    /// will.
    async fn wait_until_listening(&mut self) {
        let start = tokio::time::Instant::now();
        loop {
            if let Ok(stream) = TcpStream::connect((self.address.as_str(), self.port)).await {
                drop(stream);
                return;
            }
            if let Some(status) = self.data_plane.exited() {
                panic!(
                    "the traffic path exited with {status} instead of listening on port {}",
                    self.port
                );
            }
            assert!(
                start.elapsed() <= STARTUP_PATIENCE,
                "the traffic path never started listening on port {} (linked to the agent: {}); it said: {}",
                self.port,
                self.agent.is_linked(),
                self.data_plane.complaints()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// Everything the process wrote to its diagnostics.
    #[must_use]
    pub fn complaints(&self) -> String {
        self.data_plane.complaints()
    }

    /// The agent socket this run is using, so a replacement process can
    /// speak to the same agent.
    #[must_use]
    pub fn socket_path(&self) -> PathBuf {
        self.directory.path().join("agent.sock")
    }

    /// The process id of the running traffic path.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.data_plane.pid()
    }

    /// Asks the running traffic path to drain.
    pub fn ask_to_drain(&self) {
        self.data_plane.ask_to_drain();
    }

    /// Waits for the running traffic path to end on its own.
    pub async fn wait_for_exit(&mut self, patience: Duration) -> Option<Duration> {
        self.data_plane.wait_for_exit(patience).await
    }

    /// Starts a second traffic path against the same agent.
    ///
    /// This is the replacement half of an upgrade: it binds the same UDP
    /// port while the first one is still serving, which only works because
    /// the listener is opened with `SO_REUSEPORT` (ADR-0017).
    #[must_use]
    pub fn start_replacement(&self) -> DataPlane {
        DataPlane::start(&self.socket_path())
    }

    /// Starts a UDP frontend and waits until it answers.
    ///
    /// A UDP listener cannot be probed by connecting: there is nothing to
    /// connect to. Readiness is a datagram that comes back, and the counts
    /// it cost the backends are reset afterwards so a test measures only its
    /// own traffic.
    pub async fn start_udp(document: &Document, members: &[&UdpMember]) -> Self {
        let slot = AT_ONCE
            .acquire()
            .await
            .expect("the semaphore is never closed");
        let directory = tempfile::tempdir().expect("a temporary directory must be available");
        let socket: PathBuf = directory.path().join("agent.sock");
        let agent = Agent::start(&socket, document.delivery(1)).await;
        let data_plane = DataPlane::start(&socket);

        let mut running = Self {
            agent,
            port: document.port,
            address: document.vip_address.clone(),
            data_plane,
            directory,
            _slot: slot,
        };
        running.wait_until_answering().await;
        for member in members {
            member.reset();
        }
        running
    }

    /// Waits for the UDP frontend to answer a datagram, or says why it never
    /// will.
    async fn wait_until_answering(&mut self) {
        let start = tokio::time::Instant::now();
        let client = UdpClient::open(self.port).await;
        loop {
            client.tell("ready?").await;
            let mut buffer = vec![0_u8; 1024];
            if tokio::time::timeout(Duration::from_millis(200), client.socket.recv(&mut buffer))
                .await
                .is_ok_and(|read| read.is_ok())
            {
                return;
            }
            if let Some(status) = self.data_plane.exited() {
                panic!(
                    "the traffic path exited with {status} instead of serving udp on port {}; it said: {}",
                    self.port,
                    self.data_plane.complaints()
                );
            }
            assert!(
                start.elapsed() <= STARTUP_PATIENCE,
                "the traffic path never answered udp on port {} (linked to the agent: {}); it said: {}",
                self.port,
                self.agent.is_linked(),
                self.data_plane.complaints()
            );
        }
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
    connect_to("127.0.0.1", port).await
}

/// Connects to a named address once the binary is listening there.
///
/// Kept apart from `connect` so a test on an IPv6 listener reaches it over
/// IPv6 rather than over a loopback that happens to answer both.
pub async fn connect_to(address: &str, port: u16) -> TcpStream {
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(stream) = TcpStream::connect((address, port)).await {
            return stream;
        }
        assert!(
            start.elapsed() <= STARTUP_PATIENCE,
            "the traffic path never started listening on {address} port {port}"
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

    /// Every `Set-Cookie` line the answer carries.
    #[must_use]
    pub fn set_cookies(&self) -> Vec<String> {
        let lines = self.header("set-cookie");
        if lines.is_empty() {
            return Vec::new();
        }
        lines.lines().map(str::to_owned).collect()
    }

    /// The `Set-Cookie` line that sets this cookie, if there is one.
    #[must_use]
    pub fn set_cookie(&self, name: &str) -> Option<String> {
        self.set_cookies()
            .into_iter()
            .find(|line| line.starts_with(&format!("{name}=")))
    }

    /// The value a named cookie is set to, without its attributes.
    #[must_use]
    pub fn cookie_value(&self, name: &str) -> Option<String> {
        let line = self.set_cookie(name)?;
        let pair = line.split(';').next()?;
        pair.split_once('=').map(|(_, value)| value.to_owned())
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
            // Every occurrence is kept, joined by a newline. A response may
            // carry several `Set-Cookie` lines, and keeping only the last
            // would hide a proxy that replaces the application's cookies
            // where it must add to them.
            headers
                .entry(name.trim().to_ascii_lowercase())
                .and_modify(|kept: &mut String| {
                    kept.push('\n');
                    kept.push_str(value.trim());
                })
                .or_insert_with(|| value.trim().to_owned());
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

/// Renders an optional string as a JSON string or `null`.
fn quoted_or_null(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_owned(), |text| format!("\"{text}\""))
}

/// A request naming a host and a path of its own.
#[must_use]
pub fn request_to(host: &str, path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n")
}

/// A plain request a keep-alive connection can carry.
#[must_use]
pub fn plain_request() -> String {
    "GET / HTTP/1.1\r\nHost: ek-ek.test\r\n\r\n".to_owned()
}

/// A request that carries one cookie.
#[must_use]
pub fn request_with_cookie(name: &str, value: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: ek-ek.test\r\nCookie: {name}={value}\r\n\r\n")
}

/// A request that carries a whole `Cookie` line as given.
#[must_use]
pub fn request_with_cookie_line(line: &str) -> String {
    format!("GET / HTTP/1.1\r\nHost: ek-ek.test\r\nCookie: {line}\r\n\r\n")
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
    /// How many handshakes were refused for want of a certificate.
    pub tls_handshakes_refused: u64,
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
            tls_handshakes_refused: field(line, "tls_handshakes_refused")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
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

/// One entry of a status report's member health list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberHealthLine {
    /// The pool the member belongs to.
    pub pool: String,
    /// The member itself.
    pub member: String,
    /// Whether it is taking traffic.
    pub healthy: bool,
    /// How many times it has changed state.
    pub transitions: u64,
}

/// One entry of a status report's UDP session list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UdpSessionLine {
    /// The frontend holding the sessions.
    pub frontend: String,
    /// How many it holds right now.
    pub count: u64,
    /// The most it will hold.
    pub limit: u64,
}

/// Reads the UDP session list out of a JSON line.
fn udp_sessions(line: &str) -> Vec<UdpSessionLine> {
    let Some(at) = line.find(r#""udp_sessions":["#) else {
        return Vec::new();
    };
    let rest = &line[at + r#""udp_sessions":["#.len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };

    rest[..end]
        .split("},")
        .filter(|part| part.contains("\"frontend\""))
        .map(|part| UdpSessionLine {
            frontend: field(part, "frontend").unwrap_or_default(),
            count: field(part, "count")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            limit: field(part, "limit")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
        .collect()
}

/// Reads the member health list out of a JSON line.
fn member_health(line: &str) -> Vec<MemberHealthLine> {
    let Some(at) = line.find(r#""member_health":["#) else {
        return Vec::new();
    };
    let rest = &line[at + r#""member_health":["#.len()..];
    let Some(end) = rest.find(']') else {
        return Vec::new();
    };

    rest[..end]
        .split("},")
        .filter(|part| part.contains("\"member\""))
        .map(|part| MemberHealthLine {
            pool: field(part, "pool").unwrap_or_default(),
            member: field(part, "member").unwrap_or_default(),
            healthy: part.contains(r#""healthy":true"#),
            transitions: field(part, "transitions")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
        .collect()
}
