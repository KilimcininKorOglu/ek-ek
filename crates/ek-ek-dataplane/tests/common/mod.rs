// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A stand-in for `node-agent`, and the configurations the tests deliver.
//!
//! The agent itself is built later. What the traffic path needs from it is
//! the socket and the protocol, so that is what this provides.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use ek_ek_config::{
    ApplicationProtocol, Backend, BackendId, BackendMember, Config, ConnectionPooling, Frontend,
    FrontendId, Http2, LoadBalancingAlgorithm, MemberId, NodeId, NodeRole, ProxyProtocol,
    SchemaVersion, SessionStickiness, TransportProtocol, Vip, VipId,
};
use ek_ek_ipc::{AgentMessage, ConfigUpdate, DataPlaneMessage, decode, encode};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

fn address(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(127, 0, 0, last))
}

/// A valid configuration with `members` backend members.
pub fn config(members: u16) -> Config {
    Config {
        schema_version: SchemaVersion::CURRENT,
        nodes: vec![ek_ek_config::Node {
            id: NodeId::new("node1"),
            address: address(1),
            roles: vec![NodeRole::ControlPlane, NodeRole::DataPlane],
        }],
        vips: vec![Vip {
            id: VipId::new("vip-web"),
            address: address(1),
            prefix_length: 8,
            interface: "lo".to_owned(),
            preferred_node: Some(NodeId::new("node1")),
        }],
        frontends: vec![Frontend {
            id: FrontendId::new("web"),
            vip: VipId::new("vip-web"),
            port: 8080,
            transport: TransportProtocol::Tcp,
            application: ApplicationProtocol::Http,
            tls: None,
            proxy_protocol: ProxyProtocol::Disabled,
            routing_rules: Vec::new(),
            sni_rules: Vec::new(),
            default_backend: Some(BackendId::new("web")),
            http2: Http2::Enabled,
            connect_timeout_seconds: 5,
            request_timeout_seconds: 60,
            idle_timeout_seconds: 0,
            drain_timeout_seconds: 5,
            udp_session_limit: 0,
        }],
        backends: vec![Backend {
            id: BackendId::new("web"),
            members: (1..=members)
                .map(|number| BackendMember {
                    id: MemberId::new(format!("web-{number}")),
                    address: address(u8::try_from(number).unwrap_or(u8::MAX)),
                    port: 9000 + number,
                    weight: 1,
                    admin_state: ek_ek_config::AdminState::Enabled,
                })
                .collect(),
            algorithm: LoadBalancingAlgorithm::RoundRobin,
            health_check: None,
            stickiness: SessionStickiness::Disabled,
            connection_pooling: ConnectionPooling::Enabled,
        }],
        certificates: Vec::new(),
        dns_providers: Vec::new(),
        stickiness_key: String::new(),
    }
}

/// A configuration validation refuses: the frontend names a backend that is
/// not there.
pub fn invalid_config() -> Config {
    let mut config = config(1);
    config.frontends[0].default_backend = Some(BackendId::new("backend-missing"));
    config
}

pub fn update(generation: u64, config: Config) -> ConfigUpdate {
    ConfigUpdate { generation, config }
}

/// A stand-in `node-agent`.
pub struct Agent {
    path: PathBuf,
    initial: broadcast::Sender<String>,
    heard: mpsc::UnboundedReceiver<DataPlaneMessage>,
    heard_sender: mpsc::UnboundedSender<DataPlaneMessage>,
    greeting: std::sync::Arc<std::sync::Mutex<(u64, String)>>,
    accept: Option<JoinHandle<()>>,
    /// Cuts open connections as well as the accept loop. Aborting only the
    /// loop would leave the other side happily connected, so a test meaning
    /// to take the agent away would take nothing away.
    hangup: broadcast::Sender<()>,
}

impl Agent {
    /// Starts an agent that answers every greeting with `first`.
    pub async fn start(path: &Path, first: &ConfigUpdate) -> Self {
        let (initial, _) = broadcast::channel(64);
        let (heard_sender, heard) = mpsc::unbounded_channel();
        let greeting = std::sync::Arc::new(std::sync::Mutex::new((
            first.generation,
            encode(&AgentMessage::Config(first.clone())).expect("the delivery must encode"),
        )));

        let mut agent = Self {
            path: path.to_path_buf(),
            initial,
            heard,
            heard_sender,
            greeting,
            accept: None,
            hangup: broadcast::channel(1).0,
        };
        agent.listen().await;
        agent
    }

    async fn listen(&mut self) {
        let listener = UnixListener::bind(&self.path).expect("the socket must bind");
        let pushes = self.initial.clone();
        let heard = self.heard_sender.clone();
        let greeting = std::sync::Arc::clone(&self.greeting);
        let hangup = self.hangup.clone();

        self.accept = Some(tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let mut pushed = pushes.subscribe();
                let mut cut = hangup.subscribe();
                let heard = heard.clone();
                let greeting = greeting
                    .lock()
                    .ok()
                    .map(|held| held.clone())
                    .unwrap_or_default();

                tokio::spawn(async move {
                    let (reader, mut writer) = stream.into_split();
                    let mut lines = BufReader::new(reader).lines();

                    // A real agent reads the greeting first and only sends a
                    // configuration the other side does not already hold.
                    // Resending regardless would make every reconnection look
                    // like a configuration change.
                    let Ok(Some(line)) = lines.next_line().await else {
                        return;
                    };
                    let Ok(hello) = decode::<DataPlaneMessage>(&line) else {
                        return;
                    };
                    let held = match &hello {
                        DataPlaneMessage::Hello(hello) => hello.generation,
                        _ => None,
                    };
                    let _ = heard.send(hello);

                    if held != Some(greeting.0)
                        && writer.write_all(greeting.1.as_bytes()).await.is_err()
                    {
                        return;
                    }

                    loop {
                        tokio::select! {
                            line = lines.next_line() => {
                                match line {
                                    Ok(Some(line)) => {
                                        if let Ok(message) = decode::<DataPlaneMessage>(&line) {
                                            let _ = heard.send(message);
                                        }
                                    }
                                    _ => return,
                                }
                            }
                            push = pushed.recv() => {
                                let Ok(push) = push else { return };
                                if writer.write_all(push.as_bytes()).await.is_err() {
                                    return;
                                }
                            }
                            _ = cut.recv() => return,
                        }
                    }
                });
            }
        }));
    }

    /// Sends a configuration to whoever is connected.
    pub fn push(&self, update: &ConfigUpdate) {
        let line = encode(&AgentMessage::Config(update.clone())).expect("the delivery must encode");
        let _ = self.initial.send(line);
    }

    /// Changes what a new connection is greeted with.
    pub fn set_greeting(&self, update: &ConfigUpdate) {
        let line = encode(&AgentMessage::Config(update.clone())).expect("the delivery must encode");
        if let Ok(mut held) = self.greeting.lock() {
            *held = (update.generation, line);
        }
    }

    /// Waits until the traffic path's own link is connected.
    ///
    /// Only the link greets with a generation; the short connection that
    /// collects the first configuration greets with none. Waiting for the
    /// difference is what keeps a push from being sent to nobody.
    pub async fn connected(&mut self) -> ek_ek_ipc::Hello {
        loop {
            if let DataPlaneMessage::Hello(hello) = self.heard().await
                && hello.generation.is_some()
            {
                return hello;
            }
        }
    }

    /// Waits for the next greeting, whichever connection it comes from.
    pub async fn heard_hello(&mut self) -> ek_ek_ipc::Hello {
        loop {
            if let DataPlaneMessage::Hello(hello) = self.heard().await {
                return hello;
            }
        }
    }

    /// Waits for the next message from the traffic path.
    pub async fn heard(&mut self) -> DataPlaneMessage {
        tokio::time::timeout(Duration::from_secs(5), self.heard.recv())
            .await
            .expect("the traffic path must say something within five seconds")
            .expect("the channel must stay open")
    }

    /// Waits for the next message of one kind, ignoring the others.
    pub async fn heard_status(&mut self) -> ek_ek_ipc::StatusReport {
        loop {
            if let DataPlaneMessage::Status(report) = self.heard().await {
                return report;
            }
        }
    }

    /// Waits for the next rejection, ignoring the others.
    pub async fn heard_rejection(&mut self) -> ek_ek_ipc::ConfigRejection {
        loop {
            if let DataPlaneMessage::ConfigRejected(rejection) = self.heard().await {
                return rejection;
            }
        }
    }

    /// Stops listening and removes the socket, the way a restarting agent
    /// would.
    pub fn stop(&mut self) {
        if let Some(accept) = self.accept.take() {
            accept.abort();
        }
        let _ = self.hangup.send(());
        let _ = std::fs::remove_file(&self.path);
    }

    /// Starts listening again on the same path.
    pub async fn restart(&mut self) {
        self.stop();
        self.listen().await;
    }
}

impl Drop for Agent {
    fn drop(&mut self) {
        self.stop();
    }
}
