// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The link to `node-agent`.
//!
//! Losing the agent must never cost traffic. The control plane can restart,
//! lose quorum or be upgraded, and the traffic path keeps serving the
//! configuration it already holds and reconnects behind the scenes
//! (ADR-0004). The only moment an absent agent is fatal is startup, because
//! then there is nothing to serve.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use ek_ek_config::validate;
use ek_ek_ipc::{
    AgentMessage, ConfigRejection, ConfigUpdate, DataPlaneMessage, Hello, decode, encode,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::error::{Error, ErrorKind, Result};
use crate::live::{LiveConfig, Status};

/// How long to wait before trying the agent again.
///
/// Fixed rather than growing, because the agent is a local process that
/// either comes back in seconds or is not coming back, and a growing delay
/// would only make the first case slower.
pub const RECONNECT_DELAY: Duration = Duration::from_millis(500);

/// How often a status report goes out.
pub const STATUS_INTERVAL: Duration = Duration::from_secs(5);

/// The traffic path's side of the connection to `node-agent`.
#[derive(Debug)]
pub struct AgentLink {
    socket: PathBuf,
    live: Arc<LiveConfig>,
    status: Arc<Status>,
    reconnect_delay: Duration,
    status_interval: Duration,
}

impl AgentLink {
    /// Connects, collects the first configuration and builds the link.
    ///
    /// The connection is closed again once the configuration is in hand. The
    /// server runs on its own runtime, and a socket opened here would belong
    /// to the runtime that opened it, so the link reconnects from inside the
    /// server instead. The greeting carries the generation already held, so
    /// the agent knows it does not have to resend.
    ///
    /// # Errors
    ///
    /// Returns [`ErrorKind::AgentUnreachable`] when the agent is not
    /// listening, and [`ErrorKind::InvalidConfig`] when its first delivery
    /// does not pass validation. Either way the process stops instead of
    /// serving nothing and looking configured.
    pub async fn establish(socket: impl AsRef<Path>) -> Result<Self> {
        let socket = socket.as_ref().to_path_buf();
        let mut stream = connect(&socket).await?;

        say_hello(&mut stream, None).await?;
        let update = read_first_config(&mut stream).await?;
        drop(stream);

        validate(&update.config).map_err(|errors| {
            Error::new(
                ErrorKind::InvalidConfig,
                format!(
                    "the agent's first delivery does not validate: {:?}",
                    errors.codes()
                ),
            )
        })?;

        let status = Arc::new(Status::new());
        status.config_applied();

        Ok(Self {
            socket,
            live: Arc::new(LiveConfig::new(update)),
            status,
            reconnect_delay: RECONNECT_DELAY,
            status_interval: STATUS_INTERVAL,
        })
    }

    /// Shortens the waits, so a test does not have to sit through them.
    #[must_use]
    pub fn with_intervals(mut self, reconnect: Duration, status: Duration) -> Self {
        self.reconnect_delay = reconnect;
        self.status_interval = status;
        self
    }

    /// Returns the configuration the traffic path serves from.
    #[must_use]
    pub fn live(&self) -> Arc<LiveConfig> {
        Arc::clone(&self.live)
    }

    /// Returns what this process reports about itself.
    #[must_use]
    pub fn status(&self) -> Arc<Status> {
        Arc::clone(&self.status)
    }

    /// Serves the link until told to stop, reconnecting as often as needed.
    ///
    /// Losing the agent never stops traffic. The loop keeps the configuration
    /// it already holds and simply tries again.
    pub async fn run(&self, mut stop: tokio::sync::watch::Receiver<bool>) {
        let mut first = true;

        loop {
            if *stop.borrow() {
                return;
            }

            if first {
                first = false;
            } else {
                tokio::select! {
                    () = tokio::time::sleep(self.reconnect_delay) => {}
                    _ = stop.changed() => return,
                }
            }

            // A link that ends is not a failure to report anywhere: the
            // traffic path keeps serving and simply tries again.
            if let Ok(mut open) = connect(&self.socket).await
                && say_hello(&mut open, Some(self.live.generation()))
                    .await
                    .is_ok()
            {
                let _ = self.serve(open, &mut stop).await;
            }
        }
    }

    async fn serve(
        &self,
        stream: UnixStream,
        stop: &mut tokio::sync::watch::Receiver<bool>,
    ) -> Result<()> {
        let (reader, mut writer) = stream.into_split();
        let mut lines = BufReader::new(reader).lines();
        let mut ticker = tokio::time::interval(self.status_interval);
        // The first tick fires immediately, so the agent learns the state as
        // soon as the link is up rather than one interval later.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                line = lines.next_line() => {
                    let line = line.map_err(|error| {
                        Error::new(ErrorKind::AgentGone, format!("the link failed: {error}"))
                    })?;
                    let Some(line) = line else {
                        return Err(Error::new(
                            ErrorKind::AgentGone,
                            "the agent closed the connection".to_owned(),
                        ));
                    };
                    self.handle(&line, &mut writer).await?;
                }
                _ = ticker.tick() => {
                    let report = self.status.report(self.live.generation());
                    write(&mut writer, &DataPlaneMessage::Status(report)).await?;
                }
                _ = stop.changed() => return Ok(()),
            }
        }
    }

    async fn handle(
        &self,
        line: &str,
        writer: &mut tokio::net::unix::OwnedWriteHalf,
    ) -> Result<()> {
        let message: AgentMessage = decode(line).map_err(|error| {
            Error::new(
                ErrorKind::Protocol,
                format!("the agent sent something unreadable: {error}"),
            )
        })?;

        let AgentMessage::Config(update) = message;
        let generation = update.generation;

        match self.live.apply(update) {
            Ok(()) => {
                self.status.config_applied();
                Ok(())
            }
            Err(errors) => {
                // The delivery is dropped and the process keeps serving what
                // it had. Saying so is what lets an operator find out why
                // their change did not take effect.
                self.status.config_rejected();
                write(
                    writer,
                    &DataPlaneMessage::ConfigRejected(ConfigRejection {
                        generation,
                        errors: errors.as_slice().to_vec(),
                    }),
                )
                .await
            }
        }
    }
}

async fn connect(socket: &Path) -> Result<UnixStream> {
    UnixStream::connect(socket).await.map_err(|error| {
        Error::new(
            ErrorKind::AgentUnreachable,
            format!("{} could not be reached: {error}", socket.display()),
        )
    })
}

async fn say_hello(stream: &mut UnixStream, generation: Option<u64>) -> Result<()> {
    let hello = DataPlaneMessage::Hello(Hello {
        pid: std::process::id(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
        generation,
    });
    let line = encode(&hello).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("the greeting could not be written out: {error}"),
        )
    })?;
    stream.write_all(line.as_bytes()).await.map_err(|error| {
        Error::new(
            ErrorKind::AgentGone,
            format!("the greeting could not be sent: {error}"),
        )
    })
}

async fn read_first_config(stream: &mut UnixStream) -> Result<ConfigUpdate> {
    let mut line = String::new();
    let read = BufReader::new(stream)
        .read_line(&mut line)
        .await
        .map_err(|error| {
            Error::new(
                ErrorKind::AgentGone,
                format!("the first delivery could not be read: {error}"),
            )
        })?;

    if read == 0 {
        return Err(Error::new(
            ErrorKind::AgentGone,
            "the agent closed the connection before sending a configuration".to_owned(),
        ));
    }

    let message: AgentMessage = decode(&line).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("the first delivery was unreadable: {error}"),
        )
    })?;
    let AgentMessage::Config(update) = message;
    Ok(update)
}

async fn write(
    writer: &mut tokio::net::unix::OwnedWriteHalf,
    message: &DataPlaneMessage,
) -> Result<()> {
    let line = encode(message).map_err(|error| {
        Error::new(
            ErrorKind::Protocol,
            format!("a message could not be written out: {error}"),
        )
    })?;
    writer.write_all(line.as_bytes()).await.map_err(|error| {
        Error::new(
            ErrorKind::AgentGone,
            format!("a message could not be sent: {error}"),
        )
    })
}
