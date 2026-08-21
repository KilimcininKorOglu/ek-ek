// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Generating HTTP load from inside the cluster and reading the result.
//!
//! The generator runs in a node container, not on the host. A published port
//! would put docker's port forwarding in the measured path, and that path drops
//! connections on macOS under load, which would read as a fault in the system
//! under test rather than in the measurement.

use std::time::Duration;

use crate::cluster::Cluster;
use crate::error::{Error, Result};
use crate::node::Node;

/// What one load run produced.
///
/// Failures are counted separately from requests sent, because a run that sent
/// nothing and a run that failed everything are different faults.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadReport {
    /// Requests actually attempted.
    pub sent: u64,
    /// Requests that did not come back with a 2xx response.
    pub failed: u64,
    /// Median response time in milliseconds.
    pub p50_ms: f64,
    /// 95th percentile response time in milliseconds.
    pub p95_ms: f64,
    /// Slowest response in milliseconds.
    pub max_ms: f64,
    /// The first failure, kept so a report explains itself.
    pub first_error: Option<String>,
}

impl LoadReport {
    /// Reads the generator's `key=value` output.
    pub fn parse(text: &str) -> Result<Self> {
        let mut sent = None;
        let mut failed = None;
        let mut p50 = None;
        let mut p95 = None;
        let mut max = None;
        let mut first_error = None;

        for line in text.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            match key {
                "sent" => sent = value.parse().ok(),
                "failed" => failed = value.parse().ok(),
                "p50_ms" => p50 = value.parse().ok(),
                "p95_ms" => p95 = value.parse().ok(),
                "max_ms" => max = value.parse().ok(),
                "first_error" if !value.is_empty() => first_error = Some(value.to_string()),
                _ => {}
            }
        }

        let missing = |field: &str| Error::new(format!("load output has no {field}:\n{text}"));
        Ok(Self {
            sent: sent.ok_or_else(|| missing("sent"))?,
            failed: failed.ok_or_else(|| missing("failed"))?,
            p50_ms: p50.ok_or_else(|| missing("p50_ms"))?,
            p95_ms: p95.ok_or_else(|| missing("p95_ms"))?,
            max_ms: max.ok_or_else(|| missing("max_ms"))?,
            first_error,
        })
    }
}

impl Cluster {
    /// Sends HTTP requests from a node at a fixed rate and reports the result.
    ///
    /// The generator is built for Linux and installed on the nodes on first
    /// use. `target` is an address on the lab network, for example the address
    /// of a backend or a VIP.
    pub fn load(
        &self,
        from: &Node,
        target: &str,
        requests_per_second: u32,
        duration: Duration,
    ) -> Result<LoadReport> {
        let binary = self.install_binary("ek-ek-itest", "ek-ek-loadgen")?;
        // The generator stops on its own, but a hung connection must not hold
        // the test open past the window it was given.
        let limit = (duration.as_secs() + 15).to_string();
        let output = from.run(&[
            "timeout",
            &limit,
            &binary,
            "--target",
            target,
            "--rate",
            &requests_per_second.to_string(),
            "--duration-ms",
            &duration.as_millis().to_string(),
        ])?;
        if !output.ok() {
            return Err(Error::new(format!(
                "load generator on {} exited with {:?}\nstdout: {}\nstderr: {}",
                from.name(),
                output.code,
                output.stdout,
                output.stderr
            )));
        }
        LoadReport::parse(&output.stdout)
    }
}
