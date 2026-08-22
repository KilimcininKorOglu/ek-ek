// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Watching the wire from inside a node.
//!
//! Some of what the product must do fails silently when it is missing: a VIP
//! moves but no gratuitous ARP goes out, or an advertisement is built by hand
//! and no peer can parse it. Neither shows up in application state. Both show
//! up in a capture, and `tcpdump` parses the packet independently, so a wrong
//! wire format is caught by something other than the code that produced it.

use std::time::Duration;

use crate::error::{Error, Result};
use crate::node::{Background, Node};

/// The interface the lab network sits on.
const LAB: &str = "eth0";

/// A running capture on one node.
pub struct Capture {
    running: Background,
    filter: String,
}

impl Capture {
    /// Starts `tcpdump` and returns once it is actually listening.
    ///
    /// It returns only after the "listening on" banner, because traffic sent
    /// before that is never seen and reads as an absent packet.
    ///
    /// `filter` is pcap syntax, for example `"proto 112"` or `"arp"`. The
    /// capture stops on its own after `packets` frames or `window`, whichever
    /// comes first, so a test can never leave one behind.
    pub fn start(node: &Node, filter: &str, packets: usize, window: Duration) -> Result<Self> {
        Self::run(node, LAB, filter, packets, window, false)
    }

    /// Starts a capture on an interface other than the lab one.
    ///
    /// Kept apart from [`Capture::start`] because almost everything is
    /// measured on the lab network, and naming the interface at every call
    /// site would say nothing at the ones that use it.
    pub fn on(
        node: &Node,
        interface: &str,
        filter: &str,
        packets: usize,
        window: Duration,
    ) -> Result<Self> {
        Self::run(node, interface, filter, packets, window, false)
    }

    /// Starts a capture that prints what is inside each packet.
    ///
    /// Some fields only appear when tcpdump is asked to be verbose: the
    /// addresses a VRRP advertisement carries, and the TTL of the IP header
    /// that carried it. Kept apart from [`Capture::start`] because the extra
    /// detail changes every line, and a measurement that matches on text
    /// should choose which shape it is reading.
    pub fn verbose(node: &Node, filter: &str, packets: usize, window: Duration) -> Result<Self> {
        Self::run(node, LAB, filter, packets, window, true)
    }

    fn run(
        node: &Node,
        interface: &str,
        filter: &str,
        packets: usize,
        window: Duration,
        verbose: bool,
    ) -> Result<Self> {
        let seconds = window.as_secs().max(1).to_string();
        let mut argv = vec![
            "timeout", &seconds, "tcpdump", "-i", interface, "-n", "-l", "-e",
        ];
        if verbose {
            argv.push("-v");
        }
        let count = packets.to_string();
        argv.push("-c");
        argv.push(&count);
        argv.push(filter);
        let running = node.spawn(&argv)?;
        running.wait_for_stderr("listening on", Duration::from_secs(10))?;
        Ok(Self {
            running,
            filter: filter.to_string(),
        })
    }

    /// Waits for the capture to end and returns what it saw.
    pub fn finish(self) -> Result<CaptureResult> {
        let filter = self.filter;
        let output = self.running.finish()?;
        Ok(CaptureResult {
            text: output.stdout,
            filter,
        })
    }
}

/// Packets seen by one capture.
#[derive(Debug, Clone)]
pub struct CaptureResult {
    text: String,
    filter: String,
}

impl CaptureResult {
    /// Every captured line, as `tcpdump` printed it.
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The filter this capture ran with.
    pub fn filter(&self) -> &str {
        &self.filter
    }

    /// Number of captured packets.
    pub fn packets(&self) -> usize {
        self.text
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
    }

    /// True when any captured line contains the text.
    pub fn contains(&self, needle: &str) -> bool {
        self.text.contains(needle)
    }

    /// How many captured lines contain the text.
    pub fn count(&self, needle: &str) -> usize {
        self.text
            .lines()
            .filter(|line| line.contains(needle))
            .count()
    }

    /// Fails with the whole capture attached when the text is missing.
    ///
    /// The assertion message carries the packets that were seen, because
    /// "expected an ARP reply" without them says nothing about what went wrong.
    pub fn expect_contains(&self, needle: &str) -> Result<()> {
        if self.contains(needle) {
            return Ok(());
        }
        Err(Error::new(format!(
            "no captured packet contains {needle:?}\nfilter: {}\ncaptured {} packet(s):\n{}",
            self.filter,
            self.packets(),
            self.text
        )))
    }
}
