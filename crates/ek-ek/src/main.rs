// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command line entry point.
//!
//! One binary runs two processes (ADR-0002). `node-agent` is what an operator
//! starts; it supervises `data-plane` and replaces it when a listener changes.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "ek-ek",
    version,
    about = "Load balancer with built-in high availability",
    long_about = "Load balancer with built-in high availability.\n\n\
                  One binary runs two processes. Start `node-agent`; it \
                  supervises the `data-plane` process for you."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the node agent: configuration store, cluster, VRRP and web interface
    NodeAgent,

    /// Run the traffic path. Started by node-agent, not meant to be run directly
    DataPlane,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::NodeAgent => {
            println!("node-agent is not implemented yet");
        }
        Command::DataPlane => {
            println!("data-plane is not implemented yet");
        }
    }

    ExitCode::SUCCESS
}
