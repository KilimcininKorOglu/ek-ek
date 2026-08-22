// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command line entry point.
//!
//! One binary runs two processes (ADR-0002). `node-agent` is what an operator
//! starts; it supervises `data-plane` and replaces it when a listener changes.

use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};

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
    DataPlane(DataPlaneArgs),
}

#[derive(Args)]
struct DataPlaneArgs {
    /// Unix socket the node agent listens on
    #[arg(long, default_value = ek_ek_ipc::SOCKET_PATH)]
    agent_socket: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::NodeAgent => {
            println!("node-agent is not implemented yet");
        }
        Command::DataPlane(args) => return run_data_plane(&args),
    }

    ExitCode::SUCCESS
}

/// Starts the traffic path.
///
/// The agent has to be there. Without it there is no configuration, and a
/// process serving nothing looks exactly like a node that was never
/// configured, which is the one failure an operator must not have to guess at.
fn run_data_plane(args: &DataPlaneArgs) -> ExitCode {
    // Installed before anything else, so a failure while collecting the first
    // configuration is a log record rather than a line nobody structured.
    // The level comes from the configuration and is applied when it arrives
    // (ADR-0037).
    if let Err(error) = ek_ek_log::install(ek_ek_log::Level::default()) {
        eprintln!("data-plane: the logger could not be installed: {error}");
        return ExitCode::FAILURE;
    }

    let link = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime.block_on(ek_ek_dataplane::AgentLink::establish(&args.agent_socket)),
        Err(error) => {
            eprintln!("data-plane: a runtime could not be started: {error}");
            return ExitCode::FAILURE;
        }
    };

    let link = match link {
        Ok(link) => link,
        Err(error) => {
            eprintln!("data-plane: {error}");
            return ExitCode::FAILURE;
        }
    };

    match ek_ek_dataplane::build(link) {
        Ok(server) => server.run_forever(),
        Err(error) => {
            eprintln!("data-plane: {error}");
            ExitCode::FAILURE
        }
    }
}
