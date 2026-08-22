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

    /// Show which node should hold which virtual address, and with what numbers
    Matrix(MatrixArgs),
}

#[derive(Args)]
struct MatrixArgs {
    /// Configuration document to read
    #[arg(long)]
    config: String,

    /// Print the matrix as JSON instead of as a table
    #[arg(long)]
    json: bool,
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
        Command::Matrix(args) => return show_matrix(&args),
    }

    ExitCode::SUCCESS
}

/// Prints the virtual router matrix a configuration produces.
///
/// The numbers on the wire are computed rather than configured (ADR-0006), so
/// an operator has no other way to see them. This is that way, and it is the
/// same function the node agent runs, not a second implementation.
fn show_matrix(args: &MatrixArgs) -> ExitCode {
    let document = match std::fs::read_to_string(&args.config) {
        Ok(document) => document,
        Err(error) => {
            eprintln!("matrix: {} could not be read: {error}", args.config);
            return ExitCode::FAILURE;
        }
    };

    let config: ek_ek_config::Config = match serde_json::from_str(&document) {
        Ok(config) => config,
        Err(error) => {
            eprintln!("matrix: {} is not a configuration: {error}", args.config);
            return ExitCode::FAILURE;
        }
    };

    // A document validation refuses is a document that will never be stored,
    // and a matrix computed from one would describe a cluster that cannot
    // exist. The codes are printed as they are: turning them into sentences
    // is the interface layer's job, not this model's (ADR-0015).
    if let Err(faults) = ek_ek_config::validate(&config) {
        eprintln!("matrix: {} is not valid", args.config);
        for fault in faults.as_slice() {
            eprintln!("  {} {}", fault.path.as_text(), fault.code.key());
        }
        return ExitCode::FAILURE;
    }

    let matrix = ek_ek_config::matrix(&config);

    if args.json {
        match serde_json::to_string_pretty(&matrix) {
            Ok(written) => println!("{written}"),
            Err(error) => {
                eprintln!("matrix: the answer could not be written: {error}");
                return ExitCode::FAILURE;
            }
        }
        return ExitCode::SUCCESS;
    }

    let width = matrix
        .routers
        .iter()
        .map(|router| router.vip.as_str().len())
        .max()
        .unwrap_or(0)
        .max("VIP".len());

    println!("{:<width$}  VRID  ORDER", "VIP");
    for router in &matrix.routers {
        let order: Vec<String> = router
            .ranking
            .iter()
            .map(|placement| format!("{}({})", placement.node.as_str(), placement.priority))
            .collect();
        println!(
            "{:<width$}  {:>4}  {}",
            router.vip.as_str(),
            router.vrid,
            order.join(" > ")
        );
    }

    println!();
    for (node, count) in matrix.load() {
        println!("{} holds {count}", node.as_str());
    }

    // Two identities landing on the same number is what hashing does. It is
    // worth saying, because deleting the address that was in the way moves
    // this one back onto the number it asked for.
    let moved = matrix.moved_aside();
    if !moved.is_empty() {
        println!();
        for vip in moved {
            println!("{} did not get its first choice of VRID", vip.as_str());
        }
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
