// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Command line entry point.
//!
//! One binary runs two processes (ADR-0002). `node-agent` is what an operator
//! starts; it supervises `data-plane` and replaces it when a listener changes.

use std::net::Ipv4Addr;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};

mod acme;
mod cluster;
mod renew;
mod report;
mod secret;

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
    NodeAgent(NodeAgentArgs),

    /// Run the traffic path. Started by node-agent, not meant to be run directly
    DataPlane(DataPlaneArgs),

    /// Show which node should hold which virtual address, and with what numbers
    Matrix(MatrixArgs),

    /// Obtain one certificate from the configured ACME server and store it
    Acme(AcmeArgs),

    /// Renew the certificates that are running out and warn about the rest
    Renew(RenewArgs),

    /// Work with the credentials the configuration refers to
    #[command(subcommand)]
    Secret(SecretCommand),

    /// Work with the authority every node's peer certificate comes from
    #[command(subcommand)]
    Cluster(ClusterCommand),
}

#[derive(Subcommand)]
enum ClusterCommand {
    /// Create the cluster authority. Run once, on the first node
    Init(ClusterInitArgs),

    /// Print the authority's fingerprint, as a join token carries it
    Fingerprint(ClusterFingerprintArgs),

    /// Sign a peer certificate for one node, or keep the one it has
    Enroll(ClusterEnrollArgs),

    /// Answer peers on the peer port
    Serve(ClusterServeArgs),

    /// Run this node's consensus member until it is told to stop
    Node(ClusterNodeArgs),

    /// Print what this node holds, without asking anybody
    Status(ClusterStatusArgs),

    /// Ask one peer whether it is there
    Ping(ClusterPingArgs),
}

#[derive(Args)]
struct ClusterInitArgs {
    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,

    /// Configuration document to start an empty store from
    #[arg(long)]
    config: Option<String>,
}

#[derive(Args)]
struct ClusterFingerprintArgs {
    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,
}

#[derive(Args)]
struct ClusterEnrollArgs {
    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,

    /// Identity of the node the certificate is for
    #[arg(long)]
    node: String,

    /// Address to carry beside the identity. May be given more than once
    #[arg(long = "address")]
    addresses: Vec<String>,

    /// Directory to write the certificate, the key and the authority to
    #[arg(long)]
    out_dir: String,

    /// Decide against this moment, in seconds since the epoch, instead of the
    /// system clock. Answers "what is due later?" without waiting for later
    #[arg(long)]
    now: Option<i64>,

    /// Sign again even when the certificate on disk is not due yet
    #[arg(long)]
    force: bool,
}

#[derive(Args)]
struct ClusterNodeArgs {
    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,

    /// Identity of this node
    #[arg(long)]
    node: String,

    /// Directory holding the certificate, the key and the authority
    #[arg(long)]
    material: String,

    /// Address to listen for peers on
    #[arg(long, default_value_t = format!("0.0.0.0:{}", ek_ek_peer::DEFAULT_PORT))]
    listen: String,

    /// Bring the cluster into being with these members, as
    /// `name=address,name=address`. Run on one node, once
    #[arg(long)]
    initialise: Option<String>,

    /// Configuration file to watch and put through consensus when it changes
    #[arg(long)]
    apply: Option<String>,

    /// File to write this node's share of the live ACME challenge answers to,
    /// for the agent to deliver to the traffic path
    #[arg(long)]
    challenges: Option<String>,

    /// Order certificates that are running out, while this node leads
    #[arg(long)]
    acme: bool,
}

#[derive(Args)]
struct ClusterStatusArgs {
    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,
}

#[derive(Args)]
struct ClusterServeArgs {
    /// Address to listen on
    #[arg(long, default_value_t = format!("0.0.0.0:{}", ek_ek_peer::DEFAULT_PORT))]
    listen: String,

    /// Identity of this node
    #[arg(long)]
    node: String,

    /// Directory holding the certificate, the key and the authority
    #[arg(long)]
    material: String,

    /// How many peers to answer before stopping
    #[arg(long, default_value_t = 1)]
    connections: u32,
}

#[derive(Args)]
struct ClusterPingArgs {
    /// Address to dial
    #[arg(long)]
    to: String,

    /// Identity the peer must prove it has
    #[arg(long)]
    expect: String,

    /// Identity of this node
    #[arg(long)]
    node: String,

    /// Directory holding the certificate, the key and the authority
    #[arg(long)]
    material: String,
}

#[derive(Subcommand)]
enum SecretCommand {
    /// Store one credential, such as a DNS provider's shared key
    Set(SecretSetArgs),
}

#[derive(Args)]
struct SecretSetArgs {
    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,

    /// Identity the configuration refers to this credential by
    #[arg(long)]
    id: String,

    /// File holding the value. Never passed as an argument, because arguments
    /// are visible to every user on the machine
    #[arg(long)]
    from_file: String,

    /// Configuration document to start an empty store from
    #[arg(long)]
    config: Option<String>,
}

#[derive(Args)]
struct AcmeArgs {
    /// Configuration document to read
    #[arg(long)]
    config: String,

    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,

    /// Identity of the certificate to obtain
    #[arg(long)]
    certificate: String,

    /// File the live challenge answers are written to, for the agent to
    /// deliver to the traffic path
    #[arg(long)]
    challenges: String,
}

#[derive(Args)]
struct RenewArgs {
    /// Configuration document to read
    #[arg(long)]
    config: String,

    /// Directory the configuration store lives in
    #[arg(long, default_value = ek_ek_store::DEFAULT_DATA_DIRECTORY)]
    data_dir: String,

    /// File the live challenge answers are written to, for the agent to
    /// deliver to the traffic path
    #[arg(long)]
    challenges: String,

    /// Decide against this moment, in seconds since the epoch, instead of the
    /// system clock. Answers "what is due later?" without waiting for later
    #[arg(long)]
    now: Option<i64>,

    /// File to write the Prometheus exposition for the certificates to
    #[arg(long)]
    metrics: Option<String>,
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
struct NodeAgentArgs {
    /// Unix socket the traffic path takes its configuration from
    #[arg(long, default_value = ek_ek_ipc::SOCKET_PATH)]
    socket: String,

    /// Configuration document to deliver to the traffic path
    #[arg(long)]
    config: String,

    /// Program to run as the traffic path. Defaults to this binary, because
    /// one binary runs both processes (ADR-0002)
    #[arg(long)]
    data_plane: Option<String>,

    /// How often the traffic path is asked whether it is still answering
    #[arg(long, default_value_t = 500)]
    asking_ms: u64,

    /// How many questions may go unanswered before it counts as crashed
    #[arg(long, default_value_t = 3)]
    patience: u32,

    /// This node's own address, which advertisements come from. Given only
    /// when this node runs a virtual router
    #[arg(long)]
    address: Option<Ipv4Addr>,

    /// Another node's address. May be given more than once. Unicast only
    #[arg(long = "peer")]
    peers: Vec<Ipv4Addr>,

    /// Interface the virtual addresses are put on
    #[arg(long, default_value = "eth0")]
    interface: String,

    /// Virtual address to carry, written `address/prefix`. May be given more
    /// than once
    #[arg(long = "virtual-address")]
    virtual_addresses: Vec<String>,

    /// Which virtual router this is
    #[arg(long, default_value_t = 51)]
    vrid: u8,

    /// The claim this node makes when everything is well
    #[arg(long, default_value_t = 100)]
    priority: u8,

    /// How often an advertisement goes out
    #[arg(long, default_value_t = 300)]
    interval_ms: u64,

    /// Leave the role with whoever holds it, even when this node is stronger
    #[arg(long)]
    no_preempt: bool,

    /// Take the addresses without announcing the move. The negative control
    /// for a measurement, never something an installation wants
    #[arg(long)]
    silent: bool,

    /// Give the addresses up when the default gateway stops answering
    #[arg(long)]
    watch_gateway: bool,

    /// How often the gateway is asked
    #[arg(long, default_value_t = 2_000)]
    check_interval_ms: u64,

    /// How many answers have to go missing before the claim is lowered
    #[arg(long, default_value_t = 3)]
    failures: u32,

    /// What the claim is lowered to when this node cannot serve
    #[arg(long, default_value_t = 1)]
    demoted_priority: u8,
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
        Command::NodeAgent(args) => run_node_agent(&args),
        Command::DataPlane(args) => run_data_plane(&args),
        Command::Matrix(args) => show_matrix(&args),
        Command::Acme(args) => acme::order(&acme::Arguments {
            config: &args.config,
            data_dir: &args.data_dir,
            certificate: &args.certificate,
            challenges: &args.challenges,
        }),
        Command::Renew(args) => renew::sweep(&renew::Arguments {
            config: &args.config,
            data_dir: &args.data_dir,
            challenges: &args.challenges,
            at: args.now,
            metrics: args.metrics.as_deref(),
        }),
        Command::Secret(SecretCommand::Set(args)) => secret::set(&secret::Arguments {
            data_dir: &args.data_dir,
            id: &args.id,
            from_file: &args.from_file,
            config: args.config.as_deref(),
        }),
        Command::Cluster(ClusterCommand::Init(args)) => cluster::init(&cluster::InitArguments {
            data_dir: &args.data_dir,
            config: args.config.as_deref(),
        }),
        Command::Cluster(ClusterCommand::Fingerprint(args)) => {
            cluster::fingerprint(&cluster::FingerprintArguments {
                data_dir: &args.data_dir,
            })
        }
        Command::Cluster(ClusterCommand::Enroll(args)) => {
            cluster::enroll(&cluster::EnrollArguments {
                data_dir: &args.data_dir,
                node: &args.node,
                addresses: &args.addresses,
                out_dir: &args.out_dir,
                at: args.now,
                force: args.force,
            })
        }
        Command::Cluster(ClusterCommand::Serve(args)) => cluster::serve(&cluster::ServeArguments {
            listen: &args.listen,
            node: &args.node,
            material: &args.material,
            connections: args.connections,
        }),
        Command::Cluster(ClusterCommand::Node(args)) => cluster::node(&cluster::NodeArguments {
            data_dir: &args.data_dir,
            node: &args.node,
            material: &args.material,
            listen: &args.listen,
            initialise: args.initialise.as_deref(),
            apply: args.apply.as_deref(),
            challenges: args.challenges.as_deref(),
            acme: args.acme,
        }),
        Command::Cluster(ClusterCommand::Status(args)) => {
            cluster::status(&cluster::StatusArguments {
                data_dir: &args.data_dir,
            })
        }
        Command::Cluster(ClusterCommand::Ping(args)) => cluster::ping(&cluster::PingArguments {
            to: &args.to,
            expect: &args.expect,
            node: &args.node,
            material: &args.material,
        }),
    }
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

/// Runs the node agent: the traffic path's supervisor and the virtual router.
///
/// One binary, two processes (ADR-0002). This is the one an operator starts;
/// it starts the other and replaces it when it goes.
fn run_node_agent(args: &NodeAgentArgs) -> ExitCode {
    if let Err(error) = ek_ek_log::install(ek_ek_log::Level::default()) {
        eprintln!("node-agent: the logger could not be installed: {error}");
        return ExitCode::FAILURE;
    }

    // This binary by default, because the two processes ship as one file. An
    // override exists so a measurement can point the supervision at something
    // that crashes on purpose.
    let program = match args.data_plane.clone() {
        Some(program) => program,
        None => match std::env::current_exe() {
            Ok(path) => path.to_string_lossy().into_owned(),
            Err(error) => {
                eprintln!("node-agent: this binary's own path could not be read: {error}");
                return ExitCode::FAILURE;
            }
        },
    };

    let router = match args.address {
        None => None,
        Some(address) => {
            let mut carried = Vec::with_capacity(args.virtual_addresses.len());
            for text in &args.virtual_addresses {
                match ek_ek_agent::carrying(text) {
                    Ok(one) => carried.push(one),
                    Err(complaint) => {
                        eprintln!("node-agent: {complaint}");
                        return ExitCode::FAILURE;
                    }
                }
            }
            Some(ek_ek_agent::Vrrp {
                address,
                peers: args.peers.clone(),
                interface: args.interface.clone(),
                carried,
                vrid: args.vrid,
                priority: args.priority,
                interval: Duration::from_millis(args.interval_ms),
                preempt: !args.no_preempt,
                silent: args.silent,
                watch_gateway: args.watch_gateway,
                check_interval: Duration::from_millis(args.check_interval_ms),
                failures: args.failures,
                demoted_priority: args.demoted_priority,
            })
        }
    };

    ek_ek_agent::run(ek_ek_agent::Plan {
        socket: &args.socket,
        config: &args.config,
        program: &program,
        arguments: vec![
            "data-plane".to_owned(),
            "--agent-socket".to_owned(),
            args.socket.clone(),
        ],
        asking: Duration::from_millis(args.asking_ms),
        patience: args.patience,
        router,
    })
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
    ek_ek_dataplane::end_on_a_panic();

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
