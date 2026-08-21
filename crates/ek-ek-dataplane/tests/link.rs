// Copyright (C) 2026 Kerem Gok
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the link to `node-agent` and the in-process configuration swap must
//! hold true.
//!
//! Every rule is measured from both sides. The one criterion that cannot be
//! measured here is that a swap does not cut an open connection: that needs a
//! load generator against a running server, and lives in the integration
//! tests.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{Agent, config, invalid_config, update};
use ek_ek_config::{ApplicationProtocol, TransportProtocol, VipId};
use ek_ek_dataplane::{AgentLink, ErrorKind, ListenerKind, bindings};
use ek_ek_ipc::DataPlaneState;
use tempfile::TempDir;

/// Short enough that a test does not sit through the production waits.
const QUICK: Duration = Duration::from_millis(20);

struct Socket {
    _directory: TempDir,
    path: std::path::PathBuf,
}

fn socket() -> Socket {
    let directory = tempfile::tempdir().expect("a temporary directory must be available");
    let path = directory.path().join("agent.sock");
    Socket {
        _directory: directory,
        path,
    }
}

/// Runs the link in the background and hands back a way to stop it.
fn spawn(link: Arc<AgentLink>) -> tokio::sync::watch::Sender<bool> {
    let (stop_sender, stop) = tokio::sync::watch::channel(false);
    tokio::spawn(async move { link.run(stop).await });
    stop_sender
}

/// Waits for a condition, so a test does not depend on a fixed sleep.
async fn until(mut ready: impl FnMut() -> bool) -> bool {
    for _ in 0..500 {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn the_traffic_path_takes_its_first_config_from_the_agent() {
    let socket = socket();
    let _agent = Agent::start(&socket.path, &update(7, config(2))).await;

    let link = AgentLink::establish(&socket.path)
        .await
        .expect("the agent is listening and delivers a config");

    let live = link.live();
    assert_eq!(live.generation(), 7, "the delivery's generation is kept");
    assert_eq!(
        live.load().config.backends[0].members.len(),
        2,
        "and so is what it carried"
    );
    assert_eq!(link.status().counters().configs_applied, 1);
}

#[tokio::test]
async fn an_absent_agent_stops_the_start_rather_than_serving_nothing() {
    let socket = socket();

    let refused = AgentLink::establish(&socket.path)
        .await
        .expect_err("there is nobody to take a config from");
    assert_eq!(refused.kind(), ErrorKind::AgentUnreachable);
    assert!(
        !refused.diagnostic().is_empty(),
        "the log has to say what was unreachable"
    );

    // With an agent on the same path it starts, so the refusal is about the
    // agent being absent and nothing else.
    let _agent = Agent::start(&socket.path, &update(1, config(1))).await;
    AgentLink::establish(&socket.path)
        .await
        .expect("the same path works once somebody is listening");
}

#[tokio::test]
async fn a_first_delivery_that_does_not_validate_stops_the_start() {
    let socket = socket();
    let _agent = Agent::start(&socket.path, &update(1, invalid_config())).await;

    let refused = AgentLink::establish(&socket.path)
        .await
        .expect_err("there is nothing safe to serve");
    assert_eq!(refused.kind(), ErrorKind::InvalidConfig);
}

#[tokio::test]
async fn a_backend_change_lands_without_restarting_anything() {
    let socket = socket();
    let mut agent = Agent::start(&socket.path, &update(1, config(1))).await;

    let link = Arc::new(
        AgentLink::establish(&socket.path)
            .await
            .expect("the agent delivers")
            .with_intervals(QUICK, Duration::from_secs(60)),
    );
    let live = link.live();
    let _stop = spawn(Arc::clone(&link));

    assert_eq!(live.generation(), 1, "the first delivery is live");
    agent.connected().await;
    agent.push(&update(2, config(3)));

    assert!(
        until(|| live.generation() == 2).await,
        "the second delivery must land in the running process"
    );
    assert_eq!(
        live.load().config.backends[0].members.len(),
        3,
        "and carry the new pool"
    );
    assert_eq!(link.status().counters().configs_applied, 2);
}

#[tokio::test]
async fn a_swap_is_whole_or_not_at_all() {
    let socket = socket();
    let mut agent = Agent::start(&socket.path, &update(1, config(1))).await;

    let link = Arc::new(
        AgentLink::establish(&socket.path)
            .await
            .expect("the agent delivers")
            .with_intervals(QUICK, Duration::from_secs(60)),
    );
    let live = link.live();
    let _stop = spawn(Arc::clone(&link));
    agent.connected().await;

    // Read the configuration while it is being replaced, over and over. Every
    // snapshot must be one whole delivery: a generation and the pool that
    // came with it, never one from each.
    let reader = {
        let live = Arc::clone(&live);
        tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..2000 {
                let snapshot = live.load();
                seen.push((
                    snapshot.generation,
                    snapshot.config.backends[0].members.len(),
                ));
                tokio::task::yield_now().await;
            }
            seen
        })
    };

    for generation in 2..=20_u64 {
        let members = u16::try_from(generation).unwrap_or(1);
        agent.push(&update(generation, config(members)));
        tokio::time::sleep(Duration::from_millis(2)).await;
    }

    let seen = reader.await.expect("the reader must finish");
    assert!(seen.len() > 100, "the reader must have looked many times");
    for (generation, members) in &seen {
        let expected = usize::try_from(*generation).unwrap_or(1);
        assert_eq!(
            *members, expected,
            "generation {generation} was seen with {members} members, which belongs to another delivery"
        );
    }
    assert!(
        seen.iter().any(|(generation, _)| *generation > 1),
        "the reader must have seen a swap happen, or it measured nothing"
    );
}

#[tokio::test]
async fn losing_the_agent_keeps_traffic_and_reconnects() {
    let socket = socket();
    let mut agent = Agent::start(&socket.path, &update(1, config(1))).await;

    let link = Arc::new(
        AgentLink::establish(&socket.path)
            .await
            .expect("the agent delivers")
            .with_intervals(QUICK, QUICK),
    );
    let live = link.live();
    let _stop = spawn(Arc::clone(&link));
    agent.connected().await;
    assert_eq!(live.generation(), 1);

    agent.stop();

    // The agent is gone. The configuration stays exactly where it was, which
    // is what keeps traffic flowing while the control plane is down.
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(live.generation(), 1, "the configuration is untouched");
    assert_eq!(live.load().config.backends[0].members.len(), 1);

    agent.set_greeting(&update(5, config(4)));
    agent.restart().await;

    assert!(
        until(|| live.generation() == 5).await,
        "the link must come back on its own and take the new delivery"
    );
    assert_eq!(live.load().config.backends[0].members.len(), 4);
}

#[tokio::test]
async fn an_invalid_delivery_is_refused_and_reported() {
    let socket = socket();
    let mut agent = Agent::start(&socket.path, &update(1, config(2))).await;

    let link = Arc::new(
        AgentLink::establish(&socket.path)
            .await
            .expect("the agent delivers")
            .with_intervals(QUICK, Duration::from_secs(60)),
    );
    let live = link.live();
    let _stop = spawn(Arc::clone(&link));
    agent.connected().await;
    assert_eq!(live.generation(), 1);

    agent.push(&update(2, invalid_config()));

    let rejection = agent.heard_rejection().await;
    assert_eq!(rejection.generation, 2);
    assert!(
        rejection
            .errors
            .iter()
            .any(|error| error.code == ek_ek_config::ErrorCode::FrontendUnknownBackend),
        "the report must say what was wrong: {:?}",
        rejection.errors
    );

    assert_eq!(live.generation(), 1, "the process kept what it had");
    assert_eq!(live.load().config.backends[0].members.len(), 2);
    assert_eq!(link.status().counters().configs_rejected, 1);

    // A valid delivery on the same link still lands, so the refusal above did
    // not simply stop the link.
    agent.push(&update(3, config(5)));
    assert!(until(|| live.generation() == 3).await);
}

#[tokio::test]
async fn the_state_and_counters_go_out_on_a_timer() {
    let socket = socket();
    let mut agent = Agent::start(&socket.path, &update(4, config(1))).await;

    let link = Arc::new(
        AgentLink::establish(&socket.path)
            .await
            .expect("the agent delivers")
            .with_intervals(QUICK, QUICK),
    );
    link.status().set_state(DataPlaneState::Serving);
    link.status().request_handled();
    link.status().request_handled();
    let _stop = spawn(Arc::clone(&link));

    let first = agent.heard_status().await;
    assert_eq!(first.generation, 4);
    assert_eq!(first.state, DataPlaneState::Serving);
    assert_eq!(first.counters.requests_handled, 2);
    assert_eq!(first.counters.configs_applied, 1);

    // A second report must arrive without anything else happening, or the
    // first one could have been a one-off greeting.
    link.status().request_handled();
    let second = agent.heard_status().await;
    assert!(
        second.counters.requests_handled >= 3,
        "the later report must carry the later count: {:?}",
        second.counters
    );
}

#[tokio::test]
async fn the_greeting_names_the_process_and_what_it_already_holds() {
    let socket = socket();
    let mut agent = Agent::start(&socket.path, &update(9, config(1))).await;

    let link = Arc::new(
        AgentLink::establish(&socket.path)
            .await
            .expect("the agent delivers")
            .with_intervals(QUICK, Duration::from_secs(60)),
    );
    let _stop = spawn(Arc::clone(&link));

    // The short connection that collects the first configuration has nothing
    // yet, so it says so.
    let first = agent.heard_hello().await;
    assert_eq!(first.pid, std::process::id());
    assert_eq!(first.generation, None);
    assert!(!first.version.is_empty());

    // The link that follows already holds a configuration, and says which, so
    // the agent need not resend it.
    let second = agent.connected().await;
    assert_eq!(second.generation, Some(9));
    assert_eq!(
        link.status().counters().configs_applied,
        1,
        "reconnecting is not a configuration change"
    );
}

#[test]
fn listeners_follow_the_frontends() {
    let config = config(1);
    let found = bindings(&config).expect("the frontends resolve");

    assert_eq!(found.len(), 1);
    assert_eq!(found[0].frontend, "web");
    assert_eq!(found[0].address, "127.0.0.1:8080");
    assert_eq!(found[0].kind, ListenerKind::Http);

    // A UDP frontend is not a pingora listener, because the UDP path is hand
    // written and does not go through it.
    let mut udp = config.clone();
    udp.frontends[0].transport = TransportProtocol::Udp;
    assert!(bindings(&udp).expect("the frontends resolve").is_empty());

    // A raw frontend is a listener too, served by the L4 path rather than by
    // the HTTP one.
    let mut raw = config.clone();
    raw.frontends[0].application = ApplicationProtocol::Raw;
    let found = bindings(&raw).expect("the frontends resolve");
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].kind, ListenerKind::Stream);

    // TLS passthrough still has no listener: choosing a member needs the
    // ClientHello read first, which arrives with M4.
    let mut passthrough = config.clone();
    passthrough.frontends[0].application = ApplicationProtocol::TlsPassthrough;
    assert!(
        bindings(&passthrough)
            .expect("the frontends resolve")
            .is_empty()
    );

    // A frontend naming a VIP that is not there is an error rather than a
    // listener nobody notices is missing.
    let mut dangling = config;
    dangling.frontends[0].vip = VipId::new("vip-missing");
    assert_eq!(
        bindings(&dangling)
            .expect_err("a missing VIP has no address to bind")
            .kind(),
        ErrorKind::Listener
    );
}
