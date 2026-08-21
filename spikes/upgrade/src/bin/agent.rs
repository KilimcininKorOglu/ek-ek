// Throwaway spike code for T-009. Not product code, no error handling standards.
//
// Stands in for node-agent. It supervises a pingora process, runs a heartbeat
// that must never be interrupted (VRRP's place in the real design), and drives
// a graceful upgrade when the listener set changes.
//
// The whole point is what it measures: does the supervisor survive, does the
// heartbeat keep its cadence, and does the old process go away.

use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// The heartbeat interval matches the VRRP advertisement interval from ADR-0029.
const HEARTBEAT_MS: u64 = 300;
/// A tick later than this counts as missed. VRRP tolerates roughly three
/// intervals before a peer declares the master gone.
const HEARTBEAT_TOLERANCE_MS: u64 = 450;

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

fn spawn_proxy(listeners: &str, upgrade: bool) -> Child {
    let mut cmd = Command::new(env_str("SPIKE_PROXY_BIN", "/spike/proxy"));
    cmd.arg("-c").arg(env_str("SPIKE_CONF", "/spike/pingora.yaml"));
    if upgrade {
        cmd.arg("-u");
    }
    cmd.env("SPIKE_LISTENERS", listeners);
    cmd.env("SPIKE_BACKEND", env_str("SPIKE_BACKEND", "172.28.0.21:80"));
    cmd.spawn().expect("spawn proxy")
}

fn signal(pid: u32, sig: i32) {
    // Deliberately crude: the spike is thrown away and a real signal crate
    // would only add a dependency for one call.
    Command::new("kill")
        .arg(format!("-{sig}"))
        .arg(pid.to_string())
        .status()
        .expect("kill");
}

const SIGQUIT: i32 = 3;

fn main() {
    let agent_pid = std::process::id();
    let gen1_listeners = env_str("SPIKE_LISTENERS_GEN1", "0.0.0.0:6180");
    let gen2_listeners = env_str("SPIKE_LISTENERS_GEN2", "0.0.0.0:6180,0.0.0.0:6181");
    // "signal-first" sends SIGQUIT before starting the replacement.
    // "new-first" starts the replacement before sending SIGQUIT.
    // pingora's own documentation gives both orders, so both are measured.
    let order = env_str("SPIKE_ORDER", "signal-first");
    let upgrade_after = Duration::from_millis(env_u64("SPIKE_UPGRADE_AFTER_MS", 5_000));
    let run_for = Duration::from_millis(env_u64("SPIKE_RUN_MS", 20_000));

    eprintln!("agent pid {agent_pid}, order {order}");

    let mut gen1 = spawn_proxy(&gen1_listeners, false);
    let gen1_pid = gen1.id();
    eprintln!("gen1 pid {gen1_pid}");

    let started = Instant::now();

    // The heartbeat runs on its own thread. This is the point of the whole
    // spike: in the real design VRRP must not be starved by process
    // management, so measuring it from the same loop that spawns processes
    // would only measure the spike's own scheduling.
    let ticks = Arc::new(AtomicU64::new(0));
    let missed = Arc::new(AtomicU64::new(0));
    let longest_gap = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicU64::new(0));
    {
        let (ticks, missed, longest_gap, stop) =
            (ticks.clone(), missed.clone(), longest_gap.clone(), stop.clone());
        std::thread::spawn(move || {
            let mut last = Instant::now();
            while stop.load(Ordering::Relaxed) == 0 {
                std::thread::sleep(Duration::from_millis(HEARTBEAT_MS));
                let gap_ms = last.elapsed().as_millis() as u64;
                last = Instant::now();
                ticks.fetch_add(1, Ordering::Relaxed);
                longest_gap.fetch_max(gap_ms, Ordering::Relaxed);
                if gap_ms > HEARTBEAT_TOLERANCE_MS {
                    missed.fetch_add(1, Ordering::Relaxed);
                    eprintln!("heartbeat late: {gap_ms}ms");
                }
            }
        });
    }

    let mut upgraded = false;
    let mut gen2_pid: u32 = 0;
    let mut gen2: Option<Child> = None;
    let mut upgrade_at: Option<Instant> = None;
    let mut gen1_exit_ms: Option<u64> = None;

    // A single loop drives both the heartbeat and the supervision, which is the
    // arrangement the real agent will use: the heartbeat must not be starved by
    // process management.
    loop {
        std::thread::sleep(Duration::from_millis(100));

        if !upgraded && started.elapsed() >= upgrade_after {
            upgraded = true;
            upgrade_at = Some(Instant::now());
            eprintln!("upgrade: listener set changes, order {order}");

            if order == "signal-first" {
                signal(gen1_pid, SIGQUIT);
                std::thread::sleep(Duration::from_millis(200));
                let child = spawn_proxy(&gen2_listeners, true);
                gen2_pid = child.id();
                gen2 = Some(child);
            } else {
                let child = spawn_proxy(&gen2_listeners, true);
                gen2_pid = child.id();
                gen2 = Some(child);
                std::thread::sleep(Duration::from_millis(200));
                signal(gen1_pid, SIGQUIT);
            }
            eprintln!("gen2 pid {gen2_pid}");
        }

        // Reap the old process so its exit time can be measured and so no
        // zombie is left behind.
        if gen1_exit_ms.is_none() {
            if let Ok(Some(_)) = gen1.try_wait() {
                gen1_exit_ms = upgrade_at.map(|t| t.elapsed().as_millis() as u64);
                eprintln!("gen1 exited after {}ms", gen1_exit_ms.unwrap_or(0));
            }
        }

        if started.elapsed() >= run_for {
            break;
        }
    }

    stop.store(1, Ordering::Relaxed);
    let gen1_alive = gen1.try_wait().ok().flatten().is_none();
    if gen1_alive {
        eprintln!("gen1 still running at the end of the run");
    }
    if let Some(child) = gen2.as_mut() {
        signal(child.id(), SIGQUIT);
        std::thread::sleep(Duration::from_millis(500));
        let _ = child.try_wait();
    }

    // Machine readable so the shell script can assert on it.
    println!(
        r#"{{"agent_pid_start":{agent_pid},"agent_pid_end":{},"gen1_pid":{gen1_pid},"gen2_pid":{gen2_pid},"heartbeat_ticks":{},"heartbeat_missed":{},"heartbeat_longest_gap_ms":{},"gen1_exit_ms":{},"gen1_still_alive":{},"order":"{order}"}}"#,
        std::process::id(),
        ticks.load(Ordering::Relaxed),
        missed.load(Ordering::Relaxed),
        longest_gap.load(Ordering::Relaxed),
        gen1_exit_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
        gen1_alive,
    );
}
