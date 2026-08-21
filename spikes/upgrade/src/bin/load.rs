// Throwaway spike code for T-009. Not product code, no error handling standards.
//
// Sends a steady request rate at the proxy and counts what fails. The zero
// failure criterion is the whole measurement, so this deliberately treats any
// connection error, any non-200 status and any timeout as a failure.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

/// A minimal HTTP/1.1 request over a fresh connection. Keep-alive is avoided on
/// purpose: a pooled connection would hide exactly the failure we are looking
/// for, which happens when a listener is handed over.
async fn one_request(target: &str) -> Result<(), String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let connect = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::net::TcpStream::connect(target),
    );
    let mut stream = match connect.await {
        Err(_) => return Err("connect timeout".into()),
        Ok(Err(e)) => return Err(format!("connect: {e}")),
        Ok(Ok(s)) => s,
    };

    let req = format!("GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    if let Err(e) = stream.write_all(req.as_bytes()).await {
        return Err(format!("write: {e}"));
    }

    let mut buf = Vec::with_capacity(256);
    let read = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut buf));
    match read.await {
        Err(_) => return Err("read timeout".into()),
        Ok(Err(e)) => return Err(format!("read: {e}")),
        Ok(Ok(_)) => {}
    }

    let head = String::from_utf8_lossy(&buf[..buf.len().min(64)]);
    if head.starts_with("HTTP/1.1 200") {
        Ok(())
    } else {
        Err(format!("status: {}", head.lines().next().unwrap_or("empty")))
    }
}

#[tokio::main]
async fn main() {
    let target = env_str("SPIKE_TARGET", "127.0.0.1:6180");
    let rate = env_u64("SPIKE_RATE", 100);
    let duration_ms = env_u64("SPIKE_LOAD_MS", 20_000);

    let sent = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let first_error: Arc<std::sync::Mutex<Option<String>>> = Arc::new(std::sync::Mutex::new(None));

    let interval = Duration::from_micros(1_000_000 / rate.max(1));
    let deadline = Instant::now() + Duration::from_millis(duration_ms);
    let mut ticker = tokio::time::interval(interval);
    let mut handles = Vec::new();

    while Instant::now() < deadline {
        ticker.tick().await;
        let target = target.clone();
        let sent = sent.clone();
        let failed = failed.clone();
        let first_error = first_error.clone();
        handles.push(tokio::spawn(async move {
            sent.fetch_add(1, Ordering::Relaxed);
            if let Err(e) = one_request(&target).await {
                failed.fetch_add(1, Ordering::Relaxed);
                let mut slot = first_error.lock().expect("lock");
                if slot.is_none() {
                    *slot = Some(e);
                }
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let err = first_error.lock().expect("lock").clone().unwrap_or_default();
    println!(
        r#"{{"target":"{target}","sent":{},"failed":{},"first_error":"{}"}}"#,
        sent.load(Ordering::Relaxed),
        failed.load(Ordering::Relaxed),
        err.replace('"', "'"),
    );
}
