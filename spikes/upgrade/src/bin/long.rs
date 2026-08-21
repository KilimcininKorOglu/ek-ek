// Throwaway spike code for T-009. Not product code, no error handling standards.
//
// Holds one keep-alive connection open across the upgrade and keeps using it.
// ADR-0009 promises that a configuration change does not cut an open
// connection; this is the measurement behind that promise, and it also shows
// how long an old process is kept alive by a connection that will not close
// (R-05).

use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn env_str(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

#[tokio::main]
async fn main() {
    let target = env_str("SPIKE_TARGET", "127.0.0.1:6180");
    let duration_ms = env_u64("SPIKE_LONG_MS", 20_000);
    let every_ms = env_u64("SPIKE_LONG_EVERY_MS", 500);

    let started = Instant::now();
    let mut stream = match tokio::net::TcpStream::connect(&target).await {
        Ok(s) => s,
        Err(e) => {
            println!(r#"{{"opened":false,"error":"{e}"}}"#);
            return;
        }
    };

    let mut ok_count: u64 = 0;
    let mut fail_count: u64 = 0;
    let mut broke_after_ms: Option<u64> = None;
    let mut first_error = String::new();

    // Keep-alive on purpose. A fresh connection per request would never show
    // whether an already established one survives the handover.
    let req = format!("GET / HTTP/1.1\r\nHost: {target}\r\n\r\n");

    while started.elapsed() < Duration::from_millis(duration_ms) {
        tokio::time::sleep(Duration::from_millis(every_ms)).await;

        if let Err(e) = stream.write_all(req.as_bytes()).await {
            fail_count += 1;
            if first_error.is_empty() {
                first_error = format!("write: {e}");
            }
            broke_after_ms.get_or_insert(started.elapsed().as_millis() as u64);
            break;
        }

        let mut buf = [0u8; 512];
        match tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                // The peer closed the connection: this is the drain deadline.
                broke_after_ms.get_or_insert(started.elapsed().as_millis() as u64);
                if first_error.is_empty() {
                    first_error = "closed by peer".into();
                }
                break;
            }
            Ok(Ok(n)) => {
                let head = String::from_utf8_lossy(&buf[..n.min(32)]);
                if head.starts_with("HTTP/1.1 200") {
                    ok_count += 1;
                } else {
                    fail_count += 1;
                    if first_error.is_empty() {
                        first_error = format!("status: {}", head.lines().next().unwrap_or(""));
                    }
                }
            }
            Ok(Err(e)) => {
                fail_count += 1;
                if first_error.is_empty() {
                    first_error = format!("read: {e}");
                }
                broke_after_ms.get_or_insert(started.elapsed().as_millis() as u64);
                break;
            }
            Err(_) => {
                fail_count += 1;
                if first_error.is_empty() {
                    first_error = "read timeout".into();
                }
                break;
            }
        }
    }

    println!(
        r#"{{"opened":true,"ok":{ok_count},"failed":{fail_count},"broke_after_ms":{},"first_error":"{}","ran_ms":{}}}"#,
        broke_after_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
        first_error.replace('"', "'"),
        started.elapsed().as_millis(),
    );
}
