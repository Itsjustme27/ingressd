//! Minimal HTTP server: Prometheus `/metrics`, plus `/healthz` (liveness) and
//! `/readyz` (readiness) probes for Kubernetes and external watchdogs.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ingressd_core::metrics::Counters;

/// Serve the HTTP endpoints until cancelled (accept loop never returns on success).
pub async fn serve(
    addr: SocketAddr,
    counters: Arc<Counters>,
    ready: Arc<AtomicBool>,
    started: Instant,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!("http endpoint on http://{addr}/metrics");
    loop {
        match listener.accept().await {
            Ok((stream, _peer)) => {
                let c = Arc::clone(&counters);
                let r = Arc::clone(&ready);
                let st = started;
                tokio::spawn(async move {
                    let _ = handle(stream, c, r, st).await;
                });
            }
            Err(e) => tracing::warn!("http accept error: {e}"),
        }
    }
}

async fn handle(
    mut stream: TcpStream,
    counters: Arc<Counters>,
    ready: Arc<AtomicBool>,
    started: Instant,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await.unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    let path = head.split_whitespace().nth(1).unwrap_or("/");

    let (status, body, ctype) = match path {
        "/metrics" => (
            "200 OK",
            counters.prometheus_text(),
            "text/plain; version=0.0.4",
        ),
        "/healthz" => (
            "200 OK",
            format!("ok uptime_s={}\n", started.elapsed().as_secs()),
            "text/plain",
        ),
        "/readyz" => {
            if ready.load(Ordering::Relaxed) {
                ("200 OK", "ready\n".to_string(), "text/plain")
            } else {
                (
                    "503 Service Unavailable",
                    "starting\n".to_string(),
                    "text/plain",
                )
            }
        }
        _ => ("404 Not Found", "not found".to_string(), "text/plain"),
    };

    let resp = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    Ok(())
}
