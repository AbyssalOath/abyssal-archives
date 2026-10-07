//! A small, self-hosted, SourceForge-style file hosting site.
//!
//! The binary (`src/main.rs`) only parses the command line; everything else
//! lives in this library so integration tests can build the full router.

#![forbid(unsafe_code)]

pub mod checksums;
pub mod config;
pub mod db;
pub mod error;
pub mod fsid;
pub mod guard;
pub mod hashing;
pub mod importer;
pub mod incoming;
pub mod integrity;
pub mod limits;
pub mod markdown;
pub mod mirrors;
pub mod net;
pub mod r2;
pub mod range;
pub mod ratelimit;
pub mod routes;
pub mod sanitize;
pub mod seeder;
pub mod settings;
pub mod state;
pub mod storage;
pub mod torrent;
pub mod totp;
pub mod tree;
pub mod util;
pub mod views;

use config::{Config, LISTEN_ADDR};
use state::AppState;

/// Builds the application router from a ready state.
pub fn app(state: AppState) -> axum::Router {
    routes::router(state)
}

/// Time a client gets to send a complete request head (slowloris guard).
const HEADER_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Largest request head (request line + headers) accepted.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Starts the web server and runs until SIGINT/SIGTERM.
///
/// A hand-written accept loop instead of `axum::serve`, for limits axum
/// does not expose: header read timeout, header size, and connection caps
/// (MAX_CONNECTIONS, MAX_CONNECTIONS_PER_IP; trusted proxies only count
/// toward the global cap).
pub async fn serve(config: Config) -> anyhow::Result<()> {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use tower::ServiceExt;

    // Files and directories this process creates: owner-only by default.
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));

    tracing::info!(?config, "starting");
    let state = AppState::init(config).await?;
    // Optional R2 download origin; idle until configured in /admin/storage.
    r2::spawn_worker(state.clone());
    let sec = state.config.security.clone();
    // LISTEN_ADDR is only for running outside Docker (e.g. when 8080 is
    // taken on a dev machine); the container always uses 0.0.0.0:8080.
    let addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| LISTEN_ADDR.to_string());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .map_err(|e| anyhow::anyhow!("cannot listen on {addr}: {e}"))?;
    tracing::info!(addr = %addr, "listening");

    let router = app(state);
    let conns = limits::Limiter::new(
        sec.max_connections,
        sec.max_connections_per_ip,
        sec.proxy.trusted.clone(),
    );
    let mut builder = Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(HEADER_READ_TIMEOUT)
        .max_buf_size(MAX_HEADER_BYTES)
        .max_headers(100);
    builder
        .http2()
        .timer(TokioTimer::new())
        .max_header_list_size(MAX_HEADER_BYTES as u32);
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown_signal());

    loop {
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    // e.g. out of file descriptors: back off briefly.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    continue;
                }
            },
            _ = &mut shutdown => break,
        };
        let Some(slot) = conns.try_acquire(peer.ip()) else {
            tracing::debug!(client = %net::log_ip(peer.ip(), sec.log_ip_mode), "connection limit reached");
            drop(stream);
            continue;
        };
        let router = router.clone();
        let service =
            hyper::service::service_fn(move |mut req: hyper::Request<hyper::body::Incoming>| {
                req.extensions_mut()
                    .insert(axum::extract::ConnectInfo(peer));
                router.clone().oneshot(req.map(axum::body::Body::new))
            });
        let builder = builder.clone();
        let watcher = graceful.watcher();
        tokio::spawn(async move {
            let _slot = slot;
            // hyper-util first reads bytes to tell HTTP/1 from HTTP/2, with no
            // timeout; hyper's own header timer only starts after that. Drop
            // connections that send nothing at all within the header timeout.
            if !matches!(
                tokio::time::timeout(HEADER_READ_TIMEOUT, stream.readable()).await,
                Ok(Ok(()))
            ) {
                return;
            }
            let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), service);
            if let Err(e) = watcher.watch(conn.into_owned()).await {
                tracing::debug!(error = %e, "connection ended with an error");
            }
        });
    }
    drop(listener);
    tokio::select! {
        _ = graceful.shutdown() => {}
        _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
            tracing::info!("closing remaining connections");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        _ = ctrl_c => {},
        _ = term => {},
    }
    tracing::info!("shutting down");
}

/// `filehost healthcheck`: used by the Docker HEALTHCHECK so the runtime
/// image needs no curl. Exits 0 if GET /healthz returns 200.
pub fn healthcheck() -> bool {
    use std::io::{Read, Write};
    use std::time::Duration;
    let Ok(mut s) = std::net::TcpStream::connect_timeout(
        &"127.0.0.1:8080".parse().unwrap(),
        Duration::from_secs(3),
    ) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    if s.write_all(b"GET /healthz HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut buf = [0u8; 32];
    let n = s.read(&mut buf).unwrap_or(0);
    let head = String::from_utf8_lossy(&buf[..n]);
    head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200")
}
