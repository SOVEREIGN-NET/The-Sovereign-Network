mod api;
mod backend_pool;
mod config;
mod discovery;
mod identity;
mod metrics;
mod quic_server;
mod service;

use anyhow::{Context, Result};
use axum::Router;
use config::DaemonConfig;
use quic_server::QuicGatewayServer;
use service::ZhtpDaemonService;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_stack_size(8 * 1024 * 1024)
        .build()
        .context("Failed to build Tokio runtime")?;

    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("zhtp_daemon=info,lib_network=info")),
        )
        .init();

    let (config, config_path) = DaemonConfig::load_or_create()?;
    let root_dir = DaemonConfig::root_dir()?;
    let identity = identity::load_or_create(&root_dir)?;

    // Initialize network genesis so Web4Client can derive the network epoch.
    let _ = lib_identity::types::node_id::try_set_network_genesis(
        lib_identity::constants::TESTNET_GENESIS_HASH,
    );

    let service = Arc::new(ZhtpDaemonService::new(config.clone(), identity.clone()).await?);

    let gateway_cfg = config.effective_gateway_config();

    info!(
        config_path = %config_path.display(),
        listen_addr = %config.listen_addr,
        quic_listen_addr = %gateway_cfg.quic_listen_addr,
        backend_count = config.static_backends().len(),
        "Starting zhtp-daemon"
    );

    // Start HTTP server (local loopback for browser extension)
    let app = build_router(service.clone());
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("Failed to bind TCP {}", config.listen_addr))?;

    let http_task = tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("HTTP server error: {}", e);
        }
    });

    // Start QUIC gateway server (for native app connections)
    let quic_bind: std::net::SocketAddr = gateway_cfg
        .quic_listen_addr
        .parse()
        .with_context(|| format!("Invalid quic_listen_addr: {}", gateway_cfg.quic_listen_addr))?;

    let cert_path = root_dir.join("gateway-cert.pem");
    let key_path = root_dir.join("gateway-key.pem");

    let quic_server = QuicGatewayServer::new(
        quic_bind,
        service.clone(),
        Arc::new(identity),
        &cert_path,
        &key_path,
    )
    .await
    .context("Failed to start QUIC gateway server")?;

    let quic_task = tokio::spawn(async move {
        if let Err(e) = quic_server.run().await {
            tracing::error!("QUIC server error: {}", e);
        }
    });

    tokio::select! {
        _ = http_task => {},
        _ = quic_task => {},
    }

    Ok(())
}

fn build_router(service: Arc<ZhtpDaemonService>) -> Router {
    api::router(api::AppState { service }).layer(TraceLayer::new_for_http())
}
