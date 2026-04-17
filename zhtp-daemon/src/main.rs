mod api;
mod backend_pool;
mod config;
mod discovery;
mod identity;
mod metrics;
mod service;

use anyhow::{Context, Result};
use axum::Router;
use config::DaemonConfig;
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
    let service = Arc::new(ZhtpDaemonService::new(config.clone(), identity).await?);

    info!(
        config_path = %config_path.display(),
        listen_addr = %config.listen_addr,
        backend_count = config.static_backends().len(),
        "Starting zhtp-daemon"
    );

    let app = build_router(service);
    let listener = TcpListener::bind(&config.listen_addr)
        .await
        .with_context(|| format!("Failed to bind {}", config.listen_addr))?;

    axum::serve(listener, app)
        .await
        .context("Daemon server failed")?;
    Ok(())
}

fn build_router(service: Arc<ZhtpDaemonService>) -> Router {
    api::router(api::AppState { service }).layer(TraceLayer::new_for_http())
}
