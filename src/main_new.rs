//! ZHTP Orchestrator Main Entry Point
//!
//! Main executable for the ZHTP orchestrator

use anyhow::Result;
use tracing::{info, error};

// Import new orchestrator modules
use zhtp::{
    cli::run_cli,
    api::{start_api_server, ApiConfig},
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging system
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    info!(" ZHTP Orchestrator v{}", env!("CARGO_PKG_VERSION"));
    info!("Level 1 Orchestrator - Coordinates protocols, blockchain, network");

    // Check if this is a special server mode
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() > 1 && args[1] == "--server" {
        info!("Starting ZHTP Orchestrator in Server mode on port 9333");
        let config = ApiConfig::default();
        start_api_server(config).await?;
    } else {
        // Default: Use the full CLI structure with all subcommands
        info!("Starting ZHTP Orchestrator CLI");
        run_cli().await?;
    }

    info!(" ZHTP Orchestrator shutdown complete");
    Ok(())
}
