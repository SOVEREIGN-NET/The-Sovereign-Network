//! ZHTP Network Node
//!
//! Main entry point for the ZHTP orchestrator node.
//! Starts the unified server and manages the network node lifecycle.

use zhtp::config::{CliArgs, load_configuration, Environment};
use zhtp::runtime::{RuntimeOrchestrator, NodeType, StartupOptions};
use tracing_subscriber;
use std::env;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let filter = env::var("RUST_LOG")
        .unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    // Parse command-line arguments
    let args = parse_cli_args();

    // Load and validate configuration
    let config = load_configuration(&args).await?;

    let options = StartupOptions::from_config(&config);
    let node_type = NodeType::from_config(&config, None);
    let _orchestrator = RuntimeOrchestrator::start_for_node_type(config, node_type, options).await?;

    // Keep running indefinitely
    loop {
        tokio::time::sleep(tokio::time::Duration::from_secs(3600)).await;
    }
}

/// Parse command-line arguments
fn parse_cli_args() -> CliArgs {
    let args: Vec<String> = env::args().collect();

    let mut config = PathBuf::from("zhtp/configs/test-node1.toml");
    let mut environment = Environment::Development;
    let mut log_level = "info".to_string();
    let mut data_dir = dirs::home_dir()
        .map(|d| d.join(".zhtp"))
        .unwrap_or_else(|| PathBuf::from(".zhtp"));
    let mut mesh_port = None;
    let mut pure_mesh = false;

    // Simple argument parser
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--config" | "-c" => {
                if i + 1 < args.len() {
                    config = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--testnet" => {
                environment = Environment::Testnet;
                i += 1;
            }
            "--mainnet" => {
                environment = Environment::Mainnet;
                i += 1;
            }
            "--data-dir" => {
                if i + 1 < args.len() {
                    data_dir = PathBuf::from(&args[i + 1]);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--mesh-port" => {
                if i + 1 < args.len() {
                    if let Ok(port) = args[i + 1].parse() {
                        mesh_port = Some(port);
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--pure-mesh" => {
                pure_mesh = true;
                i += 1;
            }
            "--log-level" => {
                if i + 1 < args.len() {
                    log_level = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }

    CliArgs {
        config,
        environment,
        log_level,
        data_dir,
        mesh_port,
        pure_mesh,
    }
}
