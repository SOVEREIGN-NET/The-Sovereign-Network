//! ZHTP Network Node
//!
//! Main entry point for the ZHTP orchestrator node.
//! Starts the unified server and manages the network node lifecycle.

use std::env;
use std::path::PathBuf;
use tracing_subscriber;
use zhtp::config::{load_configuration, CliArgs, Environment, NodeType};
use zhtp::runtime::RuntimeOrchestrator;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    let filter = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Parse command-line arguments
    let args = parse_cli_args();

    // Pin the data directory globally so all components use the same path regardless
    // of how dirs::home_dir() behaves for the service account. This prevents the
    // "silent path drift" bug where changing the OS home dir causes data to be read
    // from an empty new directory while real data sits in the old location.
    zhtp::set_node_data_dir(args.data_dir.clone());

    // Load and validate configuration
    let config = load_configuration(&args).await?;

    // ========================================================================
    // Issue #454: Canonical startup dispatch based on canonical NodeType
    // ========================================================================
    // Single dispatch based on config.node_type (SINGLE SOURCE OF TRUTH)
    // to the appropriate startup function. Each startup function validates
    // it was called with the correct type and performs type-specific init.
    // ========================================================================
    let node_type = config.node_type.ok_or_else(|| {
        anyhow::anyhow!(
            "node_type not set during config aggregation. \
             derive_node_type() must be called before runtime initialization."
        )
    })?;

    let orchestrator = match node_type {
        NodeType::Validator => {
            tracing::info!("Starting node as Validator (mining and consensus enabled)");
            RuntimeOrchestrator::start_validator(config).await?
        }
        NodeType::EdgeNode => {
            tracing::info!("Starting node as EdgeNode (headers only, ZK proofs)");
            RuntimeOrchestrator::start_edge_node(config).await?
        }
        NodeType::FullNode => {
            tracing::info!(
                "Starting node as Observer via FullNode startup path (complete blockchain, no mining, no consensus)"
            );
            RuntimeOrchestrator::start_full_node(config).await?
        }
        NodeType::Relay => {
            tracing::info!("Starting node as Relay (routing only, no blockchain state)");
            RuntimeOrchestrator::start_relay(config).await?
        }
        NodeType::Gateway => {
            anyhow::bail!(
                "Gateway mode is not supported by the zhtp binary. \
                 Use the zhtp-daemon binary for gateway/ingress-proxy operation."
            )
        }
    };

    // Wrap orchestrator in Arc for shared ownership (needed by runtime handlers)
    let orchestrator = std::sync::Arc::new(orchestrator);

    // Register runtime-dependent handlers (NetworkHandler, MeshHandler) now that
    // RuntimeOrchestrator is available as Arc. Give components a moment to fully initialize.
    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
    if let Err(e) = orchestrator
        .register_runtime_handlers(orchestrator.clone())
        .await
    {
        tracing::warn!("Failed to register runtime handlers: {}", e);
    } else {
        tracing::info!("✅ Runtime handlers registered (NetworkHandler, MeshHandler)");
    }

    // Wait for shutdown signal (SIGTERM/SIGINT)
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("Received SIGINT (Ctrl+C), initiating graceful shutdown...");
        }
        _ = async {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                let mut sigterm = signal(SignalKind::terminate()).expect("Failed to install SIGTERM handler");
                sigterm.recv().await;
            }
            #[cfg(not(unix))]
            {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::info!("Received SIGTERM, initiating graceful shutdown...");
        }
    }

    // Graceful shutdown - saves blockchain before exit
    if let Err(e) = orchestrator.graceful_shutdown().await {
        tracing::error!("Error during graceful shutdown: {}", e);
    }

    tracing::info!("Node shutdown complete");
    Ok(())
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
    let mut emergency_restore_from_local = false;
    let mut allow_emergency_restore_genesis_mismatch = false;

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
            "--emergency-restore-from-local" => {
                emergency_restore_from_local = true;
                i += 1;
            }
            "--allow-emergency-restore-genesis-mismatch" => {
                allow_emergency_restore_genesis_mismatch = true;
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
        emergency_restore_from_local,
        allow_emergency_restore_genesis_mismatch,
    }
}
