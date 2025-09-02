//! ZHTP Network Node - Complete Internet Replacement System
//! 
//! This is the main orchestrator binary that coordinates all ZHTP packages
//! into a unified network node capable of:
//! 
//! - Complete ISP replacement through mesh networking
//! - Zero-knowledge privacy for all communications  
//! - Universal Basic Income through network participation
//! - Quantum-resistant cryptographic security
//! - Decentralized governance through DAO integration
//! - Revolutionary Web4 protocol stack
//! 
//! The ZHTP node can operate in two modes:
//! - Pure Mesh: Complete ISP bypass using only mesh protocols
//! - Hybrid: Mesh networking with TCP/IP fallback for transition

use anyhow::Result;
use clap::{Arg, Command};
use tracing::{info, error, warn};
use std::sync::Arc;
use tokio::sync::RwLock;

// Import orchestration modules
mod config;
mod runtime;
mod monitoring;
mod integration;
mod cli;
mod utils;
mod zk_coordinator;

// Re-export core types for main function
use config::NodeConfig;
use runtime::RuntimeOrchestrator;
use cli::{parse_arguments, display_startup_banner};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging system
    utils::logging::initialize_logging()?;

    // Display startup banner
    display_startup_banner();

    // Parse command line arguments
    let args = parse_arguments().await?;
    
    info!("🚀 ZHTP Network Node v{} - Complete Internet Replacement", env!("CARGO_PKG_VERSION"));
    info!("===============================================");
    
    // Determine operation mode
    let mode = if args.pure_mesh {
        "PURE MESH (ISP-free Internet Replacement)"
    } else {
        "HYBRID (Mesh + TCP/IP Transition Mode)"
    };
    info!("   Operation Mode: {}", mode);
    info!("   Mesh Port: {}", args.mesh_port);
    info!("   Configuration: {}", args.config.display());

    // Load and validate configuration
    let node_config = config::load_configuration(&args).await?;
    info!("✅ Configuration validated across all {} packages", node_config.package_count());

    // Initialize runtime orchestrator
    let orchestrator = Arc::new(RuntimeOrchestrator::new(node_config).await?);
    info!("🏗️ Runtime orchestrator initialized");

    // Register all ZHTP components
    info!("📦 Registering ZHTP components...");
    
    // Register components in dependency order
    orchestrator.register_component(Arc::new(runtime::CryptoComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::ZKComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::IdentityComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::StorageComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::NetworkComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::BlockchainComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::ConsensusComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::EconomicsComponent::new())).await?;
    orchestrator.register_component(Arc::new(runtime::ProtocolsComponent::new())).await?;
    
    info!("✅ All components registered successfully");

    // Start all components in proper sequence
    match orchestrator.start_all_components().await {
        Ok(()) => {
            info!("✅ All ZHTP components started successfully");
            info!("🌍 Revolutionary Internet Replacement: ACTIVE");
            info!("💰 Universal Basic Income System: OPERATIONAL");
            info!("🔐 Quantum-Resistant Security: ENABLED");
            info!("⚖️ Decentralized Governance: READY");
        }
        Err(e) => {
            error!("❌ Failed to start ZHTP components: {}", e);
            return Err(e);
        }
    }

    // Start monitoring and statistics
    let mut monitoring_system = monitoring::MonitoringSystem::new().await?;
    monitoring_system.start().await?;
    info!("📊 Real-time monitoring system: ACTIVE");

    // Register shutdown handlers
    let orchestrator_clone = Arc::clone(&orchestrator);
    let shutdown_task = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl+c");
        warn!("🛑 Shutdown signal received");
        
        if let Err(e) = orchestrator_clone.graceful_shutdown().await {
            error!("❌ Error during graceful shutdown: {}", e);
        }
    });

    // Main operational loop with proper shutdown handling
    info!("🔄 ZHTP Node operational - Ready to replace the internet!");
    
    tokio::select! {
        result = orchestrator.run_main_loop() => {
            if let Err(e) = result {
                error!("❌ Main loop error: {}", e);
            }
        }
        _ = shutdown_task => {
            info!("🛑 Shutdown signal processed");
        }
    }

    Ok(())
}
