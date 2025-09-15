//! ZHTP Orchestrator API Module
//! 
//! High-level API endpoints that orchestrate between Level 2 components:
//! - lib-protocols (protocol handling)
//! - lib-blockchain (blockchain operations)  
//! - lib-network (mesh networking)

pub mod endpoints;
pub mod config;
pub mod handlers;
pub mod types;
pub mod server;

// Re-export main types
pub use endpoints::ApiEndpoints;
pub use config::{ApiConfig, ApiTier, ApiEconomicConfig, CorsConfig};
pub use handlers::*;
pub use types::*;
pub use server::start_api_server;

/// Initialize the ZHTP API system
pub async fn initialize_api() -> anyhow::Result<ApiEndpoints> {
    let config = ApiConfig::default();
    let endpoints = ApiEndpoints::new(config).await?;
    
    tracing::info!("🚀 ZHTP Orchestrator API initialized");
    tracing::info!("📡 50+ endpoints registered for Web4 orchestration");
    
    Ok(endpoints)
}
