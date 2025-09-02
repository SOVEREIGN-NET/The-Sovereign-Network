//! Simple compilation test

use zhtp::config::NodeConfig;
use zhtp::runtime::RuntimeOrchestrator;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Test basic instantiation
    let config = NodeConfig::default();
    let _runtime = RuntimeOrchestrator::new(config).await?;
    
    println!("✅ ZHTP main orchestrator compiled successfully!");
    Ok(())
}
