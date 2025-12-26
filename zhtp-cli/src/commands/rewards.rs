//! Reward System CLI Commands
//! 
//! Commands for managing automatic rewards (routing and storage)

use anyhow::Result;
use zhtp::runtime::RuntimeOrchestrator;

/// Handle reward-related commands
pub async fn handle_reward_command(orchestrator: &RuntimeOrchestrator, subcommand: &str) -> Result<()> {
    match subcommand {
        "status" => show_reward_status(orchestrator).await,
        "metrics" => show_reward_metrics(orchestrator).await,
        "routing" => show_routing_rewards(orchestrator).await,
        "storage" => show_storage_rewards(orchestrator).await,
        "config" => show_reward_config(orchestrator).await,
        _ => {
            println!("Unknown rewards subcommand: {}", subcommand);
            println!("\nAvailable commands:");
            println!("  rewards status   - Show reward orchestrator status");
            println!("  rewards metrics  - Show combined reward metrics");
            println!("  rewards routing  - Show routing reward details");
            println!("  rewards storage  - Show storage reward details");
            println!("  rewards config   - Show reward configuration");
            Ok(())
        }
    }
}

/// Show overall reward orchestrator status
async fn show_reward_status(orchestrator: &RuntimeOrchestrator) -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║           ZHTP Reward Orchestrator Status             ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    // Get reward config from node config
    let config = &orchestrator.get_config().rewards_config;
    
    println!(" Global Configuration:");
    println!("   Rewards Enabled:      {}", if config.enabled { " YES" } else { " NO" });
    println!("   Auto-Claim:           {}", if config.auto_claim { " YES" } else { " NO" });
    println!("   Max Claims/Hour:      {}", config.max_claims_per_hour);
    println!("   Cooldown Period:      {} seconds", config.cooldown_period_secs);
    
    println!("\n Routing Rewards:");
    println!("   Status:               {}", if config.routing_rewards_enabled { " ENABLED" } else { "  DISABLED" });
    println!("   Check Interval:       {} seconds", config.routing_check_interval_secs);
    println!("   Minimum Threshold:    {} ZHTP", config.routing_minimum_threshold);
    println!("   Max Batch Size:       {} ZHTP", config.routing_max_batch_size);
    
    println!("\n💾 Storage Rewards:");
    println!("   Status:               {}", if config.storage_rewards_enabled { " ENABLED" } else { "  DISABLED" });
    println!("   Check Interval:       {} seconds", config.storage_check_interval_secs);
    println!("   Minimum Threshold:    {} ZHTP", config.storage_minimum_threshold);
    println!("   Max Batch Size:       {} ZHTP", config.storage_max_batch_size);
    
    println!("\n╚════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}

/// Show combined reward metrics
async fn show_reward_metrics(_orchestrator: &RuntimeOrchestrator) -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║              Combined Reward Metrics                   ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    println!("  Note: Metrics API requires reward orchestrator access");
    println!("   This feature requires runtime orchestrator methods to be implemented");
    
    println!("\n Routing Metrics:");
    println!("   Pending Rewards:      (not yet implemented)");
    println!("   Total Bytes Routed:   (not yet implemented)");
    println!("   Total Messages:       (not yet implemented)");
    
    println!("\n Storage Metrics:");
    println!("   Pending Rewards:      (not yet implemented)");
    println!("   Items Stored:         (not yet implemented)");
    println!("   Bytes Stored:         (not yet implemented)");
    println!("   Retrievals Served:    (not yet implemented)");
    
    println!("\n Total Pending:");
    println!("   Combined:             (not yet implemented)");
    
    println!("\n╚════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}

/// Show routing reward details
async fn show_routing_rewards(_orchestrator: &RuntimeOrchestrator) -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║              Routing Reward Details                    ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    println!(" Routing Contributions:");
    println!("   Status:               Active");
    println!("   Messages Routed:      (requires mesh server stats)");
    println!("   Bytes Routed:         (requires mesh server stats)");
    println!("   Theoretical Tokens:   (requires mesh server stats)");
    
    println!("\n⏱️  Processor Status:");
    println!("   Running:              (requires orchestrator query)");
    println!("   Last Check:           (requires orchestrator query)");
    println!("   Next Check:           (requires orchestrator query)");
    
    println!("\n Reward History:");
    println!("   Total Claims:         (requires blockchain query)");
    println!("   Total Earned:         (requires blockchain query)");
    println!("   Last Claim:           (requires blockchain query)");
    
    println!("\n╚════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}

/// Show storage reward details
async fn show_storage_rewards(_orchestrator: &RuntimeOrchestrator) -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║              Storage Reward Details                    ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    println!("💾 Storage Contributions:");
    println!("   Status:               Active");
    println!("   Items Stored:         (requires mesh server stats)");
    println!("   Bytes Stored:         (requires mesh server stats)");
    println!("   Retrievals Served:    (requires mesh server stats)");
    println!("   Storage Duration:     (requires mesh server stats)");
    println!("   Theoretical Tokens:   (requires mesh server stats)");
    
    println!("\n⏱️  Processor Status:");
    println!("   Running:              (requires orchestrator query)");
    println!("   Last Check:           (requires orchestrator query)");
    println!("   Next Check:           (requires orchestrator query)");
    
    println!("\n Reward History:");
    println!("   Total Claims:         (requires blockchain query)");
    println!("   Total Earned:         (requires blockchain query)");
    println!("   Last Claim:           (requires blockchain query)");
    
    println!("\n╚════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}

/// Show reward configuration
async fn show_reward_config(orchestrator: &RuntimeOrchestrator) -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║            Reward System Configuration                 ║");
    println!("╚════════════════════════════════════════════════════════╝\n");
    
    let config = &orchestrator.get_config().rewards_config;
    
    println!(" Global Settings:");
    println!("   enabled:                    {}", config.enabled);
    println!("   auto_claim:                 {}", config.auto_claim);
    println!("   max_claims_per_hour:        {}", config.max_claims_per_hour);
    println!("   cooldown_period_secs:       {}", config.cooldown_period_secs);
    
    println!("\n Routing Configuration:");
    println!("   routing_rewards_enabled:    {}", config.routing_rewards_enabled);
    println!("   routing_check_interval:     {}s", config.routing_check_interval_secs);
    println!("   routing_minimum_threshold:  {} ZHTP", config.routing_minimum_threshold);
    println!("   routing_max_batch_size:     {} ZHTP", config.routing_max_batch_size);
    
    println!("\n💾 Storage Configuration:");
    println!("   storage_rewards_enabled:    {}", config.storage_rewards_enabled);
    println!("   storage_check_interval:     {}s", config.storage_check_interval_secs);
    println!("   storage_minimum_threshold:  {} ZHTP", config.storage_minimum_threshold);
    println!("   storage_max_batch_size:     {} ZHTP", config.storage_max_batch_size);
    
    println!("\n💡 Configuration File:");
    println!("   To modify these settings, edit your node configuration file");
    println!("   under the [rewards_config] section and restart the node.");
    
    println!("\n╚════════════════════════════════════════════════════════╝\n");
    
    Ok(())
}
