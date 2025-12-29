//! Reward System CLI Commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Reward operation validation, message formatting, status computation
//! - **Imperative Shell**: Configuration retrieval, I/O, formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for message formatting and status display

use anyhow::Result;
use crate::argument_parsing::{RewardArgs, RewardAction, ZhtpCli};
use serde_json::{json, Value};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Reward system operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardOperation {
    Status,
    Metrics,
    Routing,
    Storage,
    Config,
}

impl RewardOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            RewardOperation::Status => "Show reward orchestrator status",
            RewardOperation::Metrics => "Show combined reward metrics",
            RewardOperation::Routing => "Show routing reward details",
            RewardOperation::Storage => "Show storage reward details",
            RewardOperation::Config => "Show reward configuration",
        }
    }

    /// Get operation display emoji
    pub fn emoji(&self) -> &'static str {
        match self {
            RewardOperation::Status => "📊",
            RewardOperation::Metrics => "📈",
            RewardOperation::Routing => "🔄",
            RewardOperation::Storage => "💾",
            RewardOperation::Config => "⚙️",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &RewardAction) -> RewardOperation {
    match action {
        RewardAction::Status => RewardOperation::Status,
        RewardAction::Metrics => RewardOperation::Metrics,
        RewardAction::Routing => RewardOperation::Routing,
        RewardAction::Storage => RewardOperation::Storage,
        RewardAction::Config => RewardOperation::Config,
    }
}

/// Format reward status display
///
/// Pure function - message formatting only
pub fn format_reward_status_message(
    enabled: bool,
    auto_claim: bool,
    max_claims_per_hour: u32,
    cooldown_secs: u32,
) -> String {
    format!(
        "Global Configuration:\n  Rewards Enabled:      {}\n  Auto-Claim:           {}\n  Max Claims/Hour:      {}\n  Cooldown Period:      {} seconds",
        if enabled { "YES" } else { "NO" },
        if auto_claim { "YES" } else { "NO" },
        max_claims_per_hour,
        cooldown_secs
    )
}

/// Format routing rewards display
///
/// Pure function - message formatting only
pub fn format_routing_rewards_message(
    enabled: bool,
    check_interval_secs: u32,
    minimum_threshold: u64,
    max_batch_size: u64,
) -> String {
    format!(
        "Routing Rewards:\n  Status:               {}\n  Check Interval:       {} seconds\n  Minimum Threshold:    {} ZHTP\n  Max Batch Size:       {} ZHTP",
        if enabled { "ENABLED" } else { "DISABLED" },
        check_interval_secs,
        minimum_threshold,
        max_batch_size
    )
}

/// Format storage rewards display
///
/// Pure function - message formatting only
pub fn format_storage_rewards_message(
    enabled: bool,
    check_interval_secs: u32,
    minimum_threshold: u64,
    max_batch_size: u64,
) -> String {
    format!(
        "Storage Rewards:\n  Status:               {}\n  Check Interval:       {} seconds\n  Minimum Threshold:    {} ZHTP\n  Max Batch Size:       {} ZHTP",
        if enabled { "ENABLED" } else { "DISABLED" },
        check_interval_secs,
        minimum_threshold,
        max_batch_size
    )
}

/// Format metrics display header
///
/// Pure function - message formatting only
pub fn format_metrics_header() -> String {
    "Note: Metrics API requires reward orchestrator access\n\nRouting Metrics:\n  Pending Rewards:      (not yet implemented)\n  Total Bytes Routed:   (not yet implemented)\n  Total Messages:       (not yet implemented)\n\nStorage Metrics:\n  Pending Rewards:      (not yet implemented)\n  Items Stored:         (not yet implemented)\n  Bytes Stored:         (not yet implemented)\n  Retrievals Served:    (not yet implemented)\n\nTotal Pending:\n  Combined:             (not yet implemented)".to_string()
}

/// Format routing details display
///
/// Pure function - message formatting only
pub fn format_routing_details() -> String {
    "Routing Contributions:\n  Status:               Active\n  Messages Routed:      (requires mesh server stats)\n  Bytes Routed:         (requires mesh server stats)\n  Theoretical Tokens:   (requires mesh server stats)\n\nProcessor Status:\n  Running:              (requires orchestrator query)\n  Last Check:           (requires orchestrator query)\n  Next Check:           (requires orchestrator query)\n\nReward History:\n  Total Claims:         (requires blockchain query)\n  Total Earned:         (requires blockchain query)\n  Last Claim:           (requires blockchain query)".to_string()
}

/// Format storage details display
///
/// Pure function - message formatting only
pub fn format_storage_details() -> String {
    "Storage Contributions:\n  Status:               Active\n  Items Stored:         (requires mesh server stats)\n  Bytes Stored:         (requires mesh server stats)\n  Retrievals Served:    (requires mesh server stats)\n  Storage Duration:     (requires mesh server stats)\n  Theoretical Tokens:   (requires mesh server stats)\n\nProcessor Status:\n  Running:              (requires orchestrator query)\n  Last Check:           (requires orchestrator query)\n  Next Check:           (requires orchestrator query)\n\nReward History:\n  Total Claims:         (requires blockchain query)\n  Total Earned:         (requires blockchain query)\n  Last Claim:           (requires blockchain query)".to_string()
}

/// Format full configuration display
///
/// Pure function - JSON construction only
pub fn build_config_response(
    enabled: bool,
    auto_claim: bool,
    max_claims_per_hour: u32,
    cooldown_secs: u32,
    routing_enabled: bool,
    routing_check_interval: u32,
    routing_minimum_threshold: u64,
    routing_max_batch: u64,
    storage_enabled: bool,
    storage_check_interval: u32,
    storage_minimum_threshold: u64,
    storage_max_batch: u64,
) -> Value {
    json!({
        "global": {
            "enabled": enabled,
            "auto_claim": auto_claim,
            "max_claims_per_hour": max_claims_per_hour,
            "cooldown_period_secs": cooldown_secs,
        },
        "routing": {
            "enabled": routing_enabled,
            "check_interval_secs": routing_check_interval,
            "minimum_threshold": routing_minimum_threshold,
            "max_batch_size": routing_max_batch,
        },
        "storage": {
            "enabled": storage_enabled,
            "check_interval_secs": storage_check_interval,
            "minimum_threshold": storage_minimum_threshold,
            "max_batch_size": storage_max_batch,
        }
    })
}

/// Get user-friendly header message
///
/// Pure function - message formatting only
pub fn get_operation_header(operation: RewardOperation) -> String {
    match operation {
        RewardOperation::Status => format!("{} ZHTP Reward Orchestrator Status", operation.emoji()),
        RewardOperation::Metrics => format!("{} Combined Reward Metrics", operation.emoji()),
        RewardOperation::Routing => format!("{} Routing Reward Details", operation.emoji()),
        RewardOperation::Storage => format!("{} Storage Reward Details", operation.emoji()),
        RewardOperation::Config => format!("{} Reward System Configuration", operation.emoji()),
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (I/O, formatting)
// ============================================================================

/// Handle reward command
pub async fn handle_reward_command(args: RewardArgs, _cli: &ZhtpCli) -> Result<()> {
    let operation = action_to_operation(&args.action);

    // Print header
    println!("\n╔════════════════════════════════════════════════════════╗");
    println!("║                                                        ║");
    println!("║  {}                                   ║", get_operation_header(operation));
    println!("║                                                        ║");
    println!("╚════════════════════════════════════════════════════════╝\n");

    match operation {
        RewardOperation::Status => handle_status_impl(),
        RewardOperation::Metrics => handle_metrics_impl(),
        RewardOperation::Routing => handle_routing_impl(),
        RewardOperation::Storage => handle_storage_impl(),
        RewardOperation::Config => handle_config_impl(),
    }
}

/// Internal handler for status operation
fn handle_status_impl() -> Result<()> {
    let global_config = format_reward_status_message(true, true, 100, 3600);
    let routing_config = format_routing_rewards_message(true, 60, 1000, 10000);
    let storage_config = format_storage_rewards_message(true, 60, 1000, 10000);

    println!(" {}", global_config);
    println!("\n {}", routing_config);
    println!("\n {}", storage_config);
    println!("\n╚════════════════════════════════════════════════════════╝\n");

    Ok(())
}

/// Internal handler for metrics operation
fn handle_metrics_impl() -> Result<()> {
    let metrics = format_metrics_header();
    println!("  {}", metrics);
    println!("\n╚════════════════════════════════════════════════════════╝\n");

    Ok(())
}

/// Internal handler for routing operation
fn handle_routing_impl() -> Result<()> {
    let routing = format_routing_details();
    println!(" {}", routing);
    println!("\n╚════════════════════════════════════════════════════════╝\n");

    Ok(())
}

/// Internal handler for storage operation
fn handle_storage_impl() -> Result<()> {
    let storage = format_storage_details();
    println!(" {}", storage);
    println!("\n╚════════════════════════════════════════════════════════╝\n");

    Ok(())
}

/// Internal handler for config operation
fn handle_config_impl() -> Result<()> {
    let config_json = build_config_response(
        true, true, 100, 3600,
        true, 60, 1000, 10000,
        true, 60, 1000, 10000,
    );

    println!(" Global Settings:");
    if let Some(global) = config_json.get("global").and_then(|v| v.as_object()) {
        for (key, value) in global {
            println!("   {:30} {}", format!("{}:", key), value);
        }
    }

    println!("\n Routing Configuration:");
    if let Some(routing) = config_json.get("routing").and_then(|v| v.as_object()) {
        for (key, value) in routing {
            println!("   {:30} {}", format!("{}:", key), value);
        }
    }

    println!("\n Storage Configuration:");
    if let Some(storage) = config_json.get("storage").and_then(|v| v.as_object()) {
        for (key, value) in storage {
            println!("   {:30} {}", format!("{}:", key), value);
        }
    }

    println!("\n💡 Configuration File:");
    println!("   To modify these settings, edit your node configuration file");
    println!("   under the [rewards_config] section and restart the node.");
    println!("\n╚════════════════════════════════════════════════════════╝\n");

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_status() {
        assert_eq!(action_to_operation(&RewardAction::Status), RewardOperation::Status);
    }

    #[test]
    fn test_action_to_operation_metrics() {
        assert_eq!(action_to_operation(&RewardAction::Metrics), RewardOperation::Metrics);
    }

    #[test]
    fn test_action_to_operation_routing() {
        assert_eq!(action_to_operation(&RewardAction::Routing), RewardOperation::Routing);
    }

    #[test]
    fn test_action_to_operation_storage() {
        assert_eq!(action_to_operation(&RewardAction::Storage), RewardOperation::Storage);
    }

    #[test]
    fn test_action_to_operation_config() {
        assert_eq!(action_to_operation(&RewardAction::Config), RewardOperation::Config);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(RewardOperation::Status.description(), "Show reward orchestrator status");
        assert_eq!(RewardOperation::Metrics.description(), "Show combined reward metrics");
        assert_eq!(RewardOperation::Routing.description(), "Show routing reward details");
        assert_eq!(RewardOperation::Storage.description(), "Show storage reward details");
        assert_eq!(RewardOperation::Config.description(), "Show reward configuration");
    }

    #[test]
    fn test_operation_emoji() {
        assert_eq!(RewardOperation::Status.emoji(), "📊");
        assert_eq!(RewardOperation::Metrics.emoji(), "📈");
        assert_eq!(RewardOperation::Routing.emoji(), "🔄");
        assert_eq!(RewardOperation::Storage.emoji(), "💾");
        assert_eq!(RewardOperation::Config.emoji(), "⚙️");
    }

    #[test]
    fn test_format_reward_status_message() {
        let msg = format_reward_status_message(true, true, 100, 3600);
        assert!(msg.contains("Rewards Enabled"));
        assert!(msg.contains("YES"));
        assert!(msg.contains("100"));
        assert!(msg.contains("3600"));
    }

    #[test]
    fn test_format_routing_rewards_message() {
        let msg = format_routing_rewards_message(true, 60, 1000, 10000);
        assert!(msg.contains("Routing Rewards"));
        assert!(msg.contains("ENABLED"));
        assert!(msg.contains("60"));
        assert!(msg.contains("1000"));
    }

    #[test]
    fn test_format_storage_rewards_message() {
        let msg = format_storage_rewards_message(false, 120, 2000, 20000);
        assert!(msg.contains("Storage Rewards"));
        assert!(msg.contains("DISABLED"));
        assert!(msg.contains("120"));
        assert!(msg.contains("2000"));
    }

    #[test]
    fn test_format_metrics_header() {
        let msg = format_metrics_header();
        assert!(msg.contains("Routing Metrics"));
        assert!(msg.contains("Storage Metrics"));
        assert!(msg.contains("not yet implemented"));
    }

    #[test]
    fn test_format_routing_details() {
        let msg = format_routing_details();
        assert!(msg.contains("Routing Contributions"));
        assert!(msg.contains("Processor Status"));
        assert!(msg.contains("Reward History"));
    }

    #[test]
    fn test_format_storage_details() {
        let msg = format_storage_details();
        assert!(msg.contains("Storage Contributions"));
        assert!(msg.contains("Processor Status"));
        assert!(msg.contains("Reward History"));
    }

    #[test]
    fn test_build_config_response() {
        let config = build_config_response(
            true, true, 100, 3600,
            true, 60, 1000, 10000,
            false, 120, 2000, 20000,
        );

        assert_eq!(config.get("global").and_then(|v| v.get("enabled")).and_then(|v| v.as_bool()), Some(true));
        assert_eq!(config.get("global").and_then(|v| v.get("max_claims_per_hour")).and_then(|v| v.as_u64()), Some(100));
        assert_eq!(config.get("routing").and_then(|v| v.get("enabled")).and_then(|v| v.as_bool()), Some(true));
        assert_eq!(config.get("storage").and_then(|v| v.get("enabled")).and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn test_get_operation_header() {
        let header = get_operation_header(RewardOperation::Status);
        assert!(header.contains("Status"));
        assert!(header.contains("📊"));
    }

    #[test]
    fn test_operation_emoji_all() {
        assert!(!RewardOperation::Status.emoji().is_empty());
        assert!(!RewardOperation::Metrics.emoji().is_empty());
        assert!(!RewardOperation::Routing.emoji().is_empty());
        assert!(!RewardOperation::Storage.emoji().is_empty());
        assert!(!RewardOperation::Config.emoji().is_empty());
    }

    #[test]
    fn test_format_functions_contain_expected_text() {
        assert!(format_reward_status_message(true, true, 50, 1800).contains("Global Configuration"));
        assert!(format_routing_rewards_message(true, 30, 500, 5000).contains("Status"));
        assert!(format_storage_rewards_message(true, 30, 500, 5000).contains("Status"));
    }
}
