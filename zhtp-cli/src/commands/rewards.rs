//! Reward System CLI Commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Reward operation validation, message formatting, status computation
//! - **Imperative Shell**: Configuration retrieval, I/O, formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing
//!
//! Placeholder implementation — commands display structured data using real
//! reward types from `lib-economy` and `zhtp::rewards` but do not yet
//! query a live node.  Future iterations will wire `ZhtpClient` calls to
//! node API endpoints such as `/api/v1/rewards/status`.

use crate::argument_parsing::{RewardAction, RewardArgs, ZhtpCli};
use crate::error::CliResult;
use crate::output::Output;
use lib_economy::rewards::{RewardRound, RewardStatistics, UsefulWorkType, ValidatorReward};
use serde_json::{json, Value};
use std::collections::HashMap;
use zhtp::rewards::budget_tracker::{BudgetTracker, RewardSource};

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
    Claim,
    History,
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
            RewardOperation::Claim => "Claim pending rewards",
            RewardOperation::History => "Show reward history",
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
            RewardOperation::Claim => "💰",
            RewardOperation::History => "📜",
        }
    }
}

/// Determine operation from arguments
pub fn action_to_operation(action: &RewardAction) -> RewardOperation {
    match action {
        RewardAction::Status => RewardOperation::Status,
        RewardAction::Metrics => RewardOperation::Metrics,
        RewardAction::Routing => RewardOperation::Routing,
        RewardAction::Storage => RewardOperation::Storage,
        RewardAction::Config => RewardOperation::Config,
        RewardAction::Claim => RewardOperation::Claim,
        RewardAction::History { .. } => RewardOperation::History,
    }
}

// ---------------------------------------------------------------------------
// Placeholder data builders (pure)
// ---------------------------------------------------------------------------

/// Build a placeholder budget tracker for display until live API is wired.
pub fn build_placeholder_budget_tracker() -> BudgetTracker {
    BudgetTracker {
        pouw_paid: 1_050_000_000_000_000_000_000_000, // 1.05M SOV (atoms)
        routing_paid: 42_000_000_000_000_000_000_000,  // 42K SOV
        storage_paid: 18_000_000_000_000_000_000_000,  // 18K SOV
        pouw_cap: 2_100_000_000_000_000_000_000_000,   // 2.1M SOV
        routing_cap: 2_100_000_000_000_000_000_000_000,
        storage_cap: 2_100_000_000_000_000_000_000_000,
        dev_grant_pool_ceiling: 100_000_000_000_000_000_000_000_000_000u128, // 100B SOV
        dev_grant_pool_paid: 1_110_000_000_000_000_000_000_000u128,
    }
}

/// Build placeholder reward statistics.
pub fn build_placeholder_reward_statistics() -> RewardStatistics {
    RewardStatistics {
        total_rounds: 1_337,
        total_rewards_distributed: 1_110_000,
        average_rewards_per_round: 830,
        current_base_reward: 500,
    }
}

/// Build a single placeholder reward round.
pub fn build_placeholder_reward_round(height: u64) -> RewardRound {
    let mut work_breakdown = HashMap::new();
    work_breakdown.insert(UsefulWorkType::NetworkRouting.to_string(), 250);
    work_breakdown.insert(UsefulWorkType::DataStorage.to_string(), 180);
    work_breakdown.insert(UsefulWorkType::Validation.to_string(), 120);

    let mut validator_rewards = HashMap::new();
    validator_rewards.insert(
        [0u8; 32],
        ValidatorReward {
            validator: [0u8; 32],
            base_reward: 500,
            work_bonus: 250,
            participation_bonus: 80,
            total_reward: 830,
            work_breakdown: work_breakdown.clone(),
        },
    );

    RewardRound {
        height,
        total_rewards: 830,
        validator_rewards,
        timestamp: 1_700_000_000 + height * 300,
    }
}

/// Build a list of placeholder reward rounds.
pub fn build_placeholder_reward_history(limit: usize) -> Vec<RewardRound> {
    let base_height = 4_200_000u64;
    (0..limit)
        .map(|i| build_placeholder_reward_round(base_height + i as u64))
        .collect()
}

// ---------------------------------------------------------------------------
// Formatting functions (pure)
// ---------------------------------------------------------------------------

/// Format budget tracker as human-readable text.
pub fn format_budget_tracker(budget: &BudgetTracker) -> String {
    fn sov(atoms: u128) -> String {
        // SOV has 18 decimals
        let whole = atoms / 1_000_000_000_000_000_000u128;
        let frac = atoms % 1_000_000_000_000_000_000u128;
        format!("{}.{:018} SOV", whole, frac)
    }

    fn pct(paid: u128, cap: u128) -> String {
        if cap == 0 {
            "0.0%".to_string()
        } else {
            format!("{:.2}%", (paid as f64 / cap as f64) * 100.0)
        }
    }

    format!(
        "Budget Tracker:\n\
         \n\
         PoUW:\n\
           Paid:   {}  ({} of cap)\n\
           Cap:    {}\n\
         Routing:\n\
           Paid:   {}  ({} of cap)\n\
           Cap:    {}\n\
         Storage:\n\
           Paid:   {}  ({} of cap)\n\
           Cap:    {}\n\
         DEV Grant Pool:\n\
           Paid:   {}\n\
           Ceiling: {}",
        sov(budget.pouw_paid),
        pct(budget.pouw_paid, budget.pouw_cap),
        sov(budget.pouw_cap),
        sov(budget.routing_paid),
        pct(budget.routing_paid, budget.routing_cap),
        sov(budget.routing_cap),
        sov(budget.storage_paid),
        pct(budget.storage_paid, budget.storage_cap),
        sov(budget.storage_cap),
        sov(budget.dev_grant_pool_paid),
        sov(budget.dev_grant_pool_ceiling),
    )
}

/// Format reward statistics as human-readable text.
pub fn format_reward_statistics(stats: &RewardStatistics) -> String {
    format!(
        "Reward Statistics:\n\
           Total Rounds:           {}\n\
           Total Distributed:      {} SOV\n\
           Average / Round:        {} SOV\n\
           Current Base Reward:    {} SOV",
        stats.total_rounds, stats.total_rewards_distributed,
        stats.average_rewards_per_round, stats.current_base_reward,
    )
}

/// Format a reward round as human-readable text.
pub fn format_reward_round(round: &RewardRound) -> String {
    let validators = round.validator_rewards.len();
    let timestamp = chrono::DateTime::from_timestamp(round.timestamp as i64, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| round.timestamp.to_string());

    format!(
        "Round {}:\n\
           Total Rewards: {} SOV\n\
           Validators:    {}\n\
           Timestamp:     {}",
        round.height, round.total_rewards, validators, timestamp,
    )
}

/// Format routing reward display using real types.
pub fn format_routing_rewards_message(
    enabled: bool,
    check_interval_secs: u32,
    minimum_threshold: u64,
    max_batch_size: u64,
    budget: &BudgetTracker,
) -> String {
    let status = if enabled { "ENABLED" } else { "DISABLED" };
    let remaining = budget.remaining(RewardSource::Routing);
    let remaining_sov = remaining / 1_000_000_000_000_000_000u128;

    format!(
        "Routing Rewards:\n\
           Status:            {}\n\
           Check Interval:    {} seconds\n\
           Min Threshold:     {} SOV\n\
           Max Batch Size:    {} SOV\n\
           Remaining Budget:  {} SOV",
        status, check_interval_secs, minimum_threshold, max_batch_size, remaining_sov,
    )
}

/// Format storage reward display using real types.
pub fn format_storage_rewards_message(
    enabled: bool,
    check_interval_secs: u32,
    minimum_threshold: u64,
    max_batch_size: u64,
    budget: &BudgetTracker,
) -> String {
    let status = if enabled { "ENABLED" } else { "DISABLED" };
    let remaining = budget.remaining(RewardSource::Storage);
    let remaining_sov = remaining / 1_000_000_000_000_000_000u128;

    format!(
        "Storage Rewards:\n\
           Status:            {}\n\
           Check Interval:    {} seconds\n\
           Min Threshold:     {} SOV\n\
           Max Batch Size:    {} SOV\n\
           Remaining Budget:  {} SOV",
        status, check_interval_secs, minimum_threshold, max_batch_size, remaining_sov,
    )
}

/// Format full configuration display as JSON.
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
    budget: &BudgetTracker,
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
            "remaining_budget": budget.remaining(RewardSource::Routing).to_string(),
        },
        "storage": {
            "enabled": storage_enabled,
            "check_interval_secs": storage_check_interval,
            "minimum_threshold": storage_minimum_threshold,
            "max_batch_size": storage_max_batch,
            "remaining_budget": budget.remaining(RewardSource::Storage).to_string(),
        }
    })
}

/// Get user-friendly header message.
pub fn get_operation_header(operation: RewardOperation) -> String {
    match operation {
        RewardOperation::Status => format!("{} SOV Reward Orchestrator Status", operation.emoji()),
        RewardOperation::Metrics => format!("{} Combined Reward Metrics", operation.emoji()),
        RewardOperation::Routing => format!("{} Routing Reward Details", operation.emoji()),
        RewardOperation::Storage => format!("{} Storage Reward Details", operation.emoji()),
        RewardOperation::Config => format!("{} Reward System Configuration", operation.emoji()),
        RewardOperation::Claim => format!("{} Claim Rewards", operation.emoji()),
        RewardOperation::History => format!("{} Reward History", operation.emoji()),
    }
}

// ============================================================================
// IMPERATIVE SHELL - Side effects and I/O
// ============================================================================

/// Handle reward command (public entry point).
pub async fn handle_reward_command(args: RewardArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_reward_command_impl(args, cli, &output).await
}

/// Handle reward command (testable implementation).
pub async fn handle_reward_command_impl(
    args: RewardArgs,
    _cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let operation = action_to_operation(&args.action);

    output.print(&format!(
        "\n╔════════════════════════════════════════════════════════╗\n\
         ║                                                        ║\n\
         ║  {:54} ║\n\
         ║                                                        ║\n\
         ╚════════════════════════════════════════════════════════╝",
        get_operation_header(operation)
    ))?;

    match operation {
        RewardOperation::Status => handle_status_impl(output).await,
        RewardOperation::Metrics => handle_metrics_impl(output).await,
        RewardOperation::Routing => handle_routing_impl(output).await,
        RewardOperation::Storage => handle_storage_impl(output).await,
        RewardOperation::Config => handle_config_impl(output).await,
        RewardOperation::Claim => handle_claim_impl(output).await,
        RewardOperation::History => {
            let limit = match args.action {
                RewardAction::History { limit } => limit.min(1000),
                _ => 10,
            };
            handle_history_impl(output, limit).await
        }
    }
}

async fn handle_status_impl(output: &dyn Output) -> CliResult<()> {
    let budget = build_placeholder_budget_tracker();
    let stats = build_placeholder_reward_statistics();

    output.print(&format_budget_tracker(&budget))?;
    output.print("")?;
    output.print(&format_reward_statistics(&stats))?;
    output.print("")?;
    output.info("Live data requires a running node with the reward orchestrator enabled.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

async fn handle_metrics_impl(output: &dyn Output) -> CliResult<()> {
    let stats = build_placeholder_reward_statistics();
    output.print(&format_reward_statistics(&stats))?;
    output.print("")?;

    output.subheader("Routing Metrics")?;
    output.print("  Pending Rewards:      1,250 SOV (placeholder)")?;
    output.print("  Total Bytes Routed:   42.3 GB (placeholder)")?;
    output.print("  Total Messages:       1,024,000 (placeholder)")?;

    output.subheader("Storage Metrics")?;
    output.print("  Pending Rewards:      890 SOV (placeholder)")?;
    output.print("  Items Stored:         5,600 (placeholder)")?;
    output.print("  Bytes Stored:         12.7 GB (placeholder)")?;
    output.print("  Retrievals Served:    8,200 (placeholder)")?;

    output.print("")?;
    output.info("Connect to a running node for live metrics.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

async fn handle_routing_impl(output: &dyn Output) -> CliResult<()> {
    let budget = build_placeholder_budget_tracker();
    let msg = format_routing_rewards_message(true, 60, 1000, 10000, &budget);
    output.print(&msg)?;
    output.print("")?;

    output.subheader("Routing Contributions")?;
    output.print("  Status:               Active (placeholder)")?;
    output.print("  Messages Routed:      1,024,000 (placeholder)")?;
    output.print("  Bytes Routed:         42.3 GB (placeholder)")?;
    output.print("  Theoretical Tokens:   1,250 SOV (placeholder)")?;

    output.subheader("Processor Status")?;
    output.print("  Running:              true (placeholder)")?;
    output.print("  Last Check:           2024-01-15T10:30:00Z (placeholder)")?;
    output.print("  Next Check:           2024-01-15T10:31:00Z (placeholder)")?;

    output.print("")?;
    output.info("Routing rewards use the NetworkRouting useful-work type.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

async fn handle_storage_impl(output: &dyn Output) -> CliResult<()> {
    let budget = build_placeholder_budget_tracker();
    let msg = format_storage_rewards_message(true, 60, 1000, 10000, &budget);
    output.print(&msg)?;
    output.print("")?;

    output.subheader("Storage Contributions")?;
    output.print("  Status:               Active (placeholder)")?;
    output.print("  Items Stored:         5,600 (placeholder)")?;
    output.print("  Bytes Stored:         12.7 GB (placeholder)")?;
    output.print("  Retrievals Served:    8,200 (placeholder)")?;
    output.print("  Storage Duration:     720 hours (placeholder)")?;
    output.print("  Theoretical Tokens:   890 SOV (placeholder)")?;

    output.subheader("Processor Status")?;
    output.print("  Running:              true (placeholder)")?;
    output.print("  Last Check:           2024-01-15T10:30:00Z (placeholder)")?;
    output.print("  Next Check:           2024-01-15T10:31:00Z (placeholder)")?;

    output.print("")?;
    output.info("Storage rewards use the DataStorage useful-work type.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

async fn handle_config_impl(output: &dyn Output) -> CliResult<()> {
    let budget = build_placeholder_budget_tracker();
    let config_json = build_config_response(
        true, true, 100, 3600, true, 60, 1000, 10000, true, 60, 1000, 10000, &budget,
    );

    output.subheader("Global Settings")?;
    if let Some(global) = config_json.get("global").and_then(|v| v.as_object()) {
        for (key, value) in global {
            output.print(&format!("   {:30} {}", format!("{}:", key), value))?;
        }
    }

    output.subheader("Routing Configuration")?;
    if let Some(routing) = config_json.get("routing").and_then(|v| v.as_object()) {
        for (key, value) in routing {
            output.print(&format!("   {:30} {}", format!("{}:", key), value))?;
        }
    }

    output.subheader("Storage Configuration")?;
    if let Some(storage) = config_json.get("storage").and_then(|v| v.as_object()) {
        for (key, value) in storage {
            output.print(&format!("   {:30} {}", format!("{}:", key), value))?;
        }
    }

    output.print("")?;
    output.info("To modify settings, edit the [rewards_config] section in your node config and restart.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

async fn handle_claim_impl(output: &dyn Output) -> CliResult<()> {
    output.warning("Reward claiming is not yet implemented.")?;
    output.print("")?;
    output.print("Planned claim flow:")?;
    output.print("  1. Query node for pending rewards via /api/v1/rewards/pending")?;
    output.print("  2. Build and sign claim transaction")?;
    output.print("  3. Submit to reward coordinator contract")?;
    output.print("  4. Display transaction receipt")?;
    output.print("")?;
    output.info("This command will be wired to the live node API in a future release.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

async fn handle_history_impl(output: &dyn Output, limit: usize) -> CliResult<()> {
    let rounds = build_placeholder_reward_history(limit);
    output.print(&format!("Showing last {} reward rounds (placeholder data):\n", rounds.len()))?;

    for round in &rounds {
        output.print(&format_reward_round(round))?;
        output.print("")?;
    }

    output.info("Live history will be fetched from the blockchain index in a future release.")?;
    output.print("╚════════════════════════════════════════════════════════╝")?;

    Ok(())
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_all_variants() {
        assert_eq!(action_to_operation(&RewardAction::Status), RewardOperation::Status);
        assert_eq!(action_to_operation(&RewardAction::Metrics), RewardOperation::Metrics);
        assert_eq!(action_to_operation(&RewardAction::Routing), RewardOperation::Routing);
        assert_eq!(action_to_operation(&RewardAction::Storage), RewardOperation::Storage);
        assert_eq!(action_to_operation(&RewardAction::Config), RewardOperation::Config);
        assert_eq!(action_to_operation(&RewardAction::Claim), RewardOperation::Claim);
        assert_eq!(
            action_to_operation(&RewardAction::History { limit: 5 }),
            RewardOperation::History
        );
    }

    #[test]
    fn test_operation_description() {
        assert!(RewardOperation::Status.description().contains("status"));
        assert!(RewardOperation::Claim.description().contains("Claim"));
        assert!(RewardOperation::History.description().contains("history"));
    }

    #[test]
    fn test_operation_emoji() {
        assert_eq!(RewardOperation::Status.emoji(), "📊");
        assert_eq!(RewardOperation::Claim.emoji(), "💰");
        assert_eq!(RewardOperation::History.emoji(), "📜");
    }

    #[test]
    fn test_build_placeholder_budget_tracker() {
        let budget = build_placeholder_budget_tracker();
        assert!(budget.can_pay(RewardSource::PoUW, 1));
        assert!(budget.total_paid() > 0);
        assert!(budget.remaining(RewardSource::Routing) > 0);
    }

    #[test]
    fn test_build_placeholder_reward_statistics() {
        let stats = build_placeholder_reward_statistics();
        assert_eq!(stats.total_rounds, 1_337);
        assert!(stats.total_rewards_distributed > 0);
    }

    #[test]
    fn test_build_placeholder_reward_round() {
        let round = build_placeholder_reward_round(100);
        assert_eq!(round.height, 100);
        assert_eq!(round.total_rewards, 830);
        assert!(!round.validator_rewards.is_empty());
    }

    #[test]
    fn test_build_placeholder_reward_history() {
        let history = build_placeholder_reward_history(5);
        assert_eq!(history.len(), 5);
        assert_eq!(history[0].height, 4_200_000);
        assert_eq!(history[1].height, 4_200_001);
    }

    #[test]
    fn test_format_budget_tracker_contains_key_data() {
        let budget = build_placeholder_budget_tracker();
        let text = format_budget_tracker(&budget);
        assert!(text.contains("PoUW"));
        assert!(text.contains("Routing"));
        assert!(text.contains("Storage"));
        assert!(text.contains("SOV"));
    }

    #[test]
    fn test_format_reward_statistics_contains_key_data() {
        let stats = build_placeholder_reward_statistics();
        let text = format_reward_statistics(&stats);
        assert!(text.contains("1337"));
        assert!(text.contains("1110000"));
    }

    #[test]
    fn test_format_reward_round_contains_key_data() {
        let round = build_placeholder_reward_round(12345);
        let text = format_reward_round(&round);
        assert!(text.contains("12345"));
        assert!(text.contains("830"));
    }

    #[test]
    fn test_format_routing_rewards_message() {
        let budget = build_placeholder_budget_tracker();
        let msg = format_routing_rewards_message(true, 60, 1000, 10000, &budget);
        assert!(msg.contains("ENABLED"));
        assert!(msg.contains("60"));
        assert!(msg.contains("SOV"));
    }

    #[test]
    fn test_format_storage_rewards_message() {
        let budget = build_placeholder_budget_tracker();
        let msg = format_storage_rewards_message(false, 120, 2000, 20000, &budget);
        assert!(msg.contains("DISABLED"));
        assert!(msg.contains("120"));
    }

    #[test]
    fn test_build_config_response_structure() {
        let budget = build_placeholder_budget_tracker();
        let config = build_config_response(
            true, true, 100, 3600, true, 60, 1000, 10000, false, 120, 2000, 20000, &budget,
        );
        assert_eq!(config.get("global").and_then(|v| v.get("enabled")).and_then(|v| v.as_bool()), Some(true));
        assert_eq!(config.get("routing").and_then(|v| v.get("enabled")).and_then(|v| v.as_bool()), Some(true));
        assert_eq!(config.get("storage").and_then(|v| v.get("enabled")).and_then(|v| v.as_bool()), Some(false));
    }

    #[test]
    fn test_get_operation_header() {
        let header = get_operation_header(RewardOperation::Claim);
        assert!(header.contains("Claim"));
        assert!(header.contains("💰"));
    }
}
