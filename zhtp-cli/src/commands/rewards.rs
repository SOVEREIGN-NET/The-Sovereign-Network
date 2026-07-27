//! Reward System CLI Commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Reward operation validation, message formatting, status computation
//! - **Imperative Shell**: Configuration retrieval, I/O, formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing
//!
//! BUBL/mobile rewards CLI — wired to `/api/v1/rewards/*` on live nodes.
//! Legacy PoUW orchestrator subcommands (metrics/routing/storage/config) remain placeholders.

use crate::argument_parsing::{format_output, RewardAction, RewardArgs, RewardClaimEvent, ZhtpCli};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::rewards_policy::{
    canonical_policy_bytes, policy_hash, validate_rewards_policy, RewardsPolicyError,
    RewardsPolicyV1,
};
use lib_economy::rewards::{RewardRound, RewardStatistics, UsefulWorkType, ValidatorReward};
use lib_network::client::ZhtpClient;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use zhtp::rewards::budget_tracker::{BudgetTracker, RewardSource};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Reward system operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RewardOperation {
    Status,
    Balance,
    Claim,
    Conversation,
    History,
    Metrics,
    Routing,
    Storage,
    Config,
    Configure,
}

impl RewardOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            RewardOperation::Status => "Show BUBL rewards status for a DID",
            RewardOperation::Balance => "Show BUBL rewards balance for a DID",
            RewardOperation::Claim => "Claim a BUBL reward event",
            RewardOperation::Conversation => "Claim new-partner BUBL reward",
            RewardOperation::History => "Show BUBL reward claim history",
            RewardOperation::Metrics => "Show combined reward metrics (legacy placeholder)",
            RewardOperation::Routing => "Show routing reward details (legacy placeholder)",
            RewardOperation::Storage => "Show storage reward details (legacy placeholder)",
            RewardOperation::Config => "Show reward configuration (legacy placeholder)",
            RewardOperation::Configure => {
                "Validate or generate rewards policy JSON (zhtp/rewards-policy/v1)"
            }
        }
    }

    /// Get operation display emoji
    pub fn emoji(&self) -> &'static str {
        match self {
            RewardOperation::Status => "📊",
            RewardOperation::Balance => "💳",
            RewardOperation::Claim => "💰",
            RewardOperation::Conversation => "💬",
            RewardOperation::History => "📜",
            RewardOperation::Metrics => "📈",
            RewardOperation::Routing => "🔄",
            RewardOperation::Storage => "💾",
            RewardOperation::Config => "⚙️",
            RewardOperation::Configure => "📋",
        }
    }
}

/// Determine operation from arguments
pub fn action_to_operation(action: &RewardAction) -> RewardOperation {
    match action {
        RewardAction::Status { .. } => RewardOperation::Status,
        RewardAction::Balance { .. } => RewardOperation::Balance,
        RewardAction::Claim { .. } => RewardOperation::Claim,
        RewardAction::Conversation { .. } => RewardOperation::Conversation,
        RewardAction::History { .. } => RewardOperation::History,
        RewardAction::Metrics => RewardOperation::Metrics,
        RewardAction::Routing => RewardOperation::Routing,
        RewardAction::Storage => RewardOperation::Storage,
        RewardAction::Config => RewardOperation::Config,
        RewardAction::Configure { .. } => RewardOperation::Configure,
    }
}

/// Normalize asset id to lowercase 64-char hex (no 0x prefix).
pub fn normalize_asset_id_hex(asset_id: &str) -> Result<String, String> {
    let trimmed = asset_id.strip_prefix("0x").unwrap_or(asset_id);
    if trimmed.len() != 64 || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "asset_id must be 64 hex chars, got {} chars",
            trimmed.len()
        ));
    }
    Ok(trimmed.to_ascii_lowercase())
}

/// BLAKE3 CID input for DHT pin (`zhtp/rewards-policy/cid/v1` + document bytes).
pub fn rewards_policy_cid(document_bytes: &[u8]) -> [u8; 32] {
    let mut cid_input = b"zhtp/rewards-policy/cid/v1\0".to_vec();
    cid_input.extend_from_slice(document_bytes);
    lib_crypto::hash_blake3(&cid_input)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardsPolicyBundle {
    pub policy: RewardsPolicyV1,
    pub document_bytes: Vec<u8>,
    pub policy_hash: [u8; 32],
    pub policy_cid: [u8; 32],
}

pub fn build_rewards_policy_bundle(
    policy: &RewardsPolicyV1,
) -> Result<RewardsPolicyBundle, RewardsPolicyError> {
    let document_bytes = canonical_policy_bytes(policy)?;
    let hash = policy_hash(policy)?.as_array();
    let policy_cid = rewards_policy_cid(&document_bytes);
    Ok(RewardsPolicyBundle {
        policy: policy.clone(),
        document_bytes,
        policy_hash: hash,
        policy_cid,
    })
}

pub fn load_policy_bytes_from_file(path: &Path) -> CliResult<Vec<u8>> {
    std::fs::read(path).map_err(|e| CliError::ConfigError(format!("read {}: {e}", path.display())))
}

pub fn apply_asset_id_to_policy(
    mut policy: RewardsPolicyV1,
    asset_id: &str,
) -> CliResult<RewardsPolicyV1> {
    policy.asset_id = normalize_asset_id_hex(asset_id).map_err(|e| CliError::ConfigError(e))?;
    Ok(policy)
}

pub fn bubl_policy_template_bytes() -> CliResult<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../schemas/zhtp/rewards-policy/examples/bubl-v1.json");
    load_policy_bytes_from_file(&path)
}

pub fn configure_response_json(bundle: &RewardsPolicyBundle, out_path: Option<&Path>) -> Value {
    json!({
        "schema": bundle.policy.schema,
        "asset_id": bundle.policy.asset_id,
        "policy_hash": hex::encode(bundle.policy_hash),
        "policy_cid": hex::encode(bundle.policy_cid),
        "trigger_count": bundle.policy.triggers.len(),
        "enabled_triggers": bundle.policy.triggers.iter().filter(|t| t.enabled).count(),
        "budget": bundle.policy.budget,
        "output_file": out_path.map(|p| p.display().to_string()),
        "dht_pin_hint": "Pin document_bytes at policy_cid before AssetLaunch / policy update",
    })
}

fn map_policy_error(err: RewardsPolicyError) -> CliError {
    CliError::ConfigError(format!("rewards policy validation failed: {err}"))
}

// ---------------------------------------------------------------------------
// Placeholder data builders (pure)
// ---------------------------------------------------------------------------

/// Build a placeholder budget tracker for display until live API is wired.
pub fn build_placeholder_budget_tracker() -> BudgetTracker {
    BudgetTracker {
        pouw_paid: 1_050_000_000_000_000_000_000_000, // 1.05M SOV (atoms)
        routing_paid: 42_000_000_000_000_000_000_000, // 42K SOV
        storage_paid: 18_000_000_000_000_000_000_000, // 18K SOV
        pouw_cap: 2_100_000_000_000_000_000_000_000,  // 2.1M SOV
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

/// Build a single placeholder reward round for CLI display.
///
/// CONS-103 changed lib-economy reward types to be keyed by `IdentityId` and
/// to carry `u128` amounts (post-#2287 widening). The placeholder values
/// below are scaled into SOV *atoms* via `lib_types::sov::atoms` so the CLI
/// formatting prints sensible whole-SOV numbers — using bare integers here
/// would print as `830 SOV` while real rounds carry `8.3e20`-class atoms,
/// which Copilot flagged in the PR #2382 review as misleading.
pub fn build_placeholder_reward_round(height: u64) -> RewardRound {
    let mut work_breakdown = HashMap::new();
    work_breakdown.insert(UsefulWorkType::NetworkRouting, 250);
    work_breakdown.insert(UsefulWorkType::DataStorage, 180);
    work_breakdown.insert(UsefulWorkType::Validation, 120);

    let placeholder_id = lib_crypto::Hash([0u8; 32]);
    let base_reward = lib_types::sov::atoms(500);
    let work_bonus = lib_types::sov::atoms(250);
    let participation_bonus = lib_types::sov::atoms(80);
    let total_reward = base_reward + work_bonus + participation_bonus;

    let mut validator_rewards = HashMap::new();
    validator_rewards.insert(
        placeholder_id.clone(),
        ValidatorReward {
            validator: placeholder_id,
            base_reward,
            work_bonus,
            participation_bonus,
            total_reward,
            work_breakdown,
        },
    );

    RewardRound {
        height,
        total_rewards: total_reward,
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
        stats.total_rounds,
        stats.total_rewards_distributed,
        stats.average_rewards_per_round,
        stats.current_base_reward,
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
        RewardOperation::Status => format!("{} BUBL Rewards Status", operation.emoji()),
        RewardOperation::Balance => format!("{} BUBL Rewards Balance", operation.emoji()),
        RewardOperation::Claim => format!("{} Claim BUBL Reward", operation.emoji()),
        RewardOperation::Conversation => format!("{} Claim Partner Reward", operation.emoji()),
        RewardOperation::History => format!("{} BUBL Reward History", operation.emoji()),
        RewardOperation::Metrics => {
            format!("{} Combined Reward Metrics (legacy)", operation.emoji())
        }
        RewardOperation::Routing => {
            format!("{} Routing Reward Details (legacy)", operation.emoji())
        }
        RewardOperation::Storage => {
            format!("{} Storage Reward Details (legacy)", operation.emoji())
        }
        RewardOperation::Config => {
            format!("{} Reward System Configuration (legacy)", operation.emoji())
        }
        RewardOperation::Configure => format!("{} Rewards Policy Configure", operation.emoji()),
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
    cli: &ZhtpCli,
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

    match args.action {
        RewardAction::Status { did } => handle_live_status_impl(&cli.server, &did, output).await,
        RewardAction::Balance { did } => handle_live_balance_impl(&cli.server, &did, output).await,
        RewardAction::Claim { did, event } => {
            handle_live_claim_impl(&cli.server, &did, event, output).await
        }
        RewardAction::Conversation { did, peer_did } => {
            handle_live_conversation_impl(&cli.server, &did, &peer_did, output).await
        }
        RewardAction::History { did, limit } => {
            handle_live_history_impl(&cli.server, &did, limit.min(200), output).await
        }
        RewardAction::Metrics => handle_metrics_impl(output).await,
        RewardAction::Routing => handle_routing_impl(output).await,
        RewardAction::Storage => handle_storage_impl(output).await,
        RewardAction::Config => handle_config_impl(output).await,
        RewardAction::Configure {
            file,
            template,
            asset_id,
            out,
        } => {
            handle_configure_impl(
                file.as_deref(),
                template,
                asset_id.as_deref(),
                out.as_deref(),
                cli,
                output,
            )
            .await
        }
    }
}

async fn handle_configure_impl(
    file: Option<&str>,
    template: bool,
    asset_id: Option<&str>,
    out: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    if !template && file.is_none() {
        return Err(CliError::ConfigError(
            "configure requires --file <path> or --template".to_string(),
        ));
    }
    if template && asset_id.is_none() {
        return Err(CliError::ConfigError(
            "--template requires --asset-id (64-char hex launch tx hash)".to_string(),
        ));
    }

    let raw_bytes = if template {
        bubl_policy_template_bytes()?
    } else {
        load_policy_bytes_from_file(Path::new(file.expect("file checked above")))?
    };

    let mut policy = validate_rewards_policy(&raw_bytes).map_err(map_policy_error)?;
    if let Some(id) = asset_id {
        policy = apply_asset_id_to_policy(policy, id)?;
    }

    let bundle = build_rewards_policy_bundle(&policy).map_err(map_policy_error)?;
    let out_path = out.map(Path::new);
    if let Some(path) = out_path {
        std::fs::write(path, &bundle.document_bytes)
            .map_err(|e| CliError::ConfigError(format!("write {}: {e}", path.display())))?;
        output.success(&format!("Wrote canonical policy to {}", path.display()))?;
    }

    let response = configure_response_json(&bundle, out_path);
    output.print(&format_output(&response, &cli.format)?)?;
    Ok(())
}

fn encode_did_for_path(did: &str) -> String {
    urlencoding::encode(did).to_string()
}

async fn rewards_get_json(client: &ZhtpClient, path: &str) -> CliResult<serde_json::Value> {
    let response = client
        .get(path)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;
    ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint: path.to_string(),
        status: 0,
        reason: format!("Failed to parse response: {}", e),
    })
}

async fn rewards_post_json(
    client: &ZhtpClient,
    path: &str,
    body: &serde_json::Value,
) -> CliResult<serde_json::Value> {
    let response = client
        .post_json(path, body)
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: path.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;
    ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint: path.to_string(),
        status: 0,
        reason: format!("Failed to parse response: {}", e),
    })
}

fn print_json_pretty(output: &dyn Output, value: &serde_json::Value) -> CliResult<()> {
    let text = serde_json::to_string_pretty(value)?;
    output.print(&text)?;
    Ok(())
}

async fn handle_live_status_impl(server: &str, did: &str, output: &dyn Output) -> CliResult<()> {
    let client = connect_default(server).await?;
    let path = format!("/api/v1/rewards/status/{}", encode_did_for_path(did));
    let json = rewards_get_json(&client, &path).await?;
    print_json_pretty(output, &json)?;
    output.print("╚════════════════════════════════════════════════════════╝")?;
    Ok(())
}

async fn handle_live_balance_impl(server: &str, did: &str, output: &dyn Output) -> CliResult<()> {
    let client = connect_default(server).await?;
    let path = format!("/api/v1/rewards/balance/{}", encode_did_for_path(did));
    let json = rewards_get_json(&client, &path).await?;
    print_json_pretty(output, &json)?;
    output.print("╚════════════════════════════════════════════════════════╝")?;
    Ok(())
}

async fn handle_live_claim_impl(
    server: &str,
    did: &str,
    event: RewardClaimEvent,
    output: &dyn Output,
) -> CliResult<()> {
    let client = connect_default(server).await?;
    let body = json!({ "did": did, "event": event.as_api_str() });
    let json = rewards_post_json(&client, "/api/v1/rewards/claim", &body).await?;
    print_json_pretty(output, &json)?;
    output.print("╚════════════════════════════════════════════════════════╝")?;
    Ok(())
}

async fn handle_live_conversation_impl(
    server: &str,
    did: &str,
    peer_did: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let client = connect_default(server).await?;
    let body = json!({ "did": did, "peer_did": peer_did });
    let json = rewards_post_json(&client, "/api/v1/rewards/conversation", &body).await?;
    print_json_pretty(output, &json)?;
    output.print("╚════════════════════════════════════════════════════════╝")?;
    Ok(())
}

async fn handle_live_history_impl(
    server: &str,
    did: &str,
    limit: usize,
    output: &dyn Output,
) -> CliResult<()> {
    let client = connect_default(server).await?;
    let path = format!(
        "/api/v1/rewards/history/{}?limit={}",
        encode_did_for_path(did),
        limit
    );
    let json = rewards_get_json(&client, &path).await?;
    print_json_pretty(output, &json)?;
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
    output.info(
        "To modify settings, edit the [rewards_config] section in your node config and restart.",
    )?;
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
        assert_eq!(
            action_to_operation(&RewardAction::Status {
                did: "did:zhtp:ab".to_string()
            }),
            RewardOperation::Status
        );
        assert_eq!(
            action_to_operation(&RewardAction::Balance {
                did: "did:zhtp:ab".to_string()
            }),
            RewardOperation::Balance
        );
        assert_eq!(
            action_to_operation(&RewardAction::Claim {
                did: "did:zhtp:ab".to_string(),
                event: RewardClaimEvent::Welcome,
            }),
            RewardOperation::Claim
        );
        assert_eq!(
            action_to_operation(&RewardAction::Metrics),
            RewardOperation::Metrics
        );
        assert_eq!(
            action_to_operation(&RewardAction::Routing),
            RewardOperation::Routing
        );
        assert_eq!(
            action_to_operation(&RewardAction::Storage),
            RewardOperation::Storage
        );
        assert_eq!(
            action_to_operation(&RewardAction::Config),
            RewardOperation::Config
        );
        assert_eq!(
            action_to_operation(&RewardAction::History {
                did: "did:zhtp:ab".to_string(),
                limit: 5
            }),
            RewardOperation::History
        );
    }

    #[test]
    fn test_encode_did_for_path() {
        assert_eq!(encode_did_for_path("did:zhtp:abc"), "did%3Azhtp%3Aabc");
        assert_eq!(
            encode_did_for_path("did:zhtp:user:colon"),
            "did%3Azhtp%3Auser%3Acolon"
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
        assert_eq!(round.total_rewards, lib_types::sov::atoms(830));
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
        assert_eq!(
            config
                .get("global")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            config
                .get("routing")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
        assert_eq!(
            config
                .get("storage")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn test_get_operation_header() {
        let header = get_operation_header(RewardOperation::Claim);
        assert!(header.contains("Claim"));
        assert!(header.contains("💰"));
    }

    #[test]
    fn test_normalize_asset_id_hex() {
        let id = "ab".repeat(32);
        assert_eq!(normalize_asset_id_hex(&id).unwrap(), id);
        assert!(normalize_asset_id_hex("0xabcd").is_err());
    }

    #[test]
    fn test_bubl_template_validates_and_hashes() {
        let bytes = bubl_policy_template_bytes().expect("template");
        let mut policy = validate_rewards_policy(&bytes).expect("valid");
        policy.asset_id = "cd".repeat(32);
        let bundle = build_rewards_policy_bundle(&policy).expect("bundle");
        assert_eq!(bundle.policy_hash.len(), 32);
        assert_eq!(bundle.policy_cid.len(), 32);
        assert!(!bundle.document_bytes.is_empty());
    }

    #[test]
    fn test_configure_rejects_invalid_policy() {
        let err = validate_rewards_policy(br#"{"schema":"wrong"}"#).unwrap_err();
        assert!(err.to_string().contains("schema") || err.to_string().contains("JSON"));
    }

    #[test]
    fn test_action_to_operation_configure() {
        assert_eq!(
            action_to_operation(&RewardAction::Configure {
                file: None,
                template: true,
                asset_id: Some("aa".repeat(32)),
                out: None,
            }),
            RewardOperation::Configure
        );
    }
}
