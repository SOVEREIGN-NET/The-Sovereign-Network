//! DAO commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: DAO operation validation, request body construction, API endpoint generation
//! - **Imperative Shell**: QUIC client calls, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation and request building

use crate::argument_parsing::{DaoArgs, DaoAction, ZhtpCli, format_output};
use crate::commands::web4_utils::connect_default;
use crate::error::{CliResult, CliError};
use crate::output::Output;
use lib_network::client::ZhtpClient;
use serde_json::{json, Value};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// DAO operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaoOperation {
    Info,
    Propose,
    Vote,
    ClaimUbi,
    Balance,
}

impl DaoOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            DaoOperation::Info => "Get DAO information",
            DaoOperation::Propose => "Create proposal",
            DaoOperation::Vote => "Vote on proposal",
            DaoOperation::ClaimUbi => "Claim UBI",
            DaoOperation::Balance => "Get DAO treasury balance",
        }
    }

    /// Get request method for this operation
    pub fn method(&self) -> &'static str {
        match self {
            DaoOperation::Info | DaoOperation::Balance => "GET",
            _ => "POST",
        }
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            DaoOperation::Info => "/api/v1/dao/data",
            DaoOperation::Propose => "/api/v1/dao/proposal/create",
            DaoOperation::Vote => "/api/v1/dao/vote/cast",
            DaoOperation::ClaimUbi => "/api/v1/dao/ubi/claim",
            DaoOperation::Balance => "/api/v1/dao/treasury/status",
        }
    }

    /// Get a user-friendly title for this operation
    pub fn title(&self) -> &'static str {
        match self {
            DaoOperation::Info => "DAO Information",
            DaoOperation::Propose => "Proposal Creation",
            DaoOperation::Vote => "Vote Submission",
            DaoOperation::ClaimUbi => "UBI Claim",
            DaoOperation::Balance => "Treasury Status",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &DaoAction) -> DaoOperation {
    match action {
        DaoAction::Info => DaoOperation::Info,
        DaoAction::Propose { .. } => DaoOperation::Propose,
        DaoAction::Vote { .. } => DaoOperation::Vote,
        DaoAction::ClaimUbi => DaoOperation::ClaimUbi,
        DaoAction::Balance | DaoAction::TreasuryBalance => DaoOperation::Balance,
    }
}

/// Validate proposal ID format
///
/// Pure function - format validation only
pub fn validate_proposal_id(id: &str) -> CliResult<()> {
    if id.is_empty() {
        return Err(CliError::ConfigError(
            "Proposal ID cannot be empty".to_string(),
        ));
    }

    // Proposal IDs should be alphanumeric with hyphens
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(CliError::ConfigError(format!(
            "Invalid proposal ID: {}. Use only alphanumeric characters and hyphens",
            id
        )));
    }

    Ok(())
}

/// Validate vote choice
///
/// Pure function - format validation only
pub fn validate_vote_choice(choice: &str) -> CliResult<()> {
    let lower = choice.to_lowercase();
    if !["yes", "no", "abstain"].contains(&lower.as_str()) {
        return Err(CliError::ConfigError(format!(
            "Invalid vote choice: {}. Must be 'yes', 'no', or 'abstain'",
            choice
        )));
    }
    Ok(())
}

/// Validate proposal title
///
/// Pure function - format validation only
pub fn validate_proposal_title(title: &str) -> CliResult<()> {
    if title.is_empty() {
        return Err(CliError::ConfigError(
            "Proposal title cannot be empty".to_string(),
        ));
    }

    if title.len() > 255 {
        return Err(CliError::ConfigError(format!(
            "Proposal title too long: {} (max 255 characters)",
            title.len()
        )));
    }

    Ok(())
}

/// Build request body for DAO operation
///
/// Pure function - JSON construction only
pub fn build_request_body(
    operation: DaoOperation,
    title: Option<&str>,
    description: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
    user_id: Option<&str>,
) -> Value {
    match operation {
        DaoOperation::Info => json!({}),
        DaoOperation::Propose => json!({
            "title": title,
            "description": description,
            "orchestrated": true
        }),
        DaoOperation::Vote => json!({
            "proposal_id": proposal_id,
            "choice": choice,
            "orchestrated": true
        }),
        DaoOperation::ClaimUbi => json!({
            "user_id": user_id.unwrap_or("anonymous"),
            "orchestrated": true
        }),
        DaoOperation::Balance => json!({}),
    }
}

/// Get user-friendly message for operation
///
/// Pure function - message formatting only
pub fn get_operation_message(
    operation: DaoOperation,
    title: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
) -> String {
    match operation {
        DaoOperation::Info => "Fetching DAO information...".to_string(),
        DaoOperation::Propose => {
            format!("Creating proposal: {}", title.unwrap_or("unknown"))
        }
        DaoOperation::Vote => format!(
            "Submitting vote: {} on proposal {}",
            choice.unwrap_or("unknown"),
            proposal_id.unwrap_or("unknown")
        ),
        DaoOperation::ClaimUbi => "Claiming UBI...".to_string(),
        DaoOperation::Balance => "Fetching DAO treasury balance...".to_string(),
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (QUIC requests, I/O)
// ============================================================================

/// Handle DAO command with proper error handling and output
pub async fn handle_dao_command(args: DaoArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_dao_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_dao_command_impl(
    args: DaoArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Connect using default keystore with bootstrap mode
    let client = connect_default(&cli.server).await?;

    match args.action {
        DaoAction::Info => {
            let operation = DaoOperation::Info;
            handle_dao_operation_impl(&client, operation, None, None, None, None, cli, output).await
        }
        DaoAction::Propose { title, description } => {
            validate_proposal_title(&title)?;
            let operation = DaoOperation::Propose;
            handle_dao_operation_impl(&client, operation, Some(&title), Some(&description), None, None, cli, output).await
        }
        DaoAction::Vote { proposal_id, choice } => {
            validate_proposal_id(&proposal_id)?;
            validate_vote_choice(&choice)?;
            let operation = DaoOperation::Vote;
            handle_dao_operation_impl(&client, operation, None, None, Some(&proposal_id), Some(&choice), cli, output).await
        }
        DaoAction::ClaimUbi => {
            let operation = DaoOperation::ClaimUbi;
            handle_dao_operation_impl(&client, operation, None, None, None, None, cli, output).await
        }
        DaoAction::Balance | DaoAction::TreasuryBalance => {
            let operation = DaoOperation::Balance;
            handle_dao_operation_impl(&client, operation, None, None, None, None, cli, output).await
        }
    }
}

/// Internal handler for DAO operations
async fn handle_dao_operation_impl(
    client: &ZhtpClient,
    operation: DaoOperation,
    title: Option<&str>,
    description: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&get_operation_message(operation, title, proposal_id, choice))?;

    let request_body = build_request_body(operation, title, description, proposal_id, choice, cli.user_id.as_deref());

    let response = match operation.method() {
        "GET" => client.get(operation.endpoint_path()).await,
        "POST" => client.post_json(operation.endpoint_path(), &request_body).await,
        _ => client.get(operation.endpoint_path()).await,
    }
    .map_err(|e| CliError::ApiCallFailed {
        endpoint: operation.endpoint_path().to_string(),
        status: 0,
        reason: e.to_string(),
    })?;

    let result: Value = ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: operation.endpoint_path().to_string(),
            status: 0,
            reason: format!("Failed to parse response: {}", e),
        })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header(operation.title())?;
    output.print(&formatted)?;
    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_info() {
        assert_eq!(action_to_operation(&DaoAction::Info), DaoOperation::Info);
    }

    #[test]
    fn test_action_to_operation_propose() {
        let action = DaoAction::Propose {
            title: "test".to_string(),
            description: "test".to_string(),
        };
        assert_eq!(action_to_operation(&action), DaoOperation::Propose);
    }

    #[test]
    fn test_action_to_operation_vote() {
        let action = DaoAction::Vote {
            proposal_id: "1".to_string(),
            choice: "yes".to_string(),
        };
        assert_eq!(action_to_operation(&action), DaoOperation::Vote);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(DaoOperation::Info.description(), "Get DAO information");
        assert_eq!(DaoOperation::Propose.description(), "Create proposal");
        assert_eq!(DaoOperation::Vote.description(), "Vote on proposal");
        assert_eq!(DaoOperation::ClaimUbi.description(), "Claim UBI");
    }

    #[test]
    fn test_operation_method() {
        assert_eq!(DaoOperation::Info.method(), "GET");
        assert_eq!(DaoOperation::Propose.method(), "POST");
        assert_eq!(DaoOperation::Vote.method(), "POST");
        assert_eq!(DaoOperation::ClaimUbi.method(), "POST");
    }

    #[test]
    fn test_operation_endpoint_path() {
        assert_eq!(DaoOperation::Info.endpoint_path(), "/api/v1/dao/data");
        assert_eq!(DaoOperation::Propose.endpoint_path(), "/api/v1/dao/proposal/create");
        assert_eq!(DaoOperation::Vote.endpoint_path(), "/api/v1/dao/vote/cast");
        assert_eq!(DaoOperation::ClaimUbi.endpoint_path(), "/api/v1/dao/ubi/claim");
        assert_eq!(DaoOperation::Balance.endpoint_path(), "/api/v1/dao/treasury/status");
    }

    #[test]
    fn test_validate_proposal_id_valid() {
        assert!(validate_proposal_id("proposal-123").is_ok());
        assert!(validate_proposal_id("1").is_ok());
    }

    #[test]
    fn test_validate_proposal_id_invalid() {
        assert!(validate_proposal_id("").is_err());
        assert!(validate_proposal_id("proposal!").is_err());
    }

    #[test]
    fn test_validate_vote_choice_valid() {
        assert!(validate_vote_choice("yes").is_ok());
        assert!(validate_vote_choice("no").is_ok());
        assert!(validate_vote_choice("abstain").is_ok());
        assert!(validate_vote_choice("YES").is_ok());
    }

    #[test]
    fn test_validate_vote_choice_invalid() {
        assert!(validate_vote_choice("maybe").is_err());
        assert!(validate_vote_choice("").is_err());
    }

    #[test]
    fn test_validate_proposal_title_valid() {
        assert!(validate_proposal_title("My Proposal").is_ok());
    }

    #[test]
    fn test_validate_proposal_title_invalid() {
        assert!(validate_proposal_title("").is_err());
        let long_title = "a".repeat(256);
        assert!(validate_proposal_title(&long_title).is_err());
    }

    #[test]
    fn test_build_request_body_propose() {
        let body = build_request_body(
            DaoOperation::Propose,
            Some("Title"),
            Some("Description"),
            None,
            None,
            None,
        );
        assert_eq!(body.get("title").and_then(|v| v.as_str()), Some("Title"));
        assert_eq!(body.get("description").and_then(|v| v.as_str()), Some("Description"));
    }

    #[test]
    fn test_get_operation_message() {
        let msg = get_operation_message(DaoOperation::Propose, Some("My Proposal"), None, None);
        assert!(msg.contains("proposal"));
        assert!(msg.contains("My Proposal"));
    }
}
