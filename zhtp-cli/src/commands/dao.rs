//! DAO commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: DAO operation validation, request body construction, API endpoint generation
//! - **Imperative Shell**: HTTP requests, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation and request building

use anyhow::Result;
use crate::argument_parsing::{DaoArgs, DaoAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
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

    /// Get HTTP method for this operation
    pub fn http_method(&self) -> &'static str {
        match self {
            DaoOperation::Info | DaoOperation::Balance => "GET",
            _ => "POST",
        }
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self) -> &'static str {
        match self {
            DaoOperation::Info => "dao/info",
            DaoOperation::Propose => "dao/proposal/create",
            DaoOperation::Vote => "dao/proposal/vote",
            DaoOperation::ClaimUbi => "dao/ubi/claim",
            DaoOperation::Balance => "dao/treasury/status",
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

/// Build API endpoint URL
///
/// Pure function - URL construction only
pub fn build_api_url(server: &str, endpoint: &str) -> String {
    format!("http://{}/api/v1/{}", server, endpoint)
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
        DaoOperation::Info => "📋 Orchestrating DAO information request...".to_string(),
        DaoOperation::Propose => {
            format!("📝 Orchestrating proposal creation: {}", title.unwrap_or("unknown"))
        }
        DaoOperation::Vote => format!(
            "🗳️  Orchestrating vote: {} on proposal {}",
            choice.unwrap_or("unknown"),
            proposal_id.unwrap_or("unknown")
        ),
        DaoOperation::ClaimUbi => "💰 Orchestrating UBI claim...".to_string(),
        DaoOperation::Balance => "💼 Fetching DAO treasury balance...".to_string(),
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (HTTP requests, I/O)
// ============================================================================

/// Handle DAO command with proper error handling and output
pub async fn handle_dao_command(args: DaoArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        DaoAction::Info => {
            let operation = DaoOperation::Info;
            handle_dao_operation_impl(operation, None, None, None, None, cli).await
        }
        DaoAction::Propose { title, description } => {
            validate_proposal_title(&title)?;
            let operation = DaoOperation::Propose;
            handle_dao_operation_impl(operation, Some(&title), Some(&description), None, None, cli).await
        }
        DaoAction::Vote { proposal_id, choice } => {
            validate_proposal_id(&proposal_id)?;
            validate_vote_choice(&choice)?;
            let operation = DaoOperation::Vote;
            handle_dao_operation_impl(operation, None, None, Some(&proposal_id), Some(&choice), cli).await
        }
        DaoAction::ClaimUbi => {
            let operation = DaoOperation::ClaimUbi;
            handle_dao_operation_impl(operation, None, None, None, None, cli).await
        }
        DaoAction::Balance | DaoAction::TreasuryBalance => {
            let operation = DaoOperation::Balance;
            handle_dao_operation_impl(operation, None, None, None, None, cli).await
        }
    }
}

/// Internal handler for DAO operations
async fn handle_dao_operation_impl(
    operation: DaoOperation,
    title: Option<&str>,
    description: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
    cli: &ZhtpCli,
) -> Result<()> {
    let client = reqwest::Client::new();
    let url = build_api_url(&cli.server, operation.endpoint_path());
    let request_body = build_request_body(operation, title, description, proposal_id, choice);

    println!("{}", get_operation_message(operation, title, proposal_id, choice));

    let response = match operation {
        DaoOperation::Info | DaoOperation::Balance => client.get(&url).send().await?,
        DaoOperation::ClaimUbi => {
            client
                .post(&url)
                .header("x-user-id", cli.user_id.as_deref().unwrap_or("anonymous"))
                .send()
                .await?
        }
        _ => client.post(&url).json(&request_body).send().await?,
    };

    if response.status().is_success() {
        let result: Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ {} orchestrated successfully!", operation.description());
        println!("{}", formatted);
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "Failed to orchestrate DAO operation: {}",
            response.status()
        ))
    }
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
    fn test_operation_http_method() {
        assert_eq!(DaoOperation::Info.http_method(), "GET");
        assert_eq!(DaoOperation::Propose.http_method(), "POST");
        assert_eq!(DaoOperation::Vote.http_method(), "POST");
        assert_eq!(DaoOperation::ClaimUbi.http_method(), "POST");
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
    fn test_build_api_url() {
        let url = build_api_url("localhost:9333", "dao/info");
        assert_eq!(url, "http://localhost:9333/api/v1/dao/info");
    }

    #[test]
    fn test_build_request_body_propose() {
        let body = build_request_body(
            DaoOperation::Propose,
            Some("Title"),
            Some("Description"),
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
