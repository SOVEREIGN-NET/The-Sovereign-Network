//! UBI status and management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, request body construction, API endpoint generation
//! - **Imperative Shell**: HTTP requests, response handling, output formatting
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation

use crate::argument_parsing::{UbiArgs, UbiAction, ZhtpCli, format_output};
use crate::error::{CliResult, CliError};
use crate::commands::common::validate_identity_id;
use serde_json::{json, Value};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// UBI operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UbiOperation {
    Status,
}

impl UbiOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            UbiOperation::Status => "Get UBI status (personal or pool)",
        }
    }

    /// Get HTTP method for this operation
    pub fn http_method(&self) -> &'static str {
        "GET"
    }

    /// Get endpoint path for this operation
    pub fn endpoint_path(&self, identity_id: Option<&str>) -> String {
        match self {
            UbiOperation::Status => {
                if let Some(id) = identity_id {
                    format!("ubi/status/{}", id)
                } else {
                    "ubi/pool".to_string()
                }
            }
        }
    }
}

// ============================================================================
// IMPERATIVE SHELL - API calls and side effects
// ============================================================================

/// Handle UBI command
pub async fn handle_ubi_command(
    args: UbiArgs,
    cli: &ZhtpCli,
) -> CliResult<()> {
    if cli.verbose {
        eprintln!("[ubi] UBI status command");
    }

    match args.action {
        UbiAction::Status { identity_id } => {
            fetch_ubi_status(identity_id.as_deref(), cli).await
        }
    }
}

/// Fetch UBI status for an identity (or global pool if None)
async fn fetch_ubi_status(
    identity_id: Option<&str>,
    cli: &ZhtpCli,
) -> CliResult<()> {
    // Validate identity ID if provided
    if let Some(id) = identity_id {
        validate_identity_id(id)?;
    }

    if cli.verbose {
        if let Some(id) = identity_id {
            eprintln!("[ubi:status] Fetching personal UBI status for: {}", id);
        } else {
            eprintln!("[ubi:status] Fetching global UBI pool status");
        }
    }

    let operation = UbiOperation::Status;

    // Build endpoint URL
    let endpoint = operation.endpoint_path(identity_id);
    let url = format!("http://{}/api/v1/{}", cli.server, endpoint);

    if cli.verbose {
        eprintln!("[ubi:status] GET {}", url);
    }

    // Create HTTP client and send request
    let client = reqwest::Client::new();

    let response = client
        .get(&url)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "ubi/status".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    let status = response.status();

    if status.is_success() {
        let result: Value = response.json().await.map_err(|e| {
            CliError::ApiCallFailed {
                endpoint: "ubi/status".to_string(),
                status: status.as_u16(),
                reason: format!("Failed to parse response: {}", e),
            }
        })?;

        let formatted = format_output(&result, &cli.format)
            .map_err(|e| CliError::Other(e.to_string()))?;

        let header = if identity_id.is_some() {
            "✓ Personal UBI Status"
        } else {
            "✓ Global UBI Pool Status"
        };

        println!("{}\n{}", header, formatted);
        Ok(())
    } else {
        let error_body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());

        Err(CliError::ApiCallFailed {
            endpoint: "ubi/status".to_string(),
            status: status.as_u16(),
            reason: error_body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubi_operation_personal_endpoint() {
        let endpoint = UbiOperation::Status.endpoint_path(Some("did:example:123"));
        assert_eq!(endpoint, "ubi/status/did:example:123");
    }

    #[test]
    fn test_ubi_operation_pool_endpoint() {
        let endpoint = UbiOperation::Status.endpoint_path(None);
        assert_eq!(endpoint, "ubi/pool");
    }

    #[test]
    fn test_ubi_operation_http_method() {
        assert_eq!(UbiOperation::Status.http_method(), "GET");
    }

    #[test]
    fn test_ubi_operation_description() {
        assert!(!UbiOperation::Status.description().is_empty());
    }
}
