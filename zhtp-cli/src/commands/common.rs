//! Common validation functions shared across commands
//!
//! This module contains shared validation logic used by multiple command modules
//! to maintain DRY principles and ensure consistent validation behavior.

use crate::error::{CliResult, CliError};
use crate::output::Output;
use crate::argument_parsing::format_output;

/// Fetch data from API endpoint and display result
///
/// Generic helper to reduce duplicate API fetching code across commands.
pub async fn fetch_and_display(
    client: &reqwest::Client,
    url: &str,
    endpoint_name: &str,
    header_text: &str,
    format: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint_name.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, format)?;
        output.header(header_text)?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: endpoint_name.to_string(),
            status: response.status().as_u16(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}

/// Post data to API endpoint and display result
///
/// Generic helper to reduce duplicate API posting code across commands.
pub async fn post_and_display(
    client: &reqwest::Client,
    url: &str,
    body: serde_json::Value,
    endpoint_name: &str,
    header_text: &str,
    format: &str,
    output: &dyn Output,
) -> CliResult<()> {
    let response = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: endpoint_name.to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, format)?;
        output.header(header_text)?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: endpoint_name.to_string(),
            status: response.status().as_u16(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}

/// Validate identity ID format
///
/// Pure function - format validation only
/// 
/// Identity IDs should:
/// - Not be empty
/// - Be at least 10 characters long
/// - Contain only alphanumeric characters, colons, and hyphens (DID format)
pub fn validate_identity_id(identity_id: &str) -> CliResult<()> {
    if identity_id.is_empty() {
        return Err(CliError::ConfigError(
            "Identity ID cannot be empty".to_string(),
        ));
    }

    if identity_id.len() < 10 {
        return Err(CliError::ConfigError(format!(
            "Invalid identity ID: {}. Must be at least 10 characters",
            identity_id
        )));
    }

    // Identity IDs can contain alphanumeric, colons, and hyphens (for DID format)
    if !identity_id
        .chars()
        .all(|c| c.is_alphanumeric() || c == ':' || c == '-')
    {
        return Err(CliError::ConfigError(format!(
            "Invalid identity ID: {}. Use only alphanumeric characters, colons, and hyphens (DID format)",
            identity_id
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_identity_id_valid() {
        assert!(validate_identity_id("did:example:123456").is_ok());
    }

    #[test]
    fn test_validate_identity_id_with_hyphens() {
        assert!(validate_identity_id("did:sovereign:citizen-001").is_ok());
    }

    #[test]
    fn test_validate_identity_id_empty() {
        assert!(validate_identity_id("").is_err());
    }

    #[test]
    fn test_validate_identity_id_too_short() {
        assert!(validate_identity_id("short").is_err());
    }

    #[test]
    fn test_validate_identity_id_invalid_chars() {
        assert!(validate_identity_id("did:example:@invalid!").is_err());
    }
}
