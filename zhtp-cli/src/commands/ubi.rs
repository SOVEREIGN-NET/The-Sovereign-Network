//! UBI status and management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, operation types
//! - **Imperative Shell**: Placeholder - awaiting server-side implementation
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation
//!
//! NOTE: The /api/v1/ubi/* endpoints are not yet implemented on the server.
//! This module is a placeholder that will be enabled once the server implements
//! the UBI distribution and status APIs.

use crate::argument_parsing::{UbiArgs, UbiAction, ZhtpCli};
use crate::error::CliResult;

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

    /// Get a user-friendly title for this operation
    pub fn title(&self, is_personal: bool) -> &'static str {
        if is_personal {
            "Personal UBI Status"
        } else {
            "Global UBI Pool Status"
        }
    }
}

// ============================================================================
// IMPERATIVE SHELL - Placeholder awaiting server-side implementation
// ============================================================================

/// Handle UBI command
///
/// NOTE: UBI endpoints are not yet implemented on the server.
pub async fn handle_ubi_command(
    args: UbiArgs,
    _cli: &ZhtpCli,
) -> CliResult<()> {
    let is_personal = match &args.action {
        UbiAction::Status { identity_id } => identity_id.is_some(),
    };

    let operation = UbiOperation::Status;

    println!("UBI: {}", operation.title(is_personal));
    println!();
    println!("Not implemented: requires server-side UBI system.");
    println!();
    println!("The UBI endpoints are not yet available:");
    println!("  - GET /api/v1/ubi/status/{{identity_id}}  (personal status)");
    println!("  - GET /api/v1/ubi/pool                   (global pool status)");
    println!();
    println!("This functionality will be available once the server implements");
    println!("the Universal Basic Income distribution system.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ubi_operation_description() {
        assert!(!UbiOperation::Status.description().is_empty());
    }

    #[test]
    fn test_ubi_operation_title_personal() {
        assert_eq!(UbiOperation::Status.title(true), "Personal UBI Status");
    }

    #[test]
    fn test_ubi_operation_title_pool() {
        assert_eq!(UbiOperation::Status.title(false), "Global UBI Pool Status");
    }
}
