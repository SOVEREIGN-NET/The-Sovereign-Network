//! Citizen management commands
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Identity validation, operation types
//! - **Imperative Shell**: Placeholder - awaiting server-side implementation
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for validation
//!
//! NOTE: The /api/v1/citizens/* endpoints are not yet implemented on the server.
//! This module is a placeholder that will be enabled once the server implements
//! citizen registration and UBI eligibility APIs.

use crate::argument_parsing::{CitizenArgs, CitizenAction, ZhtpCli};
use crate::error::CliResult;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Citizen operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CitizenOperation {
    Add,
    List,
}

impl CitizenOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            CitizenOperation::Add => "Register a new citizen for UBI",
            CitizenOperation::List => "List all registered citizens",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &CitizenAction) -> CitizenOperation {
    match action {
        CitizenAction::Add { .. } => CitizenOperation::Add,
        CitizenAction::List => CitizenOperation::List,
    }
}

// ============================================================================
// IMPERATIVE SHELL - Placeholder awaiting server-side implementation
// ============================================================================

/// Handle citizen command
///
/// NOTE: Citizen endpoints are not yet implemented on the server.
pub async fn handle_citizen_command(
    args: CitizenArgs,
    _cli: &ZhtpCli,
) -> CliResult<()> {
    let operation = action_to_operation(&args.action);

    println!("Citizen Management: {}", operation.description());
    println!();
    println!("Not implemented: requires server-side citizen registry.");
    println!();
    println!("The citizen management endpoints are not yet available:");
    println!("  - POST /api/v1/citizens/register");
    println!("  - GET /api/v1/citizens");
    println!();
    println!("This functionality will be available once the server implements");
    println!("the citizen registry and UBI eligibility system.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_add() {
        let action = CitizenAction::Add {
            identity_id: "did:example:123".to_string(),
        };
        assert_eq!(
            action_to_operation(&action),
            CitizenOperation::Add
        );
    }

    #[test]
    fn test_action_to_operation_list() {
        let action = CitizenAction::List;
        assert_eq!(
            action_to_operation(&action),
            CitizenOperation::List
        );
    }

    #[test]
    fn test_citizen_operation_descriptions() {
        assert!(!CitizenOperation::Add.description().is_empty());
        assert!(!CitizenOperation::List.description().is_empty());
    }
}
