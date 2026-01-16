//! Interactive shell for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Command parsing, validation, message formatting
//! - **Imperative Shell**: User interaction loop (placeholder - awaiting QUIC control surfaces)
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for command validation and parsing
//!
//! NOTE: This module is a placeholder. The interactive shell requires server-side
//! QUIC control surfaces that are not yet implemented.

use anyhow::Result;
use crate::argument_parsing::{InteractiveArgs, ZhtpCli};
use crate::error::{CliResult, CliError};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Interactive shell commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractiveCommand {
    Status,
    Health,
    Components,
    Start,
    Stop,
    Info,
    Help,
    Exit,
    Empty,
    Unknown,
}

impl InteractiveCommand {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            InteractiveCommand::Status => "Show orchestrator status",
            InteractiveCommand::Health => "Check component health",
            InteractiveCommand::Components => "List all components",
            InteractiveCommand::Start => "Start a component",
            InteractiveCommand::Stop => "Stop a component",
            InteractiveCommand::Info => "Get component information",
            InteractiveCommand::Help => "Show help",
            InteractiveCommand::Exit => "Exit shell",
            InteractiveCommand::Empty => "No command",
            InteractiveCommand::Unknown => "Unknown command",
        }
    }
}

/// Parse user input into command and optional component name
///
/// Pure function - deterministic parsing only
pub fn parse_command_input(input: &str) -> (InteractiveCommand, Option<String>) {
    let trimmed = input.trim();

    if trimmed.is_empty() {
        return (InteractiveCommand::Empty, None);
    }

    if trimmed == "exit" || trimmed == "quit" {
        return (InteractiveCommand::Exit, None);
    }

    if trimmed == "help" {
        return (InteractiveCommand::Help, None);
    }

    if trimmed == "status" {
        return (InteractiveCommand::Status, None);
    }

    if trimmed == "health" {
        return (InteractiveCommand::Health, None);
    }

    if trimmed == "components" {
        return (InteractiveCommand::Components, None);
    }

    if let Some(component) = trimmed.strip_prefix("start ") {
        return (InteractiveCommand::Start, Some(component.to_string()));
    }

    if let Some(component) = trimmed.strip_prefix("stop ") {
        return (InteractiveCommand::Stop, Some(component.to_string()));
    }

    if let Some(component) = trimmed.strip_prefix("info ") {
        return (InteractiveCommand::Info, Some(component.to_string()));
    }

    (InteractiveCommand::Unknown, None)
}

/// Validate component name
///
/// Pure function - format validation only
pub fn validate_component_name(name: &str) -> CliResult<()> {
    if name.is_empty() {
        return Err(CliError::ConfigError(
            "Component name cannot be empty".to_string(),
        ));
    }

    if name.len() > 128 {
        return Err(CliError::ConfigError(format!(
            "Component name too long: {} (max 128 characters)",
            name.len()
        )));
    }

    // Component names should be alphanumeric with hyphens and underscores
    if !name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        return Err(CliError::ConfigError(format!(
            "Invalid component name: {}. Use only alphanumeric characters, hyphens, and underscores",
            name
        )));
    }

    Ok(())
}

/// Get help message
///
/// Pure function - message formatting only
pub fn get_help_message() -> String {
    "Available commands:
  status      - Show orchestrator status
  health      - Check component health
  components  - List all components
  start <name> - Start a component
  stop <name>  - Stop a component
  info <name>  - Get component information
  help        - Show this help message
  exit/quit   - Exit the shell

Components: protocols, blockchain, network, consensus, storage, economy, proofs, identity, crypto
"
    .to_string()
}

/// Get command prompt
///
/// Pure function - message formatting only
pub fn get_prompt() -> &'static str {
    "zhtp> "
}

// ============================================================================
// IMPERATIVE SHELL - Placeholder awaiting server-side QUIC support
// ============================================================================

/// Handle interactive command
///
/// NOTE: Interactive shell is not yet implemented. Requires server-side QUIC
/// control surfaces for component management and status queries.
pub async fn handle_interactive_command(_args: InteractiveArgs, _cli: &ZhtpCli) -> Result<()> {
    println!("ZHTP Orchestrator Interactive Shell");
    println!("====================================");
    println!();
    println!("Not implemented: requires server-side QUIC support.");
    println!();
    println!("The interactive shell will be available once the server implements");
    println!("QUIC-based control surfaces for:");
    println!("  - Component status queries");
    println!("  - Component lifecycle management (start/stop)");
    println!("  - Health monitoring endpoints");
    println!();
    println!("For now, use individual CLI commands instead:");
    println!("  zhtp-cli network status");
    println!("  zhtp-cli blockchain info");
    println!("  zhtp-cli wallet balance <identity>");

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_command_input_status() {
        let (cmd, comp) = parse_command_input("status");
        assert_eq!(cmd, InteractiveCommand::Status);
        assert_eq!(comp, None);
    }

    #[test]
    fn test_parse_command_input_start_component() {
        let (cmd, comp) = parse_command_input("start consensus");
        assert_eq!(cmd, InteractiveCommand::Start);
        assert_eq!(comp, Some("consensus".to_string()));
    }

    #[test]
    fn test_parse_command_input_exit() {
        let (cmd, _) = parse_command_input("exit");
        assert_eq!(cmd, InteractiveCommand::Exit);

        let (cmd, _) = parse_command_input("quit");
        assert_eq!(cmd, InteractiveCommand::Exit);
    }

    #[test]
    fn test_parse_command_input_empty() {
        let (cmd, _) = parse_command_input("   ");
        assert_eq!(cmd, InteractiveCommand::Empty);
    }

    #[test]
    fn test_parse_command_input_unknown() {
        let (cmd, _) = parse_command_input("unknown");
        assert_eq!(cmd, InteractiveCommand::Unknown);
    }

    #[test]
    fn test_validate_component_name_valid() {
        assert!(validate_component_name("consensus").is_ok());
        assert!(validate_component_name("consensus-engine").is_ok());
    }

    #[test]
    fn test_validate_component_name_invalid() {
        assert!(validate_component_name("").is_err());
        assert!(validate_component_name("component!").is_err());
    }

    #[test]
    fn test_command_description() {
        assert_eq!(InteractiveCommand::Status.description(), "Show orchestrator status");
        assert_eq!(InteractiveCommand::Exit.description(), "Exit shell");
    }

    #[test]
    fn test_get_help_message() {
        let help = get_help_message();
        assert!(help.contains("status"));
        assert!(help.contains("help"));
        assert!(help.contains("exit"));
    }

    #[test]
    fn test_get_prompt() {
        assert_eq!(get_prompt(), "zhtp> ");
    }
}
