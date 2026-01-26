//! Interactive shell for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Command parsing, validation, endpoint generation, message formatting
//! - **Imperative Shell**: HTTP requests, I/O, user interaction loop
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for command validation and parsing

use anyhow::Result;
use std::io::{self, Write};
use crate::argument_parsing::{InteractiveArgs, ZhtpCli, format_output};
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

    /// Get API endpoint for this command
    pub fn endpoint(&self) -> Option<&'static str> {
        match self {
            InteractiveCommand::Status => Some("status"),
            InteractiveCommand::Health => Some("monitor/health"),
            InteractiveCommand::Components => Some("component/list"),
            InteractiveCommand::Start => Some("component/start"),
            InteractiveCommand::Stop => Some("component/stop"),
            InteractiveCommand::Info => Some("component/status"),
            _ => None,
        }
    }

    /// Get HTTP method for this command
    pub fn http_method(&self) -> &'static str {
        match self {
            InteractiveCommand::Status | InteractiveCommand::Health | InteractiveCommand::Components => "GET",
            InteractiveCommand::Start | InteractiveCommand::Stop | InteractiveCommand::Info => "POST",
            _ => "GET",
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

/// Build API endpoint URL
///
/// Pure function - URL construction only
pub fn build_api_url(server: &str, endpoint: &str) -> String {
    format!("http://{}/api/v1/{}", server, endpoint)
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
// IMPERATIVE SHELL - All side effects here (I/O, HTTP requests)
// ============================================================================

/// Execute a component command with validation
async fn execute_component_command<F, Fut>(
    client: &reqwest::Client,
    base_url: &str,
    component: Option<String>,
    usage_msg: &str,
    cli: &ZhtpCli,
    handler: F,
) where
    F: FnOnce(&reqwest::Client, &str, &str, &ZhtpCli) -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    match component {
        Some(comp) => {
            if let Err(e) = validate_component_name(&comp) {
                println!("Error: {}", e);
            } else if let Err(e) = handler(client, base_url, &comp, cli).await {
                println!("Error: {}", e);
            }
        }
        None => println!("{}", usage_msg),
    }
}

/// Execute a simple command and print error if it fails
async fn execute_simple_command<F, Fut>(handler: F)
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<()>>,
{
    if let Err(e) = handler().await {
        println!("Error: {}", e);
    }
}

/// Handle interactive command
pub async fn handle_interactive_command(_args: InteractiveArgs, cli: &ZhtpCli) -> Result<()> {
    println!("ZHTP Orchestrator Interactive Shell");
    println!("======================================");
    println!("Type 'help' for available commands, 'exit' to quit");
    println!("Server: {}", cli.server);
    println!("Format: {}", cli.format);
    println!("");

    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);

    loop {
        print!("{}", get_prompt());
        io::stdout().flush()?;

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("Error reading input");
            break;
        }

        let (command, component) = parse_command_input(&input);
        let should_exit = dispatch_command(command, component, &client, &base_url, cli, &input).await;
        if should_exit {
            break;
        }
    }

    Ok(())
}

/// Dispatch command to appropriate handler. Returns true if should exit.
async fn dispatch_command(
    command: InteractiveCommand,
    component: Option<String>,
    client: &reqwest::Client,
    base_url: &str,
    cli: &ZhtpCli,
    input: &str,
) -> bool {
    match command {
        InteractiveCommand::Exit => {
            println!("Goodbye!");
            return true;
        }
        InteractiveCommand::Help => println!("{}", get_help_message()),
        InteractiveCommand::Empty => {}
        InteractiveCommand::Unknown => {
            println!("Unknown command: {}", input.trim());
            println!("Type 'help' for available commands");
        }
        InteractiveCommand::Status => {
            execute_simple_command(|| handle_status(client, base_url, cli)).await;
        }
        InteractiveCommand::Health => {
            execute_simple_command(|| handle_health(client, base_url, cli)).await;
        }
        InteractiveCommand::Components => {
            execute_simple_command(|| handle_list_components(client, base_url, cli)).await;
        }
        InteractiveCommand::Start => {
            execute_component_command(client, base_url, component, "Usage: start <component-name>", cli, handle_start_component).await;
        }
        InteractiveCommand::Stop => {
            execute_component_command(client, base_url, component, "Usage: stop <component-name>", cli, handle_stop_component).await;
        }
        InteractiveCommand::Info => {
            execute_component_command(client, base_url, component, "Usage: info <component-name>", cli, handle_component_info).await;
        }
    }
    false
}

/// Handle status command
async fn handle_status(client: &reqwest::Client, base_url: &str, cli: &ZhtpCli) -> Result<()> {
    println!("📊 Checking orchestrator status...");
    let url = build_api_url(base_url.trim_start_matches("http://").split("/api/v1").next().unwrap_or(base_url), "status");

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ Status:\n{}", formatted);
    } else {
        println!("❌ Orchestrator status unavailable: {}", response.status());
    }

    Ok(())
}

/// Handle health command
async fn handle_health(client: &reqwest::Client, base_url: &str, cli: &ZhtpCli) -> Result<()> {
    println!("❤️  Checking component health...");
    let url = format!("{}/monitor/health", base_url);

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ Health:\n{}", formatted);
    } else {
        println!("❌ Component health check failed: {}", response.status());
    }

    Ok(())
}

/// Handle list components command
async fn handle_list_components(client: &reqwest::Client, base_url: &str, cli: &ZhtpCli) -> Result<()> {
    println!("📋 Listing components...");
    let url = format!("{}/component/list", base_url);

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ Components:\n{}", formatted);
    } else {
        println!("❌ Component list unavailable: {}", response.status());
    }

    Ok(())
}

/// Handle start component command
async fn handle_start_component(
    client: &reqwest::Client,
    base_url: &str,
    component: &str,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("▶️  Starting component: {}", component);
    let url = format!("{}/component/start", base_url);

    let request_body = serde_json::json!({
        "component": component,
        "action": "start",
        "orchestrated": true
    });

    let response = client.post(&url).json(&request_body).send().await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ Started:\n{}", formatted);
    } else {
        println!("❌ Failed to start component: {}", response.status());
    }

    Ok(())
}

/// Handle stop component command
async fn handle_stop_component(
    client: &reqwest::Client,
    base_url: &str,
    component: &str,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("⏹️  Stopping component: {}", component);
    let url = format!("{}/component/stop", base_url);

    let request_body = serde_json::json!({
        "component": component,
        "action": "stop",
        "orchestrated": true
    });

    let response = client.post(&url).json(&request_body).send().await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ Stopped:\n{}", formatted);
    } else {
        println!("❌ Failed to stop component: {}", response.status());
    }

    Ok(())
}

/// Handle component info command
async fn handle_component_info(
    client: &reqwest::Client,
    base_url: &str,
    component: &str,
    cli: &ZhtpCli,
) -> Result<()> {
    println!("ℹ️  Getting component info: {}", component);
    let url = format!("{}/component/status", base_url);

    let request_body = serde_json::json!({
        "component": component,
        "orchestrated": true
    });

    let response = client.post(&url).json(&request_body).send().await?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("✓ Info:\n{}", formatted);
    } else {
        println!("❌ Failed to get component info: {}", response.status());
    }

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
    fn test_build_api_url() {
        let url = build_api_url("localhost:9333", "status");
        assert_eq!(url, "http://localhost:9333/api/v1/status");
    }

    #[test]
    fn test_command_description() {
        assert_eq!(InteractiveCommand::Status.description(), "Show orchestrator status");
        assert_eq!(InteractiveCommand::Exit.description(), "Exit shell");
    }

    #[test]
    fn test_command_endpoint() {
        assert_eq!(InteractiveCommand::Status.endpoint(), Some("status"));
        assert_eq!(InteractiveCommand::Exit.endpoint(), None);
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
