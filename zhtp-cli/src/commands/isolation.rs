//! Network Isolation CLI Commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Operation validation, message formatting, status computation
//! - **Imperative Shell**: Network isolation operations, connectivity testing, I/O
//! - **Error Handling**: Standard anyhow::Result error handling
//! - **Testability**: Pure functions for message generation and operation description

use anyhow::Result;
use zhtp::config::network_isolation::{NetworkIsolationConfig, initialize_network_isolation, verify_mesh_isolation};
use crate::argument_parsing::{IsolationArgs, IsolationAction, ZhtpCli};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Network isolation operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsolationOperation {
    Apply,
    Check,
    Remove,
    Test,
}

impl IsolationOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            IsolationOperation::Apply => "Apply network isolation",
            IsolationOperation::Check => "Check isolation status",
            IsolationOperation::Remove => "Remove network isolation",
            IsolationOperation::Test => "Test network connectivity",
        }
    }

    /// Get operation emoji
    pub fn emoji(&self) -> &'static str {
        match self {
            IsolationOperation::Apply => "🔒",
            IsolationOperation::Check => "📊",
            IsolationOperation::Remove => "🔓",
            IsolationOperation::Test => "🔍",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &IsolationAction) -> IsolationOperation {
    match action {
        IsolationAction::Apply => IsolationOperation::Apply,
        IsolationAction::Check => IsolationOperation::Check,
        IsolationAction::Remove => IsolationOperation::Remove,
        IsolationAction::Test => IsolationOperation::Test,
    }
}

/// Format operation start message
///
/// Pure function - message formatting only
pub fn get_operation_message(operation: IsolationOperation) -> String {
    match operation {
        IsolationOperation::Apply => format!("{} Applying network isolation...", operation.emoji()),
        IsolationOperation::Check => format!("{} Checking isolation status...", operation.emoji()),
        IsolationOperation::Remove => format!("{} Removing network isolation...", operation.emoji()),
        IsolationOperation::Test => format!("{} Testing network connectivity...", operation.emoji()),
    }
}

/// Format isolation success message
///
/// Pure function - message formatting only
pub fn format_isolation_applied() -> &'static str {
    "✓ Network isolation applied successfully - mesh is now ISP-free!"
}

/// Format isolation applied with warning message
///
/// Pure function - message formatting only
pub fn format_isolation_with_warning() -> &'static str {
    "⚠ Network isolation applied but internet access still detected"
}

/// Format isolation status: isolated
///
/// Pure function - message formatting only
pub fn format_isolated_status() -> &'static str {
    "✓ Network is isolated - no internet access (ISP-free mesh)"
}

/// Format isolation status: not isolated
///
/// Pure function - message formatting only
pub fn format_not_isolated_status() -> &'static str {
    "⚠ Network has internet access - not isolated"
}

/// Format isolation removed message
///
/// Pure function - message formatting only
pub fn format_isolation_removed() -> &'static str {
    "✓ Network isolation removed - internet access restored"
}

/// Format connectivity test header
///
/// Pure function - message formatting only
pub fn format_connectivity_header() -> &'static str {
    "Network Connectivity Test Results:"
}

/// Format local connectivity result
///
/// Pure function - message formatting only
pub fn format_local_reachable() -> &'static str {
    "  ✓ Local (127.0.0.1): Reachable"
}

/// Format local connectivity failure
///
/// Pure function - message formatting only
pub fn format_local_unreachable() -> &'static str {
    "  ✗ Local (127.0.0.1): Not reachable"
}

/// Format internet host reachable (bad isolation)
///
/// Pure function - message formatting only
pub fn format_internet_reachable(host: &str) -> String {
    format!("  ⚠ Internet ({}): Reachable (isolation may be broken)", host)
}

/// Format internet host unreachable (good isolation)
///
/// Pure function - message formatting only
pub fn format_internet_unreachable(host: &str) -> String {
    format!("  ✓ Internet ({}): Not reachable (good isolation)", host)
}

/// Format configuration display
///
/// Pure function - message formatting only
pub fn get_config_display() -> String {
    "Network Isolation Configuration:\n  Isolation enabled: true\n  Default DHCP gateway: 10.0.0.1\n  DNS servers: [10.0.0.1]".to_string()
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (Network operations, I/O)
// ============================================================================

/// Handle isolation command
pub async fn handle_isolation_command(args: IsolationArgs, _cli: &ZhtpCli) -> Result<()> {
    let operation = action_to_operation(&args.action);

    println!("{}", get_operation_message(operation));

    match operation {
        IsolationOperation::Apply => handle_apply_impl().await,
        IsolationOperation::Check => handle_check_impl().await,
        IsolationOperation::Remove => handle_remove_impl().await,
        IsolationOperation::Test => handle_test_impl().await,
    }
}

/// Internal handler for apply operation
async fn handle_apply_impl() -> Result<()> {
    match initialize_network_isolation().await {
        Ok(()) => {
            // Verify it worked
            match verify_mesh_isolation().await {
                Ok(true) => println!("{}", format_isolation_applied()),
                Ok(false) => println!("{}", format_isolation_with_warning()),
                Err(e) => println!("Network isolation applied but verification failed: {}", e),
            }
        },
        Err(e) => println!("Failed to apply network isolation: {}", e),
    }
    Ok(())
}

/// Internal handler for check operation
async fn handle_check_impl() -> Result<()> {
    match verify_mesh_isolation().await {
        Ok(true) => println!("{}", format_isolated_status()),
        Ok(false) => println!("{}", format_not_isolated_status()),
        Err(e) => println!("Could not determine isolation status: {}", e),
    }
    Ok(())
}

/// Internal handler for remove operation
async fn handle_remove_impl() -> Result<()> {
    let config = NetworkIsolationConfig::default();

    match config.remove_isolation().await {
        Ok(()) => println!("{}", format_isolation_removed()),
        Err(e) => println!("Failed to remove network isolation: {}", e),
    }
    Ok(())
}

/// Internal handler for test operation
async fn handle_test_impl() -> Result<()> {
    let config = NetworkIsolationConfig::default();

    println!("{}", format_connectivity_header());

    // Test local connectivity
    match config.test_connectivity("127.0.0.1").await {
        Ok(true) => println!("{}", format_local_reachable()),
        Ok(false) => println!("{}", format_local_unreachable()),
        Err(e) => println!("  ✗ Local (127.0.0.1): Test failed - {}", e),
    }

    // Test internet connectivity
    let internet_hosts = vec!["8.8.8.8", "1.1.1.1", "google.com"];
    for host in internet_hosts {
        match config.test_connectivity(host).await {
            Ok(true) => println!("{}", format_internet_reachable(host)),
            Ok(false) => println!("{}", format_internet_unreachable(host)),
            Err(e) => println!("  ⚠ Internet ({}): Test failed - {}", host, e),
        }
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
    fn test_action_to_operation_apply() {
        assert_eq!(action_to_operation(&IsolationAction::Apply), IsolationOperation::Apply);
    }

    #[test]
    fn test_action_to_operation_check() {
        assert_eq!(action_to_operation(&IsolationAction::Check), IsolationOperation::Check);
    }

    #[test]
    fn test_action_to_operation_remove() {
        assert_eq!(action_to_operation(&IsolationAction::Remove), IsolationOperation::Remove);
    }

    #[test]
    fn test_action_to_operation_test() {
        assert_eq!(action_to_operation(&IsolationAction::Test), IsolationOperation::Test);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(IsolationOperation::Apply.description(), "Apply network isolation");
        assert_eq!(IsolationOperation::Check.description(), "Check isolation status");
        assert_eq!(IsolationOperation::Remove.description(), "Remove network isolation");
        assert_eq!(IsolationOperation::Test.description(), "Test network connectivity");
    }

    #[test]
    fn test_operation_emoji() {
        assert_eq!(IsolationOperation::Apply.emoji(), "🔒");
        assert_eq!(IsolationOperation::Check.emoji(), "📊");
        assert_eq!(IsolationOperation::Remove.emoji(), "🔓");
        assert_eq!(IsolationOperation::Test.emoji(), "🔍");
    }

    #[test]
    fn test_get_operation_message_apply() {
        let msg = get_operation_message(IsolationOperation::Apply);
        assert!(msg.contains("Applying"));
        assert!(msg.contains("🔒"));
    }

    #[test]
    fn test_get_operation_message_check() {
        let msg = get_operation_message(IsolationOperation::Check);
        assert!(msg.contains("Checking"));
        assert!(msg.contains("📊"));
    }

    #[test]
    fn test_get_operation_message_remove() {
        let msg = get_operation_message(IsolationOperation::Remove);
        assert!(msg.contains("Removing"));
        assert!(msg.contains("🔓"));
    }

    #[test]
    fn test_get_operation_message_test() {
        let msg = get_operation_message(IsolationOperation::Test);
        assert!(msg.contains("Testing"));
        assert!(msg.contains("🔍"));
    }

    #[test]
    fn test_format_isolation_applied() {
        let msg = format_isolation_applied();
        assert!(msg.contains("isolation"));
        assert!(msg.contains("ISP-free"));
    }

    #[test]
    fn test_format_isolated_status() {
        let msg = format_isolated_status();
        assert!(msg.contains("isolated"));
        assert!(msg.contains("no internet"));
    }

    #[test]
    fn test_format_not_isolated_status() {
        let msg = format_not_isolated_status();
        assert!(msg.contains("internet"));
        assert!(msg.contains("not isolated"));
    }

    #[test]
    fn test_format_isolation_removed() {
        let msg = format_isolation_removed();
        assert!(msg.contains("removed"));
        assert!(msg.contains("internet"));
    }

    #[test]
    fn test_format_connectivity_header() {
        let msg = format_connectivity_header();
        assert!(msg.contains("Connectivity"));
    }

    #[test]
    fn test_format_internet_reachable() {
        let msg = format_internet_reachable("8.8.8.8");
        assert!(msg.contains("8.8.8.8"));
        assert!(msg.contains("Reachable"));
    }

    #[test]
    fn test_format_internet_unreachable() {
        let msg = format_internet_unreachable("1.1.1.1");
        assert!(msg.contains("1.1.1.1"));
        assert!(msg.contains("Not reachable"));
    }

    #[test]
    fn test_get_config_display() {
        let config = get_config_display();
        assert!(config.contains("Network Isolation Configuration"));
    }

    #[test]
    fn test_all_operations_have_descriptions() {
        let ops = vec![
            IsolationOperation::Apply,
            IsolationOperation::Check,
            IsolationOperation::Remove,
            IsolationOperation::Test,
        ];
        for op in ops {
            assert!(!op.description().is_empty());
            assert!(!op.emoji().is_empty());
        }
    }
}
