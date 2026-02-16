//! Trust management commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Trust operation validation, path construction, message formatting
//! - **Imperative Shell**: File I/O, trust database access, user prompts
//! - **Error Handling**: Domain-specific error handling with context
//! - **Testability**: Pure functions for operation description and message generation

use anyhow::{anyhow, Result, Context};
use std::path::PathBuf;
use lib_network::web4::{TrustAuditEntry, TrustConfig, TrustDb};
use crate::argument_parsing::{TrustArgs, TrustAction};

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Trust system operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustOperation {
    List,
    Audit,
    Reset,
}

impl TrustOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            TrustOperation::List => "List trust anchors",
            TrustOperation::Audit => "Show audit log",
            TrustOperation::Reset => "Reset trust anchor",
        }
    }

    /// Get operation emoji
    pub fn emoji(&self) -> &'static str {
        match self {
            TrustOperation::List => "📋",
            TrustOperation::Audit => "📝",
            TrustOperation::Reset => "🔄",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &TrustAction) -> TrustOperation {
    match action {
        TrustAction::List => TrustOperation::List,
        TrustAction::Audit => TrustOperation::Audit,
        TrustAction::Reset { .. } => TrustOperation::Reset,
    }
}

/// Get default trust database path
///
/// Pure function - path construction only
pub fn get_trustdb_path() -> Result<String> {
    Ok(TrustConfig::default_trustdb_path()?.to_string_lossy().to_string())
}

/// Get default audit log path
///
/// Pure function - path construction only
pub fn get_audit_path() -> String {
    TrustConfig::default_audit_path().to_string_lossy().to_string()
}

/// Format audit entry for display
///
/// Pure function - message formatting only
pub fn format_audit_entry(entry: &TrustAuditEntry) -> String {
    format!(
        "{} | node={} | did={} | spki={} | version={}",
        entry.timestamp,
        entry.node_addr,
        entry.node_did.as_deref().unwrap_or("unknown"),
        entry.spki_sha256,
        entry.tool_version,
    )
}

/// Format trust anchor listing header
///
/// Pure function - message formatting only
pub fn format_anchor_header(count: usize) -> String {
    format!("Trust anchors ({} entries):", count)
}

/// Format single trust anchor entry
///
/// Pure function - message formatting only
pub fn format_anchor_entry(addr: &str, did: Option<&str>, spki: &str) -> String {
    let mut result = format!("- {}\n", addr);
    if let Some(d) = did {
        result.push_str(&format!("    DID: {}\n", d));
    }
    result.push_str(&format!("    SPKI: {}", spki));
    result
}

/// Get operation message
///
/// Pure function - message formatting only
pub fn get_operation_message(operation: TrustOperation) -> String {
    match operation {
        TrustOperation::List => format!("{} Listing trust anchors...", operation.emoji()),
        TrustOperation::Audit => format!("{} Showing audit log...", operation.emoji()),
        TrustOperation::Reset => format!("{} Resetting trust anchor...", operation.emoji()),
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (File I/O, database access)
// ============================================================================

/// Handle trust command
pub async fn handle_trust_command(args: TrustArgs) -> Result<()> {
    match &args.action {
        TrustAction::List => list_trust_impl().await,
        TrustAction::Audit => show_audit_impl().await,
        TrustAction::Reset { node } => reset_trust_impl(node).await,
    }
}

/// Internal handler for list operation
async fn list_trust_impl() -> Result<()> {
    let trustdb_path = get_trustdb_path()?;
    let db = TrustDb::load_or_create(std::path::Path::new(&trustdb_path))
        .context("Failed to load trustdb")?;

    if db.anchors.is_empty() {
        println!("No trust anchors found (trustdb: {:?})", trustdb_path);
        return Ok(());
    }

    println!("{}", format_anchor_header(db.anchors.len()));
    for (addr, anchor) in db.anchors.iter() {
        println!("{}", format_anchor_entry(addr, anchor.node_did.as_deref(), &anchor.spki_sha256));
        println!("    Policy: {:?}", anchor.policy);
        println!("    First seen: {}", anchor.first_seen);
        println!("    Last seen: {}", anchor.last_seen);
    }

    Ok(())
}

/// Internal handler for audit operation
async fn show_audit_impl() -> Result<()> {
    let audit_path = get_audit_path();
    let path = PathBuf::from(&audit_path);

    if !path.exists() {
        println!("No audit log found at {:?}", path);
        return Ok(());
    }

    let data = std::fs::read_to_string(&path)?;
    let mut count = 0;
    for line in data.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: TrustAuditEntry = serde_json::from_str(line)
            .with_context(|| format!("Failed to parse audit entry: {}", line))?;
        count += 1;
        println!("{}", format_audit_entry(&entry));
    }

    if count == 0 {
        println!("Audit log is empty ({:?})", path);
    }

    Ok(())
}

/// Internal handler for reset operation
async fn reset_trust_impl(node: &str) -> Result<()> {
    let trustdb_path = get_trustdb_path()?;
    let mut db = TrustDb::load_or_create(std::path::Path::new(&trustdb_path))
        .context("Failed to load trustdb")?;

    if db.remove(node).is_some() {
        db.save(std::path::Path::new(&trustdb_path))?;
        println!("Removed trust anchor for {}", node);
    } else {
        return Err(anyhow!("No trust anchor found for {}", node));
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
    fn test_action_to_operation_list() {
        assert_eq!(action_to_operation(&TrustAction::List), TrustOperation::List);
    }

    #[test]
    fn test_action_to_operation_audit() {
        assert_eq!(action_to_operation(&TrustAction::Audit), TrustOperation::Audit);
    }

    #[test]
    fn test_action_to_operation_reset() {
        let action = TrustAction::Reset { node: "localhost:9002".to_string() };
        assert_eq!(action_to_operation(&action), TrustOperation::Reset);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(TrustOperation::List.description(), "List trust anchors");
        assert_eq!(TrustOperation::Audit.description(), "Show audit log");
        assert_eq!(TrustOperation::Reset.description(), "Reset trust anchor");
    }

    #[test]
    fn test_operation_emoji() {
        assert_eq!(TrustOperation::List.emoji(), "📋");
        assert_eq!(TrustOperation::Audit.emoji(), "📝");
        assert_eq!(TrustOperation::Reset.emoji(), "🔄");
    }

    #[test]
    fn test_format_audit_entry() {
        let entry = TrustAuditEntry {
            timestamp: 1735689600u64,
            node_addr: "localhost:9002".to_string(),
            node_did: Some("did:zhtp:test".to_string()),
            spki_sha256: "abc123".to_string(),
            tool_version: "0.1.0".to_string(),
        };
        let formatted = format_audit_entry(&entry);
        assert!(formatted.contains("localhost:9002"));
        assert!(formatted.contains("did:zhtp:test"));
        assert!(formatted.contains("abc123"));
    }

    #[test]
    fn test_format_anchor_header() {
        let header = format_anchor_header(5);
        assert!(header.contains("5"));
        assert!(header.contains("entries"));
    }

    #[test]
    fn test_format_anchor_entry_with_did() {
        let entry = format_anchor_entry("localhost:9002", Some("did:zhtp:test"), "spki123");
        assert!(entry.contains("localhost:9002"));
        assert!(entry.contains("did:zhtp:test"));
        assert!(entry.contains("spki123"));
    }

    #[test]
    fn test_format_anchor_entry_without_did() {
        let entry = format_anchor_entry("localhost:9002", None, "spki123");
        assert!(entry.contains("localhost:9002"));
        assert!(entry.contains("spki123"));
    }

    #[test]
    fn test_get_operation_message_list() {
        let msg = get_operation_message(TrustOperation::List);
        assert!(msg.contains("Listing"));
        assert!(msg.contains("📋"));
    }

    #[test]
    fn test_get_operation_message_audit() {
        let msg = get_operation_message(TrustOperation::Audit);
        assert!(msg.contains("Showing"));
        assert!(msg.contains("📝"));
    }

    #[test]
    fn test_get_operation_message_reset() {
        let msg = get_operation_message(TrustOperation::Reset);
        assert!(msg.contains("Resetting"));
        assert!(msg.contains("🔄"));
    }

    #[test]
    fn test_all_operations_have_descriptions() {
        let ops = vec![
            TrustOperation::List,
            TrustOperation::Audit,
            TrustOperation::Reset,
        ];
        for op in ops {
            assert!(!op.description().is_empty());
            assert!(!op.emoji().is_empty());
        }
    }

    #[test]
    fn test_format_audit_entry_without_did() {
        use zhtp::web4_stub::TrustAuditEntry;
        let entry = TrustAuditEntry {
            timestamp: 1735689600u64,
            node_addr: "localhost:9003".to_string(),
            node_did: None,
            spki_sha256: "def456".to_string(),
            tool_version: "0.1.0".to_string(),
        };
        let formatted = format_audit_entry(&entry);
        assert!(formatted.contains("unknown"));
    }
}
