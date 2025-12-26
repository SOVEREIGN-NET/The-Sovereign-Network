//! Trust management commands

use anyhow::{anyhow, Result, Context};
use std::path::PathBuf;

use zhtp::web4_stub::{TrustDb, TrustConfig, TrustAuditEntry};

use crate::argument_parsing::{TrustArgs, TrustAction};

/// Handle `zhtp trust` commands
pub async fn handle_trust_command(args: TrustArgs) -> Result<()> {
    match &args.action {
        TrustAction::List => list_trust().await,
        TrustAction::Audit => show_audit().await,
        TrustAction::Reset { node } => reset_trust(node).await,
    }
}

async fn list_trust() -> Result<()> {
    let trustdb_path = TrustConfig::default_trustdb_path()?;
    let db = TrustDb::load_or_create(std::path::Path::new(&trustdb_path))
        .context("Failed to load trustdb")?;

    if db.anchors.is_empty() {
        println!("No trust anchors found (trustdb: {:?})", trustdb_path);
        return Ok(());
    }

    println!("Trust anchors ({} entries):", db.anchors.len());
    for (addr, anchor) in db.anchors.iter() {
        println!("- {}", addr);
        if let Some(did) = &anchor.node_did {
            println!("    DID: {}", did);
        }
        println!("    SPKI: {}", anchor.spki_sha256);
        println!("    Policy: {:?}", anchor.policy);
        println!("    First seen: {}", anchor.first_seen);
        println!("    Last seen: {}", anchor.last_seen);
    }

    Ok(())
}

async fn show_audit() -> Result<()> {
    let audit_path = TrustConfig::default_audit_path();
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
        println!(
            "{} | node={} | did={} | spki={} | version={}",
            entry.timestamp,
            entry.node_addr,
            entry.node_did.as_deref().unwrap_or("unknown"),
            entry.spki_sha256,
            entry.tool_version,
        );
    }

    if count == 0 {
        println!("Audit log is empty ({:?})", path);
    }

    Ok(())
}

async fn reset_trust(node: &str) -> Result<()> {
    let trustdb_path = TrustConfig::default_trustdb_path()?;
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
