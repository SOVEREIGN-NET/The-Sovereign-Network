//! Runtime NodeId derivation from DID + device name.
//!
//! Formula (spec):
//! NodeId = blake3("ZHTP_NODE_V2:" + DID + ":" + device_name) // 32-byte output

use anyhow::{anyhow, Result};
use blake3;
use lib_identity::types::NodeId;
use once_cell::sync::OnceCell;
use sysinfo::System;
use tracing::info;

#[derive(Debug, Clone)]
pub struct RuntimeNodeIdentity {
    pub did: String,
    pub device_name: String,
    pub node_id: NodeId,
}

static RUNTIME_NODE_IDENTITY: OnceCell<RuntimeNodeIdentity> = OnceCell::new();

/// Derive NodeId using the deterministic spec formula.
pub fn derive_node_id(did: &str, device_name: &str) -> Result<NodeId> {
    validate_device_name(device_name)?;
    if !did.starts_with("did:zhtp:") {
        return Err(anyhow!("Invalid DID format (expected did:zhtp:<hash>)"));
    }
    let preimage = format!("ZHTP_NODE_V2:{}:{}", did, device_name);
    let hash = blake3::hash(preimage.as_bytes());
    Ok(NodeId::from_bytes(*hash.as_bytes()))
}

/// Resolve device name: env override -> provided -> hostname fallback.
pub fn resolve_device_name(provided: Option<&str>) -> Result<String> {
    if let Ok(env_name) = std::env::var("ZHTP_DEVICE_NAME") {
        let trimmed = env_name.trim();
        if !trimmed.is_empty() {
            validate_device_name(trimmed)?;
            return Ok(trimmed.to_string());
        }
    }

    if let Some(p) = provided {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            validate_device_name(trimmed)?;
            return Ok(trimmed.to_string());
        }
    }

    // Hostname fallback
    let sys = System::new_all();
    if let Some(host) = sys.host_name() {
        let trimmed = host.trim().to_string();
        if !trimmed.is_empty() {
            validate_device_name(&trimmed)?;
            return Ok(trimmed);
        }
    }

    Err(anyhow!(
        "Device name not provided; set ZHTP_DEVICE_NAME or configure device name"
    ))
}

pub fn set_runtime_node_identity(ctx: RuntimeNodeIdentity) -> Result<()> {
    RUNTIME_NODE_IDENTITY
        .set(ctx)
        .map_err(|_| anyhow!("RuntimeNodeIdentity already initialized"))
}

pub fn try_get_runtime_node_id() -> Result<NodeId> {
    RUNTIME_NODE_IDENTITY
        .get()
        .map(|ctx| ctx.node_id)
        .ok_or_else(|| anyhow!("Runtime NodeId not initialized"))
}

pub fn get_runtime_node_id() -> NodeId {
    try_get_runtime_node_id().expect("Runtime NodeId not initialized")
}

pub fn log_runtime_node_identity() {
    if let Some(ctx) = RUNTIME_NODE_IDENTITY.get() {
        info!("DID: {}", ctx.did);
        info!("Device name: {}", ctx.device_name);
        info!("NodeId: {}", hex::encode(ctx.node_id.as_bytes()));
    }
}

fn validate_device_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(anyhow!("Device name cannot be empty"));
    }
    if name.len() > 256 {
        return Err(anyhow!("Device name too long (max 256)"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(anyhow!(
            "Device name may only contain alphanumeric characters, '-' or '_'"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let did = "did:zhtp:test123";
        let device = "device-1";
        let n1 = derive_node_id(did, device).unwrap();
        let n2 = derive_node_id(did, device).unwrap();
        assert_eq!(n1, n2);
    }

    #[test]
    fn different_device_changes_nodeid() {
        let did = "did:zhtp:test123";
        let a = derive_node_id(did, "device-1").unwrap();
        let b = derive_node_id(did, "device-2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_device_rejected() {
        assert!(derive_node_id("did:zhtp:test123", "").is_err());
    }
}
