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

const MAX_DEVICE_NAME_LEN: usize = 256;
const MAX_DID_LEN: usize = 512;

#[derive(Debug, Clone)]
pub struct RuntimeNodeIdentity {
    pub did: String,
    pub device_name: String,
    pub node_id: NodeId,
}

static RUNTIME_NODE_IDENTITY: OnceCell<RuntimeNodeIdentity> = OnceCell::new();

/// Derive NodeId using the deterministic spec formula.
pub fn derive_node_id(did: &str, device_name: &str) -> Result<NodeId> {
    validate_did(did)?;
    validate_device_name(device_name)?;
    let preimage = format!("ZHTP_NODE_V2:{}:{}", did, device_name);
    let hash = blake3::hash(preimage.as_bytes());
    Ok(NodeId::from_bytes(*hash.as_bytes()))
}

/// Resolve device name: env override -> provided -> hostname fallback.
pub fn resolve_device_name(provided: Option<&str>) -> Result<String> {
    let sys = System::new_all();
    resolve_device_name_with_host(provided, sys.host_name().as_deref())
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

/// Panics if the runtime NodeId has not been initialized by the startup path.
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
    if name.len() > MAX_DEVICE_NAME_LEN {
        return Err(anyhow!(
            "Device name too long (max {})",
            MAX_DEVICE_NAME_LEN
        ));
    }
    if !name.chars().all(is_allowed_device_char) {
        let invalid_chars: String = name
            .chars()
            .filter(|c| !is_allowed_device_char(*c))
            .collect();
        return Err(anyhow!(
            "Device name may only contain alphanumeric characters, '-' or '_'. Invalid characters: {:?}",
            invalid_chars
        ));
    }
    Ok(())
}

fn validate_did(did: &str) -> Result<()> {
    if did.len() > MAX_DID_LEN {
        return Err(anyhow!("DID too long (max {})", MAX_DID_LEN));
    }
    if !did.starts_with("did:zhtp:") {
        return Err(anyhow!("Invalid DID format (expected did:zhtp:<hash>)"));
    }
    if did.len() == "did:zhtp:".len() {
        return Err(anyhow!("Invalid DID format (missing identifier)"));
    }
    Ok(())
}

fn resolve_device_name_with_host(
    provided: Option<&str>,
    host_name: Option<&str>,
) -> Result<String> {
    if let Ok(env_name) = std::env::var("ZHTP_DEVICE_NAME") {
        let trimmed = env_name.trim();
        if !trimmed.is_empty() {
            return normalize_configured_device_name(trimmed);
        }
    }

    if let Some(p) = provided {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return normalize_configured_device_name(trimmed);
        }
    }

    if let Some(host) = host_name {
        let sanitized = sanitize_device_name(host);
        if !sanitized.is_empty() {
            validate_device_name(&sanitized)?;
            return Ok(sanitized);
        }
    }

    Err(anyhow!(
        "Device name not provided; set ZHTP_DEVICE_NAME or configure device name"
    ))
}

fn normalize_configured_device_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    validate_device_name(trimmed)?;
    Ok(trimmed.to_string())
}

fn sanitize_device_name(name: &str) -> String {
    let sanitized: String = name
        .trim()
        .chars()
        .map(|c| if is_allowed_device_char(c) { c } else { '-' })
        .collect();

    if sanitized
        .chars()
        .any(|c| c.is_ascii_alphanumeric())
    {
        sanitized
    } else {
        String::new()
    }
}

fn is_allowed_device_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
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

    #[test]
    fn hostname_with_invalid_chars_is_sanitized() {
        let resolved = resolve_device_name_with_host(None, Some("my-pc:01")).unwrap();
        assert_eq!(resolved, "my-pc-01");
    }

    #[test]
    fn very_long_did_fails_validation() {
        let long_did = format!("did:zhtp:{}", "a".repeat(1000));
        assert!(derive_node_id(&long_did, "device").is_err());
    }

    #[test]
    fn no_device_name_available_returns_error() {
        assert!(resolve_device_name_with_host(None, None).is_err());
    }
}
