//! Runtime NodeId derivation from DID + device name.
//!
//! Derivation delegates to `NodeId::from_did_device` to stay consistent with the
//! legacy deterministic NodeId format in lib-identity.

use anyhow::{anyhow, Result};
use lib_identity::types::NodeId;
use once_cell::sync::OnceCell;
use sysinfo::System;
use tracing::info;

const MAX_DEVICE_NAME_LEN: usize = 64;
const MAX_DID_LEN: usize = 512;
const DID_PREFIX: &str = "did:zhtp:";
const DID_IDENTIFIER_LEN: usize = 64;

#[derive(Debug, Clone)]
pub struct RuntimeNodeIdentity {
    pub did: String,
    pub device_name: String,
    pub node_id: NodeId,
}

static RUNTIME_NODE_IDENTITY: OnceCell<RuntimeNodeIdentity> = OnceCell::new();

/// Derive NodeId using the deterministic legacy formula (via NodeId::from_did_device).
pub fn derive_node_id(did: &str, device_name: &str) -> Result<NodeId> {
    validate_did(did)?;
    let normalized_device = normalize_device_name(device_name)?;
    NodeId::from_did_device(did, &normalized_device)
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

/// Panics if the runtime NodeId has not been initialized by the startup path
/// (set during runtime initialization in Phase 3).
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

fn normalize_device_name(name: &str) -> Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Device name cannot be empty"));
    }
    if trimmed.len() > MAX_DEVICE_NAME_LEN {
        return Err(anyhow!(
            "Device name too long (max {})",
            MAX_DEVICE_NAME_LEN
        ));
    }
    if !trimmed.chars().all(is_allowed_device_char) {
        let invalid_chars: String = trimmed
            .chars()
            .filter(|c| !is_allowed_device_char(*c))
            .collect();
        return Err(anyhow!(
            "Device name may only contain alphanumeric characters, '.', '-' or '_'. Invalid characters: {:?}",
            invalid_chars
        ));
    }
    Ok(trimmed.to_lowercase())
}

fn validate_did(did: &str) -> Result<()> {
    if did.len() > MAX_DID_LEN {
        return Err(anyhow!("DID too long (max {})", MAX_DID_LEN));
    }
    if !did.starts_with(DID_PREFIX) {
        return Err(anyhow!("Invalid DID format (expected did:zhtp:<hash>)"));
    }
    let identifier = &did[DID_PREFIX.len()..];
    if identifier.is_empty() {
        return Err(anyhow!("Invalid DID format (missing identifier)"));
    }
    if identifier.len() != DID_IDENTIFIER_LEN {
        return Err(anyhow!(
            "Invalid DID identifier length (expected {} hex characters)",
            DID_IDENTIFIER_LEN
        ));
    }
    if !identifier.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "Invalid DID identifier (must be hex-encoded Blake3 hash)"
        ));
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
            return normalize_device_name(trimmed);
        }
    }

    if let Some(p) = provided {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            return normalize_device_name(trimmed);
        }
    }

    if let Some(host) = host_name {
        let sanitized = sanitize_device_name(host);
        if !sanitized.is_empty() {
            return normalize_device_name(&sanitized);
        }
    }

    Err(anyhow!(
        "Device name not provided; set ZHTP_DEVICE_NAME or configure device name"
    ))
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
    c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_'
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_did() -> String {
        format!("did:zhtp:{}", "a".repeat(64))
    }

    #[test]
    fn deterministic() {
        let did = sample_did();
        let device = "device-1";
        let n1 = derive_node_id(did, device).unwrap();
        let n2 = derive_node_id(did, device).unwrap();
        assert_eq!(n1, n2);
    }

    #[test]
    fn different_device_changes_nodeid() {
        let did = sample_did();
        let a = derive_node_id(did, "device-1").unwrap();
        let b = derive_node_id(did, "device-2").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn empty_device_rejected() {
        let did = sample_did();
        assert!(derive_node_id(did, "").is_err());
    }

    #[test]
    fn hostname_with_invalid_chars_is_sanitized() {
        let resolved = resolve_device_name_with_host(None, Some("my-pc:01")).unwrap();
        assert_eq!(resolved, "my-pc-01");
    }

    #[test]
    fn hostname_with_only_separators_is_rejected() {
        assert!(resolve_device_name_with_host(None, Some("---")).is_err());
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

    #[test]
    fn runtime_node_identity_singleton_lifecycle() {
        assert!(try_get_runtime_node_id().is_err());

        let did = sample_did();
        let device = "device-1";
        let node_id = derive_node_id(&did, device).unwrap();

        set_runtime_node_identity(RuntimeNodeIdentity {
            did: did.clone(),
            device_name: device.to_string(),
            node_id,
        })
        .unwrap();

        let handles: Vec<_> = (0..4)
            .map(|_| std::thread::spawn(get_runtime_node_id))
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), node_id);
        }

        let second = RuntimeNodeIdentity {
            did,
            device_name: device.to_string(),
            node_id,
        };
        assert!(set_runtime_node_identity(second).is_err());
    }
}
