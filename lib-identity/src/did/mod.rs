// packages/lib-identity/src/did/mod.rs
// Decentralized Identity Document (DID) module exports

pub mod document_generation;

// Re-export all DID types and functions
pub use document_generation::*;

/// Parse DID string to identity ID hash
///
/// DID format: "did:zhtp:{identity_id_hex}"
///
/// # Example
/// ```
/// let id = parse_did_to_identity_id("did:zhtp:abc123...")?;
/// ```
pub fn parse_did_to_identity_id(did: &str) -> anyhow::Result<lib_crypto::Hash> {
    let id_hex = did.strip_prefix("did:zhtp:")
        .ok_or_else(|| anyhow::anyhow!("Invalid DID format: must start with 'did:zhtp:'"))?;
    lib_crypto::Hash::from_hex(id_hex)
        .map_err(|e| anyhow::anyhow!("Invalid DID hex: {}", e))
}
