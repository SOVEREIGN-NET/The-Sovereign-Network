//! Sovereign-asset manifest DHT pin verification (SA-7 / #2787).
//!
//! When the pin gate is active, `AssetLaunch` and `AssetManifestUpdate` require the
//! declared `manifest_cid` / `manifest_hash` to match bytes in the validator's local
//! DHT pin cache. Missing pins are rejected only in strict mode (best-effort default).

use crate::contracts::sovereign_asset::{
    manifest_pin_gate_active, manifest_pin_strict_mode,
};
use crate::execution::TxApplyError;
use crate::storage::{BlockchainStore, StorageResult};
use crate::transaction::asset_tx::ASSET_MANIFEST_SCHEMA;

/// Optional cross-checks against manifest JSON (launch name/symbol/decimals or asset_id).
#[derive(Debug, Clone, Copy)]
pub struct ManifestPinContext<'a> {
    pub name: Option<&'a str>,
    pub symbol: Option<&'a str>,
    pub decimals: Option<u8>,
    pub asset_id: Option<&'a [u8; 32]>,
}

fn validate_manifest_json(
    bytes: &[u8],
    expected_hash: &[u8; 32],
    ctx: ManifestPinContext<'_>,
) -> Result<(), TxApplyError> {
    if lib_crypto::hash_blake3(bytes) != *expected_hash {
        return Err(TxApplyError::InvalidType(
            "pinned manifest bytes do not match manifest_hash".into(),
        ));
    }

    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| {
        TxApplyError::InvalidType(format!("invalid manifest JSON: {e}"))
    })?;
    let schema = value
        .get("schema")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if schema != ASSET_MANIFEST_SCHEMA {
        return Err(TxApplyError::InvalidType(format!(
            "manifest schema must be {ASSET_MANIFEST_SCHEMA}, got '{schema}'"
        )));
    }

    if let Some(name) = ctx.name {
        if let Some(v) = value.get("name").and_then(|v| v.as_str()) {
            if v != name {
                return Err(TxApplyError::InvalidType(format!(
                    "manifest name '{v}' does not match '{name}'"
                )));
            }
        }
    }
    if let Some(symbol) = ctx.symbol {
        if let Some(v) = value.get("symbol").and_then(|v| v.as_str()) {
            if v != symbol {
                return Err(TxApplyError::InvalidType(format!(
                    "manifest symbol '{v}' does not match '{symbol}'"
                )));
            }
        }
    }
    if let Some(decimals) = ctx.decimals {
        if let Some(v) = value.get("decimals").and_then(|v| v.as_u64()) {
            if v != decimals as u64 {
                return Err(TxApplyError::InvalidType(format!(
                    "manifest decimals {v} does not match {decimals}"
                )));
            }
        }
    }
    if let Some(asset_id) = ctx.asset_id {
        if let Some(v) = value.get("asset_id").and_then(|v| v.as_str()) {
            let expected = hex::encode(asset_id);
            if v != expected {
                return Err(TxApplyError::InvalidType(format!(
                    "manifest asset_id '{v}' does not match '{expected}'"
                )));
            }
        }
    }

    Ok(())
}

/// Canonical `(manifest_cid, manifest_hash)` for raw manifest bytes (matches `asset_tx`).
pub fn manifest_cid_hash_from_content(content: &[u8]) -> ([u8; 32], [u8; 32]) {
    let hash = lib_crypto::hash_blake3(content);
    let mut cid = [0u8; 32];
    cid[..16].copy_from_slice(&hash[..16]);
    (cid, hash)
}

/// Parse a 64-char hex manifest CID (32 bytes) as used by DHT / assets API keys.
pub fn manifest_cid_from_hex(hex_str: &str) -> Option<[u8; 32]> {
    let bytes = hex::decode(hex_str).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut cid = [0u8; 32];
    cid.copy_from_slice(&bytes);
    Some(cid)
}

/// Mirror pinned content into the consensus `dht_pins` sled cache (SA-7 bridge).
pub fn record_dht_pin_content(
    store: &dyn BlockchainStore,
    content: &[u8],
) -> StorageResult<([u8; 32], [u8; 32])> {
    let (cid, hash) = manifest_cid_hash_from_content(content);
    store.put_dht_pin_content_direct(&cid, content)?;
    Ok((cid, hash))
}

/// Mirror by explicit CID when the DHT layer already computed the key.
pub fn record_dht_pin_at_cid(
    store: &dyn BlockchainStore,
    manifest_cid: &[u8; 32],
    content: &[u8],
) -> StorageResult<()> {
    store.put_dht_pin_content_direct(manifest_cid, content)
}

/// Verify a manifest CID/hash against the local DHT pin cache when the gate is active.
pub fn verify_manifest_pin(
    store: &dyn BlockchainStore,
    manifest_cid: &[u8; 32],
    manifest_hash: &[u8; 32],
    ctx: ManifestPinContext<'_>,
    block_height: u64,
) -> Result<(), TxApplyError> {
    if !manifest_pin_gate_active(block_height) {
        return Ok(());
    }
    if *manifest_cid == [0u8; 32] || *manifest_hash == [0u8; 32] {
        return Err(TxApplyError::InvalidType("manifest fields required".into()));
    }

    match store.get_dht_pin_content(manifest_cid)? {
        Some(bytes) => validate_manifest_json(&bytes, manifest_hash, ctx),
        None => {
            if manifest_pin_strict_mode() {
                Err(TxApplyError::InvalidType(
                    "manifest not pinned in local DHT cache (strict mode)".into(),
                ))
            } else {
                tracing::warn!(
                    manifest_cid = %hex::encode(&manifest_cid[..8]),
                    block_height,
                    "manifest pin gate: content not in local cache; allowing best-effort"
                );
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::SledStore;
    use crate::transaction::asset_tx::build_dao_launch_manifest_bytes;
    use std::sync::Arc;

    fn store_with_pin(
        manifest_cid: [u8; 32],
        bytes: &[u8],
    ) -> Arc<dyn crate::storage::BlockchainStore> {
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        store
            .put_dht_pin_content_direct(&manifest_cid, bytes)
            .expect("seed pin");
        store
    }

    #[test]
    fn pinned_manifest_hash_must_match_bytes() {
        let bytes = build_dao_launch_manifest_bytes("Bubble", "BUBL", 18);
        let hash = lib_crypto::hash_blake3(&bytes);
        let mut cid = [0u8; 32];
        cid[..16].copy_from_slice(&hash[..16]);
        let store = store_with_pin(cid, &bytes);

        let ctx = ManifestPinContext {
            name: Some("Bubble"),
            symbol: Some("BUBL"),
            decimals: Some(18),
            asset_id: None,
        };
        verify_manifest_pin(store.as_ref(), &cid, &hash, ctx, 1).unwrap();

        let bad_hash = [0xFFu8; 32];
        let err = verify_manifest_pin(store.as_ref(), &cid, &bad_hash, ctx, 1).unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(_)));
    }

    #[test]
    fn unpinned_manifest_rejected_in_strict_test_mode() {
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        let cid = [0xAB; 32];
        let hash = [0xCD; 32];
        let ctx = ManifestPinContext {
            name: None,
            symbol: None,
            decimals: None,
            asset_id: None,
        };
        let err = verify_manifest_pin(store.as_ref(), &cid, &hash, ctx, 1).unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(msg) if msg.contains("strict")));
    }
}