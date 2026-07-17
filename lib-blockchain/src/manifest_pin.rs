//! Sovereign-asset manifest DHT pin verification (SA-7 / #2787).
//!
//! **Consensus apply path is deterministic.** When the pin gate is active,
//! `AssetLaunch` / `AssetManifestUpdate` require non-zero on-chain
//! `manifest_cid` / `manifest_hash`. Local `dht_pins` cache is **advisory only**
//! (log/warn): reject conditions must never depend on node-local DHT state, or
//! validators with different caches would fork.
//!
//! Optional admission helpers may still use the local cache for mempool UX;
//! those must not run on the block-apply path.

use crate::contracts::sovereign_asset::manifest_pin_gate_active;
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
///
/// Always keys by the **consensus** CID (first 16 bytes of BLAKE3, rest zero), not
/// the full Web4 content-hash string, so pin lookups match `AssetLaunch` fields.
pub fn record_dht_pin_content(
    store: &dyn BlockchainStore,
    content: &[u8],
) -> StorageResult<([u8; 32], [u8; 32])> {
    let (cid, hash) = manifest_cid_hash_from_content(content);
    store.put_dht_pin_content_direct(&cid, content)?;
    Ok((cid, hash))
}

/// Mirror by explicit CID when the DHT layer already computed the key.
///
/// Prefer [`record_dht_pin_content`] for Web4/DHT bridges: Web4 CIDs are full
/// BLAKE3 digests, while consensus `manifest_cid` is the truncated form.
pub fn record_dht_pin_at_cid(
    store: &dyn BlockchainStore,
    manifest_cid: &[u8; 32],
    content: &[u8],
) -> StorageResult<()> {
    store.put_dht_pin_content_direct(manifest_cid, content)
}

/// Consensus apply-time check for manifest CID/hash commits.
///
/// When the gate is active: require non-zero on-chain fields. Local pin cache is
/// inspected only for logging — **never** returns `Err` based on cache presence
/// or content quality (that would be a consensus-split vector).
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

    // Advisory only: same accept/reject for every validator regardless of dht_pins.
    match store.get_dht_pin_content(manifest_cid)? {
        Some(bytes) => match validate_manifest_json(&bytes, manifest_hash, ctx) {
            Ok(()) => {
                tracing::debug!(
                    manifest_cid = %hex::encode(&manifest_cid[..8]),
                    block_height,
                    "manifest pin gate: local pin matches (advisory)"
                );
            }
            Err(err) => {
                tracing::warn!(
                    manifest_cid = %hex::encode(&manifest_cid[..8]),
                    block_height,
                    error = %err,
                    "manifest pin gate: local pin invalid; allowing (advisory, consensus-safe)"
                );
            }
        },
        None => {
            tracing::warn!(
                manifest_cid = %hex::encode(&manifest_cid[..8]),
                block_height,
                "manifest pin gate: content not in local cache; allowing (advisory, consensus-safe)"
            );
        }
    }
    Ok(())
}

/// Optional mempool / operator admission check against local pin cache.
///
/// **Not for block apply.** Rejects when strict and pin is missing or invalid.
pub fn check_manifest_pin_admission(
    store: &dyn BlockchainStore,
    manifest_cid: &[u8; 32],
    manifest_hash: &[u8; 32],
    ctx: ManifestPinContext<'_>,
    strict: bool,
) -> Result<(), TxApplyError> {
    if *manifest_cid == [0u8; 32] || *manifest_hash == [0u8; 32] {
        return Err(TxApplyError::InvalidType("manifest fields required".into()));
    }
    match store.get_dht_pin_content(manifest_cid)? {
        Some(bytes) => validate_manifest_json(&bytes, manifest_hash, ctx),
        None => {
            if strict {
                Err(TxApplyError::InvalidType(
                    "manifest not pinned in local DHT cache (strict admission)".into(),
                ))
            } else {
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::sovereign_asset::{
        manifest_pin_test_overrides, MANIFEST_PIN_GATE_ACTIVATION_HEIGHT,
    };
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

    fn sample_bytes_cid_hash() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let bytes = build_dao_launch_manifest_bytes("Bubble", "BUBL", 18);
        let (cid, hash) = manifest_cid_hash_from_content(&bytes);
        (bytes, cid, hash)
    }

    #[test]
    fn gate_inactive_allows_zero_manifest_fields() {
        let _guard = manifest_pin_test_overrides::Guard::new();
        // Prod activation height — height 0 is inactive.
        assert!(!crate::contracts::sovereign_asset::manifest_pin_gate_active(0));
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        let ctx = ManifestPinContext {
            name: None,
            symbol: None,
            decimals: None,
            asset_id: None,
        };
        verify_manifest_pin(store.as_ref(), &[0u8; 32], &[0u8; 32], ctx, 0).unwrap();
    }

    #[test]
    fn gate_active_requires_nonzero_manifest_fields() {
        let _guard = manifest_pin_test_overrides::Guard::new();
        manifest_pin_test_overrides::set_gate_height(Some(0));
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        let ctx = ManifestPinContext {
            name: None,
            symbol: None,
            decimals: None,
            asset_id: None,
        };
        let err = verify_manifest_pin(store.as_ref(), &[0u8; 32], &[0u8; 32], ctx, 1).unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(msg) if msg.contains("required")));
    }

    #[test]
    fn apply_path_accepts_when_local_pin_missing() {
        let _guard = manifest_pin_test_overrides::Guard::new();
        manifest_pin_test_overrides::set_gate_height(Some(0));
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        let (_bytes, cid, hash) = sample_bytes_cid_hash();
        let ctx = ManifestPinContext {
            name: Some("Bubble"),
            symbol: Some("BUBL"),
            decimals: Some(18),
            asset_id: None,
        };
        // Consensus-safe: missing pin must not reject apply.
        verify_manifest_pin(store.as_ref(), &cid, &hash, ctx, 1).unwrap();
    }

    #[test]
    fn apply_path_accepts_when_local_pin_mismatches_hash() {
        let _guard = manifest_pin_test_overrides::Guard::new();
        manifest_pin_test_overrides::set_gate_height(Some(0));
        let (bytes, cid, hash) = sample_bytes_cid_hash();
        // Corrupt cache under the correct CID — presence of bad local bytes must not reject.
        let store = store_with_pin(cid, b"not-valid-json-manifest");
        let ctx = ManifestPinContext {
            name: Some("Bubble"),
            symbol: Some("BUBL"),
            decimals: Some(18),
            asset_id: None,
        };
        verify_manifest_pin(store.as_ref(), &cid, &hash, ctx, 1).unwrap();
        // Sanity: good pin still validates under admission helper.
        let store_ok = store_with_pin(cid, &bytes);
        check_manifest_pin_admission(store_ok.as_ref(), &cid, &hash, ctx, true).unwrap();
    }

    #[test]
    fn cross_validator_determinism_same_accept_with_or_without_cache() {
        let _guard = manifest_pin_test_overrides::Guard::new();
        manifest_pin_test_overrides::set_gate_height(Some(0));
        let (bytes, cid, hash) = sample_bytes_cid_hash();
        let ctx = ManifestPinContext {
            name: Some("Bubble"),
            symbol: Some("BUBL"),
            decimals: Some(18),
            asset_id: None,
        };
        let validator_a = store_with_pin(cid, &bytes);
        let validator_b =
            Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        // A has good pin, B has none — apply must agree.
        verify_manifest_pin(validator_a.as_ref(), &cid, &hash, ctx, 1).unwrap();
        verify_manifest_pin(validator_b.as_ref(), &cid, &hash, ctx, 1).unwrap();
        // A has bad pin, B has none — apply must still agree (both Ok).
        let validator_corrupt = store_with_pin(cid, b"garbage");
        verify_manifest_pin(validator_corrupt.as_ref(), &cid, &hash, ctx, 1).unwrap();
        verify_manifest_pin(validator_b.as_ref(), &cid, &hash, ctx, 1).unwrap();
    }

    #[test]
    fn admission_strict_rejects_unpinned() {
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        let (_bytes, cid, hash) = sample_bytes_cid_hash();
        let ctx = ManifestPinContext {
            name: None,
            symbol: None,
            decimals: None,
            asset_id: None,
        };
        let err = check_manifest_pin_admission(store.as_ref(), &cid, &hash, ctx, true).unwrap_err();
        assert!(matches!(err, TxApplyError::InvalidType(msg) if msg.contains("strict")));
    }

    #[test]
    fn record_dht_pin_uses_consensus_truncated_cid() {
        let store = Arc::new(SledStore::open_temporary().unwrap()) as Arc<dyn crate::storage::BlockchainStore>;
        let (bytes, expected_cid, expected_hash) = sample_bytes_cid_hash();
        let (cid, hash) = record_dht_pin_content(store.as_ref(), &bytes).unwrap();
        assert_eq!(cid, expected_cid);
        assert_eq!(hash, expected_hash);
        // Full BLAKE3 as key must not be required for lookup.
        let full_hash_key = expected_hash;
        assert!(store.get_dht_pin_content(&full_hash_key).unwrap().is_none()
            || full_hash_key == expected_cid);
        assert!(store.get_dht_pin_content(&expected_cid).unwrap().is_some());
    }

    #[test]
    fn prod_activation_height_is_not_zero() {
        assert_eq!(MANIFEST_PIN_GATE_ACTIVATION_HEIGHT, 80_000);
    }
}
