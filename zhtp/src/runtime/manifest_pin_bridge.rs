//! Mirror DHT-pinned content into the consensus `dht_pins` sled cache (SA-7).

use lib_blockchain::manifest_pin::{manifest_cid_from_hex, record_dht_pin_at_cid, record_dht_pin_content};
use tracing::debug;

/// Best-effort: record manifest bytes so `AssetLaunch` / `AssetManifestUpdate` pin gate can verify.
pub async fn mirror_content_to_consensus_pin_store(content: &[u8]) {
    let Ok(blockchain) = crate::runtime::blockchain_provider::get_global_blockchain().await else {
        return;
    };
    let guard = blockchain.read().await;
    let Some(store) = guard.get_store() else {
        return;
    };
    match record_dht_pin_content(store.as_ref(), content) {
        Ok((cid, _hash)) => {
            debug!(
                manifest_cid = %hex::encode(&cid[..8]),
                bytes = content.len(),
                "mirrored DHT pin into consensus dht_pins cache"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to mirror DHT pin to consensus store");
        }
    }
}

/// Mirror when the DHT layer returns a hex content hash / CID string.
pub async fn mirror_hex_cid_content_to_consensus_pin_store(cid_hex: &str, content: &[u8]) {
    let Ok(blockchain) = crate::runtime::blockchain_provider::get_global_blockchain().await else {
        return;
    };
    let guard = blockchain.read().await;
    let Some(store) = guard.get_store() else {
        return;
    };
    if let Some(cid) = manifest_cid_from_hex(cid_hex) {
        if record_dht_pin_at_cid(store.as_ref(), &cid, content).is_ok() {
            debug!(
                manifest_cid = %hex::encode(&cid[..8]),
                bytes = content.len(),
                "mirrored explicit CID pin into consensus dht_pins cache"
            );
        }
    } else if record_dht_pin_content(store.as_ref(), content).is_ok() {
        debug!(bytes = content.len(), "mirrored content-derived CID pin into consensus cache");
    }
}