//! Mirror DHT-pinned content into the consensus `dht_pins` sled cache (SA-7).

use lib_blockchain::manifest_pin::record_dht_pin_content;
use tracing::debug;

/// Best-effort: record manifest bytes so operators can inspect local pin state.
///
/// Always keys by the consensus truncated CID (first 16 bytes of BLAKE3), matching
/// `AssetLaunch.manifest_cid` — not the full Web4 content-hash hex string.
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

/// Mirror when the DHT/Web4 layer returns a hex content hash / CID string.
///
/// The hex CID is ignored for keying: Web4 stores full BLAKE3 digests while
/// consensus `manifest_cid` is truncated. Content-derived recording is required.
pub async fn mirror_hex_cid_content_to_consensus_pin_store(_cid_hex: &str, content: &[u8]) {
    mirror_content_to_consensus_pin_store(content).await;
}
