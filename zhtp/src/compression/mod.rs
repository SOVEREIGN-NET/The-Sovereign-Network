//! Wire Compression Layer — SovereignCodec compression for ALL system data
//!
//! The Neural Mesh doesn't just compress its own model weights — it compresses
//! EVERYTHING flowing through the Sovereign Network:
//!
//! - **Blockchain**: Block and transaction data before mesh broadcast
//! - **DHT**: Content values before storage and network transfer
//! - **ZHTP**: Request/response bodies before QUIC transmission
//! - **Routing**: Mesh message payloads between peers
//! - **Storage**: All persisted data on disk
//! - **Neural Mesh**: AI model weights (self-compression)
//!
//! The Adaptive Codec Learner (neural network) continuously optimizes compression
//! parameters based on observed data patterns, making compression MORE EFFECTIVE
//! over time as the network sees more traffic.
//!
//! Wire format: 4-byte magic header + compressed payload
//! - Magic: `SFC\x02` (SovereignCodec Format v2)
//! - Followed by SovereignCodec-compressed data
//! - Data below MIN_COMPRESS_SIZE is stored uncompressed (no header)

use lib_compression::SovereignCodec;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info};

// ─── Wire Format Constants ──────────────────────────────────────────

/// Magic header for SFC-compressed wire data
const SFC_MAGIC: &[u8; 4] = b"SFC\x02";

/// Minimum size (bytes) to bother compressing — below this, overhead > savings
const MIN_COMPRESS_SIZE: usize = 64;

// ─── Global Compression Statistics ──────────────────────────────────

/// Tracks system-wide compression across all data paths
pub struct WireCompressionStats {
    // Blockchain
    pub blocks_compressed: AtomicU64,
    pub block_bytes_in: AtomicU64,
    pub block_bytes_out: AtomicU64,

    // Transactions
    pub txs_compressed: AtomicU64,
    pub tx_bytes_in: AtomicU64,
    pub tx_bytes_out: AtomicU64,

    // DHT
    pub dht_compressed: AtomicU64,
    pub dht_bytes_in: AtomicU64,
    pub dht_bytes_out: AtomicU64,

    // ZHTP
    pub zhtp_compressed: AtomicU64,
    pub zhtp_bytes_in: AtomicU64,
    pub zhtp_bytes_out: AtomicU64,

    // Total
    pub total_ops: AtomicU64,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
}

impl WireCompressionStats {
    pub const fn new() -> Self {
        Self {
            blocks_compressed: AtomicU64::new(0),
            block_bytes_in: AtomicU64::new(0),
            block_bytes_out: AtomicU64::new(0),
            txs_compressed: AtomicU64::new(0),
            tx_bytes_in: AtomicU64::new(0),
            tx_bytes_out: AtomicU64::new(0),
            dht_compressed: AtomicU64::new(0),
            dht_bytes_in: AtomicU64::new(0),
            dht_bytes_out: AtomicU64::new(0),
            zhtp_compressed: AtomicU64::new(0),
            zhtp_bytes_in: AtomicU64::new(0),
            zhtp_bytes_out: AtomicU64::new(0),
            total_ops: AtomicU64::new(0),
            total_bytes_in: AtomicU64::new(0),
            total_bytes_out: AtomicU64::new(0),
        }
    }

    pub fn avg_ratio(&self) -> f64 {
        let bytes_in = self.total_bytes_in.load(Ordering::Relaxed) as f64;
        let bytes_out = self.total_bytes_out.load(Ordering::Relaxed) as f64;
        if bytes_out == 0.0 {
            1.0
        } else {
            bytes_in / bytes_out
        }
    }

    pub fn total_bytes_saved(&self) -> u64 {
        let bytes_in = self.total_bytes_in.load(Ordering::Relaxed);
        let bytes_out = self.total_bytes_out.load(Ordering::Relaxed);
        bytes_in.saturating_sub(bytes_out)
    }

    pub fn log_summary(&self) {
        let total = self.total_ops.load(Ordering::Relaxed);
        if total == 0 {
            return;
        }
        let saved = self.total_bytes_saved();
        let ratio = self.avg_ratio();
        let blocks = self.blocks_compressed.load(Ordering::Relaxed);
        let txs = self.txs_compressed.load(Ordering::Relaxed);
        let dht = self.dht_compressed.load(Ordering::Relaxed);
        let zhtp = self.zhtp_compressed.load(Ordering::Relaxed);

        info!("📦 SovereignCodec wire compression: {} ops, {:.1}x avg, {} bytes saved",
            total, ratio, saved);
        info!("📦   Blocks: {} | Transactions: {} | DHT: {} | ZHTP: {}",
            blocks, txs, dht, zhtp);
    }
}

/// Global compression stats instance
pub static WIRE_STATS: WireCompressionStats = WireCompressionStats::new();

// ─── Data Category (for stats tracking) ─────────────────────────────

/// What kind of data is being compressed — drives stats tracking
#[derive(Debug, Clone, Copy)]
pub enum DataCategory {
    Block,
    Transaction,
    Dht,
    Zhtp,
}

// ─── Core Compression API ───────────────────────────────────────────

/// Compress data with SovereignCodec for wire transmission.
///
/// Returns the compressed data prefixed with `SFC\x02` magic header.
/// If data is below MIN_COMPRESS_SIZE or compression doesn't save space,
/// returns the original data unchanged (no header).
///
/// The caller can detect compressed data via `is_sfc_compressed()`.
pub fn compress_for_wire(data: &[u8], category: DataCategory) -> Vec<u8> {
    if data.len() < MIN_COMPRESS_SIZE {
        return data.to_vec();
    }

    let compressed = SovereignCodec::encode(data);

    // Only use compressed version if it actually saves space
    // (+ 4 bytes for the SFC magic header)
    if compressed.len() + 4 >= data.len() {
        debug!("📦 SFC: skipping compression ({} bytes — no benefit)", data.len());
        return data.to_vec();
    }

    // Track stats
    let raw_len = data.len() as u64;
    let compressed_len = (compressed.len() + 4) as u64;
    WIRE_STATS.total_ops.fetch_add(1, Ordering::Relaxed);
    WIRE_STATS.total_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
    WIRE_STATS.total_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);

    match category {
        DataCategory::Block => {
            WIRE_STATS.blocks_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.block_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.block_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
        DataCategory::Transaction => {
            WIRE_STATS.txs_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.tx_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.tx_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
        DataCategory::Dht => {
            WIRE_STATS.dht_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.dht_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.dht_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
        DataCategory::Zhtp => {
            WIRE_STATS.zhtp_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.zhtp_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.zhtp_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
    }

    let ratio = raw_len as f64 / compressed_len as f64;
    debug!("📦 SFC {:?}: {} → {} bytes ({:.1}x)", category, raw_len, compressed_len, ratio);

    // Build wire format: SFC_MAGIC + compressed data
    let mut result = Vec::with_capacity(4 + compressed.len());
    result.extend_from_slice(SFC_MAGIC);
    result.extend_from_slice(&compressed);
    result
}

/// Check if data has the SFC compression header.
#[inline]
pub fn is_sfc_compressed(data: &[u8]) -> bool {
    data.len() >= 4 && &data[0..4] == SFC_MAGIC
}

/// Decompress SFC-compressed wire data.
///
/// If the data doesn't have the SFC magic header, returns it unchanged
/// (it was either too small to compress or compression didn't help).
pub fn decompress_from_wire(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    if !is_sfc_compressed(data) {
        // Not compressed — return as-is
        return Ok(data.to_vec());
    }

    let compressed = &data[4..]; // Skip SFC_MAGIC
    SovereignCodec::decode(compressed)
        .map_err(|e| anyhow::anyhow!("SFC decompression failed: {:?}", e))
}

/// Compress data for wire if beneficial, using SovereignCodec with
/// neural-mesh-predicted parameters (when available).
///
/// Falls back to default SovereignCodec::encode() if no params provided.
pub fn compress_with_params(
    data: &[u8],
    params: &lib_compression::CodecParams,
    category: DataCategory,
) -> Vec<u8> {
    if data.len() < MIN_COMPRESS_SIZE {
        return data.to_vec();
    }

    let compressed = SovereignCodec::encode_with_params(data, params);

    if compressed.len() + 4 >= data.len() {
        return data.to_vec();
    }

    let raw_len = data.len() as u64;
    let compressed_len = (compressed.len() + 4) as u64;
    WIRE_STATS.total_ops.fetch_add(1, Ordering::Relaxed);
    WIRE_STATS.total_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
    WIRE_STATS.total_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);

    match category {
        DataCategory::Block => {
            WIRE_STATS.blocks_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.block_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.block_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
        DataCategory::Transaction => {
            WIRE_STATS.txs_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.tx_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.tx_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
        DataCategory::Dht => {
            WIRE_STATS.dht_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.dht_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.dht_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
        DataCategory::Zhtp => {
            WIRE_STATS.zhtp_compressed.fetch_add(1, Ordering::Relaxed);
            WIRE_STATS.zhtp_bytes_in.fetch_add(raw_len, Ordering::Relaxed);
            WIRE_STATS.zhtp_bytes_out.fetch_add(compressed_len, Ordering::Relaxed);
        }
    }

    let mut result = Vec::with_capacity(4 + compressed.len());
    result.extend_from_slice(SFC_MAGIC);
    result.extend_from_slice(&compressed);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_small_data() {
        // Small data should pass through uncompressed
        let data = b"hello";
        let wire = compress_for_wire(data, DataCategory::Zhtp);
        assert_eq!(wire, data);
        let decoded = decompress_from_wire(&wire).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_roundtrip_large_data() {
        let data: Vec<u8> = (0..10_000).map(|i| {
            let json = b"{\"key\":\"value\",\"num\":12345,\"arr\":[1,2,3]}";
            json[i % json.len()]
        }).collect();
        let wire = compress_for_wire(&data, DataCategory::Block);
        assert!(is_sfc_compressed(&wire), "Large repetitive data should be compressed");
        assert!(wire.len() < data.len(), "Compressed should be smaller");
        let decoded = decompress_from_wire(&wire).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_stats_tracking() {
        let data: Vec<u8> = vec![0x42; 10_000];
        let _ = compress_for_wire(&data, DataCategory::Dht);
        assert!(WIRE_STATS.total_ops.load(Ordering::Relaxed) > 0);
        assert!(WIRE_STATS.total_bytes_saved() > 0);
    }
}
