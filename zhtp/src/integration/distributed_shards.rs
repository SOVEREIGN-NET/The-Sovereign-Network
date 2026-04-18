//! Distributed Shard Manager — "Network as a Disk"
//!
//! Wires together the existing local primitives into a real distributed storage layer:
//!
//! **Store path:**
//!   content → BLAKE3 hash → erasure encode (k data + m parity shards)
//!           → SFC compress each shard → store in DHT keyed by `shard:{content_hash}:{index}`
//!           → store manifest in DHT keyed by `manifest:{content_hash}`
//!
//! **Fetch path:**
//!   content_hash → fetch manifest → fetch any k shards from DHT
//!               → SFC decompress → erasure decode → reconstruct original content
//!
//! **Proof path:**
//!   challenger issues storage proof challenge → shard holder builds Merkle proof
//!   from their local shard → returns proof → challenger verifies
//!
//! This module bridges:
//! - `lib_storage::erasure::ErasureCoding` — Reed-Solomon in GF(2^8)
//! - `crate::compression::{compress_for_wire, decompress_from_wire}` — SFC wire compression
//! - `crate::integration::dht_payload_handler::{store_dht_value, fetch_dht_value}` — DHT I/O
//! - `lib_storage::proofs::{generate_storage_proof, StorageProof}` — Merkle storage proofs
//! - `lib_crypto::hashing::hash_blake3` — content addressing

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use lib_crypto::hashing::hash_blake3;
use lib_storage::erasure::{ErasureCoding, EncodedShards};

use crate::compression::{compress_for_wire, decompress_from_wire, DataCategory};
use crate::integration::dht_integration::DhtStorageHandle;
use crate::integration::dht_payload_handler::{fetch_dht_value, store_dht_value};

// ─── Configuration ──────────────────────────────────────────────────

/// Default number of data shards (need all k to reconstruct)
pub const DEFAULT_DATA_SHARDS: usize = 4;

/// Default number of parity shards (can lose up to m shards)
pub const DEFAULT_PARITY_SHARDS: usize = 2;

/// Block size for storage proof chunking (4 KB)
pub const PROOF_BLOCK_SIZE: usize = 4096;

/// Minimum content size to trigger erasure coding (below this, store directly)
pub const MIN_ERASURE_SIZE: usize = 256;

// ─── Global Stats ───────────────────────────────────────────────────

/// Network-as-disk statistics (atomics for lock-free access from any task)
pub struct DistributedShardStats {
    pub store_ops: AtomicU64,
    pub fetch_ops: AtomicU64,
    pub total_content_bytes: AtomicU64,
    pub total_shard_bytes: AtomicU64,
    pub total_compressed_shard_bytes: AtomicU64,
    pub erasure_reconstructions: AtomicU64,
    pub proof_challenges_issued: AtomicU64,
    pub proof_challenges_verified: AtomicU64,
    pub dedup_hits: AtomicU64,
}

impl DistributedShardStats {
    pub const fn new() -> Self {
        Self {
            store_ops: AtomicU64::new(0),
            fetch_ops: AtomicU64::new(0),
            total_content_bytes: AtomicU64::new(0),
            total_shard_bytes: AtomicU64::new(0),
            total_compressed_shard_bytes: AtomicU64::new(0),
            erasure_reconstructions: AtomicU64::new(0),
            proof_challenges_issued: AtomicU64::new(0),
            proof_challenges_verified: AtomicU64::new(0),
            dedup_hits: AtomicU64::new(0),
        }
    }

    /// Log a summary of distributed shard stats
    pub fn log_summary(&self) {
        let store_ops = self.store_ops.load(Ordering::Relaxed);
        let fetch_ops = self.fetch_ops.load(Ordering::Relaxed);
        if store_ops == 0 && fetch_ops == 0 {
            return;
        }
        let content_bytes = self.total_content_bytes.load(Ordering::Relaxed);
        let shard_bytes = self.total_shard_bytes.load(Ordering::Relaxed);
        let compressed_bytes = self.total_compressed_shard_bytes.load(Ordering::Relaxed);
        let reconstructions = self.erasure_reconstructions.load(Ordering::Relaxed);
        let dedup = self.dedup_hits.load(Ordering::Relaxed);
        let proofs_issued = self.proof_challenges_issued.load(Ordering::Relaxed);
        let proofs_ok = self.proof_challenges_verified.load(Ordering::Relaxed);

        let effective_ratio = if compressed_bytes > 0 {
            content_bytes as f64 / compressed_bytes as f64
        } else {
            1.0
        };

        info!(
            "🌐 Network-as-Disk: {} stores, {} fetches, {} reconstructions, {} dedup hits",
            store_ops, fetch_ops, reconstructions, dedup
        );
        info!(
            "🌐   Content: {} bytes → {} shard bytes → {} compressed ({:.1}x effective)",
            content_bytes, shard_bytes, compressed_bytes, effective_ratio
        );
        if proofs_issued > 0 {
            info!(
                "🌐   Proofs: {}/{} challenges verified ({:.0}%)",
                proofs_ok,
                proofs_issued,
                proofs_ok as f64 / proofs_issued as f64 * 100.0
            );
        }
    }
}

/// Global stats instance
pub static SHARD_STATS: DistributedShardStats = DistributedShardStats::new();

// ─── Shard Manifest ─────────────────────────────────────────────────

/// Manifest stored in DHT that describes how content was sharded.
/// This is the "map" that lets any node reconstruct the original content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardManifest {
    /// BLAKE3 hash of the original content
    pub content_hash: [u8; 32],
    /// Original content size in bytes
    pub original_size: usize,
    /// Number of data shards (k)
    pub data_shards: usize,
    /// Number of parity shards (m)
    pub parity_shards: usize,
    /// Size of each shard in bytes (before compression)
    pub shard_size: usize,
    /// BLAKE3 hash of each shard (for integrity verification)
    pub shard_hashes: Vec<[u8; 32]>,
    /// Size of each compressed shard (for download planning)
    pub compressed_shard_sizes: Vec<usize>,
    /// Merkle root of all shard hashes (for storage proofs)
    pub merkle_root: [u8; 32],
    /// Timestamp of storage
    pub stored_at: u64,
    /// Node that originally stored this content
    pub origin_node: String,
}

impl ShardManifest {
    /// Get the DHT key for this manifest
    pub fn dht_key(content_hash: &[u8; 32]) -> Vec<u8> {
        let mut key = b"manifest:".to_vec();
        key.extend_from_slice(content_hash);
        key
    }

    /// Get the DHT key for a specific shard
    pub fn shard_dht_key(content_hash: &[u8; 32], shard_index: usize) -> Vec<u8> {
        let mut key = b"shard:".to_vec();
        key.extend_from_slice(content_hash);
        key.push(b':');
        key.extend_from_slice(&(shard_index as u32).to_le_bytes());
        key
    }

    /// Total number of shards (data + parity)
    pub fn total_shards(&self) -> usize {
        self.data_shards + self.parity_shards
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Manifest serialize: {}", e))
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Manifest deserialize: {}", e))
    }
}

// ─── Distributed Shard Manager ──────────────────────────────────────

/// The core integration struct that wires erasure coding, compression,
/// DHT storage, and storage proofs into a unified "network as disk" layer.
pub struct DistributedShardManager {
    /// Erasure coder (Reed-Solomon)
    erasure: ErasureCoding,
    /// Number of data shards
    data_shards: usize,
    /// Number of parity shards
    parity_shards: usize,
    /// Local node identifier
    node_id: String,
}

impl DistributedShardManager {
    /// Create a new distributed shard manager.
    ///
    /// `data_shards` (k): minimum shards needed to reconstruct
    /// `parity_shards` (m): number of redundancy shards (can lose up to m)
    pub fn new(data_shards: usize, parity_shards: usize, node_id: String) -> Result<Self> {
        let erasure = ErasureCoding::new(data_shards, parity_shards)
            .context("Failed to initialize Reed-Solomon erasure coding")?;

        info!(
            "🌐 Distributed Shard Manager initialized: k={} data + m={} parity ({} total shards)",
            data_shards,
            parity_shards,
            data_shards + parity_shards
        );

        Ok(Self {
            erasure,
            data_shards,
            parity_shards,
            node_id,
        })
    }

    /// Create with default parameters (4 data + 2 parity = 6 total, tolerates 2 losses)
    pub fn with_defaults(node_id: String) -> Result<Self> {
        Self::new(DEFAULT_DATA_SHARDS, DEFAULT_PARITY_SHARDS, node_id)
    }

    // ─── STORE PATH ─────────────────────────────────────────────────

    /// Store content in the distributed network.
    ///
    /// Pipeline: content → BLAKE3 hash → dedup check → erasure encode → SFC compress
    ///         → store each shard in DHT → store manifest in DHT
    ///
    /// Returns the content hash (network address for this content).
    pub async fn store_content(
        &self,
        content: &[u8],
        dht: &DhtStorageHandle,
    ) -> Result<[u8; 32]> {
        if content.is_empty() {
            return Err(anyhow!("Cannot store empty content"));
        }

        // 1. Content-address: BLAKE3 hash
        let content_hash = hash_blake3(content);
        let hash_hex = hex::encode(&content_hash[..8]);

        // 2. Deduplication: check if manifest already exists
        let manifest_key = ShardManifest::dht_key(&content_hash);
        if let Ok((true, Some(_))) = fetch_dht_value(dht, &manifest_key).await {
            info!(
                "🌐🔁 Content already stored (dedup hit): {} ({} bytes)",
                hash_hex,
                content.len()
            );
            SHARD_STATS.dedup_hits.fetch_add(1, Ordering::Relaxed);
            return Ok(content_hash);
        }

        // 3. For small content, store directly (no erasure overhead)
        if content.len() < MIN_ERASURE_SIZE {
            return self.store_small_content(content, &content_hash, dht).await;
        }

        // 4. Erasure encode: split into k data + m parity shards
        let encoded = self
            .erasure
            .encode(content)
            .context("Erasure encoding failed")?;

        let total_shards = encoded.data_shards.len() + encoded.parity_shards.len();
        let all_shards: Vec<&[u8]> = encoded
            .data_shards
            .iter()
            .chain(encoded.parity_shards.iter())
            .map(|s| s.as_slice())
            .collect();

        // 5. Compute shard hashes + Merkle root for storage proofs
        let shard_hashes: Vec<[u8; 32]> = all_shards.iter().map(|s| hash_blake3(s)).collect();
        let merkle_root = compute_merkle_root(&shard_hashes);

        // 6. SFC compress each shard and store in DHT
        let mut compressed_sizes = Vec::with_capacity(total_shards);
        let mut total_shard_bytes: usize = 0;
        let mut total_compressed_bytes: usize = 0;
        let mut store_successes = 0;

        for (i, shard) in all_shards.iter().enumerate() {
            let shard_key = ShardManifest::shard_dht_key(&content_hash, i);
            let compressed = compress_for_wire(shard, DataCategory::Dht);
            compressed_sizes.push(compressed.len());
            total_shard_bytes += shard.len();
            total_compressed_bytes += compressed.len();

            if store_dht_value(dht, &shard_key, &compressed).await {
                store_successes += 1;
            } else {
                warn!(
                    "🌐⚠️ Failed to store shard {}/{} for content {}",
                    i, total_shards, hash_hex
                );
            }
        }

        // 7. Build and store manifest
        let manifest = ShardManifest {
            content_hash,
            original_size: content.len(),
            data_shards: self.data_shards,
            parity_shards: self.parity_shards,
            shard_size: encoded.shard_size,
            shard_hashes,
            compressed_shard_sizes: compressed_sizes,
            merkle_root,
            stored_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            origin_node: self.node_id.clone(),
        };

        let manifest_bytes = manifest.to_bytes()?;
        let manifest_compressed = compress_for_wire(&manifest_bytes, DataCategory::Dht);
        store_dht_value(dht, &manifest_key, &manifest_compressed).await;

        // 8. Update stats
        SHARD_STATS.store_ops.fetch_add(1, Ordering::Relaxed);
        SHARD_STATS
            .total_content_bytes
            .fetch_add(content.len() as u64, Ordering::Relaxed);
        SHARD_STATS
            .total_shard_bytes
            .fetch_add(total_shard_bytes as u64, Ordering::Relaxed);
        SHARD_STATS
            .total_compressed_shard_bytes
            .fetch_add(total_compressed_bytes as u64, Ordering::Relaxed);

        let effective_ratio = content.len() as f64 / total_compressed_bytes.max(1) as f64;
        info!(
            "🌐✅ Stored content {}: {} bytes → {} shards ({}/{} stored), \
             {} shard bytes → {} compressed ({:.1}x effective)",
            hash_hex,
            content.len(),
            total_shards,
            store_successes,
            total_shards,
            total_shard_bytes,
            total_compressed_bytes,
            effective_ratio,
        );

        Ok(content_hash)
    }

    /// Store small content directly (below erasure threshold)
    async fn store_small_content(
        &self,
        content: &[u8],
        content_hash: &[u8; 32],
        dht: &DhtStorageHandle,
    ) -> Result<[u8; 32]> {
        let hash_hex = hex::encode(&content_hash[..8]);

        // Store data directly (single shard = the content itself)
        let shard_key = ShardManifest::shard_dht_key(content_hash, 0);
        let compressed = compress_for_wire(content, DataCategory::Dht);
        store_dht_value(dht, &shard_key, &compressed).await;

        // Store a minimal manifest (1 data shard, 0 parity)
        let manifest = ShardManifest {
            content_hash: *content_hash,
            original_size: content.len(),
            data_shards: 1,
            parity_shards: 0,
            shard_size: content.len(),
            shard_hashes: vec![hash_blake3(content)],
            compressed_shard_sizes: vec![compressed.len()],
            merkle_root: hash_blake3(content),
            stored_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            origin_node: self.node_id.clone(),
        };

        let manifest_bytes = manifest.to_bytes()?;
        let manifest_key = ShardManifest::dht_key(content_hash);
        store_dht_value(dht, &manifest_key, &manifest_bytes).await;

        SHARD_STATS.store_ops.fetch_add(1, Ordering::Relaxed);
        SHARD_STATS
            .total_content_bytes
            .fetch_add(content.len() as u64, Ordering::Relaxed);
        SHARD_STATS
            .total_compressed_shard_bytes
            .fetch_add(compressed.len() as u64, Ordering::Relaxed);

        debug!(
            "🌐✅ Small content stored directly: {} ({} → {} bytes)",
            hash_hex,
            content.len(),
            compressed.len()
        );
        Ok(*content_hash)
    }

    // ─── FETCH PATH ─────────────────────────────────────────────────

    /// Fetch content from the distributed network.
    ///
    /// Pipeline: content_hash → fetch manifest → fetch shards from DHT
    ///         → SFC decompress → erasure decode → verify hash → return
    ///
    /// Tolerates up to `parity_shards` missing shards thanks to Reed-Solomon.
    pub async fn fetch_content(
        &self,
        content_hash: &[u8; 32],
        dht: &DhtStorageHandle,
    ) -> Result<Vec<u8>> {
        let hash_hex = hex::encode(&content_hash[..8]);

        // 1. Fetch manifest
        let manifest_key = ShardManifest::dht_key(content_hash);
        let (found, manifest_data) = fetch_dht_value(dht, &manifest_key)
            .await
            .context("Manifest fetch failed")?;

        if !found || manifest_data.is_none() {
            return Err(anyhow!("Content not found: {}", hash_hex));
        }

        // Manifest may be SFC-compressed (from store path) — decompress transparently
        let manifest_bytes = manifest_data.unwrap();
        let manifest_decompressed = decompress_from_wire(&manifest_bytes)
            .unwrap_or(manifest_bytes);
        let manifest = ShardManifest::from_bytes(&manifest_decompressed)
            .context("Invalid manifest")?;

        // 2. Small content fast path (single shard, no erasure)
        if manifest.data_shards == 1 && manifest.parity_shards == 0 {
            return self.fetch_small_content(content_hash, &manifest, dht).await;
        }

        // 3. Fetch all shards (data + parity), tolerate missing
        let total_shards = manifest.total_shards();
        let mut available_shards: HashMap<usize, Vec<u8>> = HashMap::new();
        let mut missing_indices: Vec<usize> = Vec::new();

        for i in 0..total_shards {
            let shard_key = ShardManifest::shard_dht_key(content_hash, i);
            match fetch_dht_value(dht, &shard_key).await {
                Ok((true, Some(compressed_data))) => {
                    // Decompress shard
                    let shard_data = decompress_from_wire(&compressed_data)
                        .unwrap_or(compressed_data);

                    // Verify shard integrity
                    let shard_hash = hash_blake3(&shard_data);
                    if i < manifest.shard_hashes.len() && shard_hash != manifest.shard_hashes[i] {
                        warn!(
                            "🌐⚠️ Shard {}/{} hash mismatch for {} — treating as missing",
                            i, total_shards, hash_hex
                        );
                        missing_indices.push(i);
                    } else {
                        available_shards.insert(i, shard_data);
                    }
                }
                _ => {
                    debug!("🌐 Shard {}/{} unavailable for {}", i, total_shards, hash_hex);
                    missing_indices.push(i);
                }
            }
        }

        // 4. Check if we have enough shards to reconstruct
        let available_count = available_shards.len();
        if available_count < manifest.data_shards {
            return Err(anyhow!(
                "Insufficient shards for {}: have {}, need {} (missing: {:?})",
                hash_hex,
                available_count,
                manifest.data_shards,
                missing_indices
            ));
        }

        // 5. Reconstruct via erasure decoding
        let reconstructed = if missing_indices.is_empty() {
            // All shards present — fast path, just concatenate data shards
            let mut data = Vec::with_capacity(manifest.original_size);
            for i in 0..manifest.data_shards {
                data.extend_from_slice(&available_shards[&i]);
            }
            data.truncate(manifest.original_size);
            data
        } else {
            // Some shards missing — need Reed-Solomon reconstruction
            info!(
                "🌐🔄 Reconstructing {} from {}/{} shards (missing: {:?})",
                hash_hex, available_count, total_shards, missing_indices
            );

            // Build EncodedShards with available data, empty vecs for missing
            let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(manifest.data_shards);
            let mut parity_shards: Vec<Vec<u8>> = Vec::with_capacity(manifest.parity_shards);

            for i in 0..manifest.data_shards {
                data_shards.push(
                    available_shards
                        .get(&i)
                        .cloned()
                        .unwrap_or_else(|| vec![0u8; manifest.shard_size]),
                );
            }
            for i in manifest.data_shards..total_shards {
                parity_shards.push(
                    available_shards
                        .get(&i)
                        .cloned()
                        .unwrap_or_else(|| vec![0u8; manifest.shard_size]),
                );
            }

            let encoded = EncodedShards {
                data_shards,
                parity_shards,
                shard_size: manifest.shard_size,
                original_size: manifest.original_size,
            };

            let available_indices: Vec<usize> = available_shards.keys().copied().collect();
            let reconstructed = self
                .erasure
                .decode(&encoded, &available_indices)
                .context("Erasure decode failed")?;

            SHARD_STATS
                .erasure_reconstructions
                .fetch_add(1, Ordering::Relaxed);

            reconstructed
        };

        // 6. Verify content hash matches
        let reconstructed_hash = hash_blake3(&reconstructed);
        if reconstructed_hash != manifest.content_hash {
            return Err(anyhow!(
                "Content hash mismatch after reconstruction for {}",
                hash_hex
            ));
        }

        SHARD_STATS.fetch_ops.fetch_add(1, Ordering::Relaxed);

        info!(
            "🌐✅ Fetched content {}: {} bytes from {}/{} shards{}",
            hash_hex,
            reconstructed.len(),
            available_count,
            total_shards,
            if !missing_indices.is_empty() {
                format!(" (reconstructed from erasure coding)")
            } else {
                String::new()
            }
        );

        Ok(reconstructed)
    }

    /// Fetch small content (single shard, no erasure)
    async fn fetch_small_content(
        &self,
        content_hash: &[u8; 32],
        manifest: &ShardManifest,
        dht: &DhtStorageHandle,
    ) -> Result<Vec<u8>> {
        let hash_hex = hex::encode(&content_hash[..8]);
        let shard_key = ShardManifest::shard_dht_key(content_hash, 0);

        let (found, data) = fetch_dht_value(dht, &shard_key)
            .await
            .context("Small content fetch failed")?;

        if !found || data.is_none() {
            return Err(anyhow!("Small content shard missing: {}", hash_hex));
        }

        let content = data.unwrap();

        // Verify hash
        let actual_hash = hash_blake3(&content);
        if actual_hash != manifest.content_hash {
            return Err(anyhow!("Content hash mismatch for {}", hash_hex));
        }

        SHARD_STATS.fetch_ops.fetch_add(1, Ordering::Relaxed);
        debug!("🌐✅ Fetched small content {}: {} bytes", hash_hex, content.len());
        Ok(content)
    }

    // ─── STORAGE PROOFS ─────────────────────────────────────────────

    /// Generate a storage proof for a specific shard.
    ///
    /// This proves "I hold shard `shard_index` of content `content_hash`"
    /// by building a Merkle proof from the shard data.
    pub async fn generate_shard_proof(
        &self,
        content_hash: &[u8; 32],
        shard_index: usize,
        challenge_nonce: u64,
        dht: &DhtStorageHandle,
    ) -> Result<ShardStorageProof> {
        let hash_hex = hex::encode(&content_hash[..8]);

        // Fetch the manifest
        let manifest_key = ShardManifest::dht_key(content_hash);
        let (found, manifest_data) = fetch_dht_value(dht, &manifest_key).await?;
        if !found || manifest_data.is_none() {
            return Err(anyhow!("Manifest not found for {}", hash_hex));
        }
        let manifest_bytes = manifest_data.unwrap();
        let manifest_decompressed = decompress_from_wire(&manifest_bytes).unwrap_or(manifest_bytes);
        let manifest = ShardManifest::from_bytes(&manifest_decompressed)?;

        if shard_index >= manifest.total_shards() {
            return Err(anyhow!("Shard index {} out of range (total: {})", shard_index, manifest.total_shards()));
        }

        // Fetch the shard
        let shard_key = ShardManifest::shard_dht_key(content_hash, shard_index);
        let (found, shard_data) = fetch_dht_value(dht, &shard_key).await?;
        if !found || shard_data.is_none() {
            return Err(anyhow!("Shard {} not available for {}", shard_index, hash_hex));
        }
        let shard = shard_data.unwrap();

        // Build Merkle proof: shard_hashes form the leaves, prove shard_index
        let shard_hash = hash_blake3(&shard);
        let merkle_path = compute_merkle_path(&manifest.shard_hashes, shard_index);

        let proof = ShardStorageProof {
            content_hash: *content_hash,
            shard_index,
            shard_hash,
            merkle_root: manifest.merkle_root,
            merkle_path,
            challenge_nonce,
            shard_size: shard.len(),
            prover_node: self.node_id.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        SHARD_STATS
            .proof_challenges_issued
            .fetch_add(1, Ordering::Relaxed);

        debug!(
            "🌐🔒 Generated storage proof for shard {}/{} of {}",
            shard_index,
            manifest.total_shards(),
            hash_hex
        );

        Ok(proof)
    }

    /// Verify a storage proof from a peer.
    ///
    /// Checks: Merkle path is valid, shard hash matches, and the root
    /// matches the manifest's merkle_root.
    pub fn verify_shard_proof(
        &self,
        proof: &ShardStorageProof,
        expected_merkle_root: &[u8; 32],
    ) -> bool {
        // Verify the Merkle path from leaf (shard_hash) to root
        let computed_root =
            compute_root_from_path(&proof.shard_hash, proof.shard_index, &proof.merkle_path);

        let valid = computed_root == *expected_merkle_root && proof.merkle_root == *expected_merkle_root;

        if valid {
            SHARD_STATS
                .proof_challenges_verified
                .fetch_add(1, Ordering::Relaxed);
            debug!(
                "🌐✅ Verified storage proof: shard {} of {} from {}",
                proof.shard_index,
                hex::encode(&proof.content_hash[..8]),
                proof.prover_node
            );
        } else {
            warn!(
                "🌐❌ Storage proof FAILED: shard {} of {} from {} (root mismatch)",
                proof.shard_index,
                hex::encode(&proof.content_hash[..8]),
                proof.prover_node
            );
        }

        valid
    }

    // ─── INTROSPECTION ──────────────────────────────────────────────

    /// Check if content exists in the network
    pub async fn content_exists(
        &self,
        content_hash: &[u8; 32],
        dht: &DhtStorageHandle,
    ) -> bool {
        let manifest_key = ShardManifest::dht_key(content_hash);
        matches!(fetch_dht_value(dht, &manifest_key).await, Ok((true, Some(_))))
    }

    /// Get manifest for content (useful for inspecting shard distribution)
    pub async fn get_manifest(
        &self,
        content_hash: &[u8; 32],
        dht: &DhtStorageHandle,
    ) -> Result<Option<ShardManifest>> {
        let manifest_key = ShardManifest::dht_key(content_hash);
        let (found, data) = fetch_dht_value(dht, &manifest_key).await?;
        if !found || data.is_none() {
            return Ok(None);
        }
        let bytes = data.unwrap();
        let decompressed = decompress_from_wire(&bytes).unwrap_or(bytes);
        Ok(Some(ShardManifest::from_bytes(&decompressed)?))
    }
}

// ─── Shard Storage Proof ────────────────────────────────────────────

/// Proof that a node holds a specific shard of erasure-coded content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStorageProof {
    /// Content hash this shard belongs to
    pub content_hash: [u8; 32],
    /// Which shard (0..k+m)
    pub shard_index: usize,
    /// BLAKE3 hash of the shard data
    pub shard_hash: [u8; 32],
    /// Merkle root of all shard hashes
    pub merkle_root: [u8; 32],
    /// Merkle proof path from this shard to root
    pub merkle_path: Vec<[u8; 32]>,
    /// Challenge nonce (proves freshness — not a replay)
    pub challenge_nonce: u64,
    /// Size of the shard in bytes
    pub shard_size: usize,
    /// Node that generated the proof
    pub prover_node: String,
    /// Timestamp of proof
    pub timestamp: u64,
}

impl ShardStorageProof {
    /// Serialize for wire transmission
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Proof serialize: {}", e))
    }

    /// Deserialize from wire
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Proof deserialize: {}", e))
    }
}

// ─── Merkle Tree Helpers ────────────────────────────────────────────

/// Compute a Merkle root from a list of leaf hashes.
fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut level: Vec<[u8; 32]> = leaves.to_vec();

    // Pad to power of 2
    while level.len().count_ones() != 1 {
        level.push([0u8; 32]);
    }

    while level.len() > 1 {
        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let combined = hash_pair(&pair[0], &pair[1]);
            next_level.push(combined);
        }
        level = next_level;
    }

    level[0]
}

/// Compute Merkle path (sibling hashes) for a leaf at `index`.
fn compute_merkle_path(leaves: &[[u8; 32]], index: usize) -> Vec<[u8; 32]> {
    if leaves.len() <= 1 {
        return Vec::new();
    }

    let mut padded: Vec<[u8; 32]> = leaves.to_vec();
    while padded.len().count_ones() != 1 {
        padded.push([0u8; 32]);
    }

    let mut path = Vec::new();
    let mut current_index = index;
    let mut level = padded;

    while level.len() > 1 {
        let sibling_index = if current_index % 2 == 0 {
            current_index + 1
        } else {
            current_index - 1
        };
        path.push(level[sibling_index.min(level.len() - 1)]);

        let mut next_level = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            next_level.push(hash_pair(&pair[0], &pair[1]));
        }
        level = next_level;
        current_index /= 2;
    }

    path
}

/// Walk a Merkle path from a leaf hash back up to the root.
fn compute_root_from_path(leaf_hash: &[u8; 32], leaf_index: usize, path: &[[u8; 32]]) -> [u8; 32] {
    let mut current = *leaf_hash;
    let mut index = leaf_index;

    for sibling in path {
        if index % 2 == 0 {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        index /= 2;
    }

    current
}

/// Hash two Merkle nodes together.
fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    hash_blake3(&combined)
}
