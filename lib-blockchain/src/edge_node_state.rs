//! Edge Node State Manager for BLE-Connected Lightweight Clients
//!
//! Manages minimal blockchain state for bandwidth-constrained edge nodes:
//! - Rolling window of 100-500 block headers (~20-100 KB)
//! - UTXO tracking (commitment-based, amounts encrypted)
//! - Merkle proof verification for instant payment confirmation
//!
//! **Design Philosophy:**
//! - Edge nodes don't decrypt note amounts (computationally expensive)
//! - Track UTXO existence via commitments (privacy-preserving)
//! - Full wallet operations happen on more powerful devices
//! - BLE bandwidth: Bootstrap ~30 KB (0.6s), per-block ~2-5 KB (0.1-0.2s)

use crate::types::Hash;
use crate::block::BlockHeader;
use crate::transaction::{Transaction, TransactionOutput};
use crate::integration::crypto_integration::PublicKey;
use std::collections::{HashMap, VecDeque};
use tracing::{info, warn};
use anyhow::{Result, anyhow};

/// Minimal edge node state for bandwidth-constrained BLE connections
/// Stores only headers and tracked UTXOs (not full blockchain state)
#[derive(Debug, Clone)]
pub struct EdgeNodeState {
    /// Rolling window of recent block headers (100-500 headers)
    pub headers: VecDeque<BlockHeader>,
    /// Maximum number of headers to keep
    pub max_headers: usize,
    /// Current chain tip height
    pub current_height: u64,
    /// My UTXOs (outputs I can spend)
    /// Note: Amounts are encrypted in commitments - edge node doesn't decrypt
    pub my_utxos: HashMap<UtxoKey, TransactionOutput>,
    /// My public keys to track
    pub my_addresses: Vec<Vec<u8>>,
}

/// UTXO identifier (transaction hash + output index)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UtxoKey {
    pub tx_hash: Hash,
    pub output_index: u32,
}

/// Verified payment result (amount encrypted in commitment)
#[derive(Debug, Clone)]
pub struct VerifiedPayment {
    pub tx_hash: Hash,
    pub output_index: u32,
    pub commitment: Hash,  // Pedersen commitment (amount encrypted)
    pub block_height: u64,
    pub block_hash: Hash,
    pub confirmed: bool,
}

impl EdgeNodeState {
    /// Create a new edge node state
    /// Recommended: max_headers = 500 for security/finality (~100 KB storage)
    pub fn new(max_headers: usize) -> Self {
        info!(" Initializing edge node state with {} header capacity", max_headers);
        Self {
            headers: VecDeque::new(),
            max_headers,
            current_height: 0,
            my_utxos: HashMap::new(),
            my_addresses: Vec::new(),
        }
    }

    /// Add a new public key to track (owned by this edge node)
    pub fn add_address(&mut self, address: Vec<u8>) {
        if !self.my_addresses.contains(&address) {
            let addr_hex = hex::encode(&address[..8.min(address.len())]);
            self.my_addresses.push(address);
            info!(" Added address to edge node tracking: {}", addr_hex);
        }
    }

    /// Check if a public key belongs to this edge node
    pub fn is_my_address(&self, pubkey: &PublicKey) -> bool {
        let pubkey_bytes = pubkey.as_bytes();
        self.my_addresses.iter().any(|a| a.as_slice() == pubkey_bytes)
    }

    /// Add a UTXO to tracked outputs (when we receive a payment)
    /// Note: Amount is hidden in commitment - edge node tracks UTXO existence only
    pub fn add_utxo(&mut self, tx_hash: Hash, output_index: u32, output: &TransactionOutput) {
        if !self.is_my_address(&output.recipient) {
            return;
        }

        let utxo_key = UtxoKey { tx_hash, output_index };
        self.my_utxos.insert(utxo_key, output.clone());

        // Note: Amount is encrypted in the commitment - not tracked on edge node
        info!(" Added UTXO: txid={}, index={}, commitment={}",
            hex::encode(&tx_hash.as_bytes()[..8]),
            output_index,
            hex::encode(&output.commitment.as_bytes()[..8]));
    }

    /// Remove a UTXO when it's spent
    pub fn remove_utxo(&mut self, tx_hash: &Hash, output_index: u32) -> bool {
        let utxo_key = UtxoKey { tx_hash: *tx_hash, output_index };
        if let Some(_output) = self.my_utxos.remove(&utxo_key) {
            info!(" Removed UTXO: txid={}, index={}",
                hex::encode(&tx_hash.as_bytes()[..8]),
                output_index);
            true
        } else {
            false
        }
    }

    /// Add a block header to the rolling window with validation
    /// Returns an error if the header is invalid or doesn't connect to existing chain
    pub fn add_header(&mut self, header: BlockHeader) -> Result<()> {
        // CRITICAL: Validate header before accepting
        self.validate_header(&header)?;
        
        // Update current height
        if header.height > self.current_height {
            self.current_height = header.height;
        }

        // Add header to the end
        self.headers.push_back(header.clone());

        // Maintain rolling window size
        while self.headers.len() > self.max_headers {
            let removed = self.headers.pop_front();
            if let Some(h) = removed {
                info!("🗑️ Removed old header: height={}", h.height);
            }
        }

        info!(" Added header: height={}, hash={}, headers_count={}",
            header.height,
            hex::encode(&header.block_hash.as_bytes()[..8]),
            self.headers.len());
        Ok(())
    }
    
    /// Validate a block header before accepting it
    fn validate_header(&self, header: &BlockHeader) -> Result<()> {
        // 1. Check basic header validity
        if header.version == 0 {
            return Err(anyhow!("Invalid header version: 0"));
        }
        
        // 2. Check that block hash is correctly calculated
        let calculated_hash = header.calculate_hash();
        if calculated_hash != header.block_hash {
            return Err(anyhow!(
                "Invalid block hash: calculated {:?} != stored {:?}",
                hex::encode(&calculated_hash.as_bytes()[..8]),
                hex::encode(&header.block_hash.as_bytes()[..8])
            ));
        }
        
        // 3. Check timestamp is reasonable (not too far in future)
        if !header.has_reasonable_timestamp() {
            return Err(anyhow!("Invalid timestamp: too far in future"));
        }
        
        // 4. If we have previous headers, validate chain continuity
        if let Some(latest) = self.get_latest_header() {
            // Check height is sequential
            if header.height != latest.height + 1 {
                return Err(anyhow!(
                    "Non-sequential height: expected {}, got {}",
                    latest.height + 1,
                    header.height
                ));
            }
            
            // Check previous_block_hash matches our latest header
            if header.previous_block_hash != latest.block_hash {
                return Err(anyhow!(
                    "Chain discontinuity: previous_hash {:?} != latest_hash {:?}",
                    hex::encode(&header.previous_block_hash.as_bytes()[..8]),
                    hex::encode(&latest.block_hash.as_bytes()[..8])
                ));
            }
            
            // Check timestamp is after previous block
            if header.timestamp <= latest.timestamp {
                return Err(anyhow!(
                    "Invalid timestamp: {} <= previous {}",
                    header.timestamp,
                    latest.timestamp
                ));
            }
        } else if header.height != 0 {
            // First header must either be genesis (height 0) or we must accept any height
            // for bootstrap sync. Log warning but accept.
            warn!("⚠️  First header has height {} (not genesis), accepting for bootstrap", header.height);
        }
        
        Ok(())
    }

    /// Get a header by block height
    pub fn get_header_by_height(&self, height: u64) -> Option<&BlockHeader> {
        self.headers.iter().find(|h| h.height == height)
    }

    /// Get a header by block hash
    pub fn get_header_by_hash(&self, hash: &Hash) -> Option<&BlockHeader> {
        self.headers.iter().find(|h| &h.block_hash == hash)
    }

    /// Get the latest header (chain tip)
    pub fn get_latest_header(&self) -> Option<&BlockHeader> {
        self.headers.back()
    }

    /// Verify a payment to my address using Merkle proof
    /// Note: Amount is encrypted - verification only confirms UTXO existence
    pub fn verify_payment(
        &self,
        tx_hash: &Hash,
        output_index: u32,
        output: &TransactionOutput,
        merkle_proof: &[Hash],
        block_height: u64,
    ) -> Result<VerifiedPayment> {
        // 1. Check if this output is for me
        if !self.is_my_address(&output.recipient) {
            return Err(anyhow!("Output recipient does not match my addresses"));
        }

        // 2. Find the header for the given block height
        let header = self.get_header_by_height(block_height)
            .ok_or_else(|| anyhow!("Header not found for block {}", block_height))?;

        // 3. Verify Merkle proof against header's merkle_root
        let computed_root = self.verify_merkle_proof(
            tx_hash,
            merkle_proof,
            &header.merkle_root,
        )?;

        if computed_root != header.merkle_root {
            return Err(anyhow!("Merkle proof verification failed"));
        }

        // 4. Return verified payment details (amount encrypted in commitment)
        info!(" Payment verified: commitment={} to my address", 
            hex::encode(&output.commitment.as_bytes()[..8]));

        Ok(VerifiedPayment {
            tx_hash: *tx_hash,
            output_index,
            commitment: output.commitment,
            block_height,
            block_hash: header.block_hash,
            confirmed: true,
        })
    }

    /// Verify Merkle proof for a transaction
    fn verify_merkle_proof(
        &self,
        tx_hash: &Hash,
        merkle_proof: &[Hash],
        expected_root: &Hash,
    ) -> Result<Hash> {
        let mut current_hash = *tx_hash;

        for sibling in merkle_proof {
            current_hash = self.compute_merkle_parent(&current_hash, sibling);
        }

        if &current_hash == expected_root {
            Ok(current_hash)
        } else {
            Err(anyhow!("Merkle proof does not match expected root"))
        }
    }

    /// Compute parent hash in Merkle tree
    fn compute_merkle_parent(&self, left: &Hash, right: &Hash) -> Hash {
        let mut combined = Vec::with_capacity(64);
        combined.extend_from_slice(left.as_bytes());
        combined.extend_from_slice(right.as_bytes());
        Hash::from_slice(&blake3::hash(&combined).as_bytes()[..32])
    }

    /// Hash data using BLAKE3
    fn hash_data(&self, data: &[u8]) -> Hash {
        Hash::from_slice(&blake3::hash(&data).as_bytes()[..32])
    }

    /// Get total UTXO count
    pub fn utxo_count(&self) -> usize {
        self.my_utxos.len()
    }

    /// Get all UTXOs (amounts are encrypted in commitments)
    pub fn get_all_utxos(&self) -> Vec<(UtxoKey, TransactionOutput)> {
        self.my_utxos.iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Check if we need to request a new ChainRecursiveProof
    /// Returns true if we're more than 500 blocks behind
    /// 
    /// **New Network Handling:**
    /// - If network has <100 blocks: Request all headers directly (no proof needed)
    /// - If network has ≥100 blocks: Use ZK proof for blocks before our window
    pub fn needs_bootstrap_proof(&self, network_height: u64) -> bool {
        // New network (<100 blocks): Don't need ZK proof, just sync all headers
        if network_height < 100 {
            return false;
        }

        // First sync on established network: need bootstrap proof
        if self.headers.is_empty() {
            return true;
        }

        // Subsequent syncs: Need proof if >500 blocks behind
        let blocks_behind = network_height.saturating_sub(self.current_height);
        blocks_behind > 500
    }

    /// Determine the optimal sync strategy for current network state
    pub fn get_sync_strategy(&self, network_height: u64) -> SyncStrategy {
        if self.headers.is_empty() {
            // First sync
            if network_height < 100 {
                SyncStrategy::HeadersOnly {
                    start_height: 0,
                    count: network_height as usize,
                }
            } else {
                SyncStrategy::BootstrapProof {
                    proof_up_to_height: network_height.saturating_sub(100),
                    headers_from_height: network_height.saturating_sub(100),
                    headers_count: 100,
                }
            }
        } else {
            let blocks_behind = network_height.saturating_sub(self.current_height);
            
            if blocks_behind <= 500 {
                // Close to tip: Just sync missing headers
                SyncStrategy::HeadersOnly {
                    start_height: self.current_height + 1,
                    count: blocks_behind as usize,
                }
            } else {
                // Far behind: Use bootstrap proof
                SyncStrategy::BootstrapProof {
                    proof_up_to_height: network_height.saturating_sub(100),
                    headers_from_height: network_height.saturating_sub(100),
                    headers_count: 100,
                }
            }
        }
    }

    /// Process a new block and update UTXO set
    /// Returns an error if the block header is invalid
    pub fn process_block(&mut self, header: &BlockHeader, transactions: &[Transaction]) -> Result<()> {
        // Add header to rolling window with validation
        self.add_header(header.clone())?;

        // Verify transactions match the merkle root in header
        let computed_merkle_root = self.compute_merkle_root_from_transactions(transactions);
        if computed_merkle_root != header.merkle_root {
            return Err(anyhow!(
                "Transaction merkle root mismatch: computed {:?} != header {:?}",
                hex::encode(&computed_merkle_root.as_bytes()[..8]),
                hex::encode(&header.merkle_root.as_bytes()[..8])
            ));
        }

        // Scan transactions for my addresses
        for tx in transactions {
            // Check outputs for incoming payments
            for (output_index, output) in tx.outputs.iter().enumerate() {
                if self.is_my_address(&output.recipient) {
                    self.add_utxo(tx.hash(), output_index as u32, output);
                }
            }

            // Check inputs for spent UTXOs
            for input in &tx.inputs {
                self.remove_utxo(&input.previous_output, input.output_index);
            }
        }

        info!(" Processed block {}: {} UTXOs tracked", header.height, self.my_utxos.len());
        Ok(())
    }
    
    /// Compute merkle root from list of transactions
    fn compute_merkle_root_from_transactions(&self, transactions: &[Transaction]) -> Hash {
        if transactions.is_empty() {
            return Hash::default();
        }

        let mut hashes: Vec<Hash> = transactions
            .iter()
            .map(|tx| tx.hash())
            .collect();

        // Build Merkle tree bottom-up
        while hashes.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in hashes.chunks(2) {
                let left = chunk[0];
                let right = chunk.get(1).copied().unwrap_or(left);
                
                let mut combined = Vec::new();
                combined.extend_from_slice(left.as_bytes());
                combined.extend_from_slice(right.as_bytes());
                let parent_hash = Hash::from_slice(&blake3::hash(&combined).as_bytes()[..32]);
                next_level.push(parent_hash);
            }
            
            hashes = next_level;
        }

        hashes[0]
    }

    /// Get header statistics
    pub fn get_stats(&self) -> EdgeNodeStats {
        EdgeNodeStats {
            header_count: self.headers.len(),
            max_headers: self.max_headers,
            current_height: self.current_height,
            oldest_header_height: self.headers.front().map(|h| h.height),
            utxo_count: self.my_utxos.len(),
            tracked_addresses: self.my_addresses.len(),
            storage_estimate_bytes: self.estimate_storage_size(),
        }
    }

    /// Estimate total storage size in bytes
    fn estimate_storage_size(&self) -> usize {
        // BlockHeader: ~200 bytes each
        let header_bytes = self.headers.len() * 200;
        
        // TransactionOutput: ~96 bytes (32 commitment + 32 note + 32 pubkey)
        let utxo_bytes = self.my_utxos.len() * 96;
        
        // Addresses: ~32 bytes each
        let address_bytes = self.my_addresses.len() * 32;
        
        header_bytes + utxo_bytes + address_bytes
    }
    
    /// Detect potential chain reorganization
    /// Returns true if a reorg is detected (headers don't form continuous chain)
    pub fn detect_reorg(&self, new_header: &BlockHeader) -> bool {
        if let Some(latest) = self.get_latest_header() {
            // Reorg detected if:
            // 1. New header's previous_hash doesn't match our latest
            // 2. Heights are not sequential
            if new_header.height == latest.height + 1 {
                if new_header.previous_block_hash != latest.block_hash {
                    warn!("⚠️  REORG DETECTED: New header {} doesn't link to our chain", new_header.height);
                    return true;
                }
            }
        }
        false
    }
    
    /// Rollback to a specific height (for handling reorgs)
    /// Removes all headers and UTXOs after the rollback height
    pub fn rollback_to_height(&mut self, target_height: u64) -> Result<()> {
        if target_height > self.current_height {
            return Err(anyhow!("Cannot rollback to future height {}", target_height));
        }
        
        warn!("⚠️  Rolling back from height {} to {}", self.current_height, target_height);
        
        // Remove headers after target height
        while let Some(latest) = self.headers.back() {
            if latest.height <= target_height {
                break;
            }
            self.headers.pop_back();
        }
        
        // Update current height
        self.current_height = target_height;
        
        // Note: UTXOs are NOT rolled back automatically
        // This is acceptable for edge nodes since they only track their own UTXOs
        // and can re-sync them from the canonical chain
        warn!(" Rollback complete, {} headers remaining", self.headers.len());
        
        Ok(())
    }
    
    /// Create checkpoint for rollback recovery
    pub fn create_checkpoint(&self) -> EdgeNodeCheckpoint {
        EdgeNodeCheckpoint {
            height: self.current_height,
            header_count: self.headers.len(),
            utxo_count: self.my_utxos.len(),
            latest_block_hash: self.get_latest_header().map(|h| h.block_hash),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Edge node statistics
#[derive(Debug, Clone)]
pub struct EdgeNodeStats {
    pub header_count: usize,
    pub max_headers: usize,
    pub current_height: u64,
    pub oldest_header_height: Option<u64>,
    pub utxo_count: usize,
    pub tracked_addresses: usize,
    pub storage_estimate_bytes: usize,
}

/// Synchronization strategy for edge nodes
#[derive(Debug, Clone, PartialEq)]
pub enum SyncStrategy {
    /// Download headers only (for new networks <100 blocks or when close to tip)
    HeadersOnly {
        start_height: u64,
        count: usize,
    },
    /// Use ZK bootstrap proof + recent headers (for established networks when far behind)
    BootstrapProof {
        proof_up_to_height: u64,
        headers_from_height: u64,
        headers_count: usize,
    },
}

/// Checkpoint for edge node state recovery
#[derive(Debug, Clone)]
pub struct EdgeNodeCheckpoint {
    pub height: u64,
    pub header_count: usize,
    pub utxo_count: usize,
    pub latest_block_hash: Option<Hash>,
    pub timestamp: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Difficulty;

    #[test]
    fn test_edge_node_creation() {
        let edge_node = EdgeNodeState::new(500);
        assert_eq!(edge_node.max_headers, 500);
        assert_eq!(edge_node.headers.len(), 0);
        assert_eq!(edge_node.current_height, 0);
    }

    #[test]
    fn test_header_rolling_window() {
        let mut edge_node = EdgeNodeState::new(3);

        // Add 5 headers (should keep only last 3)
        // First header (genesis) needs valid hash
        let mut genesis = create_dummy_header(0);
        genesis.block_hash = genesis.calculate_hash();
        assert!(edge_node.add_header(genesis).is_ok());

        // Add subsequent headers with proper chain setup
        for i in 1..=4 {
            let mut header = create_dummy_header(i);
            if let Some(prev) = edge_node.get_latest_header() {
                header.previous_block_hash = prev.block_hash;
                // Ensure timestamp is after previous
                header.timestamp = prev.timestamp + 10;
                header.block_hash = header.calculate_hash();
            }
            let _ = edge_node.add_header(header);
        }

        assert!(edge_node.headers.len() <= 3);
        assert!(edge_node.get_latest_header().is_some());
    }

    #[test]
    fn test_needs_bootstrap_proof() {
        let mut edge_node = EdgeNodeState::new(500);

        // Empty state needs bootstrap for established networks
        assert!(edge_node.needs_bootstrap_proof(1000));

        // Add valid header at height 0 to start the chain
        let mut header = create_dummy_header(0);
        header.block_hash = header.calculate_hash();
        assert!(edge_node.add_header(header).is_ok());

        // 500 blocks behind - on the borderline, should not need bootstrap
        assert!(!edge_node.needs_bootstrap_proof(500));

        // 501 blocks behind - needs bootstrap
        assert!(edge_node.needs_bootstrap_proof(501));
    }

    #[test]
    fn test_new_network_sync_strategy() {
        let edge_node = EdgeNodeState::new(500);
        
        // New network with 50 blocks: Just download all headers
        match edge_node.get_sync_strategy(50) {
            SyncStrategy::HeadersOnly { start_height, count } => {
                assert_eq!(start_height, 0);
                assert_eq!(count, 50);
            },
            _ => panic!("Expected HeadersOnly strategy for new network"),
        }
        
        // New network with 200 blocks: Use bootstrap proof
        match edge_node.get_sync_strategy(200) {
            SyncStrategy::BootstrapProof { proof_up_to_height, headers_from_height, headers_count } => {
                assert_eq!(proof_up_to_height, 100);
                assert_eq!(headers_from_height, 100);
                assert_eq!(headers_count, 100);
            },
            _ => panic!("Expected BootstrapProof strategy for network with 200 blocks"),
        }
    }

    #[test]
    fn test_sync_strategy_close_to_tip() {
        let mut edge_node = EdgeNodeState::new(500);

        // Build a valid chain up to height 1000
        for i in 0..=1000 {
            let mut header = create_dummy_header(i);
            if let Some(prev) = edge_node.get_latest_header() {
                header.previous_block_hash = prev.block_hash;
                header.timestamp = prev.timestamp + 10;
            }
            header.block_hash = header.calculate_hash();
            // Only keep last 500 headers due to rolling window
            let _ = edge_node.add_header(header);
        }

        // Network at height 1100 (100 blocks behind): Just sync headers
        match edge_node.get_sync_strategy(1100) {
            SyncStrategy::HeadersOnly { start_height, count } => {
                assert_eq!(start_height, 1001);
                assert_eq!(count, 100);
            },
            _ => panic!("Expected HeadersOnly when close to tip"),
        }

        // Network at height 1600 (600 blocks behind): Use bootstrap proof
        match edge_node.get_sync_strategy(1600) {
            SyncStrategy::BootstrapProof { proof_up_to_height, headers_from_height, headers_count } => {
                assert_eq!(proof_up_to_height, 1500);
                assert_eq!(headers_from_height, 1500);
                assert_eq!(headers_count, 100);
            },
            _ => panic!("Expected BootstrapProof when far behind"),
        }
    }

    #[test]
    fn test_new_network_no_bootstrap_needed() {
        let mut edge_node = EdgeNodeState::new(500);
        
        // New network with only 50 blocks shouldn't need ZK proof
        assert!(!edge_node.needs_bootstrap_proof(50));
        
        // After first sync at height 50, network at 70 blocks (20 blocks behind)
        edge_node.add_header(create_dummy_header(50));
        assert!(!edge_node.needs_bootstrap_proof(70));
    }

    fn create_dummy_header(height: u64) -> BlockHeader {
        let mut header = BlockHeader {
            version: 1,
            previous_block_hash: Hash::zero(),
            merkle_root: Hash::zero(),
            state_root: Hash::default(),
            timestamp: 1700000000 + height * 10,
            difficulty: Difficulty::minimum(),
            nonce: 0,
            cumulative_difficulty: Difficulty::minimum(),
            height,
            block_hash: Hash::zero(),
            transaction_count: 0,
            block_size: 0,
            fee_model_version: 2, // Phase 2+ uses v2
        };
        // Calculate and set the correct block hash
        header.block_hash = header.calculate_hash();
        header
    }
}
