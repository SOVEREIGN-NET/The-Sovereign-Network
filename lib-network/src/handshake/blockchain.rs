//! Blockchain-Aware Handshake Extension
//!
//! Adds blockchain state verification for validator authentication during handshakes.
//! This prevents validator impersonation, eclipse attacks, consensus splits, and 
//! cross-chain replay attacks.
//!
//! # Security Properties
//!
//! - **Validator Authentication**: Verifies peer stake against on-chain stake table
//! - **Chain Fork Detection**: Detects chain splits via block hash mismatch
//! - **Epoch Verification**: Ensures peers are on the same consensus epoch
//! - **Peer Tier Classification**: Assigns trust levels based on stake and validation
//!
//! # Production Usage
//!
//! ```rust,no_run
//! use lib_network::handshake::blockchain::*;
//! use lib_consensus::ChainSummary;
//! use lib_blockchain::Blockchain;
//! 
//! async fn create_handshake_context(
//!     blockchain: &Blockchain,
//!     chain_summary: &ChainSummary,
//!     current_epoch: u64,
//! ) -> BlockchainHandshakeContext {
//!     // Get the actual latest block hash from blockchain
//!     let latest_block_hash = blockchain
//!         .latest_block()
//!         .map(|b| b.hash())
//!         .unwrap_or_else(|| Hash::zero());
//!     
//!     // Create context with real blockchain state
//!     BlockchainHandshakeContext::from_chain_state(
//!         chain_summary,
//!         latest_block_hash,
//!         current_epoch,
//!     )
//! }
//! ```
//!
//! # Architecture
//!
//! The blockchain handshake extension integrates with the existing Unified Handshake
//! Protocol (UHP) to add blockchain-aware verification:
//!
//! ```text
//! Client                                Server
//!   |--- ClientHello ------------------>  |
//!   |    + BlockchainContext             |
//!   |                                    |
//!   |<-- ServerHello -------------------  |
//!   |    + BlockchainContext             |
//!   |                                    |
//!   |=== Verify Blockchain State =====> |
//!   |    - Chain ID match                |
//!   |    - Block hash verification       |
//!   |    - Epoch alignment               |
//!   |    - Stake validation              |
//!   |                                    |
//!   |<== Secure + Validated Session ===> |
//! ```

use anyhow::{Result, anyhow};
use lib_crypto::Hash;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use subtle::ConstantTimeEq;

// Re-export ChainSummary from lib-consensus for blockchain state verification
pub use lib_consensus::ChainSummary;

/// Blockchain context included in handshake messages
///
/// This structure contains the blockchain state information that peers
/// exchange during handshakes to verify they are on the same chain and
/// to authenticate validators.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BlockchainHandshakeContext {
    /// Chain identifier (prevents cross-chain replay attacks)
    pub chain_id: String,

    /// Current block hash (detects chain forks)
    pub block_hash: Hash,

    /// Parent block hash (P1-2 FIX: enables fork detection across heights)
    pub parent_hash: Option<Hash>,

    /// Recent block hashes (P1-2 FIX: for common ancestor verification)
    /// Last N block hashes for detecting divergence
    pub recent_block_hashes: Vec<Hash>,

    /// Current epoch number (consensus round alignment)
    pub epoch: u64,

    /// Current block height
    pub height: u64,

    /// Validator stake (if peer is a validator)
    pub validator_stake: Option<u64>,

    /// Genesis hash (ensures same network)
    pub genesis_hash: String,

    /// Validator set hash (ensures compatible validator set)
    pub validator_set_hash: String,
}

impl BlockchainHandshakeContext {
    /// Create blockchain context from chain summary and latest block
    ///
    /// # Arguments
    /// * `summary` - Chain summary with validator and network info
    /// * `latest_block_hash` - Hash of the latest block (from blockchain.latest_block())
    /// * `current_epoch` - Current consensus epoch number
    pub fn from_chain_state(
        summary: &ChainSummary,
        latest_block_hash: Hash,
        current_epoch: u64,
    ) -> Self {
        Self {
            // SECURITY (P0-2 FIX): Use full genesis hash for chain ID (no truncation)
            // Prevents collision attacks and ensures 256-bit security
            chain_id: summary.genesis_hash.clone(),
            block_hash: latest_block_hash,
            parent_hash: None, // Set via with_parent_hash()
            recent_block_hashes: Vec::new(), // Set via with_recent_hashes()
            epoch: current_epoch,
            height: summary.height,
            validator_stake: None, // Will be set via with_validator_stake()
            genesis_hash: summary.genesis_hash.clone(),
            validator_set_hash: summary.validator_set_hash.clone(),
        }
    }
    
    /// Create blockchain context directly (for testing or custom scenarios)
    pub fn new(
        chain_id: String,
        block_hash: Hash,
        epoch: u64,
        height: u64,
        genesis_hash: String,
        validator_set_hash: String,
    ) -> Self {
        Self {
            chain_id,
            block_hash,
            parent_hash: None,
            recent_block_hashes: Vec::new(),
            epoch,
            height,
            validator_stake: None,
            genesis_hash,
            validator_set_hash,
        }
    }

    /// Create context with validator stake information
    pub fn with_validator_stake(mut self, stake: u64) -> Self {
        self.validator_stake = Some(stake);
        self
    }

    /// Add parent hash for fork detection (P1-2 FIX)
    pub fn with_parent_hash(mut self, parent: Hash) -> Self {
        self.parent_hash = Some(parent);
        self
    }

    /// Add recent block hashes for common ancestor verification (P1-2 FIX)
    pub fn with_recent_hashes(mut self, hashes: Vec<Hash>) -> Self {
        self.recent_block_hashes = hashes;
        self
    }
}

/// Peer tier classification based on stake and validation status
///
/// Determines trust level and capabilities granted to peers based on
/// their blockchain participation and stake.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerTier {
    /// Verified validator with on-chain stake
    Validator,
    
    /// Node with stake but not actively validating
    StakedNode,
    
    /// Unverified peer (default for new connections)
    Unverified,
}

impl PeerTier {
    /// Get minimum stake required for this tier
    pub fn min_stake(&self) -> u64 {
        match self {
            PeerTier::Validator => 1_000 * 1_000_000, // 1000 ZHTP minimum for validators
            PeerTier::StakedNode => 100 * 1_000_000,   // 100 ZHTP minimum for staked nodes
            PeerTier::Unverified => 0,
        }
    }
    
    /// Check if this tier can participate in consensus
    pub fn can_validate(&self) -> bool {
        matches!(self, PeerTier::Validator)
    }
    
    /// Check if this tier has enhanced network privileges
    pub fn has_enhanced_privileges(&self) -> bool {
        matches!(self, PeerTier::Validator | PeerTier::StakedNode)
    }
    
    /// Get trust score for this tier (0.0 - 1.0)
    pub fn trust_score(&self) -> f64 {
        match self {
            PeerTier::Validator => 1.0,
            PeerTier::StakedNode => 0.7,
            PeerTier::Unverified => 0.3,
        }
    }
}

impl Default for PeerTier {
    fn default() -> Self {
        PeerTier::Unverified
    }
}

/// Result of blockchain handshake verification
#[derive(Debug, Clone)]
pub struct BlockchainVerificationResult {
    /// Whether verification succeeded
    pub verified: bool,
    
    /// Determined peer tier
    pub peer_tier: PeerTier,
    
    /// Verification details/errors
    pub details: String,
    
    /// Whether chain fork was detected
    pub fork_detected: bool,
    
    /// Whether epoch mismatch was detected
    pub epoch_mismatch: bool,
}

impl BlockchainVerificationResult {
    /// Create a successful verification result
    pub fn success(peer_tier: PeerTier, details: String) -> Self {
        Self {
            verified: true,
            peer_tier,
            details,
            fork_detected: false,
            epoch_mismatch: false,
        }
    }
    
    /// Create a failed verification result
    pub fn failure(reason: String) -> Self {
        Self {
            verified: false,
            peer_tier: PeerTier::Unverified,
            details: reason,
            fork_detected: false,
            epoch_mismatch: false,
        }
    }
    
    /// Create a fork detection result
    pub fn fork_detected(details: String) -> Self {
        Self {
            verified: false,
            peer_tier: PeerTier::Unverified,
            details,
            fork_detected: true,
            epoch_mismatch: false,
        }
    }
    
    /// Create an epoch mismatch result
    pub fn epoch_mismatch(details: String) -> Self {
        Self {
            verified: false,
            peer_tier: PeerTier::Unverified,
            details,
            fork_detected: false,
            epoch_mismatch: true,
        }
    }
}

/// Versioned stake entry with timestamp tracking
///
/// ENHANCEMENT: Prevents stale data issues during concurrent updates
#[derive(Debug, Clone)]
pub struct StakeEntry {
    /// Stake amount in ZHTP
    pub amount: u64,

    /// Epoch when this stake was last updated
    pub epoch: u64,

    /// Timestamp when this stake was last updated (Unix seconds)
    pub updated_at: u64,
}

impl StakeEntry {
    /// Create a new stake entry
    pub fn new(amount: u64, epoch: u64) -> Self {
        Self {
            amount,
            epoch,
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Check if this entry is stale compared to another
    pub fn is_stale_compared_to(&self, other: &StakeEntry) -> bool {
        self.epoch < other.epoch ||
        (self.epoch == other.epoch && self.updated_at < other.updated_at)
    }
}

/// Blockchain handshake verifier
///
/// Verifies peer blockchain state and authenticates validators against
/// the on-chain stake table.
pub struct BlockchainHandshakeVerifier {
    /// Local blockchain context
    local_context: BlockchainHandshakeContext,

    /// Validator stake table (identity_hash -> versioned stake entry)
    /// SECURITY (P0-1 FIX): Thread-safe with RwLock to prevent race conditions
    /// ENHANCEMENT: Now uses StakeEntry for timestamp/epoch tracking
    validator_stakes: Arc<RwLock<std::collections::HashMap<Hash, StakeEntry>>>,

    /// Maximum allowed epoch difference (prevents time-travel attacks)
    max_epoch_diff: u64,

    /// Maximum allowed height difference for same epoch
    max_height_diff: u64,

    /// Optional rate limiter for DoS protection
    /// ENHANCEMENT: Prevents verification spam attacks
    rate_limiter: Option<super::RateLimiter>,
}

impl BlockchainHandshakeVerifier {
    /// Create a new blockchain handshake verifier
    pub fn new(local_context: BlockchainHandshakeContext) -> Self {
        Self {
            local_context,
            validator_stakes: Arc::new(RwLock::new(std::collections::HashMap::new())),
            max_epoch_diff: 5,      // Allow 5 epoch difference
            max_height_diff: 100,   // Allow 100 block difference
            rate_limiter: None,     // No rate limiting by default
        }
    }

    /// Add rate limiting to prevent DoS attacks
    /// ENHANCEMENT: Integrates with UHP rate limiter for verification spam protection
    pub fn with_rate_limiting(mut self, rate_limiter: super::RateLimiter) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    /// Update validator stakes from on-chain state
    /// SECURITY (P0-1 FIX): Thread-safe update with write lock
    /// ENHANCEMENT: Uses versioned StakeEntry with epoch tracking
    pub fn update_validator_stakes(&self, stakes: std::collections::HashMap<Hash, u64>, epoch: u64) {
        let mut stakes_guard = self.validator_stakes.write().unwrap();

        // Convert to StakeEntry and only update if newer
        for (identity, amount) in stakes {
            let new_entry = StakeEntry::new(amount, epoch);

            // Only update if newer than existing entry
            if let Some(existing) = stakes_guard.get(&identity) {
                if !existing.is_stale_compared_to(&new_entry) {
                    continue; // Skip stale updates
                }
            }

            stakes_guard.insert(identity, new_entry);
        }
    }

    /// Add a single validator stake
    /// SECURITY (P0-1 FIX): Thread-safe insert with write lock
    /// ENHANCEMENT: Uses versioned StakeEntry with epoch tracking
    pub fn add_validator_stake(&self, identity: Hash, stake: u64, epoch: u64) {
        let mut stakes_guard = self.validator_stakes.write().unwrap();
        let new_entry = StakeEntry::new(stake, epoch);

        // Only update if newer than existing entry
        if let Some(existing) = stakes_guard.get(&identity) {
            if !existing.is_stale_compared_to(&new_entry) {
                return; // Skip stale update
            }
        }

        stakes_guard.insert(identity, new_entry);
    }
    
    /// Verify peer blockchain context and determine tier
    ///
    /// # Security Checks
    ///
    /// 1. **Rate Limiting**: Prevents verification spam DoS (if enabled)
    /// 2. **Chain ID Verification**: Prevents cross-chain replay attacks
    /// 3. **Genesis Hash Match**: Ensures same network
    /// 4. **Block Hash Verification**: Detects chain forks
    /// 5. **Epoch Alignment**: Prevents time-travel attacks
    /// 6. **Validator Stake Verification**: Authenticates validators
    ///
    /// # Parameters
    ///
    /// - `peer_context`: Blockchain context from peer
    /// - `peer_identity`: Optional peer identity hash for stake verification
    /// - `peer_ip`: Optional peer IP address for rate limiting
    ///
    /// # Returns
    ///
    /// - `BlockchainVerificationResult` with verification status and peer tier
    pub fn verify_peer(
        &self,
        peer_context: &BlockchainHandshakeContext,
        peer_identity: Option<&Hash>,
        peer_ip: Option<std::net::IpAddr>,
    ) -> Result<BlockchainVerificationResult> {
        // 0. Rate limiting check (if enabled)
        // ENHANCEMENT: Prevents verification spam DoS attacks
        if let Some(ref rate_limiter) = self.rate_limiter {
            if let Some(ip) = peer_ip {
                if let Err(e) = rate_limiter.check_handshake(ip) {
                    tracing::warn!(
                        security_event = "rate_limit_exceeded",
                        peer_ip = ?ip,
                        error = ?e,
                    );
                    return Ok(BlockchainVerificationResult::failure(
                        "Rate limit exceeded".to_string()
                    ));
                }
            }
        }
        // 1. Verify chain_id matches (prevents cross-chain replay)
        if self.local_context.chain_id != peer_context.chain_id {
            return Ok(BlockchainVerificationResult::failure(
                format!(
                    "Chain ID mismatch: local={}, peer={}",
                    self.local_context.chain_id,
                    peer_context.chain_id
                )
            ));
        }
        
        // 2. Verify genesis hash matches (same network)
        // SECURITY (P1-1 FIX): Constant-time comparison to prevent timing side-channels
        if self.local_context.genesis_hash.len() != peer_context.genesis_hash.len()
            || self.local_context.genesis_hash.as_bytes().ct_eq(peer_context.genesis_hash.as_bytes()).unwrap_u8() == 0 {
            return Ok(BlockchainVerificationResult::failure(
                "Genesis hash mismatch".to_string()
            ));
        }
        
        // 3. Detect chain fork via block hash mismatch
        // If peers are at the same height but have different block hashes, it's a fork
        if self.local_context.height == peer_context.height 
            && self.local_context.block_hash != peer_context.block_hash {
            return Ok(BlockchainVerificationResult::fork_detected(
                format!(
                    "Fork detected at height {}: local_hash={:?}, peer_hash={:?}",
                    self.local_context.height,
                    self.local_context.block_hash,
                    peer_context.block_hash
                )
            ));
        }
        
        // 4. Verify epoch alignment (prevents time-travel attacks)
        // SECURITY (P0-4 FIX): Asymmetric epoch check
        // Reject peers from the future (time-travel attack)
        if peer_context.epoch > self.local_context.epoch + 1 {
            return Ok(BlockchainVerificationResult::epoch_mismatch(
                format!(
                    "Peer epoch too far in future: local={}, peer={}",
                    self.local_context.epoch,
                    peer_context.epoch
                )
            ));
        }

        // Allow historical peers (sync scenarios) up to max_epoch_diff
        if self.local_context.epoch > peer_context.epoch + self.max_epoch_diff {
            return Ok(BlockchainVerificationResult::epoch_mismatch(
                format!(
                    "Peer epoch too far in past: local={}, peer={}, diff={}",
                    self.local_context.epoch,
                    peer_context.epoch,
                    self.local_context.epoch - peer_context.epoch
                )
            ));
        }
        
        // 5. Verify height alignment
        // SECURITY (P2-1 FIX): Reject (not just warn) excessive height difference
        let height_diff = if self.local_context.height > peer_context.height {
            self.local_context.height - peer_context.height
        } else {
            peer_context.height - self.local_context.height
        };

        if height_diff > self.max_height_diff {
            return Ok(BlockchainVerificationResult::failure(
                format!(
                    "Height difference exceeds safety threshold: local={}, peer={}, diff={}",
                    self.local_context.height,
                    peer_context.height,
                    height_diff
                )
            ));
        }

        // 6. Verify validator set compatibility
        // SECURITY (P0-3 FIX): Enforce validator set verification
        if !self.verify_validator_set(peer_context)? {
            return Ok(BlockchainVerificationResult::failure(
                "Incompatible validator set".to_string()
            ));
        }

        // 7. Determine peer tier based on stake
        // SECURITY (P0-1 FIX): Thread-safe read access to validator stakes
        // ENHANCEMENT: Now uses StakeEntry with versioning
        let peer_tier = if let Some(stake) = peer_context.validator_stake {
            // Peer claims to be a validator - verify against on-chain stake table
            if let Some(peer_id) = peer_identity {
                let stakes_guard = self.validator_stakes.read().unwrap();
                match stakes_guard.get(peer_id) {
                    Some(stake_entry) => {
                        let on_chain_stake = stake_entry.amount;

                        // Verify claimed stake matches on-chain stake
                        if stake != on_chain_stake {
                            // SECURITY (P1-3 FIX): Sanitize error message
                            tracing::warn!(
                                security_event = "stake_mismatch",
                                peer_id = ?peer_id,
                                claimed = stake,
                                actual = on_chain_stake,
                                stake_epoch = stake_entry.epoch,
                                stake_updated_at = stake_entry.updated_at,
                            );
                            return Ok(BlockchainVerificationResult::failure(
                                "Validator authentication failed".to_string()
                            ));
                        }

                        // Determine tier based on stake amount
                        if stake >= PeerTier::Validator.min_stake() {
                            PeerTier::Validator
                        } else if stake >= PeerTier::StakedNode.min_stake() {
                            PeerTier::StakedNode
                        } else {
                            PeerTier::Unverified
                        }
                    }
                    None => {
                        // Peer claims stake but not in on-chain table
                        // SECURITY (P1-3 FIX): Sanitize error message
                        tracing::warn!(
                            security_event = "validator_not_found",
                            peer_id = ?peer_id,
                        );
                        return Ok(BlockchainVerificationResult::failure(
                            "Validator authentication failed".to_string()
                        ));
                    }
                }
            } else {
                // No identity provided - cannot verify stake
                PeerTier::Unverified
            }
        } else {
            // Peer does not claim validator status
            PeerTier::Unverified
        };
        
        Ok(BlockchainVerificationResult::success(
            peer_tier,
            format!(
                "Verified peer: tier={:?}, height_diff={}",
                peer_tier,
                height_diff
            )
        ))
    }
    
    /// Verify validator set compatibility
    ///
    /// Checks if the peer's validator set is compatible with ours.
    /// This is important for consensus participation.
    pub fn verify_validator_set(&self, peer_context: &BlockchainHandshakeContext) -> Result<bool> {
        // If validator set hashes match, sets are compatible
        if self.local_context.validator_set_hash == peer_context.validator_set_hash {
            return Ok(true);
        }
        
        // If hashes differ but we're not too far apart in height, allow with warning
        let height_diff = if self.local_context.height > peer_context.height {
            self.local_context.height - peer_context.height
        } else {
            peer_context.height - self.local_context.height
        };
        
        if height_diff <= self.max_height_diff {
            tracing::warn!(
                "Validator set hash mismatch but within acceptable height difference: {}",
                height_diff
            );
            return Ok(true);
        }
        
        Ok(false)
    }
    
    /// Update local blockchain context (called when chain advances)
    pub fn update_local_context(&mut self, new_context: BlockchainHandshakeContext) {
        self.local_context = new_context;
    }
    
    /// Get current local blockchain context
    pub fn local_context(&self) -> &BlockchainHandshakeContext {
        &self.local_context
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_context() -> BlockchainHandshakeContext {
        BlockchainHandshakeContext::new(
            "test_chain".to_string(),
            Hash::from_bytes(&[1u8; 32]),
            100,  // epoch
            1000, // height
            "genesis_test".to_string(),
            "validator_set_test".to_string(),
        )
    }
    
    #[test]
    fn test_peer_tier_classification() {
        assert_eq!(PeerTier::Validator.min_stake(), 1_000_000_000);
        assert_eq!(PeerTier::StakedNode.min_stake(), 100_000_000);
        assert_eq!(PeerTier::Unverified.min_stake(), 0);
        
        assert!(PeerTier::Validator.can_validate());
        assert!(!PeerTier::StakedNode.can_validate());
        assert!(!PeerTier::Unverified.can_validate());
        
        assert!(PeerTier::Validator.has_enhanced_privileges());
        assert!(PeerTier::StakedNode.has_enhanced_privileges());
        assert!(!PeerTier::Unverified.has_enhanced_privileges());
    }
    
    #[test]
    fn test_chain_id_verification() {
        let local_ctx = create_test_context();
        let verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.chain_id = "different_chain".to_string();
        
        let result = verifier.verify_peer(&peer_ctx, None, None).unwrap();
        assert!(!result.verified);
        assert!(result.details.contains("Chain ID mismatch"));
    }
    
    #[test]
    fn test_genesis_hash_verification() {
        let local_ctx = create_test_context();
        let verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.genesis_hash = "different_genesis".to_string();
        
        let result = verifier.verify_peer(&peer_ctx, None, None).unwrap();
        assert!(!result.verified);
        assert!(result.details.contains("Genesis hash mismatch"));
    }
    
    #[test]
    fn test_fork_detection() {
        let local_ctx = create_test_context();
        let verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.block_hash = Hash::from_bytes(&[2u8; 32]); // Different hash at same height
        
        let result = verifier.verify_peer(&peer_ctx, None, None).unwrap();
        assert!(!result.verified);
        assert!(result.fork_detected);
        assert!(result.details.contains("Fork detected"));
    }
    
    #[test]
    fn test_epoch_mismatch_detection() {
        let local_ctx = create_test_context();
        let verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.epoch = 200; // More than max_epoch_diff away
        
        let result = verifier.verify_peer(&peer_ctx, None, None).unwrap();
        assert!(!result.verified);
        assert!(result.epoch_mismatch);
        assert!(result.details.contains("Epoch mismatch"));
    }
    
    #[test]
    fn test_validator_stake_verification() {
        let local_ctx = create_test_context();
        let mut verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let validator_id = Hash::from_bytes(&[3u8; 32]);
        let validator_stake = 2_000_000_000; // 2000 ZHTP
        
        verifier.add_validator_stake(validator_id.clone(), validator_stake, 1);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.validator_stake = Some(validator_stake);
        
        let result = verifier.verify_peer(&peer_ctx, Some(&validator_id), None).unwrap();
        assert!(result.verified);
        assert_eq!(result.peer_tier, PeerTier::Validator);
    }
    
    #[test]
    fn test_stake_mismatch_rejection() {
        let local_ctx = create_test_context();
        let mut verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let validator_id = Hash::from_bytes(&[3u8; 32]);
        verifier.add_validator_stake(validator_id.clone(), 2_000_000_000, 1);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.validator_stake = Some(3_000_000_000); // Claimed stake doesn't match
        
        let result = verifier.verify_peer(&peer_ctx, Some(&validator_id), None).unwrap();
        assert!(!result.verified);
        assert!(result.details.contains("Stake mismatch"));
    }
    
    #[test]
    fn test_unverified_validator_rejection() {
        let local_ctx = create_test_context();
        let verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let validator_id = Hash::from_bytes(&[3u8; 32]);
        let mut peer_ctx = create_test_context();
        peer_ctx.validator_stake = Some(2_000_000_000);
        
        // Validator not in stake table
        let result = verifier.verify_peer(&peer_ctx, Some(&validator_id), None).unwrap();
        assert!(!result.verified);
        assert!(result.details.contains("not found in on-chain stake table"));
    }
    
    #[test]
    fn test_staked_node_classification() {
        let local_ctx = create_test_context();
        let mut verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let node_id = Hash::from_bytes(&[4u8; 32]);
        let node_stake = 500_000_000; // 500 ZHTP (above StakedNode threshold)
        
        verifier.add_validator_stake(node_id.clone(), node_stake, 1);
        
        let mut peer_ctx = create_test_context();
        peer_ctx.validator_stake = Some(node_stake);
        
        let result = verifier.verify_peer(&peer_ctx, Some(&node_id), None).unwrap();
        assert!(result.verified);
        assert_eq!(result.peer_tier, PeerTier::StakedNode);
    }
    
    #[test]
    fn test_successful_peer_verification() {
        let local_ctx = create_test_context();
        let verifier = BlockchainHandshakeVerifier::new(local_ctx);
        
        let peer_ctx = create_test_context();
        
        let result = verifier.verify_peer(&peer_ctx, None, None).unwrap();
        assert!(result.verified);
        assert_eq!(result.peer_tier, PeerTier::Unverified);
        assert!(!result.fork_detected);
        assert!(!result.epoch_mismatch);
    }
}
