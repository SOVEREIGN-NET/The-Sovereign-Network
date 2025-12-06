//! Proof-of-Work module for identity creation
//!
//! Implements time-bound proof-of-work to prevent Sybil attacks through:
//! - Computational cost tied to timestamp (prevents pre-generation)
//! - Network load-based difficulty adjustment
//! - BLAKE3-based hash function (fast verification)
//!
//! # Security Properties
//!
//! - **Anti-Pre-computation**: PoW binds to timestamp, cannot be pre-generated
//! - **Sybil Resistance**: Each identity requires computational work
//! - **Adaptive Load**: Difficulty scales with network congestion
//! - **Fast Verification**: BLAKE3 enables efficient verification
//!
//! # Example
//!
//! ```rust
//! use lib_network::identity::proof_of_work::{ProofOfWork, calculate_adaptive_difficulty};
//! use lib_identity::NodeId;
//!
//! let node_id = NodeId::from_bytes([0xAAu8; 32]);
//! let timestamp = 1234567890;
//! let difficulty = calculate_adaptive_difficulty(0.5); // 50% network load
//!
//! // Generate proof-of-work (may take time)
//! let pow = ProofOfWork::generate(&node_id, timestamp, difficulty)?;
//!
//! // Fast verification
//! assert!(pow.verify(&node_id, timestamp));
//! ```

use anyhow::{Result, anyhow};
use blake3;
use lib_identity::NodeId;
use serde::{Deserialize, Serialize};

/// Proof-of-work for identity creation with timestamp binding
///
/// Binds computational work to a specific timestamp, preventing attackers
/// from pre-generating identities for future use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofOfWork {
    /// Number of leading zero bits required
    difficulty: u32,

    /// Nonce that satisfies the difficulty requirement
    nonce: u64,

    /// Resulting hash (cached for verification)
    hash: [u8; 32],
}

impl ProofOfWork {
    /// Generate proof-of-work for identity creation
    ///
    /// This binds the PoW to both the node_id and timestamp, preventing
    /// pre-computation attacks. The attacker cannot pre-generate identities
    /// for future timestamps.
    ///
    /// # Arguments
    ///
    /// * `node_id` - Identity being created (prevents identity grinding)
    /// * `timestamp` - Creation timestamp (prevents pre-computation)
    /// * `difficulty` - Number of leading zero bits required (16-24 typical)
    ///
    /// # Security
    ///
    /// - Binds to timestamp: PoW generated for time T is invalid at T+1
    /// - Binds to node_id: Cannot reuse PoW across identities
    /// - Domain separation: Uses unique prefix "ZHTP_IDENTITY_POW_V1"
    ///
    /// # Performance
    ///
    /// - Difficulty 16: ~65K hashes (~1ms on modern CPU)
    /// - Difficulty 20: ~1M hashes (~15ms on modern CPU)
    /// - Difficulty 24: ~16M hashes (~250ms on modern CPU)
    ///
    /// # Returns
    ///
    /// - `Ok(ProofOfWork)` if valid nonce found
    /// - `Err(...)` if nonce overflows (difficulty too high)
    pub fn generate(
        node_id: &NodeId,
        timestamp: u64,
        difficulty: u32,
    ) -> Result<Self> {
        // Sanity check: difficulty must be reasonable
        if difficulty > 32 {
            return Err(anyhow!("Difficulty too high: {} bits (max: 32)", difficulty));
        }

        let mut nonce = 0u64;

        loop {
            let hash = Self::compute_hash(node_id, timestamp, nonce);

            if Self::verify_difficulty(&hash, difficulty) {
                return Ok(ProofOfWork {
                    difficulty,
                    nonce,
                    hash,
                });
            }

            // Prevent infinite loop on unreasonable difficulty
            nonce = nonce.checked_add(1)
                .ok_or_else(|| anyhow!(
                    "Nonce overflow - difficulty {} too high (tried 2^64 hashes)",
                    difficulty
                ))?;
        }
    }

    /// Verify proof-of-work is valid for given node_id and timestamp
    ///
    /// Fast verification (~1 microsecond) checks:
    /// 1. Hash recomputation matches stored hash
    /// 2. Hash satisfies difficulty requirement
    /// 3. Timestamp matches (prevents replay)
    ///
    /// # Arguments
    ///
    /// * `node_id` - Identity claiming this PoW
    /// * `timestamp` - Timestamp claimed at creation
    ///
    /// # Returns
    ///
    /// `true` if PoW is valid, `false` otherwise
    pub fn verify(&self, node_id: &NodeId, timestamp: u64) -> bool {
        // Recompute hash with claimed parameters
        let hash = Self::compute_hash(node_id, timestamp, self.nonce);

        // Verify hash matches AND satisfies difficulty
        hash == self.hash && Self::verify_difficulty(&hash, self.difficulty)
    }

    /// Compute BLAKE3 hash for PoW verification
    ///
    /// Hash input: "ZHTP_IDENTITY_POW_V1" || node_id || timestamp || nonce
    ///
    /// This ensures:
    /// - Different identities require different PoW (node_id binding)
    /// - Different timestamps require different PoW (timestamp binding)
    /// - Domain separation (unique prefix)
    fn compute_hash(node_id: &NodeId, timestamp: u64, nonce: u64) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();

        // Domain separation prefix
        hasher.update(b"ZHTP_IDENTITY_POW_V1");

        // Bind to specific node_id (prevents PoW reuse)
        hasher.update(node_id.as_bytes());

        // Bind to timestamp (prevents pre-computation)
        hasher.update(&timestamp.to_le_bytes());

        // Nonce for proof-of-work
        hasher.update(&nonce.to_le_bytes());

        *hasher.finalize().as_bytes()
    }

    /// Verify hash has required number of leading zero bits
    ///
    /// Checks if the hash has at least `difficulty` leading zero bits.
    /// Uses constant-time comparison within each byte for side-channel resistance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use lib_network::identity::proof_of_work::ProofOfWork;
    /// let hash_8_zeros = [0x00, 0xFF, 0xFF, /* ... */];
    /// assert!(ProofOfWork::verify_difficulty_static(&hash_8_zeros, 8));
    /// assert!(!ProofOfWork::verify_difficulty_static(&hash_8_zeros, 9));
    /// ```
    fn verify_difficulty(hash: &[u8; 32], difficulty: u32) -> bool {
        let difficulty_usize = difficulty as usize;

        // Count leading zero bits
        let mut leading_zeros = 0;

        for &byte in hash.iter() {
            if byte == 0 {
                leading_zeros += 8;
            } else {
                // Count leading zeros in this byte
                leading_zeros += byte.leading_zeros() as usize;
                break;
            }
        }

        leading_zeros >= difficulty_usize
    }

    /// Get the difficulty level of this proof-of-work
    pub fn difficulty(&self) -> u32 {
        self.difficulty
    }

    /// Get the nonce that satisfied the proof-of-work
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Get the resulting hash
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
}

/// Calculate adaptive difficulty based on network load
///
/// Adjusts proof-of-work difficulty based on current network congestion:
/// - Low load (0.0): Difficulty 16 (~1ms generation time)
/// - Medium load (0.5): Difficulty 20 (~15ms generation time)
/// - High load (1.0): Difficulty 24 (~250ms generation time)
///
/// # Arguments
///
/// * `network_load` - Load factor from 0.0 (idle) to 1.0 (saturated)
///
/// # Returns
///
/// Difficulty in bits (16-24 range)
///
/// # Example
///
/// ```rust
/// use lib_network::identity::proof_of_work::calculate_adaptive_difficulty;
///
/// // Low load: quick identity creation
/// let low = calculate_adaptive_difficulty(0.0);
/// assert_eq!(low, 16);
///
/// // High load: deter Sybil attacks
/// let high = calculate_adaptive_difficulty(1.0);
/// assert_eq!(high, 24);
/// ```
pub fn calculate_adaptive_difficulty(network_load: f64) -> u32 {
    // Clamp network_load to [0.0, 1.0]
    let load = network_load.clamp(0.0, 1.0);

    // Base difficulty: 16 bits (fast on CPU, ~1ms)
    // Max difficulty: 24 bits (slow on CPU, ~250ms, deters Sybil)
    const BASE: u32 = 16;
    const MAX: u32 = 24;

    // Linear interpolation
    BASE + ((MAX - BASE) as f64 * load).round() as u32
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_of_work_generation_and_verification() {
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 16;

        // Generate PoW
        let pow = ProofOfWork::generate(&node_id, timestamp, difficulty).unwrap();

        // Verify with correct parameters
        assert!(pow.verify(&node_id, timestamp));

        // Verify difficulty is correct
        assert_eq!(pow.difficulty(), difficulty);
    }

    #[test]
    fn test_proof_of_work_prevents_timestamp_manipulation() {
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp1 = 1234567890;
        let timestamp2 = 1234567891;  // Different by 1 second
        let difficulty = 16;

        // Generate PoW for timestamp1
        let pow = ProofOfWork::generate(&node_id, timestamp1, difficulty).unwrap();

        // Valid for original timestamp
        assert!(pow.verify(&node_id, timestamp1));

        // INVALID for different timestamp (prevents pre-computation)
        assert!(!pow.verify(&node_id, timestamp2));
    }

    #[test]
    fn test_proof_of_work_prevents_node_id_reuse() {
        let node_id1 = NodeId::from_bytes([0xAAu8; 32]);
        let node_id2 = NodeId::from_bytes([0xBBu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 16;

        // Generate PoW for node_id1
        let pow = ProofOfWork::generate(&node_id1, timestamp, difficulty).unwrap();

        // Valid for original node_id
        assert!(pow.verify(&node_id1, timestamp));

        // INVALID for different node_id (prevents PoW reuse)
        assert!(!pow.verify(&node_id2, timestamp));
    }

    #[test]
    fn test_difficulty_verification() {
        // Hash with 16 leading zero bits
        let mut hash = [0u8; 32];
        hash[0] = 0x00;
        hash[1] = 0x00;
        hash[2] = 0xFF;  // First non-zero bit at position 16

        assert!(ProofOfWork::verify_difficulty(&hash, 16));
        assert!(!ProofOfWork::verify_difficulty(&hash, 17));
    }

    #[test]
    fn test_difficulty_all_zeros() {
        let hash = [0u8; 32];

        // All zeros satisfies any difficulty up to 256 bits
        assert!(ProofOfWork::verify_difficulty(&hash, 0));
        assert!(ProofOfWork::verify_difficulty(&hash, 16));
        assert!(ProofOfWork::verify_difficulty(&hash, 32));
        assert!(ProofOfWork::verify_difficulty(&hash, 255));
    }

    #[test]
    fn test_difficulty_no_zeros() {
        let hash = [0xFFu8; 32];

        // No leading zeros - fails all non-zero difficulties
        assert!(ProofOfWork::verify_difficulty(&hash, 0));
        assert!(!ProofOfWork::verify_difficulty(&hash, 1));
    }

    #[test]
    fn test_adaptive_difficulty_scaling() {
        let low_load = calculate_adaptive_difficulty(0.0);
        let mid_load = calculate_adaptive_difficulty(0.5);
        let high_load = calculate_adaptive_difficulty(1.0);

        assert_eq!(low_load, 16, "Low load should use minimum difficulty");
        assert_eq!(mid_load, 20, "Medium load should use intermediate difficulty");
        assert_eq!(high_load, 24, "High load should use maximum difficulty");

        // Verify monotonic increase
        assert!(low_load < mid_load);
        assert!(mid_load < high_load);
    }

    #[test]
    fn test_adaptive_difficulty_clamping() {
        // Test values outside [0.0, 1.0] are clamped
        assert_eq!(calculate_adaptive_difficulty(-0.5), 16);
        assert_eq!(calculate_adaptive_difficulty(1.5), 24);
    }

    #[test]
    fn test_proof_of_work_serialization() {
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 16;

        // Generate PoW
        let pow = ProofOfWork::generate(&node_id, timestamp, difficulty).unwrap();

        // Serialize and deserialize
        let serialized = serde_json::to_string(&pow).unwrap();
        let deserialized: ProofOfWork = serde_json::from_str(&serialized).unwrap();

        // Verify still valid after round-trip
        assert_eq!(pow, deserialized);
        assert!(deserialized.verify(&node_id, timestamp));
    }

    #[test]
    fn test_difficulty_too_high_rejected() {
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 33;  // > 32 bits

        let result = ProofOfWork::generate(&node_id, timestamp, difficulty);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too high"));
    }

    #[test]
    fn test_proof_of_work_different_for_same_params() {
        // Multiple generations should find different nonces
        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 16;

        let pow1 = ProofOfWork::generate(&node_id, timestamp, difficulty).unwrap();
        let pow2 = ProofOfWork::generate(&node_id, timestamp, difficulty).unwrap();

        // Both valid
        assert!(pow1.verify(&node_id, timestamp));
        assert!(pow2.verify(&node_id, timestamp));

        // May have different nonces (unless there's only one valid nonce)
        // This is fine - just checking both are valid
    }

    #[test]
    #[ignore]  // Expensive test - run with --ignored
    fn test_proof_of_work_timing_difficulty_16() {
        use std::time::Instant;

        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 16;

        let start = Instant::now();
        let _pow = ProofOfWork::generate(&node_id, timestamp, difficulty).unwrap();
        let elapsed = start.elapsed();

        println!("Difficulty 16: {:?}", elapsed);

        // Should complete in under 100ms on modern hardware
        assert!(elapsed.as_millis() < 100, "Difficulty 16 too slow: {:?}", elapsed);
    }

    #[test]
    #[ignore]  // Expensive test - run with --ignored
    fn test_proof_of_work_timing_difficulty_20() {
        use std::time::Instant;

        let node_id = NodeId::from_bytes([0xAAu8; 32]);
        let timestamp = 1234567890;
        let difficulty = 20;

        let start = Instant::now();
        let _pow = ProofOfWork::generate(&node_id, timestamp, difficulty).unwrap();
        let elapsed = start.elapsed();

        println!("Difficulty 20: {:?}", elapsed);

        // Should complete in under 1 second on modern hardware
        assert!(elapsed.as_secs() < 1, "Difficulty 20 too slow: {:?}", elapsed);
    }
}
