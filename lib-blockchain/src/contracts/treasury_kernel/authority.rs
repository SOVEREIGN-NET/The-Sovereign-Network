//! Treasury Kernel Minting Authority
//!
//! Enforces that only the Treasury Kernel can mint tokens.
//! No other contract can perform minting operations.
//!
//! # Security Model
//!
//! The minting authority model implements strict access control:
//! - **Single Authority**: Only the Kernel's PublicKey can mint
//! - **No Delegation**: Authority cannot be transferred or delegated
//! - **Immutable**: Set at Kernel initialization, never changes
//!
//! This guarantees that no other contract, even malicious ones, can
//! forge tokens or bypass validation.
//!
//! # Deterministic Transaction IDs
//!
//! Every minting operation produces a deterministic transaction ID based on:
//! - Constant identifier: `b"KERNEL_MINT"`
//! - Citizen ID (recipient)
//! - Epoch number
//! - Amount minted
//!
//! This enables:
//! - **Idempotency**: Same claim always produces same transaction ID
//! - **Auditability**: Every mint is traceable to a specific citizen/epoch/amount
//! - **Recovery**: Replaying transactions produces identical results
//!
//! # Example
//! ```ignore
//! // Only the Kernel can mint
//! KernelState::verify_minting_authority(&kernel_address, &kernel_address)?; // OK
//! KernelState::verify_minting_authority(&attacker_address, &kernel_address)?; // ERROR
//!
//! // Transaction IDs are deterministic
//! let txid1 = KernelState::compute_kernel_txid(&[1u8; 32], 100, 1000);
//! let txid2 = KernelState::compute_kernel_txid(&[1u8; 32], 100, 1000);
//! assert_eq!(txid1, txid2); // Same inputs → same output
//! ```

use super::types::KernelState;

/// Minting authority enforcement for Treasury Kernel
///
/// The Kernel is the **only** contract authorized to mint tokens.
/// This module provides the core logic for verifying minting authorization.
impl KernelState {
    /// Verify minting authority
    ///
    /// # Arguments
    /// * `caller` - The entity attempting to mint (must be kernel itself)
    /// * `kernel_address` - The kernel's own address
    ///
    /// # Returns
    /// Ok(()) if caller is authorized (is the kernel)
    /// Err if caller is not authorized
    pub fn verify_minting_authority(
        caller: &[u8; 32],
        kernel_address: &[u8; 32],
    ) -> Result<(), String> {
        if caller == kernel_address {
            Ok(())
        } else {
            Err("Only Treasury Kernel can mint tokens".to_string())
        }
    }

    /// Compute deterministic transaction ID for minting
    ///
    /// # Arguments
    /// * `citizen_id` - Recipient citizen ID
    /// * `epoch` - Epoch for which distribution occurs
    /// * `amount` - Amount being minted
    ///
    /// # Returns
    /// Deterministic 32-byte transaction ID
    pub fn compute_kernel_txid(citizen_id: &[u8; 32], epoch: u64, amount: u64) -> [u8; 32] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        b"KERNEL_MINT".hash(&mut hasher);
        citizen_id.hash(&mut hasher);
        epoch.hash(&mut hasher);
        amount.hash(&mut hasher);

        let hash = hasher.finish();
        let mut result = [0u8; 32];
        result[0..8].copy_from_slice(&hash.to_le_bytes());
        // Fill rest with deterministic pattern
        for i in 8..32 {
            result[i] = ((i as u64 ^ hash) % 256) as u8;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kernel_address() -> [u8; 32] {
        [88u8; 32]
    }

    fn test_attacker_address() -> [u8; 32] {
        [99u8; 32]
    }

    #[test]
    fn test_verify_minting_authority_kernel() {
        let kernel_addr = test_kernel_address();
        let result = KernelState::verify_minting_authority(&kernel_addr, &kernel_addr);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_minting_authority_not_kernel() {
        let kernel_addr = test_kernel_address();
        let attacker_addr = test_attacker_address();
        let result = KernelState::verify_minting_authority(&attacker_addr, &kernel_addr);
        assert!(result.is_err());
        assert_eq!(
            result,
            Err("Only Treasury Kernel can mint tokens".to_string())
        );
    }

    #[test]
    fn test_compute_kernel_txid_deterministic() {
        let citizen_id = [1u8; 32];
        let epoch = 100u64;
        let amount = 1000u64;

        let txid1 = KernelState::compute_kernel_txid(&citizen_id, epoch, amount);
        let txid2 = KernelState::compute_kernel_txid(&citizen_id, epoch, amount);

        assert_eq!(txid1, txid2);
    }

    #[test]
    fn test_compute_kernel_txid_different_citizen() {
        let citizen_id1 = [1u8; 32];
        let citizen_id2 = [2u8; 32];
        let epoch = 100u64;
        let amount = 1000u64;

        let txid1 = KernelState::compute_kernel_txid(&citizen_id1, epoch, amount);
        let txid2 = KernelState::compute_kernel_txid(&citizen_id2, epoch, amount);

        assert_ne!(txid1, txid2);
    }

    #[test]
    fn test_compute_kernel_txid_different_epoch() {
        let citizen_id = [1u8; 32];
        let epoch1 = 100u64;
        let epoch2 = 101u64;
        let amount = 1000u64;

        let txid1 = KernelState::compute_kernel_txid(&citizen_id, epoch1, amount);
        let txid2 = KernelState::compute_kernel_txid(&citizen_id, epoch2, amount);

        assert_ne!(txid1, txid2);
    }

    #[test]
    fn test_compute_kernel_txid_different_amount() {
        let citizen_id = [1u8; 32];
        let epoch = 100u64;
        let amount1 = 1000u64;
        let amount2 = 2000u64;

        let txid1 = KernelState::compute_kernel_txid(&citizen_id, epoch, amount1);
        let txid2 = KernelState::compute_kernel_txid(&citizen_id, epoch, amount2);

        assert_ne!(txid1, txid2);
    }

    #[test]
    fn test_authorization_chain() {
        // Verify that no other address can mint, even if modified
        let kernel_addr = test_kernel_address();

        for i in 0..255 {
            let addr = [i as u8; 32];
            if addr == kernel_addr {
                assert!(KernelState::verify_minting_authority(&addr, &kernel_addr).is_ok());
            } else {
                assert!(KernelState::verify_minting_authority(&addr, &kernel_addr).is_err());
            }
        }
    }

    #[test]
    fn test_txid_uniqueness() {
        let mut seen_txids = std::collections::HashSet::new();

        // Generate 100 unique TxIDs and verify no collisions
        for i in 0..100 {
            let citizen_id = [(i % 256) as u8; 32];
            let epoch = i as u64;
            let amount = 1000 + i as u64;

            let txid = KernelState::compute_kernel_txid(&citizen_id, epoch, amount);

            assert!(
                seen_txids.insert(txid),
                "Collision detected for citizen_id={:?}, epoch={}, amount={}",
                citizen_id,
                epoch,
                amount
            );
        }
    }
}
