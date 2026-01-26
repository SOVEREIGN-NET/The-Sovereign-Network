//! Minting Authority - Kernel-only token minting
//!
//! This module implements the authority enforcement for UBI minting.
//! Only the Treasury Kernel can mint tokens for UBI distribution.
//!
//! # Integration Points (Phase 5)
//!
//! The mint_ubi() method will be integrated with ContractExecutor in Phase 5:
//! 1. ContractExecutor.get_or_load_zhtp() - Load SOV token contract
//! 2. token.mint_kernel_only(kernel_addr, citizen, 1000) - Kernel-authorized minting
//! 3. Kernel tracks minting in state for deduplication and pool management

use crate::contracts::treasury_kernel::TreasuryKernel;

impl TreasuryKernel {
    /// Compute a deterministic transaction ID for a kernel mint operation
    ///
    /// The transaction ID is derived from:
    /// - Kernel identifier
    /// - Citizen ID
    /// - Epoch
    /// - Amount
    ///
    /// This allows auditing to trace back which kernel operation created a mint.
    /// Different citizens, epochs, or amounts produce different transaction IDs.
    pub fn compute_kernel_txid(
        &self,
        citizen_id: &[u8; 32],
        epoch: u64,
        amount: u64,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"KERNEL_TX");
        hasher.update(citizen_id);
        hasher.update(&epoch.to_be_bytes());
        hasher.update(&amount.to_be_bytes());
        hasher.update(&self.kernel_address().key_id);
        hasher.finalize().into()
    }

    /// Verify that a caller is the kernel (for external callers to check)
    ///
    /// This is used to validate that only the kernel can perform certain operations.
    pub fn verify_kernel_authority(&self, caller: &crate::integration::crypto_integration::PublicKey) -> bool {
        caller == self.kernel_address()
    }

    /// Get minting parameters for UBI
    ///
    /// Returns (per_citizen_amount, pool_cap_per_epoch)
    pub fn get_ubi_parameters(&self) -> (u64, u64) {
        let config = self.config();
        (config.ubi_per_citizen, config.pool_cap_per_epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::PublicKey;

    fn create_test_kernel() -> TreasuryKernel {
        let gov_auth = PublicKey::new(vec![1u8; 1312]);
        let kernel_addr = PublicKey::new(vec![2u8; 1312]);
        TreasuryKernel::new(gov_auth, kernel_addr, 60_480)
    }

    #[test]
    fn test_compute_kernel_txid_deterministic() {
        let kernel = create_test_kernel();
        let citizen = [1u8; 32];
        let epoch = 100;
        let amount = 1000;

        let txid1 = kernel.compute_kernel_txid(&citizen, epoch, amount);
        let txid2 = kernel.compute_kernel_txid(&citizen, epoch, amount);

        assert_eq!(txid1, txid2);
    }

    #[test]
    fn test_compute_kernel_txid_differs_by_citizen() {
        let kernel = create_test_kernel();
        let citizen1 = [1u8; 32];
        let citizen2 = [2u8; 32];

        let txid1 = kernel.compute_kernel_txid(&citizen1, 100, 1000);
        let txid2 = kernel.compute_kernel_txid(&citizen2, 100, 1000);

        assert_ne!(txid1, txid2);
    }

    #[test]
    fn test_compute_kernel_txid_differs_by_epoch() {
        let kernel = create_test_kernel();
        let citizen = [1u8; 32];

        let txid1 = kernel.compute_kernel_txid(&citizen, 100, 1000);
        let txid2 = kernel.compute_kernel_txid(&citizen, 101, 1000);

        assert_ne!(txid1, txid2);
    }

    #[test]
    fn test_compute_kernel_txid_differs_by_amount() {
        let kernel = create_test_kernel();
        let citizen = [1u8; 32];

        let txid1 = kernel.compute_kernel_txid(&citizen, 100, 1000);
        let txid2 = kernel.compute_kernel_txid(&citizen, 100, 2000);

        assert_ne!(txid1, txid2);
    }

    #[test]
    fn test_verify_kernel_authority_self() {
        let kernel = create_test_kernel();
        let kernel_addr = kernel.kernel_address().clone();

        assert!(kernel.verify_kernel_authority(&kernel_addr));
    }

    #[test]
    fn test_verify_kernel_authority_not_kernel() {
        let kernel = create_test_kernel();
        let other = PublicKey::new(vec![99u8; 1312]);

        assert!(!kernel.verify_kernel_authority(&other));
    }

    #[test]
    fn test_get_ubi_parameters() {
        let kernel = create_test_kernel();
        let (per_citizen, pool_cap) = kernel.get_ubi_parameters();

        assert_eq!(per_citizen, 1_000);
        assert_eq!(pool_cap, 1_000_000);
    }

    #[test]
    fn test_kernel_txid_formatting() {
        let kernel = create_test_kernel();
        let citizen = [42u8; 32];
        let epoch = 12345;
        let amount = 5000;

        let txid = kernel.compute_kernel_txid(&citizen, epoch, amount);

        // Verify it's a valid hash
        assert_eq!(txid.len(), 32);

        // Verify it's not all zeros
        assert!(!txid.iter().all(|&b| b == 0));
    }
}
