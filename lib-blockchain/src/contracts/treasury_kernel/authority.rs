//! Minting Authority - Kernel-only token minting
//!
//! This module implements the authority enforcement for UBI minting.
//! Only the Treasury Kernel can mint tokens for UBI distribution.

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
}
