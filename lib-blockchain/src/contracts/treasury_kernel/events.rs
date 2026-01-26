//! Event Emission - UBI distribution events and pool status
//!
//! This module implements event emission for:
//! - UbiDistributed: Successful UBI distributions
//! - UbiClaimRejected: Rejected claims with reason codes
//! - UbiPoolStatus: Summary of pool usage per epoch

use crate::contracts::treasury_kernel::{TreasuryKernel, RejectionReason, UbiDistributed, UbiClaimRejected, UbiPoolStatus};
use crate::contracts::ContractStorage;

impl TreasuryKernel {
    /// Emit a successful UBI distribution event
    ///
    /// This creates an immutable audit trail of who received UBI and when.
    pub fn emit_ubi_distributed(
        &self,
        citizen_id: [u8; 32],
        amount: u64,
        epoch: u64,
        kernel_txid: [u8; 32],
        storage: &dyn ContractStorage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = UbiDistributed {
            citizen_id,
            amount,
            epoch,
            kernel_txid,
        };

        let key = format!("kernel:events:UbiDistributed:{}:{:?}", epoch, citizen_id);
        let value = bincode::serialize(&event)?;
        storage.set(key.as_bytes(), &value)?;

        Ok(())
    }

    /// Emit a UBI claim rejection event
    ///
    /// Documents why a claim was rejected for auditing purposes.
    pub fn emit_ubi_rejected(
        &self,
        citizen_id: [u8; 32],
        epoch: u64,
        reason: RejectionReason,
        block_height: u64,
        storage: &dyn ContractStorage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let event = UbiClaimRejected {
            citizen_id,
            epoch,
            reason_code: reason.code(),
            timestamp: block_height,
        };

        let key = format!(
            "kernel:events:UbiClaimRejected:{}:{}",
            epoch,
            hex::encode(citizen_id)
        );
        let value = bincode::serialize(&event)?;
        storage.set(key.as_bytes(), &value)?;

        Ok(())
    }

    /// Emit a UBI pool status summary event
    ///
    /// Emitted after all claims for an epoch are processed.
    /// Documents the state of the UBI pool for that epoch.
    pub fn emit_ubi_pool_status(
        &self,
        epoch: u64,
        eligible_count: u64,
        total_distributed: u64,
        storage: &dyn ContractStorage,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const POOL_CAP: u64 = 1_000_000;
        let remaining = POOL_CAP.saturating_sub(total_distributed);

        let event = UbiPoolStatus {
            epoch,
            eligible_count,
            total_distributed,
            remaining_capacity: remaining,
        };

        let key = format!("kernel:events:UbiPoolStatus:{}", epoch);
        let value = bincode::serialize(&event)?;
        storage.set(key.as_bytes(), &value)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::MemoryStorage;
    use crate::integration::crypto_integration::PublicKey;

    fn create_test_kernel() -> TreasuryKernel {
        let gov_auth = PublicKey::new(vec![1u8; 1312]);
        let kernel_addr = PublicKey::new(vec![2u8; 1312]);
        TreasuryKernel::new(gov_auth, kernel_addr, 60_480)
    }

    fn create_test_storage() -> MemoryStorage {
        MemoryStorage::default()
    }

    #[test]
    fn test_emit_ubi_distributed() {
        let kernel = create_test_kernel();
        let storage = create_test_storage();

        let citizen_id = [1u8; 32];
        let epoch = 100;
        let amount = 1000;
        let txid = [2u8; 32];

        let result = kernel.emit_ubi_distributed(citizen_id, amount, epoch, txid, &storage);
        assert!(result.is_ok());

        // Verify event was stored
        let key = format!("kernel:events:UbiDistributed:{}:{:?}", epoch, citizen_id);
        let stored = storage.get(key.as_bytes()).expect("get from storage");
        assert!(stored.is_some());
    }

    #[test]
    fn test_emit_ubi_rejected() {
        let kernel = create_test_kernel();
        let storage = create_test_storage();

        let citizen_id = [1u8; 32];
        let epoch = 100;
        let block_height = 6_048_000;

        let result = kernel.emit_ubi_rejected(
            citizen_id,
            epoch,
            RejectionReason::NotACitizen,
            block_height,
            &storage,
        );
        assert!(result.is_ok());

        // Verify event was stored
        let key = format!(
            "kernel:events:UbiClaimRejected:{}:{}",
            epoch,
            hex::encode(citizen_id)
        );
        let stored = storage.get(key.as_bytes()).expect("get from storage");
        assert!(stored.is_some());

        // Deserialize and verify
        let data = stored.unwrap();
        let event: UbiClaimRejected = bincode::deserialize(&data).expect("deserialize");
        assert_eq!(event.citizen_id, citizen_id);
        assert_eq!(event.reason_code, RejectionReason::NotACitizen.code());
    }

    #[test]
    fn test_emit_ubi_pool_status() {
        let kernel = create_test_kernel();
        let storage = create_test_storage();

        let epoch = 100;
        let eligible_count = 500;
        let total_distributed = 400_000;

        let result =
            kernel.emit_ubi_pool_status(epoch, eligible_count, total_distributed, &storage);
        assert!(result.is_ok());

        // Verify event was stored
        let key = format!("kernel:events:UbiPoolStatus:{}", epoch);
        let stored = storage.get(key.as_bytes()).expect("get from storage");
        assert!(stored.is_some());

        // Deserialize and verify
        let data = stored.unwrap();
        let event: UbiPoolStatus = bincode::deserialize(&data).expect("deserialize");
        assert_eq!(event.epoch, epoch);
        assert_eq!(event.eligible_count, eligible_count);
        assert_eq!(event.total_distributed, total_distributed);
        assert_eq!(event.remaining_capacity, 1_000_000 - total_distributed);
    }

    #[test]
    fn test_pool_status_remaining_capacity() {
        let kernel = create_test_kernel();
        let storage = create_test_storage();

        // Test with exhausted pool
        let epoch = 100;
        let result =
            kernel.emit_ubi_pool_status(epoch, 1000, 1_000_000, &storage);
        assert!(result.is_ok());

        let key = format!("kernel:events:UbiPoolStatus:{}", epoch);
        let data = storage.get(key.as_bytes()).unwrap().unwrap();
        let event: UbiPoolStatus = bincode::deserialize(&data).unwrap();
        assert_eq!(event.remaining_capacity, 0);
    }

    #[test]
    fn test_multiple_rejection_reasons() {
        let kernel = create_test_kernel();
        let storage = create_test_storage();

        let reasons = vec![
            RejectionReason::NotACitizen,
            RejectionReason::AlreadyRevoked,
            RejectionReason::AlreadyClaimedEpoch,
            RejectionReason::PoolExhausted,
            RejectionReason::EligibilityNotMet,
        ];

        for (i, reason) in reasons.iter().enumerate() {
            let citizen = [(i + 1) as u8; 32];
            let result = kernel.emit_ubi_rejected(citizen, 100, *reason, 6_048_000, &storage);
            assert!(result.is_ok());
        }
    }
}
