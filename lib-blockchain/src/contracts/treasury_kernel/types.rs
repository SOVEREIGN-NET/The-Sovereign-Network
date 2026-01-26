use serde::{Deserialize, Serialize};
use std::fmt;

/// Rejection reason codes for UBI claims
/// These codes are used in rejection events to document why a claim was denied
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum RejectionReason {
    /// Citizen not found in CitizenRegistry
    NotACitizen = 1,
    /// Citizen has been revoked
    AlreadyRevoked = 2,
    /// Already claimed UBI for this epoch
    AlreadyClaimedEpoch = 3,
    /// Pool is exhausted for this epoch
    PoolExhausted = 4,
    /// Citizen not yet eligible (citizenship_epoch > current_epoch)
    EligibilityNotMet = 5,
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RejectionReason::NotACitizen => write!(f, "Not a citizen"),
            RejectionReason::AlreadyRevoked => write!(f, "Citizen revoked"),
            RejectionReason::AlreadyClaimedEpoch => write!(f, "Already claimed this epoch"),
            RejectionReason::PoolExhausted => write!(f, "Pool exhausted"),
            RejectionReason::EligibilityNotMet => write!(f, "Not yet eligible"),
        }
    }
}

impl RejectionReason {
    /// Get the numeric code for this rejection reason
    pub fn code(&self) -> u8 {
        *self as u8
    }

    /// Convert a code back to RejectionReason
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(RejectionReason::NotACitizen),
            2 => Some(RejectionReason::AlreadyRevoked),
            3 => Some(RejectionReason::AlreadyClaimedEpoch),
            4 => Some(RejectionReason::PoolExhausted),
            5 => Some(RejectionReason::EligibilityNotMet),
            _ => None,
        }
    }
}

/// A UBI claim recorded by the UBI contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiClaimRecorded {
    /// Citizen ID (blake3 hash of public key)
    pub citizen_id: [u8; 32],
    /// The epoch in which the claim was recorded
    pub epoch: u64,
    /// Block height where the claim was recorded
    pub block_height: u64,
}

/// Event emitted when UBI is successfully distributed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiDistributed {
    /// Citizen ID who received UBI
    pub citizen_id: [u8; 32],
    /// Amount minted (fixed 1,000 SOV)
    pub amount: u64,
    /// Epoch in which distribution occurred
    pub epoch: u64,
    /// Deterministic transaction ID (for auditability)
    pub kernel_txid: [u8; 32],
}

/// Event emitted when a UBI claim is rejected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiClaimRejected {
    /// Citizen ID of the rejected claim
    pub citizen_id: [u8; 32],
    /// Epoch in which the claim was made
    pub epoch: u64,
    /// Numeric code for rejection reason
    pub reason_code: u8,
    /// Block height when rejection was recorded
    pub timestamp: u64,
}

/// Summary event emitted after all claims for an epoch are processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UbiPoolStatus {
    /// The epoch that was processed
    pub epoch: u64,
    /// Total eligible citizens in this epoch
    pub eligible_count: u64,
    /// Total amount distributed in this epoch
    pub total_distributed: u64,
    /// Remaining capacity in pool (1,000,000 - total_distributed)
    pub remaining_capacity: u64,
}

/// Statistics tracked by the Kernel for monitoring
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KernelStats {
    /// Total citizens processed (successful + rejected)
    pub total_processed: u64,
    /// Successful distributions
    pub successful_distributions: u64,
    /// Rejected claims
    pub rejected_claims: u64,
    /// Last update epoch
    pub last_update_epoch: Option<u64>,
}

impl KernelStats {
    /// Create new empty stats
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful distribution
    pub fn record_success(&mut self) {
        self.total_processed += 1;
        self.successful_distributions += 1;
    }

    /// Record a rejected claim
    pub fn record_rejection(&mut self) {
        self.total_processed += 1;
        self.rejected_claims += 1;
    }
}

/// Kernel configuration parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelConfig {
    /// Number of blocks per epoch (default: 60,480)
    pub blocks_per_epoch: u64,
    /// UBI amount per citizen per epoch (fixed: 1,000 SOV)
    pub ubi_per_citizen: u64,
    /// Hard pool cap per epoch (fixed: 1,000,000 SOV)
    pub pool_cap_per_epoch: u64,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            blocks_per_epoch: 60_480,
            ubi_per_citizen: 1_000,
            pool_cap_per_epoch: 1_000_000,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejection_reason_codes() {
        assert_eq!(RejectionReason::NotACitizen.code(), 1);
        assert_eq!(RejectionReason::AlreadyRevoked.code(), 2);
        assert_eq!(RejectionReason::AlreadyClaimedEpoch.code(), 3);
        assert_eq!(RejectionReason::PoolExhausted.code(), 4);
        assert_eq!(RejectionReason::EligibilityNotMet.code(), 5);
    }

    #[test]
    fn test_rejection_reason_from_code() {
        assert_eq!(RejectionReason::from_code(1), Some(RejectionReason::NotACitizen));
        assert_eq!(RejectionReason::from_code(2), Some(RejectionReason::AlreadyRevoked));
        assert_eq!(RejectionReason::from_code(3), Some(RejectionReason::AlreadyClaimedEpoch));
        assert_eq!(RejectionReason::from_code(4), Some(RejectionReason::PoolExhausted));
        assert_eq!(RejectionReason::from_code(5), Some(RejectionReason::EligibilityNotMet));
        assert_eq!(RejectionReason::from_code(99), None);
    }

    #[test]
    fn test_rejection_reason_display() {
        assert_eq!(RejectionReason::NotACitizen.to_string(), "Not a citizen");
        assert_eq!(RejectionReason::AlreadyRevoked.to_string(), "Citizen revoked");
    }

    #[test]
    fn test_kernel_stats_tracking() {
        let mut stats = KernelStats::new();
        assert_eq!(stats.total_processed, 0);
        assert_eq!(stats.successful_distributions, 0);
        assert_eq!(stats.rejected_claims, 0);

        stats.record_success();
        assert_eq!(stats.total_processed, 1);
        assert_eq!(stats.successful_distributions, 1);

        stats.record_rejection();
        assert_eq!(stats.total_processed, 2);
        assert_eq!(stats.rejected_claims, 1);
    }

    #[test]
    fn test_kernel_config_defaults() {
        let config = KernelConfig::default();
        assert_eq!(config.blocks_per_epoch, 60_480);
        assert_eq!(config.ubi_per_citizen, 1_000);
        assert_eq!(config.pool_cap_per_epoch, 1_000_000);
    }
}
