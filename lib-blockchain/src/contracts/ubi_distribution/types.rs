use serde::{Deserialize, Serialize};
use std::fmt;

/// Month index - deterministic height-based identification
/// month_index = current_height / blocks_per_month
pub type MonthIndex = u64;

/// Epoch index - deterministic height-based identification (Issue #844 Prep Phase)
/// epoch = current_height / blocks_per_epoch (where blocks_per_epoch = 604,800 seconds / block_time)
/// For 10-second blocks: epoch = current_height / 60,480
pub type EpochIndex = u64;

/// Amount in smallest token units with overflow checking
///
/// **Invariant Encapsulation:** The inner u64 is private. Use `get()` or arithmetic
/// methods (`checked_add`, `checked_sub`) to access/modify values. This prevents
/// direct bypassing of any future invariants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(u64);

impl Amount {
    /// Create a new Amount with validation (non-zero)
    ///
    /// # Errors
    /// Returns error if value is zero
    pub fn try_new(value: u64) -> Result<Self, Error> {
        if value == 0 {
            return Err(Error::ZeroAmount);
        }
        Ok(Amount(value))
    }

    /// Create Amount from u64, allowing zero (for initial state)
    pub fn from_u64(value: u64) -> Self {
        Amount(value)
    }

    /// Get the inner value
    pub fn get(self) -> u64 {
        self.0
    }

    /// Check if amount is zero
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// Safe addition with overflow check
    pub fn checked_add(self, other: Amount) -> Result<Amount, Error> {
        self.0
            .checked_add(other.0)
            .map(Amount)
            .ok_or(Error::Overflow)
    }

    /// Safe subtraction with underflow check
    pub fn checked_sub(self, other: Amount) -> Result<Amount, Error> {
        self.0
            .checked_sub(other.0)
            .map(Amount)
            .ok_or(Error::Overflow)
    }
}

/// Error types for UBI Distribution contract
///
/// All failures return explicit errors (no panics, no silent failures)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Caller is not the governance authority
    Unauthorized,

    /// Citizen (by key_id) already registered
    AlreadyRegistered,

    /// Citizen (by key_id) not registered
    NotRegistered,

    /// Citizen already claimed UBI for this month
    AlreadyPaidThisMonth,

    /// Contract balance insufficient for payout
    InsufficientFunds,

    /// Amount is zero (not allowed)
    ZeroAmount,

    /// Arithmetic overflow/underflow
    Overflow,

    /// Token transfer failed
    TokenTransferFailed,

    /// Invalid schedule configuration (e.g., end_month < start_month)
    InvalidSchedule,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Unauthorized => write!(f, "Unauthorized: not governance authority"),
            Error::AlreadyRegistered => write!(f, "Citizen already registered"),
            Error::NotRegistered => write!(f, "Citizen not registered"),
            Error::AlreadyPaidThisMonth => write!(f, "Citizen already paid this month"),
            Error::InsufficientFunds => write!(f, "Insufficient funds for payout"),
            Error::ZeroAmount => write!(f, "Amount must be greater than zero"),
            Error::Overflow => write!(f, "Arithmetic overflow/underflow"),
            Error::TokenTransferFailed => write!(f, "Token transfer failed"),
            Error::InvalidSchedule => write!(f, "Invalid schedule configuration"),
        }
    }
}

// ============================================================================
// ISSUE #844: UBI DISTRIBUTION - EVENT SCHEMAS (PREP PHASE)
// ============================================================================
// Per ADR-0017 and the economics specification, UBI is a Treasury Kernel client.
// These event schemas enable Kernel-based distribution with full audit trail.
// All events use ABI-compatible types ([u8; 32], u64) for cross-language support.
// ============================================================================

/// Event: Citizen records intent to claim UBI
///
/// # Design
/// - Emitted when citizen requests UBI claim
/// - Does NOT mean claim is approved (Kernel validates asynchronously)
/// - Provides audit trail of all claim attempts
/// - Treasury Kernel reads these intents at epoch boundaries
///
/// # Fields
/// - `citizen_id`: [u8; 32] - verified citizen identifier
/// - `amount`: u64 - requested amount (should be 1000 in current spec, but extensible)
/// - `epoch`: u64 - which epoch this claim is for
/// - `timestamp`: u64 - block height when claimed (audit trail)
///
/// # Integration
/// Treasury Kernel polls for these events to know which citizens to process
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UbiClaimRecorded {
    /// Citizen identity (linked to CitizenRole verification)
    pub citizen_id: [u8; 32],

    /// Amount being claimed (1000 SOV in current spec)
    /// Stored as u64 (smallest token units)
    pub amount: u64,

    /// Epoch for which claim is made
    /// epoch = current_block_height / blocks_per_epoch
    pub epoch: EpochIndex,

    /// Block height when claim was recorded
    /// Used for audit trail and ordering claims
    pub timestamp: u64,
}

impl fmt::Display for UbiClaimRecorded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UbiClaimRecorded {{ citizen_id: {:?}, amount: {}, epoch: {}, timestamp: {} }}",
            &self.citizen_id[..4],
            self.amount,
            self.epoch,
            self.timestamp
        )
    }
}

/// Event: Treasury Kernel executed UBI distribution
///
/// # Design
/// - Emitted ONLY by Treasury Kernel when minting succeeds
/// - Proves that citizen's claim was validated and processed
/// - Post-validation amount (may differ from claim if validation changed it)
/// - Kernel transaction ID enables tracing execution
///
/// # Fields
/// - `citizen_id`: [u8; 32] - who received payment
/// - `amount`: u64 - actual amount paid (post-validation, should be 1000)
/// - `epoch`: u64 - which epoch was processed
/// - `kernel_txid`: [u8; 32] - Kernel transaction ID (audit trail)
///
/// # Invariants (enforced by Kernel)
/// - citizen_id is a registered Citizen (role verified)
/// - citizen is not revoked (revoked == false)
/// - citizen did not claim in this epoch (dedup check)
/// - total_distributed for epoch < 1,000,000 SOV (pool cap)
/// - amount == 1000 (payout amount, hardcoded in Kernel)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UbiDistributed {
    /// Citizen who received payment
    pub citizen_id: [u8; 32],

    /// Amount actually paid
    /// Should equal 1000 SOV in current spec
    pub amount: u64,

    /// Epoch for which distribution was made
    pub epoch: EpochIndex,

    /// Kernel transaction ID (uniquely identifies this mint)
    /// Format: blake3(kernel_state || citizen_id || epoch || amount)
    /// Allows external verification of execution
    pub kernel_txid: [u8; 32],
}

impl fmt::Display for UbiDistributed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UbiDistributed {{ citizen_id: {:?}, amount: {}, epoch: {}, txid: {:?} }}",
            &self.citizen_id[..4],
            self.amount,
            self.epoch,
            &self.kernel_txid[..4]
        )
    }
}

/// Event: UBI pool status at epoch boundary
///
/// # Design
/// - Emitted at end of each epoch by Treasury Kernel
/// - Provides rollup of distribution results
/// - Enables governance monitoring and auditing
/// - Deterministic from all UbiDistributed events in epoch
///
/// # Fields
/// - `epoch`: u64 - which epoch this status is for
/// - `citizens_eligible`: u64 - how many citizens were eligible to claim
/// - `total_distributed`: u64 - total amount actually distributed
/// - `remaining_capacity`: u64 - unused portion of 1M SOV pool
///
/// # Calculation
/// - remaining_capacity = 1,000,000 - total_distributed
/// - If remaining_capacity == 0: pool was fully utilized
/// - If remaining_capacity > 0: pool had unclaimed capacity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UbiPoolStatus {
    /// Epoch for which this status applies
    pub epoch: EpochIndex,

    /// Number of citizens that were eligible in this epoch
    /// (registered, not revoked, citizenship_epoch <= current_epoch)
    pub citizens_eligible: u64,

    /// Total amount distributed in this epoch
    /// Sum of all UbiDistributed.amount for this epoch
    pub total_distributed: u64,

    /// Remaining pool capacity (1,000,000 - total_distributed)
    /// If 0: pool exhausted
    /// If > 0: unclaimed capacity (citizens didn't claim or cap was hit)
    pub remaining_capacity: u64,
}

impl UbiPoolStatus {
    /// Total pool capacity for a single epoch (in smallest token units).
    pub const TOTAL_POOL_CAPACITY: u64 = 1_000_000;

    /// Construct a new `UbiPoolStatus`, computing `remaining_capacity` from `total_distributed`.
    ///
    /// # Invariant
    /// Ensures `remaining_capacity = TOTAL_POOL_CAPACITY - total_distributed`,
    /// using saturating subtraction to avoid underflow if `total_distributed`
    /// exceeds the configured pool capacity.
    pub fn new(epoch: EpochIndex, citizens_eligible: u64, total_distributed: u64) -> Self {
        let remaining_capacity =
            Self::TOTAL_POOL_CAPACITY.saturating_sub(total_distributed);

        UbiPoolStatus {
            epoch,
            citizens_eligible,
            total_distributed,
            remaining_capacity,
        }
    }

    /// Validate that this instance satisfies the documented invariant.
    ///
    /// Returns `true` if `remaining_capacity` matches
    /// `TOTAL_POOL_CAPACITY - total_distributed` (with saturating semantics),
    /// otherwise `false`.
    pub fn is_valid(&self) -> bool {
        let expected =
            Self::TOTAL_POOL_CAPACITY.saturating_sub(self.total_distributed);
        self.remaining_capacity == expected
    }

    /// Verify the pool status invariant is maintained
    ///
    /// # Returns
    /// true if: remaining_capacity + total_distributed == 1_000_000
    /// false if invariant is violated (indicates corrupted state)
    pub fn invariant_holds(&self) -> bool {
        self.remaining_capacity
            .checked_add(self.total_distributed)
            .map(|sum| sum == Self::TOTAL_POOL_CAPACITY)
            .unwrap_or(false) // Overflow indicates corruption
    }
}

impl fmt::Display for UbiPoolStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UbiPoolStatus {{ epoch: {}, eligible: {}, distributed: {}, remaining: {} }}",
            self.epoch, self.citizens_eligible, self.total_distributed, self.remaining_capacity
        )
    }
}

/// Event: UBI claim was rejected (silent failure)
///
/// # Design
/// - Emitted by Kernel when claim validation FAILS
/// - Reason is encoded but not exposed to caller (privacy)
/// - Citizen sees "no payment this epoch" with no error details
/// - Governance can query reason for auditing
///
/// # Fields
/// - `citizen_id`: [u8; 32] - who tried to claim
/// - `epoch`: u64 - which epoch they tried to claim
/// - `reason_code`: u8 - why it was rejected (see enum below)
/// - `timestamp`: u64 - when rejection was recorded
///
/// # Reason Codes
/// - 1 = NotACitizen (citizen_id not in CitizenRegistry)
/// - 2 = AlreadyRevoked (citizen.revoked == true)
/// - 3 = AlreadyClaimedEpoch (already_claimed[citizen][epoch] == true)
/// - 4 = PoolExhausted (total_distributed >= 1,000,000)
/// - 5 = EligibilityNotMet (citizenship_epoch > current_epoch)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UbiClaimRejected {
    /// Citizen who attempted the claim
    pub citizen_id: [u8; 32],

    /// Epoch for which claim was attempted
    pub epoch: EpochIndex,

    /// Why claim was rejected (1-5 per spec above)
    /// Not exposed to citizen (privacy via silent failure)
    pub reason_code: u8,

    /// Block height when rejection was recorded
    pub timestamp: u64,
}

impl fmt::Display for UbiClaimRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason_name = match self.reason_code {
            1 => "NotACitizen",
            2 => "AlreadyRevoked",
            3 => "AlreadyClaimedEpoch",
            4 => "PoolExhausted",
            5 => "EligibilityNotMet",
            _ => "Unknown",
        };
        write!(
            f,
            "UbiClaimRejected {{ citizen_id: {:?}, epoch: {}, reason: {}, timestamp: {} }}",
            &self.citizen_id[..4],
            self.epoch,
            reason_name,
            self.timestamp
        )
    }
}

#[cfg(test)]
mod event_tests {
    use super::*;

    #[test]
    fn test_ubi_claim_recorded_creation() {
        let claim = UbiClaimRecorded {
            citizen_id: [1u8; 32],
            amount: 1000,
            epoch: 5,
            timestamp: 123456,
        };

        assert_eq!(claim.citizen_id, [1u8; 32]);
        assert_eq!(claim.amount, 1000);
        assert_eq!(claim.epoch, 5);
        assert_eq!(claim.timestamp, 123456);
    }

    #[test]
    fn test_ubi_distributed_creation() {
        let txid = [2u8; 32];
        let dist = UbiDistributed {
            citizen_id: [1u8; 32],
            amount: 1000,
            epoch: 5,
            kernel_txid: txid,
        };

        assert_eq!(dist.citizen_id, [1u8; 32]);
        assert_eq!(dist.amount, 1000);
        assert_eq!(dist.epoch, 5);
        assert_eq!(dist.kernel_txid, txid);
    }

    #[test]
    fn test_ubi_pool_status_constructor() {
        // Test: Pool partially used - constructor calculates remaining_capacity automatically
        let status = UbiPoolStatus::new(5, 950, 950_000);

        assert_eq!(status.epoch, 5);
        assert_eq!(status.citizens_eligible, 950);
        assert_eq!(status.total_distributed, 950_000);
        assert_eq!(status.remaining_capacity, 50_000);
        assert!(status.invariant_holds());
    }

    #[test]
    fn test_ubi_pool_status_full_pool() {
        // Test: Pool fully utilized
        let status = UbiPoolStatus::new(1, 1000, 1_000_000);

        assert_eq!(status.total_distributed, 1_000_000);
        assert_eq!(status.remaining_capacity, 0);
        assert!(status.invariant_holds());
    }

    #[test]
    fn test_ubi_pool_status_empty_pool() {
        // Test: Nothing distributed yet
        let status = UbiPoolStatus::new(1, 1000, 0);

        assert_eq!(status.total_distributed, 0);
        assert_eq!(status.remaining_capacity, 1_000_000);
        assert!(status.invariant_holds());
    }

    #[test]
    fn test_ubi_pool_status_invariant_verification() {
        // Invariant: remaining_capacity + total_distributed == 1_000_000
        for total_distributed in [0, 500_000, 999_999, 1_000_000] {
            let status = UbiPoolStatus::new(1, 100, total_distributed);
            assert!(status.invariant_holds(),
                "invariant should hold for total_distributed={}", total_distributed);
            assert_eq!(
                status.remaining_capacity + status.total_distributed,
                1_000_000,
                "invariant equation failed for total_distributed={}", total_distributed
            );
        }
    }

    #[test]
    fn test_ubi_pool_status_direct_construction_still_works() {
        // Old-style direct construction still works (for deserialization, etc.)
        let status = UbiPoolStatus {
            epoch: 5,
            citizens_eligible: 950,
            total_distributed: 950_000,
            remaining_capacity: 50_000,
        };

        assert_eq!(status.epoch, 5);
        assert_eq!(status.citizens_eligible, 950);
        assert_eq!(status.total_distributed, 950_000);
        assert_eq!(status.remaining_capacity, 50_000);
        assert!(status.invariant_holds());
    }

    #[test]
    fn test_ubi_pool_status_constructor_saturating_overflow() {
        // Constructor uses saturating_sub to prevent panics in consensus code
        // If total_distributed > pool cap, remaining_capacity saturates to 0
        let status = UbiPoolStatus::new(1, 1000, 1_000_001);
        assert_eq!(status.total_distributed, 1_000_001);
        assert_eq!(status.remaining_capacity, 0);  // Saturated, not negative

        // Verify invariant still holds even with overflow
        assert!(!status.invariant_holds());  // Invariant detects the overflow
    }

    #[test]
    fn test_ubi_claim_rejected_creation() {
        let rejected = UbiClaimRejected {
            citizen_id: [1u8; 32],
            epoch: 5,
            reason_code: 2, // AlreadyRevoked
            timestamp: 123456,
        };

        assert_eq!(rejected.citizen_id, [1u8; 32]);
        assert_eq!(rejected.epoch, 5);
        assert_eq!(rejected.reason_code, 2);
        assert_eq!(rejected.timestamp, 123456);
    }

    #[test]
    fn test_event_serialization() {
        let claim = UbiClaimRecorded {
            citizen_id: [1u8; 32],
            amount: 1000,
            epoch: 5,
            timestamp: 123456,
        };

        // Should be serializable (for storage and transmission)
        let json = serde_json::to_string(&claim).expect("should serialize");
        let deserialized: UbiClaimRecorded = serde_json::from_str(&json).expect("should deserialize");

        assert_eq!(claim, deserialized);
    }

    #[test]
    fn test_pool_capacity_calculations() {
        // Test various pool utilization scenarios
        let scenarios = vec![
            (0, "empty pool"),
            (250_000, "25% utilized"),
            (500_000, "50% utilized"),
            (750_000, "75% utilized"),
            (1_000_000, "fully utilized"),
        ];

        for (total_distributed, desc) in scenarios {
            let status = UbiPoolStatus::new(1, 1000, total_distributed);

            // Verify invariant holds
            assert!(status.invariant_holds(), "invariant failed for {}", desc);

            // Verify calculation
            assert_eq!(
                status.total_distributed + status.remaining_capacity,
                1_000_000,
                "calculation failed for {}", desc
            );

            // Verify individual values
            let expected_remaining = 1_000_000 - total_distributed;
            assert_eq!(status.remaining_capacity, expected_remaining,
                "remaining capacity wrong for {}", desc);
        }
    }
}
