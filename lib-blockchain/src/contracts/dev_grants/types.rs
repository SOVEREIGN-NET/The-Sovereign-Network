use serde::{Deserialize, Serialize};

/// Unique identifier for a governance proposal
/// Invariant: ProposalId must be globally unique and non-repeating
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProposalId(pub u64);

/// Amount in smallest unit (e.g., cents, satoshis)
/// Invariant: All amounts are non-negative and checked for overflow
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u128);

impl Amount {
    /// Create a new Amount, panicking if zero
    pub fn new(value: u128) -> Self {
        assert!(value > 0, "Amount must be greater than zero");
        Amount(value)
    }

    /// Create Amount from u128, allowing zero
    pub fn from_u128(value: u128) -> Self {
        Amount(value)
    }

    /// Check if amount is zero
    pub fn is_zero(&self) -> bool {
        self.0 == 0
    }

    /// Safe addition with overflow check
    pub fn checked_add(&self, other: Amount) -> Option<Amount> {
        self.0.checked_add(other.0).map(Amount)
    }

    /// Safe subtraction with underflow check
    pub fn checked_sub(&self, other: Amount) -> Option<Amount> {
        self.0.checked_sub(other.0).map(Amount)
    }
}

/// Recipient of a grant (opaque identifier)
/// Invariant: No validation of recipient format or eligibility
/// That is governance's responsibility, not this contract's
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Recipient(pub Vec<u8>);

impl Recipient {
    pub fn new(bytes: Vec<u8>) -> Self {
        Recipient(bytes)
    }
}

/// Immutable record of a governance-approved disbursement
/// Invariant A3 — Append-only ledger
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Disbursement {
    /// Reference to the governance proposal that authorized this
    /// Invariant G2 — Every disbursement must reference an approved proposal
    pub proposal_id: ProposalId,

    /// Who receives the grant
    /// Invariant S2 — Recipient is opaque; no validation here
    pub recipient: Recipient,

    /// Amount transferred
    pub amount: Amount,

    /// Block height at execution
    /// Used for audit trail only, not for logic
    pub executed_at_height: u64,

    /// Index of this disbursement in the append-only log
    pub index: u64,
}

impl Disbursement {
    pub fn new(proposal_id: ProposalId, recipient: Recipient, amount: Amount, height: u64, index: u64) -> Self {
        Disbursement {
            proposal_id,
            recipient,
            amount,
            executed_at_height: height,
            index,
        }
    }
}

/// Proposal status (governance authority owns this)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal was approved by governance
    Approved,
    /// Proposal was rejected
    Rejected,
    /// Proposal execution was already completed
    Executed,
}

/// State of a grant proposal (governance provides this)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalData {
    pub status: ProposalStatus,
    pub amount_approved: Amount,
}
