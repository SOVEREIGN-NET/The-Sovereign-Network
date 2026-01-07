use serde::{Deserialize, Serialize};

/// Proposal identifier (u64, not newtype)
pub type ProposalId = u64;

/// Amount in smallest units with overflow checking
///
/// Uses u64 (not u128) for alignment with token contract transfer signature:
/// `transfer(&mut self, from: &PublicKey, to: &PublicKey, amount: u64)`
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Amount(pub u64);

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

    /// Create Amount from u64, allowing zero
    ///
    /// Only use when zero is explicitly valid (e.g., initial state)
    pub fn from_u64(value: u64) -> Self {
        Amount(value)
    }

    /// Get the inner value
    pub fn get(self) -> u64 {
        self.0
    }

    /// Safe addition with overflow check
    pub fn checked_add(self, other: Amount) -> Result<Amount, Error> {
        self.0.checked_add(other.0)
            .map(Amount)
            .ok_or(Error::Overflow)
    }

    /// Safe subtraction with underflow check
    pub fn checked_sub(self, other: Amount) -> Result<Amount, Error> {
        self.0.checked_sub(other.0)
            .map(Amount)
            .ok_or(Error::Overflow)
    }

    /// Check if amount is zero
    pub fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Proposal status - two-phase approval and execution
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal has been approved by governance but not yet executed
    Approved,
    /// Proposal has been executed (disbursement occurred)
    Executed,
}

/// Approved grant - governance-binding payload
///
/// **Consensus-Critical Invariant (Payload Binding):**
/// Once approved, the recipient and amount are IMMUTABLE.
/// Execution must use only these governance-approved values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovedGrant {
    /// Unique proposal identifier
    pub proposal_id: ProposalId,

    /// Recipient key ID (fixed-width, from PublicKey.key_id)
    /// Only the key_id is stored, never the full PQC material
    pub recipient_key_id: [u8; 32],

    /// Governance-approved amount
    pub amount: Amount,

    /// Block height when approved (audit trail)
    pub approved_at: u64,

    /// Current execution status (Approved or Executed)
    pub status: ProposalStatus,
}

/// Disbursement record - immutable execution log
///
/// **Consensus-Critical Invariant (Append-Only Ledger):**
/// - Never modified or deleted
/// - Includes actual burn amount from token transfer
/// - Provides full auditability of fund movements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disbursement {
    /// Reference to the approved proposal
    pub proposal_id: ProposalId,

    /// Recipient key ID (from approved grant)
    pub recipient_key_id: [u8; 32],

    /// Amount transferred (from approved grant)
    pub amount: Amount,

    /// Block height at execution
    pub executed_at: u64,

    /// Tokens burned (from token contract's transfer return value)
    /// For deflationary tokens; 0 for fixed-supply tokens
    pub token_burned: u64,
}

/// Error types for DevGrants contract
///
/// All failures return explicit errors (no panics, no silent failures)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Caller is not the governance authority
    Unauthorized,

    /// Proposal already approved
    ProposalAlreadyApproved,

    /// Proposal not found in approved set
    ProposalNotApproved,

    /// Proposal already executed (cannot replay)
    ProposalAlreadyExecuted,

    /// Disbursement amount exceeds current balance
    InsufficientBalance,

    /// Amount is zero (not allowed)
    ZeroAmount,

    /// Arithmetic overflow/underflow
    Overflow,

    /// Recipient key_id does not match approved grant
    InvalidRecipient,

    /// Token transfer failed
    TokenTransferFailed,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unauthorized => write!(f, "Unauthorized: not governance authority"),
            Error::ProposalAlreadyApproved => write!(f, "Proposal already approved"),
            Error::ProposalNotApproved => write!(f, "Proposal not approved"),
            Error::ProposalAlreadyExecuted => write!(f, "Proposal already executed"),
            Error::InsufficientBalance => write!(f, "Insufficient balance"),
            Error::ZeroAmount => write!(f, "Amount must be greater than zero"),
            Error::Overflow => write!(f, "Arithmetic overflow/underflow"),
            Error::InvalidRecipient => write!(f, "Recipient key_id mismatch"),
            Error::TokenTransferFailed => write!(f, "Token transfer failed"),
        }
    }
}
