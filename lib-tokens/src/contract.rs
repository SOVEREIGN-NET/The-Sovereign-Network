//! TokenContract (spec_version = 2)
//!
//! The canonical token contract structure for Phase 2 consensus.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use lib_types::{Address, Amount, TokenId};

// =============================================================================
// CONSTANTS
// =============================================================================

/// Maximum basis points (100%)
pub const MAX_BPS: u16 = 10_000;

/// Spec version for Phase 2
pub const SPEC_VERSION: u16 = 2;

// =============================================================================
// ROLE & AUTHORITY
// =============================================================================

/// Role enumeration for authority checks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Kernel authority (system-level operations)
    Kernel,
    /// Governance authority (protocol changes)
    Governance,
    /// Treasury authority (fund management)
    Treasury,
    /// Mint authority (token minting)
    Mint,
    /// Pause authority (emergency pause)
    Pause,
}

/// Authority set: maps roles to sets of authorized addresses
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthoritySet {
    authorities: HashMap<Role, HashSet<Address>>,
}

impl AuthoritySet {
    /// Create empty authority set
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an address to a role
    pub fn add(&mut self, role: Role, address: Address) {
        self.authorities
            .entry(role)
            .or_default()
            .insert(address);
    }

    /// Remove an address from a role
    pub fn remove(&mut self, role: Role, address: &Address) {
        if let Some(set) = self.authorities.get_mut(&role) {
            set.remove(address);
        }
    }

    /// Check if an address has a role
    pub fn has_role(&self, role: Role, address: &Address) -> bool {
        self.authorities
            .get(&role)
            .map(|set| set.contains(address))
            .unwrap_or(false)
    }

    /// Get all addresses for a role
    pub fn addresses(&self, role: Role) -> impl Iterator<Item = &Address> {
        self.authorities
            .get(&role)
            .map(|set| set.iter())
            .into_iter()
            .flatten()
    }
}

// =============================================================================
// SUPPLY POLICY
// =============================================================================

/// Supply policy determines minting behavior
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupplyPolicy {
    /// Fixed cap: no minting after creation
    FixedCap { max: Amount },
    /// Capped mint: minting allowed up to max by authority
    CappedMint { max: Amount, authority: Role },
    /// Uncapped mint: unlimited minting by authority
    UncappedMint { authority: Role },
}

impl SupplyPolicy {
    /// Get max supply if applicable
    pub fn max_supply(&self) -> Option<Amount> {
        match self {
            SupplyPolicy::FixedCap { max } => Some(*max),
            SupplyPolicy::CappedMint { max, .. } => Some(*max),
            SupplyPolicy::UncappedMint { .. } => None,
        }
    }

    /// Get mint authority if applicable
    pub fn mint_authority(&self) -> Option<Role> {
        match self {
            SupplyPolicy::FixedCap { .. } => None,
            SupplyPolicy::CappedMint { authority, .. } => Some(*authority),
            SupplyPolicy::UncappedMint { authority } => Some(*authority),
        }
    }

    /// Check if minting is allowed
    pub fn can_mint(&self) -> bool {
        !matches!(self, SupplyPolicy::FixedCap { .. })
    }
}

// =============================================================================
// TRANSFER POLICY
// =============================================================================

/// Transfer policy determines transfer restrictions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferPolicy {
    /// Transfers are freely allowed
    Free,
    /// Transfers only allowed between allowlisted addresses
    AllowlistOnly { allowlist: HashSet<Address> },
    /// Transfers are completely disabled
    NonTransferable,
}

impl TransferPolicy {
    /// Check if a transfer is allowed by policy
    pub fn allows_transfer(&self, from: &Address, to: &Address) -> bool {
        match self {
            TransferPolicy::Free => true,
            TransferPolicy::AllowlistOnly { allowlist } => {
                allowlist.contains(from) && allowlist.contains(to)
            }
            TransferPolicy::NonTransferable => false,
        }
    }
}

impl Default for TransferPolicy {
    fn default() -> Self {
        TransferPolicy::Free
    }
}

// =============================================================================
// FEE SCHEDULE
// =============================================================================

/// Fee schedule for transfers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Transfer fee in basis points (0-10000)
    pub transfer_fee_bps: u16,
    /// Burn fee in basis points (0-10000)
    pub burn_fee_bps: u16,
    /// Maximum fee amount (cap), 0 = no cap
    pub fee_cap: Amount,
    /// Minimum fee amount
    pub min_fee: Amount,
}

impl FeeSchedule {
    /// Create a fee schedule with no fees
    pub fn zero() -> Self {
        Self {
            transfer_fee_bps: 0,
            burn_fee_bps: 0,
            fee_cap: 0,
            min_fee: 0,
        }
    }

    /// Compute transfer fee for an amount
    ///
    /// Formula: clamp(amount * transfer_fee_bps / 10_000, min_fee, fee_cap)
    pub fn compute_transfer_fee(&self, amount: Amount) -> Amount {
        if self.transfer_fee_bps == 0 {
            return 0;
        }

        let raw_fee = amount
            .saturating_mul(self.transfer_fee_bps as Amount)
            / MAX_BPS as Amount;

        let clamped = raw_fee.max(self.min_fee);
        if self.fee_cap > 0 {
            clamped.min(self.fee_cap)
        } else {
            clamped
        }
    }

    /// Compute burn fee for an amount
    ///
    /// Formula: min(amount * burn_fee_bps / 10_000, fee_cap)
    pub fn compute_burn_fee(&self, amount: Amount) -> Amount {
        if self.burn_fee_bps == 0 {
            return 0;
        }

        let raw_fee = amount
            .saturating_mul(self.burn_fee_bps as Amount)
            / MAX_BPS as Amount;

        if self.fee_cap > 0 {
            raw_fee.min(self.fee_cap)
        } else {
            raw_fee
        }
    }

    /// Total deduction for a transfer (amount + fees)
    pub fn total_debit(&self, amount: Amount) -> Option<Amount> {
        let transfer_fee = self.compute_transfer_fee(amount);
        let burn_fee = self.compute_burn_fee(amount);

        amount
            .checked_add(transfer_fee)
            .and_then(|v| v.checked_add(burn_fee))
    }
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// TOKEN CONTRACT
// =============================================================================

/// TokenContract (spec_version = 2)
///
/// The canonical token contract structure for Phase 2 consensus.
/// All fields are consensus-critical.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenContract {
    // =========================================================================
    // Identity
    // =========================================================================
    /// Unique token identifier
    pub id: TokenId,
    /// Spec version - MUST be 2
    pub spec_version: u16,

    // =========================================================================
    // Metadata
    // =========================================================================
    /// Human-readable token name
    pub name: String,
    /// Token symbol (e.g., "SOV", "CBE")
    pub symbol: String,
    /// Number of decimal places (display only)
    pub decimals: u8,
    /// Hash of extended metadata (IPFS CID, etc.)
    pub metadata_hash: [u8; 32],

    // =========================================================================
    // Economic Configuration
    // =========================================================================
    /// Supply policy (controls minting)
    pub supply_policy: SupplyPolicy,
    /// Transfer policy (controls restrictions)
    pub transfer_policy: TransferPolicy,
    /// Fee schedule (transfer + burn fees)
    pub fee_schedule: FeeSchedule,

    // =========================================================================
    // Authorities
    // =========================================================================
    /// Role-based authority set
    pub authorities: AuthoritySet,
    /// Treasury address (primary recipient)
    pub treasury: Address,
    /// Fee recipient address
    pub fee_recipient: Address,

    // =========================================================================
    // Ledger State
    // =========================================================================
    /// Total supply in circulation
    pub total_supply: Amount,
    /// Total amount burned
    pub total_burned: Amount,

    // =========================================================================
    // Safety Flags
    // =========================================================================
    /// Whether transfers are paused
    pub paused: bool,
}

impl TokenContract {
    /// Create a new token contract
    pub fn new(
        id: TokenId,
        name: String,
        symbol: String,
        decimals: u8,
        supply_policy: SupplyPolicy,
        treasury: Address,
    ) -> Self {
        Self {
            id,
            spec_version: SPEC_VERSION,
            name,
            symbol,
            decimals,
            metadata_hash: [0u8; 32],
            supply_policy,
            transfer_policy: TransferPolicy::Free,
            fee_schedule: FeeSchedule::zero(),
            authorities: AuthoritySet::new(),
            treasury,
            fee_recipient: treasury,
            total_supply: 0,
            total_burned: 0,
            paused: false,
        }
    }

    /// Get the token ID as a reference
    pub fn token_id(&self) -> &TokenId {
        &self.id
    }

    /// Check if the contract is valid
    pub fn is_valid(&self) -> bool {
        // spec_version MUST be 2
        if self.spec_version != SPEC_VERSION {
            return false;
        }

        // Validate supply cap invariant
        if let Some(max) = self.supply_policy.max_supply() {
            if self.total_supply > max {
                return false;
            }
        }

        true
    }

    /// Check if an address can mint
    pub fn can_mint(&self, address: &Address) -> bool {
        if let Some(role) = self.supply_policy.mint_authority() {
            self.authorities.has_role(role, address)
        } else {
            false
        }
    }

    /// Check if an address can pause
    pub fn can_pause(&self, address: &Address) -> bool {
        self.authorities.has_role(Role::Pause, address)
    }

    /// Get remaining mintable supply (None = unlimited)
    pub fn mintable_supply(&self) -> Option<Amount> {
        self.supply_policy.max_supply().map(|max| {
            max.saturating_sub(self.total_supply)
        })
    }
}

// =============================================================================
// TRANSFER RESULT
// =============================================================================

/// Result of a successful transfer
#[derive(Debug, Clone)]
pub struct TransferResult {
    /// Amount transferred to recipient
    pub amount: Amount,
    /// Fee sent to fee_recipient
    pub transfer_fee: Amount,
    /// Amount burned
    pub burn_fee: Amount,
    /// Total debited from sender
    pub total_debit: Amount,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_schedule_zero() {
        let schedule = FeeSchedule::zero();
        assert_eq!(schedule.compute_transfer_fee(1_000_000), 0);
        assert_eq!(schedule.compute_burn_fee(1_000_000), 0);
    }

    #[test]
    fn test_fee_schedule_with_fees() {
        let schedule = FeeSchedule {
            transfer_fee_bps: 100, // 1%
            burn_fee_bps: 50,      // 0.5%
            fee_cap: 0,
            min_fee: 0,
        };

        // 1% of 10000 = 100
        assert_eq!(schedule.compute_transfer_fee(10_000), 100);
        // 0.5% of 10000 = 50
        assert_eq!(schedule.compute_burn_fee(10_000), 50);
    }

    #[test]
    fn test_fee_schedule_with_cap() {
        let schedule = FeeSchedule {
            transfer_fee_bps: 1000, // 10%
            burn_fee_bps: 0,
            fee_cap: 500,
            min_fee: 0,
        };

        // 10% of 10000 = 1000, but capped at 500
        assert_eq!(schedule.compute_transfer_fee(10_000), 500);
    }

    #[test]
    fn test_fee_schedule_with_min() {
        let schedule = FeeSchedule {
            transfer_fee_bps: 10, // 0.1%
            burn_fee_bps: 0,
            fee_cap: 0,
            min_fee: 100,
        };

        // 0.1% of 1000 = 1, but min is 100
        assert_eq!(schedule.compute_transfer_fee(1_000), 100);
    }

    #[test]
    fn test_supply_policy_fixed_cap() {
        let policy = SupplyPolicy::FixedCap { max: 1_000_000 };
        assert_eq!(policy.max_supply(), Some(1_000_000));
        assert_eq!(policy.mint_authority(), None);
        assert!(!policy.can_mint());
    }

    #[test]
    fn test_supply_policy_capped_mint() {
        let policy = SupplyPolicy::CappedMint {
            max: 1_000_000,
            authority: Role::Treasury,
        };
        assert_eq!(policy.max_supply(), Some(1_000_000));
        assert_eq!(policy.mint_authority(), Some(Role::Treasury));
        assert!(policy.can_mint());
    }

    #[test]
    fn test_supply_policy_uncapped() {
        let policy = SupplyPolicy::UncappedMint {
            authority: Role::Governance,
        };
        assert_eq!(policy.max_supply(), None);
        assert_eq!(policy.mint_authority(), Some(Role::Governance));
        assert!(policy.can_mint());
    }

    #[test]
    fn test_authority_set() {
        let mut authorities = AuthoritySet::new();
        let addr = Address::default();

        authorities.add(Role::Mint, addr);
        assert!(authorities.has_role(Role::Mint, &addr));
        assert!(!authorities.has_role(Role::Treasury, &addr));

        authorities.remove(Role::Mint, &addr);
        assert!(!authorities.has_role(Role::Mint, &addr));
    }

    #[test]
    fn test_transfer_policy() {
        let from = Address::default();
        let to = Address::new([1u8; 32]);

        assert!(TransferPolicy::Free.allows_transfer(&from, &to));
        assert!(!TransferPolicy::NonTransferable.allows_transfer(&from, &to));

        let mut allowlist = HashSet::new();
        allowlist.insert(from);
        let policy = TransferPolicy::AllowlistOnly { allowlist };
        assert!(!policy.allows_transfer(&from, &to)); // to not in list
    }

    #[test]
    fn test_token_contract_validity() {
        let contract = TokenContract::new(
            TokenId::default(),
            "Test".to_string(),
            "TST".to_string(),
            18,
            SupplyPolicy::FixedCap { max: 1_000_000 },
            Address::default(),
        );

        assert!(contract.is_valid());
        assert_eq!(contract.spec_version, SPEC_VERSION);
    }
}
