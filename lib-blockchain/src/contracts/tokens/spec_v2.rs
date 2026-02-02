//! TokenContract Formal Specification v2 (Phase-2 Consensus Lock)
//!
//! This specification defines a single extensible TokenContract that instantiates
//! SOV and CBE purely through configuration. No V2 contract, no forks, no parallel semantics.
//!
//! This module is **consensus-critical**.
//!
//! # Phase-2 Rules
//!
//! - `spec_version` MUST be 2
//! - `emission_model` MUST be `None`
//! - `transfer_policy` MUST NOT be `ComplianceGated`
//! - Transfers enforce `FeeSchedule` and `TransferPolicy`
//! - Supply invariants are enforced
//! - Genesis creates SOV and CBE via configuration only

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

// =============================================================================
// §1. Scalar Types
// =============================================================================

/// Address: 32-byte identifier
pub type Address = [u8; 32];

/// TokenId: 32-byte token identifier
pub type TokenId = [u8; 32];

/// Amount: u128 internal accounting unit
/// All arithmetic MUST be performed in Amount and MUST be checked for overflow/underflow.
pub type Amount = u128;

/// Decimals: display only; MUST NOT affect invariants
pub type Decimals = u8;

/// Basis points: u16 in range [0, 10_000]
pub type Bps = u16;

/// Block height
pub type BlockHeight = u64;

/// Lock identifier
pub type LockId = [u8; 32];

/// Maximum basis points (100%)
pub const MAX_BPS: Bps = 10_000;

// =============================================================================
// §1.2 Roles and Authority
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
    /// Auditor authority (read-only verification)
    Auditor,
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
            .or_insert_with(HashSet::new)
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
    pub fn get_addresses(&self, role: Role) -> Option<&HashSet<Address>> {
        self.authorities.get(&role)
    }

    /// Check if a role has any members
    pub fn role_is_empty(&self, role: Role) -> bool {
        self.authorities
            .get(&role)
            .map(|set| set.is_empty())
            .unwrap_or(true)
    }
}

// =============================================================================
// §2. Enumerations (Locked)
// =============================================================================

/// §2.1 Supply Policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SupplyPolicy {
    /// Fixed cap: no minting after creation
    FixedCap {
        max_supply: Amount,
    },
    /// Capped mint: minting allowed up to max_supply by mint_authority
    CappedMint {
        max_supply: Amount,
        mint_authority: Role,
    },
    /// Uncapped mint: unlimited minting by mint_authority
    UncappedMint {
        mint_authority: Role,
    },
}

impl SupplyPolicy {
    /// Get max supply if applicable
    pub fn max_supply(&self) -> Option<Amount> {
        match self {
            SupplyPolicy::FixedCap { max_supply } => Some(*max_supply),
            SupplyPolicy::CappedMint { max_supply, .. } => Some(*max_supply),
            SupplyPolicy::UncappedMint { .. } => None,
        }
    }

    /// Get mint authority if applicable
    pub fn mint_authority(&self) -> Option<Role> {
        match self {
            SupplyPolicy::FixedCap { .. } => None,
            SupplyPolicy::CappedMint { mint_authority, .. } => Some(*mint_authority),
            SupplyPolicy::UncappedMint { mint_authority } => Some(*mint_authority),
        }
    }
}

/// §2.2 Emission Model (stored but NOT executed in Phase 2)
///
/// Phase-2 rule: Only `None` is allowed. Any other value MUST cause contract creation to fail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EmissionModel {
    /// No automatic emission
    None,
    /// Kernel-metered emission (NOT supported in Phase 2)
    KernelMetered {
        rate_per_block: Amount,
        recipient: Address,
    },
    /// Epoch-based emission curve (NOT supported in Phase 2)
    EpochCurve {
        initial_rate: Amount,
        decay_factor_bps: Bps,
        epoch_blocks: BlockHeight,
    },
    /// Governance-controlled budget (NOT supported in Phase 2)
    GovernanceBudget {
        budget_authority: Role,
    },
}

impl EmissionModel {
    /// Check if this emission model is allowed in Phase 2
    pub fn is_phase2_allowed(&self) -> bool {
        matches!(self, EmissionModel::None)
    }
}

/// §2.3 Transfer Policy
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferPolicy {
    /// Transfers are freely allowed
    Free,
    /// Transfers only allowed between allowlisted addresses
    AllowlistOnly,
    /// Transfers are completely disabled
    NonTransferable,
    /// Transfers gated by external compliance contract (NOT supported in Phase 2)
    ComplianceGated {
        gate_contract: Address,
    },
}

impl TransferPolicy {
    /// Check if this transfer policy is allowed in Phase 2
    pub fn is_phase2_allowed(&self) -> bool {
        !matches!(self, TransferPolicy::ComplianceGated { .. })
    }
}

/// §2.4 Fee Schedule
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeSchedule {
    /// Transfer fee in basis points (0-10000)
    pub transfer_fee_bps: Bps,
    /// Burn fee in basis points (0-10000)
    pub burn_fee_bps: Bps,
    /// Maximum fee amount (cap)
    pub fee_cap_amount: Amount,
    /// Minimum fee amount
    pub min_fee_amount: Amount,
}

impl FeeSchedule {
    /// Create a fee schedule with no fees
    pub fn zero() -> Self {
        Self {
            transfer_fee_bps: 0,
            burn_fee_bps: 0,
            fee_cap_amount: 0,
            min_fee_amount: 0,
        }
    }

    /// Compute transfer fee for an amount
    ///
    /// Formula: clamp(amount * transfer_fee_bps / 10_000, min_fee_amount, fee_cap_amount)
    pub fn compute_transfer_fee(&self, amount: Amount) -> Amount {
        if self.transfer_fee_bps == 0 {
            return 0;
        }

        let raw_fee = amount
            .saturating_mul(self.transfer_fee_bps as Amount)
            / MAX_BPS as Amount;

        // Apply min and cap
        let clamped = raw_fee.max(self.min_fee_amount);
        if self.fee_cap_amount > 0 {
            clamped.min(self.fee_cap_amount)
        } else {
            clamped
        }
    }

    /// Compute burn fee for an amount
    ///
    /// Formula: min(amount * burn_fee_bps / 10_000, fee_cap_amount)
    pub fn compute_burn_fee(&self, amount: Amount) -> Amount {
        if self.burn_fee_bps == 0 {
            return 0;
        }

        let raw_fee = amount
            .saturating_mul(self.burn_fee_bps as Amount)
            / MAX_BPS as Amount;

        if self.fee_cap_amount > 0 {
            raw_fee.min(self.fee_cap_amount)
        } else {
            raw_fee
        }
    }
}

impl Default for FeeSchedule {
    fn default() -> Self {
        Self::zero()
    }
}

// =============================================================================
// §3.5 Locks (Vesting)
// =============================================================================

/// Vesting schedule for locked balances
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VestingSchedule {
    /// Total amount locked
    pub total_amount: Amount,
    /// Amount already released
    pub released_amount: Amount,
    /// Block height when vesting starts
    pub start_block: BlockHeight,
    /// Block height of cliff (before which nothing vests)
    pub cliff_block: BlockHeight,
    /// Block height when fully vested
    pub end_block: BlockHeight,
}

impl VestingSchedule {
    /// Create a new vesting schedule
    pub fn new(
        total_amount: Amount,
        start_block: BlockHeight,
        cliff_block: BlockHeight,
        end_block: BlockHeight,
    ) -> Result<Self, ContractError> {
        // Validation: start <= cliff <= end
        if start_block > cliff_block {
            return Err(ContractError::InvalidVestingSchedule(
                "start_block > cliff_block".to_string(),
            ));
        }
        if cliff_block > end_block {
            return Err(ContractError::InvalidVestingSchedule(
                "cliff_block > end_block".to_string(),
            ));
        }
        if total_amount == 0 {
            return Err(ContractError::InvalidVestingSchedule(
                "total_amount is zero".to_string(),
            ));
        }

        Ok(Self {
            total_amount,
            released_amount: 0,
            start_block,
            cliff_block,
            end_block,
        })
    }

    /// Calculate vested amount at a given block height
    pub fn vested_at(&self, current_block: BlockHeight) -> Amount {
        if current_block < self.cliff_block {
            return 0;
        }
        if current_block >= self.end_block {
            return self.total_amount;
        }

        // Linear vesting between cliff and end
        let vesting_duration = self.end_block - self.start_block;
        if vesting_duration == 0 {
            return self.total_amount;
        }

        let elapsed = current_block.saturating_sub(self.start_block);
        let vested = (self.total_amount as u128)
            .saturating_mul(elapsed as u128)
            / (vesting_duration as u128);

        vested as Amount
    }

    /// Calculate remaining locked amount
    pub fn remaining(&self) -> Amount {
        self.total_amount.saturating_sub(self.released_amount)
    }

    /// Check if schedule is valid
    pub fn is_valid(&self) -> bool {
        self.start_block <= self.cliff_block && self.cliff_block <= self.end_block
    }
}

// =============================================================================
// Error Types
// =============================================================================

/// Contract errors
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractError {
    /// Caller is not authorized
    Unauthorized(String),
    /// Insufficient balance
    InsufficientBalance { available: Amount, required: Amount },
    /// Insufficient unlocked balance (locked funds)
    InsufficientUnlockedBalance { available: Amount, required: Amount },
    /// Transfer amount is zero
    ZeroAmount,
    /// Contract is paused
    Paused,
    /// Transfer policy forbids this transfer
    TransferNotAllowed(String),
    /// Would exceed max supply
    ExceedsMaxSupply { current: Amount, requested: Amount, max: Amount },
    /// Invalid spec version
    InvalidSpecVersion(u16),
    /// Emission model not allowed in Phase 2
    EmissionModelNotAllowed,
    /// Transfer policy not allowed in Phase 2
    TransferPolicyNotAllowed,
    /// Invalid vesting schedule
    InvalidVestingSchedule(String),
    /// Invalid fee schedule
    InvalidFeeSchedule(String),
    /// Initial allocation exceeds max supply
    InitialAllocationExceedsMaxSupply { allocated: Amount, max: Amount },
    /// Overflow in arithmetic
    Overflow,
    /// Genesis block required
    GenesisRequired,
    /// Lock not found
    LockNotFound(LockId),
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            ContractError::InsufficientBalance { available, required } => {
                write!(f, "Insufficient balance: have {}, need {}", available, required)
            }
            ContractError::InsufficientUnlockedBalance { available, required } => {
                write!(f, "Insufficient unlocked balance: have {}, need {}", available, required)
            }
            ContractError::ZeroAmount => write!(f, "Amount must be greater than zero"),
            ContractError::Paused => write!(f, "Contract is paused"),
            ContractError::TransferNotAllowed(msg) => write!(f, "Transfer not allowed: {}", msg),
            ContractError::ExceedsMaxSupply { current, requested, max } => {
                write!(f, "Exceeds max supply: {} + {} > {}", current, requested, max)
            }
            ContractError::InvalidSpecVersion(v) => write!(f, "Invalid spec version: {}", v),
            ContractError::EmissionModelNotAllowed => {
                write!(f, "Emission model not allowed in Phase 2")
            }
            ContractError::TransferPolicyNotAllowed => {
                write!(f, "Transfer policy not allowed in Phase 2")
            }
            ContractError::InvalidVestingSchedule(msg) => {
                write!(f, "Invalid vesting schedule: {}", msg)
            }
            ContractError::InvalidFeeSchedule(msg) => {
                write!(f, "Invalid fee schedule: {}", msg)
            }
            ContractError::InitialAllocationExceedsMaxSupply { allocated, max } => {
                write!(f, "Initial allocation {} exceeds max supply {}", allocated, max)
            }
            ContractError::Overflow => write!(f, "Arithmetic overflow"),
            ContractError::GenesisRequired => write!(f, "Operation only allowed at genesis"),
            ContractError::LockNotFound(id) => write!(f, "Lock not found: {:?}", id),
        }
    }
}

impl std::error::Error for ContractError {}

/// Result type for contract operations
pub type ContractResult<T> = Result<T, ContractError>;

// =============================================================================
// §3. Contract State (Authoritative)
// =============================================================================

/// §3.1 Immutable Metadata (set at creation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadata {
    /// Human-readable token name
    pub name: String,
    /// Token symbol (e.g., "SOV", "CBE")
    pub symbol: String,
    /// Number of decimal places (display only)
    pub decimals: Decimals,
    /// Spec version (MUST be 2 for Phase 2)
    pub spec_version: u16,
    /// Hash of human-readable constitution/metadata
    pub metadata_hash: [u8; 32],
}

/// §3.2 Economic Configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicConfig {
    /// Supply policy
    pub supply_policy: SupplyPolicy,
    /// Emission model (MUST be None in Phase 2)
    pub emission_model: EmissionModel,
    /// Fee schedule for transfers
    pub fee_schedule: FeeSchedule,
    /// Transfer policy
    pub transfer_policy: TransferPolicy,
    /// Legacy compatibility flag (ignored if spec_version >= 2)
    pub kernel_only_mode: bool,
}

/// Main TokenContract structure (Phase 2 spec-compliant)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenContractV2 {
    // =========================================================================
    // Token Identity
    // =========================================================================
    /// Unique token identifier
    pub token_id: TokenId,

    // =========================================================================
    // §3.1 Immutable Metadata
    // =========================================================================
    pub metadata: TokenMetadata,

    // =========================================================================
    // §3.2 Economic Configuration
    // =========================================================================
    pub economic_config: EconomicConfig,

    // =========================================================================
    // §3.3 Authorities
    // =========================================================================
    pub authorities: AuthoritySet,
    /// Treasury address for fee collection
    pub treasury_address: Address,
    /// Fee recipient (defaults to treasury_address)
    pub fee_recipient: Address,
    /// Role that can pause the contract
    pub pause_authority: Role,

    // =========================================================================
    // §3.4 Ledger
    // =========================================================================
    pub balances: HashMap<Address, Amount>,
    pub total_supply: Amount,
    pub total_burned: Amount,
    /// Track total minted for invariant checking
    pub total_minted: Amount,

    // =========================================================================
    // §3.5 Locks
    // =========================================================================
    pub locked_balances: HashMap<(Address, LockId), VestingSchedule>,
    pub total_locked: HashMap<Address, Amount>,

    // =========================================================================
    // §3.6 Safety Flags
    // =========================================================================
    pub paused: bool,

    // =========================================================================
    // Creation info
    // =========================================================================
    /// Block height at creation
    pub created_at_block: BlockHeight,
}

// =============================================================================
// §4. Creation Semantics
// =============================================================================

/// Parameters for creating a new TokenContractV2
#[derive(Debug, Clone)]
pub struct TokenCreationParams {
    pub token_id: TokenId,
    pub name: String,
    pub symbol: String,
    pub decimals: Decimals,
    pub metadata_hash: [u8; 32],
    pub supply_policy: SupplyPolicy,
    pub emission_model: EmissionModel,
    pub fee_schedule: FeeSchedule,
    pub transfer_policy: TransferPolicy,
    pub authorities: AuthoritySet,
    pub treasury_address: Address,
    pub fee_recipient: Option<Address>,
    pub pause_authority: Role,
    pub initial_allocations: Vec<(Address, Amount, Option<VestingSchedule>)>,
}

impl TokenContractV2 {
    /// Phase 2 spec version
    pub const SPEC_VERSION: u16 = 2;

    /// §4.1 Constructor
    pub fn new_custom(
        params: TokenCreationParams,
        current_block: BlockHeight,
    ) -> ContractResult<Self> {
        // §4.2 Validation rules

        // Creation MUST FAIL if spec_version != 2
        // (We always create with version 2)

        // Creation MUST FAIL if emission_model != None
        if !params.emission_model.is_phase2_allowed() {
            return Err(ContractError::EmissionModelNotAllowed);
        }

        // Creation MUST FAIL if transfer_policy == ComplianceGated
        if !params.transfer_policy.is_phase2_allowed() {
            return Err(ContractError::TransferPolicyNotAllowed);
        }

        // Calculate total initial allocation
        let mut total_allocation: Amount = 0;
        for (_, amount, _) in &params.initial_allocations {
            // Any allocation amount is zero -> FAIL
            if *amount == 0 {
                return Err(ContractError::ZeroAmount);
            }
            total_allocation = total_allocation
                .checked_add(*amount)
                .ok_or(ContractError::Overflow)?;
        }

        // FixedCap.max_supply < sum(initial_allocations) -> FAIL
        if let Some(max_supply) = params.supply_policy.max_supply() {
            if total_allocation > max_supply {
                return Err(ContractError::InitialAllocationExceedsMaxSupply {
                    allocated: total_allocation,
                    max: max_supply,
                });
            }
        }

        // Validate vesting schedules
        for (_, _, schedule) in &params.initial_allocations {
            if let Some(s) = schedule {
                if !s.is_valid() {
                    return Err(ContractError::InvalidVestingSchedule(
                        "Invalid vesting schedule in initial allocation".to_string(),
                    ));
                }
            }
        }

        // Create the contract
        let fee_recipient = params.fee_recipient.unwrap_or(params.treasury_address);

        let mut contract = Self {
            token_id: params.token_id,
            metadata: TokenMetadata {
                name: params.name,
                symbol: params.symbol,
                decimals: params.decimals,
                spec_version: Self::SPEC_VERSION,
                metadata_hash: params.metadata_hash,
            },
            economic_config: EconomicConfig {
                supply_policy: params.supply_policy,
                emission_model: params.emission_model,
                fee_schedule: params.fee_schedule,
                transfer_policy: params.transfer_policy,
                kernel_only_mode: false,
            },
            authorities: params.authorities,
            treasury_address: params.treasury_address,
            fee_recipient,
            pause_authority: params.pause_authority,
            balances: HashMap::new(),
            total_supply: 0,
            total_burned: 0,
            total_minted: 0,
            locked_balances: HashMap::new(),
            total_locked: HashMap::new(),
            paused: false,
            created_at_block: current_block,
        };

        // Apply initial allocations
        for (address, amount, schedule) in params.initial_allocations {
            // Add to balance
            *contract.balances.entry(address).or_insert(0) += amount;
            contract.total_supply += amount;
            contract.total_minted += amount;

            // Apply vesting if specified
            if let Some(mut vesting) = schedule {
                let lock_id = generate_lock_id(&address, current_block);
                vesting.total_amount = amount;
                contract.locked_balances.insert((address, lock_id), vesting);
                *contract.total_locked.entry(address).or_insert(0) += amount;
            }
        }

        Ok(contract)
    }

    /// §4.3 Genesis rule - convenience method for genesis block creation
    pub fn new_at_genesis(
        params: TokenCreationParams,
    ) -> ContractResult<Self> {
        Self::new_custom(params, 0)
    }

    // =========================================================================
    // Query Methods
    // =========================================================================

    /// Get balance of an address
    pub fn balance_of(&self, address: &Address) -> Amount {
        self.balances.get(address).copied().unwrap_or(0)
    }

    /// Get available (unlocked) balance
    pub fn available_balance(&self, address: &Address) -> Amount {
        let total = self.balance_of(address);
        let locked = self.total_locked.get(address).copied().unwrap_or(0);
        total.saturating_sub(locked)
    }

    /// Get total locked balance for an address
    pub fn locked_balance(&self, address: &Address) -> Amount {
        self.total_locked.get(address).copied().unwrap_or(0)
    }

    // =========================================================================
    // §5. Transfer Semantics
    // =========================================================================

    /// Transfer tokens between addresses
    ///
    /// §5.1 Preconditions:
    /// - paused == false
    /// - transfer_policy == Free (NonTransferable/AllowlistOnly revert)
    /// - amount > 0
    /// - available_balance(from) >= amount + fees
    pub fn transfer(
        &mut self,
        caller: &Address,
        from: &Address,
        to: &Address,
        amount: Amount,
    ) -> ContractResult<TransferResult> {
        // Check paused
        if self.paused {
            return Err(ContractError::Paused);
        }

        // Check transfer policy
        match &self.economic_config.transfer_policy {
            TransferPolicy::Free => {}
            TransferPolicy::NonTransferable => {
                return Err(ContractError::TransferNotAllowed(
                    "Token is non-transferable".to_string(),
                ));
            }
            TransferPolicy::AllowlistOnly => {
                return Err(ContractError::TransferNotAllowed(
                    "AllowlistOnly not supported in Phase 2".to_string(),
                ));
            }
            TransferPolicy::ComplianceGated { .. } => {
                return Err(ContractError::TransferNotAllowed(
                    "ComplianceGated not supported in Phase 2".to_string(),
                ));
            }
        }

        // Check amount > 0
        if amount == 0 {
            return Err(ContractError::ZeroAmount);
        }

        // §5.2 Fee computation
        let transfer_fee = self.economic_config.fee_schedule.compute_transfer_fee(amount);
        let burn_fee = self.economic_config.fee_schedule.compute_burn_fee(amount);

        // §5.3 State transitions
        let sender_debit = amount
            .checked_add(transfer_fee)
            .and_then(|v| v.checked_add(burn_fee))
            .ok_or(ContractError::Overflow)?;

        // Check sufficient unlocked balance
        let available = self.available_balance(from);
        if available < sender_debit {
            return Err(ContractError::InsufficientUnlockedBalance {
                available,
                required: sender_debit,
            });
        }

        // Apply atomically
        // balances[from] -= sender_debit
        let from_balance = self.balances.entry(*from).or_insert(0);
        *from_balance = from_balance.checked_sub(sender_debit)
            .ok_or(ContractError::InsufficientBalance {
                available: *from_balance,
                required: sender_debit,
            })?;

        // balances[to] += amount
        *self.balances.entry(*to).or_insert(0) += amount;

        // balances[fee_recipient] += transfer_fee
        if transfer_fee > 0 {
            *self.balances.entry(self.fee_recipient).or_insert(0) += transfer_fee;
        }

        // total_supply -= burn_fee
        // total_burned += burn_fee
        if burn_fee > 0 {
            self.total_supply = self.total_supply.saturating_sub(burn_fee);
            self.total_burned += burn_fee;
        }

        // §5.4 Conservation invariant: sender_debit == amount + transfer_fee + burn_fee
        debug_assert_eq!(sender_debit, amount + transfer_fee + burn_fee);

        Ok(TransferResult {
            amount,
            transfer_fee,
            burn_fee,
            total_debit: sender_debit,
        })
    }

    // =========================================================================
    // §6. Mint Semantics
    // =========================================================================

    /// Mint new tokens
    ///
    /// §6.1 Preconditions:
    /// - Caller ∈ authorities[supply_policy.mint_authority]
    /// - amount > 0
    /// - If capped: total_supply + amount <= max_supply
    pub fn mint(
        &mut self,
        caller: &Address,
        to: &Address,
        amount: Amount,
    ) -> ContractResult<()> {
        // Check paused
        if self.paused {
            return Err(ContractError::Paused);
        }

        // Check amount > 0
        if amount == 0 {
            return Err(ContractError::ZeroAmount);
        }

        // Check mint authority
        let mint_authority = self.economic_config.supply_policy.mint_authority()
            .ok_or_else(|| ContractError::Unauthorized(
                "FixedCap tokens cannot be minted".to_string()
            ))?;

        if !self.authorities.has_role(mint_authority, caller) {
            return Err(ContractError::Unauthorized(format!(
                "Caller not in {:?} role",
                mint_authority
            )));
        }

        // Check supply cap
        if let Some(max_supply) = self.economic_config.supply_policy.max_supply() {
            let new_supply = self.total_supply.checked_add(amount)
                .ok_or(ContractError::Overflow)?;
            if new_supply > max_supply {
                return Err(ContractError::ExceedsMaxSupply {
                    current: self.total_supply,
                    requested: amount,
                    max: max_supply,
                });
            }
        }

        // §6.2 State transitions
        *self.balances.entry(*to).or_insert(0) += amount;
        self.total_supply += amount;
        self.total_minted += amount;

        Ok(())
    }

    // =========================================================================
    // §7. Burn Semantics
    // =========================================================================

    /// Burn tokens
    ///
    /// §7.1 Preconditions:
    /// - Caller == from OR caller ∈ authorities[Kernel]
    /// - balances[from] - total_locked[from] >= amount
    pub fn burn(
        &mut self,
        caller: &Address,
        from: &Address,
        amount: Amount,
    ) -> ContractResult<()> {
        // Check paused
        if self.paused {
            return Err(ContractError::Paused);
        }

        // Check amount > 0
        if amount == 0 {
            return Err(ContractError::ZeroAmount);
        }

        // Check authorization: caller == from OR caller ∈ Kernel
        if caller != from && !self.authorities.has_role(Role::Kernel, caller) {
            return Err(ContractError::Unauthorized(
                "Only owner or Kernel can burn".to_string()
            ));
        }

        // Check sufficient unlocked balance
        let available = self.available_balance(from);
        if available < amount {
            return Err(ContractError::InsufficientUnlockedBalance {
                available,
                required: amount,
            });
        }

        // §7.2 State transitions
        let from_balance = self.balances.entry(*from).or_insert(0);
        *from_balance = from_balance.checked_sub(amount)
            .ok_or(ContractError::InsufficientBalance {
                available: *from_balance,
                required: amount,
            })?;

        self.total_supply = self.total_supply.saturating_sub(amount);
        self.total_burned += amount;

        Ok(())
    }

    // =========================================================================
    // §8. Pause Semantics
    // =========================================================================

    /// Pause or unpause the contract
    ///
    /// §8.1 Preconditions:
    /// - Caller ∈ authorities[pause_authority]
    ///
    /// §8.2 Effect:
    /// - If paused == true: All state-mutating functions EXCEPT pause(false) REVERT
    pub fn pause(&mut self, caller: &Address, paused: bool) -> ContractResult<()> {
        if !self.authorities.has_role(self.pause_authority, caller) {
            return Err(ContractError::Unauthorized(format!(
                "Caller not in {:?} role",
                self.pause_authority
            )));
        }

        self.paused = paused;
        Ok(())
    }

    // =========================================================================
    // Vesting/Lock Management
    // =========================================================================

    /// Claim vested tokens for an address at a given block height.
    ///
    /// This releases tokens that have vested according to the vesting schedule.
    /// The released tokens become available for transfer.
    ///
    /// # Arguments
    /// * `address` - The address to claim vested tokens for
    /// * `current_block` - The current block height for vesting calculation
    ///
    /// # Returns
    /// The amount of tokens that were released.
    pub fn claim_vested(
        &mut self,
        address: &Address,
        current_block: BlockHeight,
    ) -> ContractResult<Amount> {
        let mut total_released: Amount = 0;
        let mut locks_to_remove: Vec<LockId> = Vec::new();

        // Calculate vested amounts for all locks belonging to this address
        for (key, schedule) in self.locked_balances.iter_mut() {
            let (addr, lock_id) = key;
            // Compare byte arrays explicitly
            if addr != address {
                continue;
            }

            let vested = schedule.vested_at(current_block);
            let releasable = vested.saturating_sub(schedule.released_amount);

            if releasable > 0 {
                schedule.released_amount += releasable;
                total_released += releasable;

                // Mark fully vested locks for removal
                if schedule.released_amount >= schedule.total_amount {
                    locks_to_remove.push(*lock_id);
                }
            }
        }

        // Update total_locked for the address
        if total_released > 0 {
            if let Some(locked) = self.total_locked.get_mut(address) {
                *locked = locked.saturating_sub(total_released);
                if *locked == 0 {
                    self.total_locked.remove(address);
                }
            }
        }

        // Remove fully vested locks
        for lock_id in locks_to_remove {
            self.locked_balances.remove(&(*address, lock_id));
        }

        Ok(total_released)
    }

    /// Get all locks for an address
    pub fn get_locks(&self, address: &Address) -> Vec<(LockId, &VestingSchedule)> {
        self.locked_balances
            .iter()
            .filter(|((addr, _), _)| addr == address)
            .map(|((_, lock_id), schedule)| (*lock_id, schedule))
            .collect()
    }

    // =========================================================================
    // Authority Management
    // =========================================================================

    /// Add an address to a role.
    ///
    /// # Requirements
    /// - Caller must be in Governance role
    pub fn add_authority(
        &mut self,
        caller: &Address,
        role: Role,
        address: Address,
    ) -> ContractResult<()> {
        // Only Governance can modify authorities
        if !self.authorities.has_role(Role::Governance, caller) {
            return Err(ContractError::Unauthorized(
                "Only Governance can modify authorities".to_string()
            ));
        }

        self.authorities.add(role, address);
        Ok(())
    }

    /// Remove an address from a role.
    ///
    /// # Requirements
    /// - Caller must be in Governance role
    pub fn remove_authority(
        &mut self,
        caller: &Address,
        role: Role,
        address: &Address,
    ) -> ContractResult<()> {
        // Only Governance can modify authorities
        if !self.authorities.has_role(Role::Governance, caller) {
            return Err(ContractError::Unauthorized(
                "Only Governance can modify authorities".to_string()
            ));
        }

        self.authorities.remove(role, address);
        Ok(())
    }

    // =========================================================================
    // Configuration Updates
    // =========================================================================

    /// Update the fee recipient address.
    ///
    /// # Requirements
    /// - Caller must be in Treasury role
    pub fn update_fee_recipient(
        &mut self,
        caller: &Address,
        new_recipient: Address,
    ) -> ContractResult<()> {
        if !self.authorities.has_role(Role::Treasury, caller) {
            return Err(ContractError::Unauthorized(
                "Only Treasury can update fee recipient".to_string()
            ));
        }

        self.fee_recipient = new_recipient;
        Ok(())
    }

    /// Update the fee schedule.
    ///
    /// # Requirements
    /// - Caller must be in Governance role
    /// - Contract must not be paused
    pub fn update_fee_schedule(
        &mut self,
        caller: &Address,
        new_schedule: FeeSchedule,
    ) -> ContractResult<()> {
        if self.paused {
            return Err(ContractError::Paused);
        }

        if !self.authorities.has_role(Role::Governance, caller) {
            return Err(ContractError::Unauthorized(
                "Only Governance can update fee schedule".to_string()
            ));
        }

        // Validate fee schedule
        if new_schedule.transfer_fee_bps > MAX_BPS {
            return Err(ContractError::InvalidFeeSchedule(
                "transfer_fee_bps exceeds 100%".to_string()
            ));
        }
        if new_schedule.burn_fee_bps > MAX_BPS {
            return Err(ContractError::InvalidFeeSchedule(
                "burn_fee_bps exceeds 100%".to_string()
            ));
        }

        self.economic_config.fee_schedule = new_schedule;
        Ok(())
    }

    /// Update the transfer policy (Phase 3D).
    ///
    /// # Requirements
    /// - Caller must be in Governance role
    /// - Contract must not be paused
    /// - New policy must be Phase 2 allowed (not ComplianceGated)
    ///
    /// # Allowed policies
    /// - Free: Transfers are freely allowed
    /// - AllowlistOnly: Transfers only between allowlisted addresses
    /// - NonTransferable: Transfers are completely disabled
    ///
    /// # NOT allowed
    /// - ComplianceGated: Requires external contract execution (not consensus-safe)
    pub fn update_transfer_policy(
        &mut self,
        caller: &Address,
        new_policy: TransferPolicy,
    ) -> ContractResult<()> {
        if self.paused {
            return Err(ContractError::Paused);
        }

        if !self.authorities.has_role(Role::Governance, caller) {
            return Err(ContractError::Unauthorized(
                "Only Governance can update transfer policy".to_string()
            ));
        }

        // Validate policy is Phase 2 allowed
        if !new_policy.is_phase2_allowed() {
            return Err(ContractError::TransferPolicyNotAllowed);
        }

        self.economic_config.transfer_policy = new_policy;
        Ok(())
    }

    // =========================================================================
    // §9. Formal Invariants
    // =========================================================================

    /// Verify all formal invariants hold
    ///
    /// Returns Ok(()) if all invariants pass, or Err with description of failure.
    pub fn verify_invariants(&self) -> ContractResult<()> {
        // 1. total_supply == Σ balances[*]
        let sum_balances: Amount = self.balances.values().sum();
        if self.total_supply != sum_balances {
            return Err(ContractError::Unauthorized(format!(
                "Invariant violated: total_supply {} != sum(balances) {}",
                self.total_supply, sum_balances
            )));
        }

        // 2. total_supply + total_burned == initial_supply + minted_to_date
        // (initial_supply == total_minted at creation, subsequent mints add to total_minted)
        let lhs = self.total_supply + self.total_burned;
        let rhs = self.total_minted;
        if lhs != rhs {
            return Err(ContractError::Unauthorized(format!(
                "Invariant violated: total_supply + total_burned ({}) != total_minted ({})",
                lhs, rhs
            )));
        }

        // 3. No balance < 0 (implicit in u128)

        // 4. For all a: total_locked[a] == Σ locks[a,*].remaining
        for (address, expected_locked) in &self.total_locked {
            let mut actual_locked: Amount = 0;
            for ((addr, _), schedule) in &self.locked_balances {
                if addr == address {
                    actual_locked += schedule.remaining();
                }
            }
            if *expected_locked != actual_locked {
                return Err(ContractError::Unauthorized(format!(
                    "Invariant violated: total_locked[{:?}] {} != sum(locks) {}",
                    address, expected_locked, actual_locked
                )));
            }
        }

        // 5. Supply caps MUST NOT be exceeded
        if let Some(max_supply) = self.economic_config.supply_policy.max_supply() {
            if self.total_supply > max_supply {
                return Err(ContractError::ExceedsMaxSupply {
                    current: self.total_supply,
                    requested: 0,
                    max: max_supply,
                });
            }
        }

        Ok(())
    }
}

/// Result of a transfer operation
#[derive(Debug, Clone)]
pub struct TransferResult {
    /// Amount transferred to recipient
    pub amount: Amount,
    /// Fee sent to fee_recipient
    pub transfer_fee: Amount,
    /// Amount burned
    pub burn_fee: Amount,
    /// Total deducted from sender
    pub total_debit: Amount,
}

// =============================================================================
// §12. SOV and CBE Instantiation (Authoritative Configs)
// =============================================================================

/// Create SOV token configuration
///
/// SOV:
/// - spec_version = 2
/// - supply_policy = FixedCap { 1_000_000_000_000 * 10^decimals }
/// - emission_model = None
/// - fee_schedule = { transfer_fee_bps = 100, burn_fee_bps = 0, ... }
/// - transfer_policy = Free
/// - mint_authority = None (after genesis)
pub fn create_sov_params(
    token_id: TokenId,
    treasury_address: Address,
    initial_allocations: Vec<(Address, Amount, Option<VestingSchedule>)>,
) -> TokenCreationParams {
    const SOV_DECIMALS: Decimals = 8;
    const SOV_MAX_SUPPLY: Amount = 1_000_000_000_000 * 100_000_000; // 1T with 8 decimals

    TokenCreationParams {
        token_id,
        name: "Sovereign Token".to_string(),
        symbol: "SOV".to_string(),
        decimals: SOV_DECIMALS,
        metadata_hash: [0u8; 32], // TODO: Set actual metadata hash
        supply_policy: SupplyPolicy::FixedCap {
            max_supply: SOV_MAX_SUPPLY,
        },
        emission_model: EmissionModel::None,
        fee_schedule: FeeSchedule {
            transfer_fee_bps: 100, // 1% transfer fee
            burn_fee_bps: 0,
            fee_cap_amount: Amount::MAX,
            min_fee_amount: 0,
        },
        transfer_policy: TransferPolicy::Free,
        authorities: AuthoritySet::new(),
        treasury_address,
        fee_recipient: None,
        pause_authority: Role::Governance,
        initial_allocations,
    }
}

/// Create CBE token configuration
///
/// CBE:
/// - spec_version = 2
/// - supply_policy = CappedMint { max = 100B, mint_authority = Governance }
/// - emission_model = None (Phase-2)
/// - fee_schedule = zero fees
/// - transfer_policy = AllowlistOnly (transfers revert in Phase 2)
pub fn create_cbe_params(
    token_id: TokenId,
    treasury_address: Address,
    governance_addresses: Vec<Address>,
    initial_allocations: Vec<(Address, Amount, Option<VestingSchedule>)>,
) -> TokenCreationParams {
    const CBE_DECIMALS: Decimals = 8;
    const CBE_MAX_SUPPLY: Amount = 100_000_000_000 * 100_000_000; // 100B with 8 decimals

    let mut authorities = AuthoritySet::new();
    for addr in governance_addresses {
        authorities.add(Role::Governance, addr);
    }

    TokenCreationParams {
        token_id,
        name: "Compensation and Benefits Equity".to_string(),
        symbol: "CBE".to_string(),
        decimals: CBE_DECIMALS,
        metadata_hash: [0u8; 32],
        supply_policy: SupplyPolicy::CappedMint {
            max_supply: CBE_MAX_SUPPLY,
            mint_authority: Role::Governance,
        },
        emission_model: EmissionModel::None,
        fee_schedule: FeeSchedule::zero(),
        transfer_policy: TransferPolicy::AllowlistOnly, // Transfers revert in Phase 2
        authorities,
        treasury_address,
        fee_recipient: None,
        pause_authority: Role::Governance,
        initial_allocations,
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Generate a deterministic lock ID
fn generate_lock_id(address: &Address, block: BlockHeight) -> LockId {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    address.hash(&mut hasher);
    block.hash(&mut hasher);
    let hash = hasher.finish();

    let mut lock_id = [0u8; 32];
    lock_id[..8].copy_from_slice(&hash.to_le_bytes());
    lock_id[8..16].copy_from_slice(&block.to_le_bytes());
    lock_id
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(n: u8) -> Address {
        let mut addr = [0u8; 32];
        addr[0] = n;
        addr
    }

    fn test_token_id() -> TokenId {
        [1u8; 32]
    }

    #[test]
    fn test_create_sov_token() {
        let treasury = test_address(1);
        let user = test_address(2);

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(user, 1_000_000_000_000, None)], // 1T tokens
        );

        let token = TokenContractV2::new_at_genesis(params).unwrap();

        assert_eq!(token.metadata.symbol, "SOV");
        assert_eq!(token.metadata.spec_version, 2);
        assert_eq!(token.total_supply, 1_000_000_000_000);
        assert_eq!(token.balance_of(&user), 1_000_000_000_000);
        assert!(token.verify_invariants().is_ok());
    }

    #[test]
    fn test_create_cbe_token() {
        let treasury = test_address(1);
        let governance = test_address(2);

        let params = create_cbe_params(
            test_token_id(),
            treasury,
            vec![governance],
            vec![],
        );

        let token = TokenContractV2::new_at_genesis(params).unwrap();

        assert_eq!(token.metadata.symbol, "CBE");
        assert!(matches!(
            token.economic_config.transfer_policy,
            TransferPolicy::AllowlistOnly
        ));
        assert!(token.authorities.has_role(Role::Governance, &governance));
    }

    #[test]
    fn test_transfer_with_fee() {
        let treasury = test_address(1);
        let sender = test_address(2);
        let recipient = test_address(3);

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(sender, 10_000, None)],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Transfer 1000 tokens with 1% fee
        let result = token.transfer(&sender, &sender, &recipient, 1000).unwrap();

        assert_eq!(result.amount, 1000);
        assert_eq!(result.transfer_fee, 10); // 1% of 1000
        assert_eq!(result.burn_fee, 0);
        assert_eq!(result.total_debit, 1010);

        // Verify balances
        assert_eq!(token.balance_of(&sender), 10_000 - 1010);
        assert_eq!(token.balance_of(&recipient), 1000);
        assert_eq!(token.balance_of(&treasury), 10); // Fee goes to treasury

        assert!(token.verify_invariants().is_ok());
    }

    #[test]
    fn test_transfer_non_transferable_fails() {
        let treasury = test_address(1);
        let sender = test_address(2);
        let recipient = test_address(3);

        let mut params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(sender, 10_000, None)],
        );
        params.transfer_policy = TransferPolicy::NonTransferable;

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        let result = token.transfer(&sender, &sender, &recipient, 1000);
        assert!(matches!(result, Err(ContractError::TransferNotAllowed(_))));
    }

    #[test]
    fn test_cbe_transfer_fails_allowlist_only() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let user = test_address(3);
        let recipient = test_address(4);

        let mut params = create_cbe_params(
            test_token_id(),
            treasury,
            vec![governance],
            vec![(user, 10_000, None)],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // CBE transfer should fail due to AllowlistOnly
        let result = token.transfer(&user, &user, &recipient, 1000);
        assert!(matches!(result, Err(ContractError::TransferNotAllowed(_))));
    }

    #[test]
    fn test_mint_capped() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let recipient = test_address(3);

        let params = create_cbe_params(
            test_token_id(),
            treasury,
            vec![governance],
            vec![],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Mint should succeed when called by governance
        token.mint(&governance, &recipient, 1000).unwrap();
        assert_eq!(token.balance_of(&recipient), 1000);
        assert_eq!(token.total_supply, 1000);

        assert!(token.verify_invariants().is_ok());
    }

    #[test]
    fn test_mint_unauthorized_fails() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let attacker = test_address(3);

        let params = create_cbe_params(
            test_token_id(),
            treasury,
            vec![governance],
            vec![],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        let result = token.mint(&attacker, &attacker, 1000);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_mint_fixed_cap_fails() {
        let treasury = test_address(1);
        let user = test_address(2);

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // SOV is FixedCap, minting should fail
        let result = token.mint(&user, &user, 1000);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_burn() {
        let treasury = test_address(1);
        let user = test_address(2);

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(user, 10_000, None)],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        token.burn(&user, &user, 3000).unwrap();

        assert_eq!(token.balance_of(&user), 7000);
        assert_eq!(token.total_supply, 7000);
        assert_eq!(token.total_burned, 3000);

        assert!(token.verify_invariants().is_ok());
    }

    #[test]
    fn test_pause() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let user = test_address(3);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);

        let mut params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(user, 10_000, None)],
        );
        params.authorities = authorities;
        params.pause_authority = Role::Governance;

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Pause the contract
        token.pause(&governance, true).unwrap();
        assert!(token.paused);

        // Transfers should fail
        let result = token.transfer(&user, &user, &treasury, 1000);
        assert!(matches!(result, Err(ContractError::Paused)));

        // Unpause
        token.pause(&governance, false).unwrap();
        assert!(!token.paused);

        // Transfers should work again
        token.transfer(&user, &user, &treasury, 1000).unwrap();
    }

    #[test]
    fn test_vesting_schedule() {
        let treasury = test_address(1);
        let user = test_address(2);

        let vesting = VestingSchedule::new(
            10_000,  // total
            0,       // start
            10,      // cliff
            100,     // end
        ).unwrap();

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(user, 10_000, Some(vesting))],
        );

        let token = TokenContractV2::new_at_genesis(params).unwrap();

        // All tokens are locked
        assert_eq!(token.balance_of(&user), 10_000);
        assert_eq!(token.available_balance(&user), 0);
        assert_eq!(token.locked_balance(&user), 10_000);

        assert!(token.verify_invariants().is_ok());
    }

    #[test]
    fn test_emission_model_phase2_restriction() {
        let treasury = test_address(1);

        let mut params = create_sov_params(
            test_token_id(),
            treasury,
            vec![],
        );
        params.emission_model = EmissionModel::KernelMetered {
            rate_per_block: 100,
            recipient: treasury,
        };

        let result = TokenContractV2::new_at_genesis(params);
        assert!(matches!(result, Err(ContractError::EmissionModelNotAllowed)));
    }

    #[test]
    fn test_compliance_gated_phase2_restriction() {
        let treasury = test_address(1);

        let mut params = create_sov_params(
            test_token_id(),
            treasury,
            vec![],
        );
        params.transfer_policy = TransferPolicy::ComplianceGated {
            gate_contract: treasury,
        };

        let result = TokenContractV2::new_at_genesis(params);
        assert!(matches!(result, Err(ContractError::TransferPolicyNotAllowed)));
    }

    #[test]
    fn test_fee_schedule_computation() {
        let schedule = FeeSchedule {
            transfer_fee_bps: 100, // 1%
            burn_fee_bps: 50,      // 0.5%
            fee_cap_amount: 100,
            min_fee_amount: 5,
        };

        // Normal transfer
        assert_eq!(schedule.compute_transfer_fee(1000), 10); // 1% of 1000

        // Minimum fee applies
        assert_eq!(schedule.compute_transfer_fee(100), 5); // Would be 1, but min is 5

        // Cap applies
        assert_eq!(schedule.compute_transfer_fee(20000), 100); // Would be 200, but cap is 100

        // Burn fee
        assert_eq!(schedule.compute_burn_fee(1000), 5); // 0.5% of 1000
    }

    #[test]
    fn test_initial_allocation_exceeds_max_supply() {
        let treasury = test_address(1);
        let user = test_address(2);

        // Try to allocate more than max supply
        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities: AuthoritySet::new(),
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![(user, 2000, None)], // Exceeds max
        };

        let result = TokenContractV2::new_at_genesis(params);
        assert!(matches!(
            result,
            Err(ContractError::InitialAllocationExceedsMaxSupply { .. })
        ));
    }

    #[test]
    fn test_claim_vested() {
        let treasury = test_address(1);
        let user = test_address(2);

        // Create vesting schedule: start=0, cliff=10, end=100
        let vesting = VestingSchedule::new(
            10_000,  // total
            0,       // start
            10,      // cliff
            100,     // end
        ).unwrap();

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(user, 10_000, Some(vesting))],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Before cliff: no tokens available
        assert_eq!(token.available_balance(&user), 0);
        let released = token.claim_vested(&user, 5).unwrap();
        assert_eq!(released, 0);
        assert_eq!(token.available_balance(&user), 0);

        // At cliff (block 10): some tokens vested
        let released = token.claim_vested(&user, 10).unwrap();
        assert_eq!(released, 1000); // 10% of 10_000 (10 blocks into 100 block period)
        assert_eq!(token.available_balance(&user), 1000);
        assert_eq!(token.locked_balance(&user), 9000);

        // At block 50: 50% vested
        let released = token.claim_vested(&user, 50).unwrap();
        assert_eq!(released, 4000); // 50% - 10% already released = 40%
        assert_eq!(token.available_balance(&user), 5000);
        assert_eq!(token.locked_balance(&user), 5000);

        // At end (block 100): fully vested
        let released = token.claim_vested(&user, 100).unwrap();
        assert_eq!(released, 5000); // remaining 50%
        assert_eq!(token.available_balance(&user), 10_000);
        assert_eq!(token.locked_balance(&user), 0);

        // Lock should be removed
        assert!(token.get_locks(&user).is_empty());

        assert!(token.verify_invariants().is_ok());
    }

    #[test]
    fn test_get_locks() {
        let treasury = test_address(1);
        let user = test_address(2);

        let vesting = VestingSchedule::new(
            10_000,
            0,
            10,
            100,
        ).unwrap();

        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![(user, 10_000, Some(vesting))],
        );

        let token = TokenContractV2::new_at_genesis(params).unwrap();

        let locks = token.get_locks(&user);
        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].1.total_amount, 10_000);
        assert_eq!(locks[0].1.cliff_block, 10);
        assert_eq!(locks[0].1.end_block, 100);

        // User with no locks
        let other_user = test_address(3);
        assert!(token.get_locks(&other_user).is_empty());
    }

    #[test]
    fn test_add_authority() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let new_auditor = test_address(3);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);

        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities,
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![],
        };

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Add new auditor (by governance)
        token.add_authority(&governance, Role::Auditor, new_auditor).unwrap();
        assert!(token.authorities.has_role(Role::Auditor, &new_auditor));

        // Non-governance cannot add authorities
        let attacker = test_address(4);
        let result = token.add_authority(&attacker, Role::Kernel, attacker);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_remove_authority() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let auditor = test_address(3);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);
        authorities.add(Role::Auditor, auditor);

        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities,
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![],
        };

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Auditor exists
        assert!(token.authorities.has_role(Role::Auditor, &auditor));

        // Remove auditor (by governance)
        token.remove_authority(&governance, Role::Auditor, &auditor).unwrap();
        assert!(!token.authorities.has_role(Role::Auditor, &auditor));

        // Non-governance cannot remove authorities
        let attacker = test_address(4);
        let result = token.remove_authority(&attacker, Role::Governance, &governance);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_update_fee_recipient() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let treasury_admin = test_address(3);
        let new_recipient = test_address(4);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);
        authorities.add(Role::Treasury, treasury_admin);

        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities,
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![],
        };

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Initial fee recipient is treasury
        assert_eq!(token.fee_recipient, treasury);

        // Treasury admin can update fee recipient
        token.update_fee_recipient(&treasury_admin, new_recipient).unwrap();
        assert_eq!(token.fee_recipient, new_recipient);

        // Non-treasury cannot update
        let attacker = test_address(5);
        let result = token.update_fee_recipient(&attacker, attacker);
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_update_fee_schedule() {
        let treasury = test_address(1);
        let governance = test_address(2);
        let sender = test_address(3);
        let recipient = test_address(4);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);

        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities,
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![(sender, 100_000, None)],
        };

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Initial: no fees
        let result = token.transfer(&sender, &sender, &recipient, 1000).unwrap();
        assert_eq!(result.transfer_fee, 0);

        // Update fee schedule
        let new_schedule = FeeSchedule {
            transfer_fee_bps: 500, // 5%
            burn_fee_bps: 100,     // 1%
            fee_cap_amount: 0,
            min_fee_amount: 0,
        };
        token.update_fee_schedule(&governance, new_schedule).unwrap();

        // Now transfers have fees
        let result = token.transfer(&sender, &sender, &recipient, 1000).unwrap();
        assert_eq!(result.transfer_fee, 50); // 5% of 1000
        assert_eq!(result.burn_fee, 10);     // 1% of 1000

        // Non-governance cannot update
        let attacker = test_address(5);
        let result = token.update_fee_schedule(&attacker, FeeSchedule::zero());
        assert!(matches!(result, Err(ContractError::Unauthorized(_))));
    }

    #[test]
    fn test_update_fee_schedule_invalid() {
        let treasury = test_address(1);
        let governance = test_address(2);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);

        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities,
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![],
        };

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Invalid: transfer_fee_bps > 100%
        let invalid_schedule = FeeSchedule {
            transfer_fee_bps: 15_000, // 150%
            burn_fee_bps: 0,
            fee_cap_amount: 0,
            min_fee_amount: 0,
        };
        let result = token.update_fee_schedule(&governance, invalid_schedule);
        assert!(matches!(result, Err(ContractError::InvalidFeeSchedule(_))));

        // Invalid: burn_fee_bps > 100%
        let invalid_schedule = FeeSchedule {
            transfer_fee_bps: 0,
            burn_fee_bps: 12_000, // 120%
            fee_cap_amount: 0,
            min_fee_amount: 0,
        };
        let result = token.update_fee_schedule(&governance, invalid_schedule);
        assert!(matches!(result, Err(ContractError::InvalidFeeSchedule(_))));
    }

    #[test]
    fn test_update_fee_schedule_when_paused() {
        let treasury = test_address(1);
        let governance = test_address(2);

        let mut authorities = AuthoritySet::new();
        authorities.add(Role::Governance, governance);

        let params = TokenCreationParams {
            token_id: test_token_id(),
            name: "Test".to_string(),
            symbol: "TST".to_string(),
            decimals: 8,
            metadata_hash: [0u8; 32],
            supply_policy: SupplyPolicy::FixedCap { max_supply: 1_000_000 },
            emission_model: EmissionModel::None,
            fee_schedule: FeeSchedule::zero(),
            transfer_policy: TransferPolicy::Free,
            authorities,
            treasury_address: treasury,
            fee_recipient: None,
            pause_authority: Role::Governance,
            initial_allocations: vec![],
        };

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // Pause the contract
        token.pause(&governance, true).unwrap();

        // Cannot update fee schedule when paused
        let result = token.update_fee_schedule(&governance, FeeSchedule::zero());
        assert!(matches!(result, Err(ContractError::Paused)));
    }

    #[test]
    fn test_transfer_with_locked_balance() {
        let treasury = test_address(1);
        let user = test_address(2);
        let recipient = test_address(3);

        // Create vesting schedule: when applied to an allocation, the full allocation
        // amount becomes locked (the vesting's total_amount is overwritten)
        let vesting = VestingSchedule::new(
            5_000,   // This value is overwritten by the allocation amount
            0,       // start
            100,     // cliff at 100
            1000,    // end at 1000
        ).unwrap();

        // Allocate: 5k without vesting (available), 5k with vesting (locked)
        let params = create_sov_params(
            test_token_id(),
            treasury,
            vec![
                (user, 5_000, None),           // 5k immediately available
                (user, 5_000, Some(vesting)),  // 5k locked via vesting
            ],
        );

        let mut token = TokenContractV2::new_at_genesis(params).unwrap();

        // User has 10k total, 5k locked (from vesting), 5k available
        assert_eq!(token.balance_of(&user), 10_000);
        assert_eq!(token.locked_balance(&user), 5_000);
        assert_eq!(token.available_balance(&user), 5_000);

        // Can transfer available balance (5k available, transfer 1k + 1% fee = 1010)
        let result = token.transfer(&user, &user, &recipient, 1000);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&user), 10_000 - 1000 - 10); // 1000 + 1% fee = 1010

        // Cannot transfer more than available (5k - 1010 = 3990 remaining available)
        // Try to transfer 4000 which exceeds available
        let result = token.transfer(&user, &user, &recipient, 4000);
        assert!(matches!(result, Err(ContractError::InsufficientUnlockedBalance { .. })));
    }
}
