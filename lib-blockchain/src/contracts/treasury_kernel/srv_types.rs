//! SOV Reference Value (SRV) Types
//!
//! Defines the data structures for the SOV Reference Value mechanism.
//! SRV is the protocol-defined internal valuation of SOV in USD terms.
//!
//! # Consensus-Critical
//! All calculations use integer math for deterministic consensus.
//! No floating-point operations are permitted.

use serde::{Deserialize, Serialize};

/// SOV Reference Value (SRV) State
///
/// Tracks the protocol-defined internal valuation of SOV in USD terms.
/// All values use integer math for consensus determinism.
///
/// # SRV Formula
/// ```text
/// SRV = (Committed_Value_USD / Circulating_SOV) × Stability_Multiplier
/// ```
///
/// # Precision
/// - SRV: 8 decimal places (same as SOV token)
/// - USD values: cents (2 decimal places)
/// - Multiplier: basis points (4 decimal places)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRVState {
    /// Current SRV in USD per SOV (8 decimal precision)
    /// Example: 2_180_000 = $0.0218 per SOV
    pub current_srv: u64,

    /// Total committed value in USD cents
    /// Example: 109_000_000 = $1,090,000
    pub committed_value_usd: u64,

    /// Circulating supply at time of last SRV calculation (8 decimals)
    pub circulating_supply_sov: u64,

    /// Stability multiplier in basis points (10000 = 1.0)
    pub stability_multiplier_bps: u16,

    /// Maximum allowed change per update (basis points)
    /// Default: 100 = 1% max change
    pub max_change_bps: u16,

    /// Block height of last SRV update
    pub last_update_height: u64,

    /// Epoch of last SRV update
    pub last_update_epoch: u64,

    /// Update history (last N updates for audit trail)
    #[serde(default)]
    pub update_history: Vec<SRVUpdateRecord>,

    /// Emergency pause flag
    #[serde(default)]
    pub emergency_paused: bool,
}

/// SRV Update Record for audit trail
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SRVUpdateRecord {
    /// Block height of update
    pub height: u64,
    /// Epoch of update
    pub epoch: u64,
    /// SRV value after update
    pub new_srv: u64,
    /// Previous SRV value
    pub previous_srv: u64,
    /// Committed value used
    pub committed_value_usd: u64,
    /// Circulating supply used
    pub circulating_supply_sov: u64,
    /// Proposal ID that authorized this update
    pub proposal_id: [u8; 32],
}

/// Errors specific to SRV operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SRVError {
    /// Proposed SRV change exceeds maximum allowed
    ChangeExceedsLimit,
    /// Invalid circulating supply (zero)
    InvalidCirculatingSupply,
    /// Invalid stability multiplier
    InvalidStabilityMultiplier,
    /// SRV updates are paused
    Paused,
    /// Proposal not found or invalid
    InvalidProposal,
    /// Arithmetic overflow
    Overflow,
    /// Unauthorized operation
    Unauthorized,
}

impl std::fmt::Display for SRVError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SRVError::ChangeExceedsLimit => write!(f, "SRV change exceeds maximum allowed limit"),
            SRVError::InvalidCirculatingSupply => write!(f, "Invalid circulating supply (must be > 0)"),
            SRVError::InvalidStabilityMultiplier => write!(f, "Invalid stability multiplier (must be > 0)"),
            SRVError::Paused => write!(f, "SRV updates are paused"),
            SRVError::InvalidProposal => write!(f, "Invalid SRV update proposal"),
            SRVError::Overflow => write!(f, "Arithmetic overflow in SRV calculation"),
            SRVError::Unauthorized => write!(f, "Unauthorized SRV operation"),
        }
    }
}

impl SRVState {
    /// Create new SRV state with genesis values
    ///
    /// # Arguments
    /// * `initial_srv` - Initial SRV value (8 decimals)
    /// * `committed_value_usd` - Initial committed value in USD cents
    /// * `circulating_supply_sov` - Initial circulating supply (8 decimals)
    /// * `stability_multiplier_bps` - Initial stability multiplier (basis points)
    ///
    /// # Returns
    /// New SRVState instance
    pub fn new(
        initial_srv: u64,
        committed_value_usd: u64,
        circulating_supply_sov: u64,
        stability_multiplier_bps: u16,
    ) -> Self {
        Self {
            current_srv: initial_srv,
            committed_value_usd,
            circulating_supply_sov,
            stability_multiplier_bps,
            max_change_bps: 100, // 1% default
            last_update_height: 0,
            last_update_epoch: 0,
            update_history: Vec::new(),
            emergency_paused: false,
        }
    }

    /// Create SRV state with default genesis configuration
    ///
    /// Default genesis values:
    /// - SRV: $0.0218 (2_180_000 with 8 decimals)
    /// - Committed value: $1,090,000 (109_000_000 cents)
    /// - Circulating supply: 50M SOV (50_000_000_000_000_000 with 8 decimals)
    /// - Stability multiplier: 1.0 (10_000 basis points)
    pub fn new_genesis() -> Self {
        Self::new(
            2_180_000,                    // $0.0218
            109_000_000,                  // $1,090,000
            50_000_000_000_000_000,       // 50M SOV
            10_000,                       // 1.0
        )
    }

    /// Calculate SRV using deterministic integer math
    ///
    /// Formula: SRV = (Committed_Value_USD / Circulating_SOV) × Multiplier
    ///
    /// Where:
    /// - Committed_Value_USD is in cents (2 decimals)
    /// - Circulating_SOV is in atomic units (8 decimals)
    /// - SRV result is in USD per SOV (8 decimals)
    ///
    /// # Arguments
    /// * `committed_value_usd` - Total committed value in USD cents
    /// * `circulating_supply_sov` - Circulating SOV (8 decimals, atomic units)
    /// * `multiplier_bps` - Stability multiplier in basis points
    ///
    /// # Returns
    /// SRV in USD per SOV (8 decimal precision)
    pub fn calculate_srv(
        committed_value_usd: u64,
        circulating_supply_sov: u64,
        multiplier_bps: u16,
    ) -> Result<u64, SRVError> {
        // Prevent division by zero
        if circulating_supply_sov == 0 {
            return Err(SRVError::InvalidCirculatingSupply);
        }

        // Validate multiplier
        if multiplier_bps == 0 {
            return Err(SRVError::InvalidStabilityMultiplier);
        }

        // Integer math for determinism:
        // SRV = committed_value_usd * 10^14 / circulating_supply_sov * multiplier_bps / 10^4
        //
        // Explanation:
        // - committed_value_usd is in cents ($1 = 100 cents)
        // - circulating_supply_sov is in atomic units (1 SOV = 10^8)
        // - We want SRV in USD per SOV with 8 decimals
        // - 10^14 = 10^8 (SRV decimals) * 10^8 (SOV decimals) / 10^2 (cents to USD)
        //
        // Rearranging to avoid overflow:
        // SRV = (committed_value_usd * 10^14 / circulating_supply_sov) * multiplier_bps / 10^4

        let base_srv = (committed_value_usd as u128)
            .checked_mul(10_000_000_000_000_00u128) // 10^14
            .ok_or(SRVError::Overflow)?
            .checked_div(circulating_supply_sov as u128)
            .ok_or(SRVError::Overflow)?;

        let srv = base_srv
            .checked_mul(multiplier_bps as u128)
            .ok_or(SRVError::Overflow)?
            .checked_div(10_000)
            .ok_or(SRVError::Overflow)?;

        Ok(srv as u64)
    }

    /// Validate proposed SRV against smoothing rules
    ///
    /// # Arguments
    /// * `proposed_srv` - New SRV value
    ///
    /// # Returns
    /// Ok if change is within limits, Err otherwise
    pub fn validate_proposed_change(&self, proposed_srv: u64) -> Result<(), SRVError> {
        if self.emergency_paused {
            return Err(SRVError::Paused);
        }

        // Handle initial case where current_srv might be 0
        if self.current_srv == 0 {
            return Ok(());
        }

        // Calculate absolute change
        let change = if proposed_srv > self.current_srv {
            proposed_srv - self.current_srv
        } else {
            self.current_srv - proposed_srv
        };

        // Calculate change as percentage of current (basis points)
        let change_bps = (change as u128)
            .checked_mul(10_000)
            .ok_or(SRVError::Overflow)?
            .checked_div(self.current_srv as u128)
            .ok_or(SRVError::Overflow)? as u16;

        if change_bps > self.max_change_bps {
            return Err(SRVError::ChangeExceedsLimit);
        }

        Ok(())
    }

    /// Apply SRV update with validation
    ///
    /// # Arguments
    /// * `new_committed_value` - Updated committed value in USD cents
    /// * `circulating_supply` - Current circulating supply (8 decimals)
    /// * `proposal_id` - Authorizing proposal ID
    /// * `height` - Current block height
    /// * `epoch` - Current epoch
    ///
    /// # Returns
    /// New SRV value if successful
    pub fn apply_update(
        &mut self,
        new_committed_value: u64,
        circulating_supply: u64,
        proposal_id: [u8; 32],
        height: u64,
        epoch: u64,
    ) -> Result<u64, SRVError> {
        // Calculate new SRV
        let new_srv = Self::calculate_srv(
            new_committed_value,
            circulating_supply,
            self.stability_multiplier_bps,
        )?;

        // Validate against smoothing rules
        self.validate_proposed_change(new_srv)?;

        // Record history
        let record = SRVUpdateRecord {
            height,
            epoch,
            new_srv,
            previous_srv: self.current_srv,
            committed_value_usd: new_committed_value,
            circulating_supply_sov: circulating_supply,
            proposal_id,
        };

        self.update_history.push(record);

        // Prune history if needed (keep last 100)
        if self.update_history.len() > 100 {
            self.update_history.remove(0);
        }

        // Apply update
        self.committed_value_usd = new_committed_value;
        self.circulating_supply_sov = circulating_supply;
        self.current_srv = new_srv;
        self.last_update_height = height;
        self.last_update_epoch = epoch;

        Ok(new_srv)
    }

    /// Update stability multiplier
    ///
    /// # Arguments
    /// * `new_multiplier_bps` - New multiplier in basis points
    ///
    /// # Returns
    /// Ok if valid, Err otherwise
    pub fn update_stability_multiplier(&mut self, new_multiplier_bps: u16) -> Result<(), SRVError> {
        if new_multiplier_bps == 0 {
            return Err(SRVError::InvalidStabilityMultiplier);
        }
        self.stability_multiplier_bps = new_multiplier_bps;
        Ok(())
    }

    /// Set emergency pause state
    pub fn set_emergency_pause(&mut self, paused: bool) {
        self.emergency_paused = paused;
    }

    /// Get current SRV as a human-readable string
    pub fn current_srv_formatted(&self) -> String {
        let whole = self.current_srv / 100_000_000;
        let frac = self.current_srv % 100_000_000;
        format!("${}.{:08}", whole, frac)
    }
}

impl Default for SRVState {
    fn default() -> Self {
        Self::new_genesis()
    }
}

/// Genesis configuration for SRV
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SRVGenesisConfig {
    /// Initial SRV value (8 decimals)
    pub initial_srv: u64,
    /// Initial committed value in USD cents
    pub initial_committed_value_usd: u64,
    /// Initial circulating supply (8 decimals)
    pub initial_circulating_supply: u64,
    /// Initial stability multiplier (basis points)
    pub stability_multiplier_bps: u16,
    /// Maximum change per update (basis points)
    pub max_change_bps: u16,
}

impl Default for SRVGenesisConfig {
    fn default() -> Self {
        Self {
            initial_srv: 2_180_000,                  // $0.0218
            initial_committed_value_usd: 109_000_000, // $1,090,000
            initial_circulating_supply: 50_000_000_000_000_000, // 50M SOV
            stability_multiplier_bps: 10_000,        // 1.0
            max_change_bps: 100,                     // 1%
        }
    }
}

impl SRVGenesisConfig {
    /// Initialize SRV state from genesis config
    pub fn initialize(&self) -> SRVState {
        SRVState::new(
            self.initial_srv,
            self.initial_committed_value_usd,
            self.initial_circulating_supply,
            self.stability_multiplier_bps,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srv_state_new() {
        let state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);
        assert_eq!(state.current_srv, 2_180_000);
        assert_eq!(state.committed_value_usd, 109_000_000);
        assert_eq!(state.circulating_supply_sov, 50_000_000_000_000_000);
        assert_eq!(state.stability_multiplier_bps, 10_000);
        assert_eq!(state.max_change_bps, 100);
    }

    #[test]
    fn test_srv_state_new_genesis() {
        let state = SRVState::new_genesis();
        assert_eq!(state.current_srv, 2_180_000);
        assert_eq!(state.committed_value_usd, 109_000_000);
        assert_eq!(state.circulating_supply_sov, 50_000_000_000_000_000);
        assert_eq!(state.stability_multiplier_bps, 10_000);
    }

    #[test]
    fn test_calculate_srv_genesis_values() {
        // Test with genesis values
        // Committed: $1,090,000 = 109,000,000 cents
        // Circulating: 50M SOV = 50,000,000,000,000,000 (8 decimals)
        // Multiplier: 1.0 = 10,000 bps
        // Expected: $0.0218 = 2,180,000 (8 decimals)

        let srv = SRVState::calculate_srv(109_000_000, 50_000_000_000_000_000, 10_000).unwrap();
        assert_eq!(srv, 2_180_000);
    }

    #[test]
    fn test_calculate_srv_with_damping() {
        // Test with 0.95 stability multiplier
        // Expected: $0.0218 * 0.95 = $0.02071

        let srv = SRVState::calculate_srv(109_000_000, 50_000_000_000_000_000, 9_500).unwrap();
        assert_eq!(srv, 2_071_000); // 2,071,000 = $0.02071
    }

    #[test]
    fn test_calculate_srv_zero_circulating_fails() {
        let result = SRVState::calculate_srv(109_000_000, 0, 10_000);
        assert_eq!(result, Err(SRVError::InvalidCirculatingSupply));
    }

    #[test]
    fn test_calculate_srv_zero_multiplier_fails() {
        let result = SRVState::calculate_srv(109_000_000, 50_000_000_000_000_000, 0);
        assert_eq!(result, Err(SRVError::InvalidStabilityMultiplier));
    }

    #[test]
    fn test_validate_proposed_change_within_limit() {
        let state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);

        // 0.5% increase (within 1% limit)
        let new_srv = 2_180_000 + (2_180_000 / 200); // +0.5%
        assert!(state.validate_proposed_change(new_srv).is_ok());

        // Exact 1% increase (at limit)
        let new_srv = 2_180_000 + (2_180_000 / 100); // +1%
        assert!(state.validate_proposed_change(new_srv).is_ok());
    }

    #[test]
    fn test_validate_proposed_change_exceeds_limit() {
        let state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);

        // 2% increase (exceeds 1% limit)
        let new_srv = 2_180_000 + (2_180_000 / 50); // +2%
        assert_eq!(
            state.validate_proposed_change(new_srv),
            Err(SRVError::ChangeExceedsLimit)
        );
    }

    #[test]
    fn test_validate_proposed_change_when_paused() {
        let mut state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);
        state.set_emergency_pause(true);

        assert_eq!(
            state.validate_proposed_change(2_180_000),
            Err(SRVError::Paused)
        );
    }

    #[test]
    fn test_apply_update() {
        let mut state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);

        // Update with small committed value increase (within 1% limit)
        // Increase from $1.09M to $1.10M = ~0.9% increase
        let result = state.apply_update(
            110_000_000, // slight increase from 109M
            50_000_000_000_000_000,
            [1u8; 32],
            100,
            1,
        );

        assert!(result.is_ok());
        // SRV should increase from $0.0218 to $0.0220 (exactly)
        assert_eq!(state.current_srv, 2_200_000);
        assert_eq!(state.update_history.len(), 1);
        assert_eq!(state.last_update_height, 100);
        assert_eq!(state.last_update_epoch, 1);
    }

    #[test]
    fn test_apply_update_exceeds_limit_fails() {
        let mut state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);

        // Try to increase SRV by 50% (way over 1% limit)
        let result = state.apply_update(
            163_500_000, // would give 50% increase
            50_000_000_000_000_000,
            [1u8; 32],
            100,
            1,
        );

        assert_eq!(result, Err(SRVError::ChangeExceedsLimit));
        assert_eq!(state.current_srv, 2_180_000); // unchanged
    }

    #[test]
    fn test_update_stability_multiplier() {
        let mut state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);

        assert!(state.update_stability_multiplier(9_500).is_ok());
        assert_eq!(state.stability_multiplier_bps, 9_500);

        // Zero should fail
        assert_eq!(
            state.update_stability_multiplier(0),
            Err(SRVError::InvalidStabilityMultiplier)
        );
    }

    #[test]
    fn test_history_pruning() {
        let mut state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);

        // Add 105 updates
        for i in 0..105 {
            let _ = state.apply_update(
                109_000_000 + i as u64,
                50_000_000_000_000_000,
                [i as u8; 32],
                i as u64,
                i as u64,
            );
        }

        // Should only keep last 100
        assert_eq!(state.update_history.len(), 100);
    }

    #[test]
    fn test_current_srv_formatted() {
        let state = SRVState::new(2_180_000, 109_000_000, 50_000_000_000_000_000, 10_000);
        assert_eq!(state.current_srv_formatted(), "$0.02180000");
    }

    #[test]
    fn test_genesis_config_default() {
        let config = SRVGenesisConfig::default();
        assert_eq!(config.initial_srv, 2_180_000);
        assert_eq!(config.initial_committed_value_usd, 109_000_000);
        assert_eq!(config.initial_circulating_supply, 50_000_000_000_000_000);
        assert_eq!(config.stability_multiplier_bps, 10_000);
        assert_eq!(config.max_change_bps, 100);
    }

    #[test]
    fn test_genesis_config_initialize() {
        let config = SRVGenesisConfig::default();
        let state = config.initialize();

        assert_eq!(state.current_srv, config.initial_srv);
        assert_eq!(state.committed_value_usd, config.initial_committed_value_usd);
        assert_eq!(state.circulating_supply_sov, config.initial_circulating_supply);
        assert_eq!(state.stability_multiplier_bps, config.stability_multiplier_bps);
        assert_eq!(state.max_change_bps, config.max_change_bps);
    }
}
