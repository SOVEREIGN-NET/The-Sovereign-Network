//! SOV Reference Value (SRV) Operations
//!
//! Implements SRV-related operations for the Treasury Kernel.
//! These operations provide USD-equivalent calculations and governance
//! integration for SRV updates.

use crate::contracts::tokens::core::TokenContract;
use crate::integration::crypto_integration::PublicKey;
use super::{
    TreasuryKernel, KernelState,
    interface::KernelOpError,
    srv_types::{SRVState, SRVError, SRVUpdateRecord},
};

impl TreasuryKernel {
    // ============================================================================
    // SRV Query Operations
    // ============================================================================

    /// Get current SRV value
    ///
    /// # Returns
    /// Current SRV in USD per SOV (8 decimal precision)
    pub fn get_current_srv(&self) -> u64 {
        self.state.srv_state.current_srv
    }

    /// Get full SRV state (read-only)
    pub fn srv_state(&self) -> &SRVState {
        &self.state.srv_state
    }

    /// Check if SRV updates are paused
    pub fn is_srv_paused(&self) -> bool {
        self.state.srv_state.emergency_paused
    }

    /// Get SRV update history
    pub fn srv_update_history(&self) -> &[SRVUpdateRecord] {
        &self.state.srv_state.update_history
    }

    // ============================================================================
    // USD/SOV Conversion Operations
    // ============================================================================

    /// Calculate USD value of SOV amount using current SRV
    ///
    /// # Arguments
    /// * `sov_amount` - Amount in SOV atomic units (8 decimals)
    ///
    /// # Returns
    /// USD value in cents
    ///
    /// # Formula
    /// ```text
    /// USD_cents = SOV_atomic × (SRV / 10^6) / 10^8
    ///           = SOV_atomic × SRV / 10^14
    /// ```
    ///
    /// Where SRV is USD per SOV with 8 decimals (e.g., 2_180_000 = $0.0218)
    /// We divide SRV by 10^6 to convert from 8-decimal USD to cents
    pub fn sov_to_usd(&self, sov_amount: u64) -> Result<u64, KernelOpError> {
        let srv = self.get_current_srv();

        if srv == 0 {
            return Err(KernelOpError::InvalidState);
        }

        // USD = SOV_amount * SRV / 10^14
        // 10^14 = 10^8 (SRV USD decimals to cents) * 10^8 (SOV decimals) * 10^2 (cents)
        // Actually simpler: SRV/10^6 = cents per SOV, then /10^8 for atomic units
        // = SOV_amount * SRV / 10^14
        let usd = (sov_amount as u128)
            .checked_mul(srv as u128)
            .ok_or(KernelOpError::Overflow)?
            .checked_div(100_000_000_000_000) // 10^14
            .ok_or(KernelOpError::Overflow)? as u64;

        Ok(usd)
    }

    /// Calculate SOV amount from USD using current SRV
    ///
    /// # Arguments
    /// * `usd_cents` - Amount in USD cents
    ///
    /// # Returns
    /// SOV amount in atomic units (8 decimals)
    ///
    /// # Formula
    /// ```text
    /// SOV_atomic = USD_cents × 10^14 / SRV
    /// ```
    pub fn usd_to_sov(&self, usd_cents: u64) -> Result<u64, KernelOpError> {
        let srv = self.get_current_srv();

        if srv == 0 {
            return Err(KernelOpError::InvalidState);
        }

        // SOV = USD * 10^14 / SRV
        let sov = (usd_cents as u128)
            .checked_mul(100_000_000_000_000) // 10^14
            .ok_or(KernelOpError::Overflow)?
            .checked_div(srv as u128)
            .ok_or(KernelOpError::Overflow)? as u64;

        Ok(sov)
    }

    /// Format SOV amount with USD equivalent for display
    ///
    /// # Arguments
    /// * `sov_amount` - Amount in SOV (8 decimals)
    ///
    /// # Returns
    /// Formatted string like "458715.00000000 SOV ($100.00)"
    pub fn format_sov_with_usd(&self, sov_amount: u64) -> Result<String, KernelOpError> {
        let usd_cents = self.sov_to_usd(sov_amount)?;

        let sov_whole = sov_amount / 100_000_000;
        let sov_frac = sov_amount % 100_000_000;
        let usd_whole = usd_cents / 100;
        let usd_frac = usd_cents % 100;

        Ok(format!(
            "{}.{:08} SOV (${}.{:02})",
            sov_whole, sov_frac, usd_whole, usd_frac
        ))
    }

    // ============================================================================
    // Governance Operations
    // ============================================================================

    /// Apply SRV update from governance proposal
    ///
    /// This is called by the governance executor after a proposal passes
    /// and the timelock expires.
    ///
    /// # Arguments
    /// * `caller` - Must be governance authority
    /// * `new_committed_value` - New committed value in USD cents
    /// * `new_multiplier_bps` - Optional new stability multiplier
    /// * `proposal_id` - Authorizing proposal ID
    /// * `height` - Current block height
    /// * `epoch` - Current epoch
    /// * `token` - Token contract for circulating supply query
    ///
    /// # Returns
    /// New SRV value if successful
    pub fn apply_srv_update(
        &mut self,
        caller: &PublicKey,
        new_committed_value: u64,
        new_multiplier_bps: Option<u16>,
        proposal_id: [u8; 32],
        height: u64,
        epoch: u64,
        token: &TokenContract,
    ) -> Result<u64, KernelOpError> {
        // Verify caller is governance authority
        if *caller != self.governance_authority {
            return Err(KernelOpError::Unauthorized);
        }

        // Update stability multiplier if provided
        if let Some(mult) = new_multiplier_bps {
            self.state
                .srv_state
                .update_stability_multiplier(mult)
                .map_err(|_| KernelOpError::InvalidState)?;
        }

        // Get current circulating supply from token contract
        let circulating_supply = token.total_supply;

        // Apply the update
        let new_srv = self
            .state
            .srv_state
            .apply_update(new_committed_value, circulating_supply, proposal_id, height, epoch)
            .map_err(|e| match e {
                SRVError::ChangeExceedsLimit => KernelOpError::DelayNotElapsed, // Reuse error
                SRVError::Paused => KernelOpError::Paused,
                _ => KernelOpError::InvalidState,
            })?;

        Ok(new_srv)
    }

    /// Set SRV emergency pause
    ///
    /// # Arguments
    /// * `caller` - Must be governance authority
    /// * `paused` - New pause state
    pub fn set_srv_emergency_pause(
        &mut self,
        caller: &PublicKey,
        paused: bool,
    ) -> Result<(), KernelOpError> {
        if *caller != self.governance_authority {
            return Err(KernelOpError::Unauthorized);
        }

        self.state.srv_state.set_emergency_pause(paused);
        Ok(())
    }

    /// Update maximum SRV change limit
    ///
    /// # Arguments
    /// * `caller` - Must be governance authority
    /// * `new_limit_bps` - New limit in basis points (e.g., 100 = 1%)
    pub fn set_srv_max_change(
        &mut self,
        caller: &PublicKey,
        new_limit_bps: u16,
    ) -> Result<(), KernelOpError> {
        if *caller != self.governance_authority {
            return Err(KernelOpError::Unauthorized);
        }

        self.state.srv_state.max_change_bps = new_limit_bps;
        Ok(())
    }

    // ============================================================================
    // UBI Integration
    // ============================================================================

    /// Calculate UBI payout in SOV based on USD target
    ///
    /// Used by the UBI engine to determine how much SOV to distribute
    /// when targeting a specific USD amount.
    ///
    /// # Arguments
    /// * `target_usd_cents` - Target USD amount in cents (e.g., 10000 = $100)
    ///
    /// # Returns
    /// SOV amount to distribute (8 decimals)
    pub fn calculate_ubi_sov_amount(&self, target_usd_cents: u64) -> Result<u64, KernelOpError> {
        self.usd_to_sov(target_usd_cents)
    }
}

/// Extension trait for KernelState to access SRV state
impl KernelState {
    /// Get SRV state reference
    pub fn srv(&self) -> &SRVState {
        &self.srv_state
    }

    /// Get mutable SRV state reference
    pub fn srv_mut(&mut self) -> &mut SRVState {
        &mut self.srv_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::treasury_kernel::types::{KernelState, KernelStats};

    fn test_governance() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![99u8],
            kyber_pk: vec![99u8],
            key_id: [99u8; 32],
        }
    }

    fn test_kernel_address() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![88u8],
            kyber_pk: vec![88u8],
            key_id: [88u8; 32],
        }
    }

    fn test_unauthorized() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![77u8],
            kyber_pk: vec![77u8],
            key_id: [77u8; 32],
        }
    }

    fn test_user() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![1u8],
            kyber_pk: vec![1u8],
            key_id: [1u8; 32],
        }
    }

    fn setup_kernel() -> TreasuryKernel {
        TreasuryKernel::new(
            test_governance(),
            test_kernel_address(),
            60_480,
        )
    }

    #[test]
    fn test_get_current_srv() {
        let kernel = setup_kernel();
        // Default genesis SRV is $0.0218 = 2_180_000
        assert_eq!(kernel.get_current_srv(), 2_180_000);
    }

    #[test]
    fn test_sov_to_usd() {
        let kernel = setup_kernel();

        // With SRV = $0.0218 (2_180_000 with 8 decimals):
        // 1 SOV (100_000_000 atomic units) = $0.0218 = 2.18 cents
        // USD = 100_000_000 * 2_180_000 / 10^14 = 2 cents (truncated)
        let usd = kernel.sov_to_usd(100_000_000).unwrap();
        assert_eq!(usd, 2); // 2.18 cents truncated to 2

        // For $10 USD (1000 cents), we need:
        // SOV = 1000 * 10^14 / 2_180_000 = ~458_715_596_330 SOV atomic units
        // Converting back: USD = 458_715_596_330 * 2_180_000 / 10^14 = 999 cents (~$10)
        let sov_for_10usd = kernel.usd_to_sov(1000).unwrap();
        let usd_back = kernel.sov_to_usd(sov_for_10usd).unwrap();
        assert!(usd_back >= 999 && usd_back <= 1000); // ~$10.00
    }

    #[test]
    fn test_usd_to_sov() {
        let kernel = setup_kernel();

        // With SRV = $0.0218 (2_180_000):
        // $1 (100 cents) = 100 * 10^14 / 2_180_000 = ~4_587_155_963 SOV atomic units
        let sov = kernel.usd_to_sov(100).unwrap();
        // 4_587_155_963 atomic units = ~45.87 SOV
        assert!(sov > 4_500_000_000); // > 45 SOV
        assert!(sov < 5_000_000_000); // < 50 SOV

        // $100 should give ~4587 SOV
        let sov = kernel.usd_to_sov(10_000).unwrap();
        assert!(sov > 458_000_000_000); // > 4580 SOV
        assert!(sov < 460_000_000_000); // < 4600 SOV
    }

    #[test]
    fn test_roundtrip_conversion() {
        let kernel = setup_kernel();

        // Convert SOV -> USD -> SOV should approximate original
        let original_sov = 1_000_000_000_000_000; // 10,000 SOV
        let usd = kernel.sov_to_usd(original_sov).unwrap();
        let back_to_sov = kernel.usd_to_sov(usd).unwrap();

        // Due to integer truncation, we lose some precision
        // The difference should be small relative to the amount
        let diff = if original_sov > back_to_sov {
            original_sov - back_to_sov
        } else {
            back_to_sov - original_sov
        };

        // Difference should be less than 1%
        assert!(diff < original_sov / 100);
    }

    #[test]
    fn test_format_sov_with_usd() {
        let kernel = setup_kernel();

        // 100 SOV at $0.0218 = ~$2.18
        let formatted = kernel.format_sov_with_usd(100 * 100_000_000).unwrap();
        assert!(formatted.contains("SOV"));
        assert!(formatted.contains("$"));
        assert!(formatted.contains("100.00000000"));
    }

    #[test]
    fn test_apply_srv_update_unauthorized() {
        let mut kernel = setup_kernel();
        let token = TokenContract::new_sov_with_kernel_authority(test_kernel_address());

        let result = kernel.apply_srv_update(
            &test_unauthorized(),
            200_000_000,
            None,
            [1u8; 32],
            100,
            1,
            &token,
        );

        assert_eq!(result, Err(KernelOpError::Unauthorized));
    }

    #[test]
    fn test_apply_srv_update_valid() {
        let mut kernel = setup_kernel();
        let mut token = TokenContract::new_sov_with_kernel_authority(test_kernel_address());

        // Pre-mint some tokens to have non-zero circulating supply
        // Use the kernel address to mint (it has kernel authority)
        let _ = token.mint_kernel_only(&test_kernel_address(), &test_user(), 50_000_000_000_000_000);
        assert_eq!(token.total_supply, 50_000_000_000_000_000); // 50M SOV

        // Small increase from 109M to 110M committed value
        // With circulating supply of 50M SOV, SRV changes from ~$0.0218 to ~$0.0220
        // which is about 0.9% increase - within the 1% limit
        let result = kernel.apply_srv_update(
            &test_governance(),
            110_000_000, // Small increase from 109M
            None,
            [1u8; 32],
            100,
            1,
            &token,
        );

        // This should succeed as it's within 1% change
        assert!(result.is_ok(), "Expected Ok, got {:?}", result);
        assert_eq!(kernel.state.srv_state.last_update_height, 100);
        assert_eq!(kernel.state.srv_state.update_history.len(), 1);
    }

    #[test]
    fn test_set_srv_emergency_pause() {
        let mut kernel = setup_kernel();

        assert!(!kernel.is_srv_paused());

        // Unauthorized should fail
        assert_eq!(
            kernel.set_srv_emergency_pause(&test_unauthorized(), true),
            Err(KernelOpError::Unauthorized)
        );

        // Governance should succeed
        assert!(kernel.set_srv_emergency_pause(&test_governance(), true).is_ok());
        assert!(kernel.is_srv_paused());

        // Unpause
        assert!(kernel.set_srv_emergency_pause(&test_governance(), false).is_ok());
        assert!(!kernel.is_srv_paused());
    }

    #[test]
    fn test_set_srv_max_change() {
        let mut kernel = setup_kernel();

        assert_eq!(kernel.srv_state().max_change_bps, 100); // default 1%

        // Unauthorized should fail
        assert_eq!(
            kernel.set_srv_max_change(&test_unauthorized(), 200),
            Err(KernelOpError::Unauthorized)
        );

        // Governance should succeed
        assert!(kernel.set_srv_max_change(&test_governance(), 200).is_ok());
        assert_eq!(kernel.srv_state().max_change_bps, 200); // now 2%
    }

    #[test]
    fn test_calculate_ubi_sov_amount() {
        let kernel = setup_kernel();

        // $100 UBI target
        let sov = kernel.calculate_ubi_sov_amount(10_000).unwrap();

        // With SRV = $0.0218, $100 = ~4587 SOV
        assert!(sov > 450_000_000_000); // > 4500 SOV
        assert!(sov < 470_000_000_000); // < 4700 SOV
    }

    #[test]
    fn test_kernel_state_srv_accessors() {
        let mut state = KernelState::new();

        // Test immutable accessor
        assert_eq!(state.srv().current_srv, 2_180_000);

        // Test mutable accessor
        state.srv_mut().current_srv = 3_000_000;
        assert_eq!(state.srv().current_srv, 3_000_000);
    }

    #[test]
    fn test_sov_to_usd_zero_srv() {
        let mut kernel = setup_kernel();
        kernel.state.srv_state.current_srv = 0;

        assert_eq!(
            kernel.sov_to_usd(100_000_000),
            Err(KernelOpError::InvalidState)
        );
    }

    #[test]
    fn test_usd_to_sov_zero_srv() {
        let mut kernel = setup_kernel();
        kernel.state.srv_state.current_srv = 0;

        assert_eq!(
            kernel.usd_to_sov(100),
            Err(KernelOpError::InvalidState)
        );
    }
}
