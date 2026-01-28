//! Vesting Operations for Treasury Kernel
//!
//! Implements time-locked token vesting with cliff periods.
//!
//! # Operations
//!
//! - `create_vesting`: Lock tokens with a vesting schedule
//! - `release_vested`: Release tokens that have vested past the cliff
//! - `revoke_vesting`: Governance can revoke revocable vestings
//! - `get_vesting`: Query vesting lock details
//!
//! # Flow
//!
//! 1. Governance/authorized caller creates vesting via `create_vesting`
//! 2. Tokens are locked in beneficiary's account
//! 3. After cliff, beneficiary can call `release_vested` periodically
//! 4. Tokens release linearly until end_epoch when all are released
//!
//! # Consensus-Critical
//!
//! All vesting state is deterministically serializable.
//! Calculations use integer math only.

use std::collections::BTreeMap;
use crate::contracts::tokens::core::TokenContract;
use crate::integration::crypto_integration::PublicKey;
use super::TreasuryKernel;
use super::interface::{KernelOpError, LockReason, ReleaseReason};
use super::vesting_types::{VestingId, VestingSchedule, VestingLock, VestingStatus};

/// Vesting state stored in the Treasury Kernel
///
/// Uses BTreeMap for deterministic serialization (consensus-critical).
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct VestingState {
    /// All vesting locks indexed by VestingId
    pub locks: BTreeMap<VestingId, VestingLock>,

    /// Index: beneficiary -> list of their vesting IDs
    pub by_beneficiary: BTreeMap<[u8; 32], Vec<VestingId>>,

    /// Counter for generating unique vesting IDs
    pub next_id: u64,

    /// Total tokens currently locked in vesting
    pub total_locked: u64,
}

impl VestingState {
    /// Create new empty vesting state
    pub fn new() -> Self {
        Self {
            locks: BTreeMap::new(),
            by_beneficiary: BTreeMap::new(),
            next_id: 0,
            total_locked: 0,
        }
    }

    /// Generate a deterministic vesting ID
    ///
    /// Uses kernel address + counter for uniqueness
    pub fn generate_id(&mut self, kernel_address: &[u8; 32]) -> VestingId {
        let mut id = [0u8; 32];
        // First 24 bytes from kernel address
        id[..24].copy_from_slice(&kernel_address[..24]);
        // Last 8 bytes from counter
        id[24..].copy_from_slice(&self.next_id.to_be_bytes());
        self.next_id += 1;
        id
    }

    /// Add a vesting lock
    pub fn add_lock(&mut self, lock: VestingLock) {
        let id = lock.id;
        let beneficiary = lock.beneficiary;
        let amount = lock.schedule.total_amount;

        self.locks.insert(id, lock);
        self.by_beneficiary
            .entry(beneficiary)
            .or_insert_with(Vec::new)
            .push(id);
        self.total_locked = self.total_locked.saturating_add(amount);
    }

    /// Get a vesting lock by ID
    pub fn get_lock(&self, id: &VestingId) -> Option<&VestingLock> {
        self.locks.get(id)
    }

    /// Get a mutable vesting lock by ID
    pub fn get_lock_mut(&mut self, id: &VestingId) -> Option<&mut VestingLock> {
        self.locks.get_mut(id)
    }

    /// Get all vesting IDs for a beneficiary
    pub fn get_beneficiary_vestings(&self, beneficiary: &[u8; 32]) -> Vec<VestingId> {
        self.by_beneficiary
            .get(beneficiary)
            .cloned()
            .unwrap_or_default()
    }

    /// Update total locked after a release
    pub fn record_release(&mut self, amount: u64) {
        self.total_locked = self.total_locked.saturating_sub(amount);
    }
}

impl TreasuryKernel {
    /// Create a new vesting lock
    ///
    /// Locks tokens in the beneficiary's account with the specified vesting schedule.
    /// Tokens are locked immediately but only become releasable after the cliff.
    ///
    /// # Arguments
    /// * `token` - Token contract to lock tokens in
    /// * `caller` - Must be kernel or governance
    /// * `beneficiary` - Account that will receive vested tokens
    /// * `schedule` - Vesting schedule (start, cliff, end, amount)
    /// * `current_epoch` - Current epoch for recording creation time
    /// * `revocable` - Whether governance can revoke this vesting
    /// * `vesting_state` - Mutable vesting state to update
    ///
    /// # Returns
    /// Ok(VestingId) on success, Err(KernelOpError) on failure
    ///
    /// # Errors
    /// - `Unauthorized` - Caller not kernel or governance
    /// - `Paused` - Kernel is paused
    /// - `InvalidVestingSchedule` - Schedule parameters invalid
    /// - `InsufficientBalance` - Beneficiary doesn't have enough tokens to lock
    pub fn create_vesting(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        beneficiary: &PublicKey,
        schedule: VestingSchedule,
        current_epoch: u64,
        revocable: bool,
        vesting_state: &mut VestingState,
    ) -> Result<VestingId, KernelOpError> {
        // Verify caller authorization
        self.verify_caller_for_vesting(caller)?;

        // Validate schedule
        if !schedule.is_valid() {
            return Err(KernelOpError::InvalidVestingSchedule);
        }

        // Generate unique vesting ID
        let vesting_id = vesting_state.generate_id(&self.kernel_address().key_id);

        // Lock tokens in beneficiary's account
        self.lock(
            token,
            caller,
            beneficiary,
            schedule.total_amount,
            LockReason::Vesting,
        )?;

        // Create and store vesting lock
        let lock = VestingLock::new(
            vesting_id,
            beneficiary.key_id,
            schedule,
            current_epoch,
            revocable,
        );
        vesting_state.add_lock(lock);

        Ok(vesting_id)
    }

    /// Release vested tokens
    ///
    /// Calculates the amount vested and releasable, then unlocks those tokens.
    /// Can be called by the beneficiary or by kernel/governance.
    ///
    /// # Arguments
    /// * `token` - Token contract to release tokens from
    /// * `caller` - Beneficiary or kernel/governance
    /// * `vesting_id` - ID of the vesting lock
    /// * `current_epoch` - Current epoch for vesting calculation
    /// * `vesting_state` - Mutable vesting state to update
    ///
    /// # Returns
    /// Ok(amount_released) on success, Err(KernelOpError) on failure
    ///
    /// # Errors
    /// - `VestingNotFound` - No vesting with this ID
    /// - `Unauthorized` - Caller not beneficiary or kernel/governance
    /// - `VestingCliffNotReached` - Cliff epoch not yet reached
    /// - `VestingNotStarted` - Vesting period hasn't started
    /// - `VestingAlreadyFullyReleased` - All tokens already released
    pub fn release_vested(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        vesting_id: &VestingId,
        current_epoch: u64,
        vesting_state: &mut VestingState,
    ) -> Result<u64, KernelOpError> {
        // Get the vesting lock
        let lock = vesting_state
            .get_lock(vesting_id)
            .ok_or(KernelOpError::VestingNotFound)?;

        // Verify caller is beneficiary or authorized
        let beneficiary_key_id = lock.beneficiary;
        if caller.key_id != beneficiary_key_id {
            self.verify_caller_for_vesting(caller)?;
        }

        // Check vesting status
        let status = lock.status(current_epoch);
        match status {
            VestingStatus::Pending => return Err(KernelOpError::VestingNotStarted),
            VestingStatus::BeforeCliff => return Err(KernelOpError::VestingCliffNotReached),
            VestingStatus::Completed => return Err(KernelOpError::VestingAlreadyFullyReleased),
            VestingStatus::Revoked => return Err(KernelOpError::VestingAlreadyFullyReleased),
            VestingStatus::Active => {} // OK to proceed
        }

        // Calculate amount to release
        let available = lock.available_to_release(current_epoch);
        if available == 0 {
            return Err(KernelOpError::VestingAlreadyFullyReleased);
        }

        // Build beneficiary PublicKey for token operation
        // We need to look up or reconstruct the beneficiary's PublicKey
        // For now, we'll use the key_id which is what token contract uses for lookups
        let beneficiary_pk = self.find_beneficiary_key(token, &beneficiary_key_id)?;

        // Clone kernel address before mutable borrow
        let kernel_addr = self.kernel_address().clone();

        // Release tokens (unlock them)
        self.release(
            token,
            &kernel_addr,
            &beneficiary_pk,
            available,
            ReleaseReason::VestingRelease,
        )?;

        // Update vesting state
        let lock_mut = vesting_state
            .get_lock_mut(vesting_id)
            .ok_or(KernelOpError::VestingNotFound)?;
        lock_mut
            .record_release(available)
            .map_err(|_| KernelOpError::Overflow)?;
        vesting_state.record_release(available);

        Ok(available)
    }

    /// Revoke a vesting lock (governance only)
    ///
    /// Stops further vesting and returns unvested tokens to a destination account.
    /// Only works for revocable vestings.
    ///
    /// # Arguments
    /// * `token` - Token contract
    /// * `caller` - Must be governance
    /// * `vesting_id` - ID of the vesting lock to revoke
    /// * `return_to` - Account to return unvested tokens to
    /// * `current_epoch` - Current epoch
    /// * `vesting_state` - Mutable vesting state
    ///
    /// # Returns
    /// Ok(unvested_amount) returned to destination
    pub fn revoke_vesting(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        vesting_id: &VestingId,
        return_to: &PublicKey,
        current_epoch: u64,
        vesting_state: &mut VestingState,
    ) -> Result<u64, KernelOpError> {
        // Only governance can revoke
        if caller != self.governance_authority() {
            return Err(KernelOpError::Unauthorized);
        }

        // Get the vesting lock
        let lock = vesting_state
            .get_lock_mut(vesting_id)
            .ok_or(KernelOpError::VestingNotFound)?;

        // Revoke and get unvested amount
        let unvested = lock
            .revoke(current_epoch)
            .map_err(|_| KernelOpError::Unauthorized)?;

        if unvested > 0 {
            // Get beneficiary key for token operations
            let beneficiary_key_id = lock.beneficiary;
            let beneficiary_pk = self.find_beneficiary_key(token, &beneficiary_key_id)?;

            // Clone kernel address before mutable borrows
            let kernel_addr = self.kernel_address().clone();

            // Release the unvested tokens from beneficiary
            self.release(
                token,
                &kernel_addr,
                &beneficiary_pk,
                unvested,
                ReleaseReason::VestingRelease,
            )?;

            // Transfer unvested to return_to address
            self.transfer(token, &kernel_addr, &beneficiary_pk, return_to, unvested)?;

            vesting_state.record_release(unvested);
        }

        Ok(unvested)
    }

    /// Get vesting lock details
    pub fn get_vesting<'a>(
        &self,
        vesting_id: &VestingId,
        vesting_state: &'a VestingState,
    ) -> Option<&'a VestingLock> {
        vesting_state.get_lock(vesting_id)
    }

    /// Get all vesting locks for a beneficiary
    pub fn get_beneficiary_vestings(
        &self,
        beneficiary: &[u8; 32],
        vesting_state: &VestingState,
    ) -> Vec<VestingId> {
        vesting_state.get_beneficiary_vestings(beneficiary)
    }

    /// Calculate total releasable across all vestings for a beneficiary
    pub fn total_releasable_for_beneficiary(
        &self,
        beneficiary: &[u8; 32],
        current_epoch: u64,
        vesting_state: &VestingState,
    ) -> u64 {
        let vesting_ids = vesting_state.get_beneficiary_vestings(beneficiary);
        vesting_ids
            .iter()
            .filter_map(|id| vesting_state.get_lock(id))
            .map(|lock| lock.available_to_release(current_epoch))
            .sum()
    }

    // ─── Private helpers ────────────────────────────────────────────────

    /// Verify caller is authorized for vesting operations
    fn verify_caller_for_vesting(&self, caller: &PublicKey) -> Result<(), KernelOpError> {
        if self.paused {
            return Err(KernelOpError::Paused);
        }
        if caller == self.kernel_address() || caller == self.governance_authority() {
            Ok(())
        } else {
            Err(KernelOpError::Unauthorized)
        }
    }

    /// Find a PublicKey by key_id from token contract balances
    ///
    /// This is a helper to reconstruct PublicKey from key_id.
    /// In production, this would use a proper key registry.
    fn find_beneficiary_key(
        &self,
        token: &TokenContract,
        key_id: &[u8; 32],
    ) -> Result<PublicKey, KernelOpError> {
        // Search through token balances for matching key_id
        for pk in token.balances.keys() {
            if &pk.key_id == key_id {
                return Ok(pk.clone());
            }
        }
        // Also check locked_balances
        for pk in token.locked_balances.keys() {
            if &pk.key_id == key_id {
                return Ok(pk.clone());
            }
        }
        Err(KernelOpError::VestingNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn test_beneficiary() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![1u8],
            kyber_pk: vec![1u8],
            key_id: [1u8; 32],
        }
    }

    fn test_other_account() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![2u8],
            kyber_pk: vec![2u8],
            key_id: [2u8; 32],
        }
    }

    fn setup() -> (TreasuryKernel, TokenContract, VestingState) {
        let gov = test_governance();
        let kernel_addr = test_kernel_address();
        let kernel = TreasuryKernel::new(gov, kernel_addr.clone(), 60_480);
        let token = TokenContract::new_sov_with_kernel_authority(kernel_addr);
        let vesting_state = VestingState::new();
        (kernel, token, vesting_state)
    }

    #[test]
    fn test_create_vesting_success() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        // Pre-fund beneficiary
        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        let schedule = VestingSchedule::new(100, 110, 200, 5000).unwrap();
        let result = kernel.create_vesting(
            &mut token,
            &caller,
            &beneficiary,
            schedule,
            100,
            false,
            &mut vesting_state,
        );

        assert!(result.is_ok());
        let vesting_id = result.unwrap();
        assert!(vesting_state.get_lock(&vesting_id).is_some());
        assert_eq!(token.available_balance(&beneficiary), 5000); // 10000 - 5000 locked
    }

    #[test]
    fn test_create_vesting_invalid_schedule() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        // Invalid: cliff before start
        let schedule = VestingSchedule {
            start_epoch: 100,
            cliff_epoch: 50,
            end_epoch: 200,
            total_amount: 5000,
        };
        let result = kernel.create_vesting(
            &mut token,
            &caller,
            &beneficiary,
            schedule,
            100,
            false,
            &mut vesting_state,
        );

        assert_eq!(result, Err(KernelOpError::InvalidVestingSchedule));
    }

    #[test]
    fn test_create_vesting_insufficient_balance() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        // Beneficiary has no tokens
        let schedule = VestingSchedule::new(100, 110, 200, 5000).unwrap();
        let result = kernel.create_vesting(
            &mut token,
            &caller,
            &beneficiary,
            schedule,
            100,
            false,
            &mut vesting_state,
        );

        assert_eq!(result, Err(KernelOpError::InsufficientBalance));
    }

    #[test]
    fn test_release_vested_after_cliff() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        // Pre-fund and create vesting
        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let vesting_id = kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();

        // At epoch 150, 50% vested
        let result = kernel.release_vested(
            &mut token,
            &beneficiary,
            &vesting_id,
            150,
            &mut vesting_state,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5000);
        assert_eq!(token.available_balance(&beneficiary), 5000);
    }

    #[test]
    fn test_release_vested_before_cliff() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        let schedule = VestingSchedule::new(100, 150, 200, 10000).unwrap();
        let vesting_id = kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();

        // Try to release before cliff (epoch 120 < cliff 150)
        let result = kernel.release_vested(
            &mut token,
            &beneficiary,
            &vesting_id,
            120,
            &mut vesting_state,
        );

        assert_eq!(result, Err(KernelOpError::VestingCliffNotReached));
    }

    #[test]
    fn test_release_vested_multiple_times() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let vesting_id = kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();

        // First release at 25%
        let r1 = kernel
            .release_vested(&mut token, &beneficiary, &vesting_id, 125, &mut vesting_state)
            .unwrap();
        assert_eq!(r1, 2500);

        // Second release at 50%
        let r2 = kernel
            .release_vested(&mut token, &beneficiary, &vesting_id, 150, &mut vesting_state)
            .unwrap();
        assert_eq!(r2, 2500); // Additional 2500 vested

        // Third release at 100%
        let r3 = kernel
            .release_vested(&mut token, &beneficiary, &vesting_id, 200, &mut vesting_state)
            .unwrap();
        assert_eq!(r3, 5000); // Remaining 5000

        // Fourth release should fail - all released
        let r4 = kernel.release_vested(
            &mut token,
            &beneficiary,
            &vesting_id,
            250,
            &mut vesting_state,
        );
        assert_eq!(r4, Err(KernelOpError::VestingAlreadyFullyReleased));
    }

    #[test]
    fn test_revoke_vesting() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let governance = test_governance();
        let beneficiary = test_beneficiary();
        let treasury = test_other_account();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let vesting_id = kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule,
                100,
                true, // revocable
                &mut vesting_state,
            )
            .unwrap();

        // Revoke at 50% vested
        let result = kernel.revoke_vesting(
            &mut token,
            &governance,
            &vesting_id,
            &treasury,
            150,
            &mut vesting_state,
        );

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 5000); // 5000 unvested returned
        assert_eq!(token.balance_of(&treasury), 5000);
    }

    #[test]
    fn test_revoke_vesting_non_revocable() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let governance = test_governance();
        let beneficiary = test_beneficiary();
        let treasury = test_other_account();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 10000)
            .unwrap();

        let schedule = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let vesting_id = kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule,
                100,
                false, // not revocable
                &mut vesting_state,
            )
            .unwrap();

        let result = kernel.revoke_vesting(
            &mut token,
            &governance,
            &vesting_id,
            &treasury,
            150,
            &mut vesting_state,
        );

        assert_eq!(result, Err(KernelOpError::Unauthorized));
    }

    #[test]
    fn test_vesting_state_generate_id() {
        let mut state = VestingState::new();
        let kernel_id = [88u8; 32];

        let id1 = state.generate_id(&kernel_id);
        let id2 = state.generate_id(&kernel_id);

        assert_ne!(id1, id2);
        assert_eq!(state.next_id, 2);
    }

    #[test]
    fn test_get_beneficiary_vestings() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 20000)
            .unwrap();

        // Create two vestings for same beneficiary
        let schedule1 = VestingSchedule::new(100, 100, 200, 5000).unwrap();
        let schedule2 = VestingSchedule::new(100, 100, 200, 5000).unwrap();

        kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule1,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();
        kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule2,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();

        let vestings = kernel.get_beneficiary_vestings(&beneficiary.key_id, &vesting_state);
        assert_eq!(vestings.len(), 2);
    }

    #[test]
    fn test_total_releasable_for_beneficiary() {
        let (mut kernel, mut token, mut vesting_state) = setup();
        let caller = test_kernel_address();
        let beneficiary = test_beneficiary();

        token
            .mint_kernel_only(kernel.kernel_address(), &beneficiary, 20000)
            .unwrap();

        // Two vestings: 10000 each, both 50% vested at epoch 150
        let schedule1 = VestingSchedule::new(100, 100, 200, 10000).unwrap();
        let schedule2 = VestingSchedule::new(100, 100, 200, 10000).unwrap();

        kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule1,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();
        kernel
            .create_vesting(
                &mut token,
                &caller,
                &beneficiary,
                schedule2,
                100,
                false,
                &mut vesting_state,
            )
            .unwrap();

        let total = kernel.total_releasable_for_beneficiary(&beneficiary.key_id, 150, &vesting_state);
        assert_eq!(total, 10000); // 5000 + 5000
    }
}
