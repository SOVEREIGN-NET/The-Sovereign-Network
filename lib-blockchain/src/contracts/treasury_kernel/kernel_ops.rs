//! Treasury Kernel Operations — Implementation of the single balance mutation authority
//!
//! Every token balance mutation flows through these methods.
//! Authorization: only `governance_authority` or `kernel_address` may invoke.

use crate::contracts::tokens::core::TokenContract;
use crate::integration::crypto_integration::PublicKey;
use super::TreasuryKernel;
use super::interface::{
    KernelOpError, CreditReason, DebitReason, LockReason, ReleaseReason,
    MintAuthorization, BurnAuthorization,
};

impl TreasuryKernel {
    /// Verify that the caller is authorized (kernel address or governance authority)
    fn verify_caller(&self, caller: &PublicKey) -> Result<(), KernelOpError> {
        if self.paused {
            return Err(KernelOpError::Paused);
        }
        if caller == self.kernel_address() || caller == self.governance_authority() {
            Ok(())
        } else {
            Err(KernelOpError::Unauthorized)
        }
    }

    /// Credit tokens to an account
    ///
    /// - `Mint` / `UbiDistribution`: mints new tokens (increases supply)
    /// - `FeeDistribution` / `Reward` / `Transfer`: credits existing tokens (no supply change)
    pub fn credit(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        to: &PublicKey,
        amount: u64,
        reason: CreditReason,
    ) -> Result<(), KernelOpError> {
        self.verify_caller(caller)?;

        match reason {
            CreditReason::Mint | CreditReason::UbiDistribution => {
                token
                    .mint_kernel_only(self.kernel_address(), to, amount)
                    .map_err(|e| {
                        if e.contains("exceed maximum supply") {
                            KernelOpError::ExceedsMaxSupply
                        } else if e.contains("disabled") {
                            KernelOpError::MintingDisabled
                        } else {
                            KernelOpError::Unauthorized
                        }
                    })
            }
            CreditReason::FeeDistribution | CreditReason::Reward | CreditReason::Transfer => {
                token
                    .credit_balance(to, amount)
                    .map_err(|_| KernelOpError::Overflow)
            }
        }
    }

    /// Debit tokens from an account
    ///
    /// - `Burn`: destroys tokens (decreases supply)
    /// - `FeeCollection` / `Slash` / `Transfer`: debits existing tokens (no supply change)
    pub fn debit(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        from: &PublicKey,
        amount: u64,
        reason: DebitReason,
    ) -> Result<(), KernelOpError> {
        self.verify_caller(caller)?;

        match reason {
            DebitReason::Burn => {
                // Bypass kernel_only_mode gate — kernel IS the authority
                let balance = token.balance_of(from);
                if balance < amount {
                    return Err(KernelOpError::InsufficientBalance);
                }
                token.balances.insert(from.clone(), balance - amount);
                token.total_supply = token.total_supply.saturating_sub(amount);
                Ok(())
            }
            DebitReason::FeeCollection | DebitReason::Slash | DebitReason::Transfer => {
                token
                    .debit_balance(from, amount)
                    .map_err(|_| KernelOpError::InsufficientBalance)
            }
        }
    }

    /// Lock tokens in an account (cannot be transferred until released)
    pub fn lock(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        account: &PublicKey,
        amount: u64,
        _reason: LockReason,
    ) -> Result<(), KernelOpError> {
        self.verify_caller(caller)?;

        token
            .lock_balance(account, amount)
            .map_err(|_| KernelOpError::InsufficientBalance)
    }

    /// Release previously locked tokens
    pub fn release(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        account: &PublicKey,
        amount: u64,
        _reason: ReleaseReason,
    ) -> Result<(), KernelOpError> {
        self.verify_caller(caller)?;

        token
            .release_balance(account, amount)
            .map_err(|_| KernelOpError::InsufficientLockedBalance)
    }

    /// Pause all mutation operations (emergency governance action)
    /// Only governance authority can pause.
    pub fn pause(&mut self, caller: &PublicKey) -> Result<(), KernelOpError> {
        if caller != self.governance_authority() {
            return Err(KernelOpError::Unauthorized);
        }
        self.paused = true;
        Ok(())
    }

    /// Unpause mutation operations
    /// Only governance authority can unpause.
    pub fn unpause(&mut self, caller: &PublicKey) -> Result<(), KernelOpError> {
        if caller != self.governance_authority() {
            return Err(KernelOpError::Unauthorized);
        }
        self.paused = false;
        Ok(())
    }

    /// Transfer tokens between accounts via the kernel
    ///
    /// Combines debit from source + credit to destination atomically.
    /// No supply change.
    pub fn transfer(
        &mut self,
        token: &mut TokenContract,
        caller: &PublicKey,
        from: &PublicKey,
        to: &PublicKey,
        amount: u64,
    ) -> Result<(), KernelOpError> {
        self.verify_caller(caller)?;

        // Debit source (respects locked balances)
        token
            .debit_balance(from, amount)
            .map_err(|_| KernelOpError::InsufficientBalance)?;

        // Credit destination
        token
            .credit_balance(to, amount)
            .map_err(|_| KernelOpError::Overflow)?;

        Ok(())
    }

    // ─── Governance-Gated Authorization (M2) ────────────────────────────

    /// Register a mint authorization from a passed DAO proposal.
    /// The authorization becomes executable after the delay period elapses.
    pub fn register_mint_authorization(
        &mut self,
        auth: MintAuthorization,
    ) -> Result<(), KernelOpError> {
        if self.consumed_authorizations.contains(&auth.proposal_id) {
            return Err(KernelOpError::AuthorizationConsumed);
        }
        // Validate that executable_after_epoch respects the configured delay
        // Use saturating_add to handle overflow: if the sum overflows, any executable_after_epoch will be valid
        let minimum_executable_epoch = auth.authorized_at_epoch.saturating_add(self.mint_delay_epochs);
        if auth.executable_after_epoch < minimum_executable_epoch {
            return Err(KernelOpError::DelayNotElapsed);
        }
        self.pending_mint_authorizations.insert(auth.proposal_id, auth);
        Ok(())
    }

    /// Execute a previously registered mint authorization after the delay period.
    ///
    /// Flow: check paused → lookup auth → check consumed → check delay → mint → mark consumed
    pub fn execute_authorized_mint(
        &mut self,
        token: &mut TokenContract,
        proposal_id: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), KernelOpError> {
        if self.paused {
            return Err(KernelOpError::Paused);
        }
        if self.consumed_authorizations.contains(proposal_id) {
            return Err(KernelOpError::AuthorizationConsumed);
        }
        let auth = self.pending_mint_authorizations.get(proposal_id)
            .ok_or(KernelOpError::MissingAuthorization)?
            .clone();
        if auth.consumed {
            return Err(KernelOpError::AuthorizationConsumed);
        }
        if current_epoch < auth.executable_after_epoch {
            return Err(KernelOpError::DelayNotElapsed);
        }

        // Build recipient PublicKey from key_id for mint_kernel_only
        let recipient = PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: auth.recipient_key_id,
        };

        // Execute mint through the existing kernel credit path
        let kernel_addr = self.kernel_address.clone();
        self.credit(token, &kernel_addr, &recipient, auth.authorized_amount, CreditReason::Mint)?;

        // Mark consumed
        self.consumed_authorizations.insert(*proposal_id);
        if let Some(a) = self.pending_mint_authorizations.get_mut(proposal_id) {
            a.consumed = true;
        }
        Ok(())
    }

    /// Register a burn authorization from a passed DAO proposal.
    pub fn register_burn_authorization(
        &mut self,
        auth: BurnAuthorization,
    ) -> Result<(), KernelOpError> {
        if self.consumed_authorizations.contains(&auth.proposal_id) {
            return Err(KernelOpError::AuthorizationConsumed);
        }
        // Validate that executable_after_epoch respects the configured delay
        // Use saturating_add to handle overflow: if the sum overflows, any executable_after_epoch will be valid
        let minimum_executable_epoch = auth.authorized_at_epoch.saturating_add(self.mint_delay_epochs);
        if auth.executable_after_epoch < minimum_executable_epoch {
            return Err(KernelOpError::DelayNotElapsed);
        }
        self.pending_burn_authorizations.insert(auth.proposal_id, auth);
        Ok(())
    }

    /// Execute a previously registered burn authorization after the delay period.
    pub fn execute_authorized_burn(
        &mut self,
        token: &mut TokenContract,
        proposal_id: &[u8; 32],
        current_epoch: u64,
    ) -> Result<(), KernelOpError> {
        if self.paused {
            return Err(KernelOpError::Paused);
        }
        if self.consumed_authorizations.contains(proposal_id) {
            return Err(KernelOpError::AuthorizationConsumed);
        }
        let auth = self.pending_burn_authorizations.get(proposal_id)
            .ok_or(KernelOpError::MissingAuthorization)?
            .clone();
        if auth.consumed {
            return Err(KernelOpError::AuthorizationConsumed);
        }
        if current_epoch < auth.executable_after_epoch {
            return Err(KernelOpError::DelayNotElapsed);
        }

        // Build from PublicKey from key_id
        let from = PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: auth.from_key_id,
        };

        // Execute burn through the existing kernel debit path
        let kernel_addr = self.kernel_address.clone();
        self.debit(token, &kernel_addr, &from, auth.authorized_amount, DebitReason::Burn)?;

        // Mark consumed
        self.consumed_authorizations.insert(*proposal_id);
        if let Some(a) = self.pending_burn_authorizations.get_mut(proposal_id) {
            a.consumed = true;
        }
        Ok(())
    }

    /// Get the configured mint delay in epochs
    pub fn mint_delay_epochs(&self) -> u64 {
        self.mint_delay_epochs
    }

    /// Set mint delay (governance authority only)
    pub fn set_mint_delay_epochs(
        &mut self,
        caller: &PublicKey,
        delay: u64,
    ) -> Result<(), KernelOpError> {
        if caller != self.governance_authority() {
            return Err(KernelOpError::Unauthorized);
        }
        self.mint_delay_epochs = delay;
        Ok(())
    }

    /// Get pending mint authorizations (read-only)
    pub fn pending_mint_authorizations(&self) -> &std::collections::BTreeMap<[u8; 32], MintAuthorization> {
        &self.pending_mint_authorizations
    }

    /// Get pending burn authorizations (read-only)
    pub fn pending_burn_authorizations(&self) -> &std::collections::BTreeMap<[u8; 32], BurnAuthorization> {
        &self.pending_burn_authorizations
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

    fn test_user() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![1u8],
            kyber_pk: vec![1u8],
            key_id: [1u8; 32],
        }
    }

    fn test_recipient() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![2u8],
            kyber_pk: vec![2u8],
            key_id: [2u8; 32],
        }
    }

    fn unauthorized_caller() -> PublicKey {
        PublicKey {
            dilithium_pk: vec![77u8],
            kyber_pk: vec![77u8],
            key_id: [77u8; 32],
        }
    }

    fn setup() -> (TreasuryKernel, TokenContract) {
        let gov = test_governance();
        let kernel_addr = test_kernel_address();
        let kernel = TreasuryKernel::new(gov, kernel_addr.clone(), 60_480);
        let token = TokenContract::new_sov_with_kernel_authority(kernel_addr);
        (kernel, token)
    }

    // ─── Credit tests ───────────────────────────────────────────────────

    #[test]
    fn test_credit_mint_authorized_succeeds() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let recipient = test_recipient();

        let result = kernel.credit(&mut token, &caller, &recipient, 1000, CreditReason::Mint);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&recipient), 1000);
        assert_eq!(token.total_supply, 1000);
    }

    #[test]
    fn test_credit_ubi_distribution_succeeds() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let citizen = test_user();

        let result = kernel.credit(&mut token, &caller, &citizen, 500, CreditReason::UbiDistribution);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&citizen), 500);
    }

    #[test]
    fn test_credit_transfer_no_supply_change() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let recipient = test_recipient();

        // Pre-mint some tokens
        token.mint_kernel_only(kernel.kernel_address(), &recipient, 1000).unwrap();
        let supply_before = token.total_supply;

        // Credit via Transfer reason — no supply change
        let result = kernel.credit(&mut token, &caller, &recipient, 500, CreditReason::Transfer);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&recipient), 1500);
        assert_eq!(token.total_supply, supply_before); // supply unchanged
    }

    #[test]
    fn test_credit_unauthorized_fails() {
        let (mut kernel, mut token) = setup();
        let bad_caller = unauthorized_caller();
        let recipient = test_recipient();

        let result = kernel.credit(&mut token, &bad_caller, &recipient, 1000, CreditReason::Mint);
        assert_eq!(result, Err(KernelOpError::Unauthorized));
        assert_eq!(token.balance_of(&recipient), 0);
    }

    #[test]
    fn test_credit_when_paused_fails() {
        let (mut kernel, mut token) = setup();
        let gov = test_governance();
        let caller = test_kernel_address();
        let recipient = test_recipient();

        kernel.pause(&gov).unwrap();

        let result = kernel.credit(&mut token, &caller, &recipient, 1000, CreditReason::Mint);
        assert_eq!(result, Err(KernelOpError::Paused));
    }

    #[test]
    fn test_credit_governance_authorized() {
        let (mut kernel, mut token) = setup();
        let gov = test_governance();
        let recipient = test_recipient();

        // Governance can also invoke kernel ops (governance IS an authority)
        // But for Mint it uses mint_kernel_only which checks kernel_address, not governance
        // So governance can only do non-mint credits
        let result = kernel.credit(&mut token, &gov, &recipient, 500, CreditReason::Transfer);
        assert!(result.is_ok());
    }

    // ─── Debit tests ────────────────────────────────────────────────────

    #[test]
    fn test_debit_transfer_succeeds() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        // Pre-fund user
        token.mint_kernel_only(kernel.kernel_address(), &user, 1000).unwrap();

        let result = kernel.debit(&mut token, &caller, &user, 300, DebitReason::Transfer);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&user), 700);
    }

    #[test]
    fn test_debit_burn_decreases_supply() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        token.mint_kernel_only(kernel.kernel_address(), &user, 1000).unwrap();
        let supply_before = token.total_supply;

        let result = kernel.debit(&mut token, &caller, &user, 400, DebitReason::Burn);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&user), 600);
        assert_eq!(token.total_supply, supply_before - 400);
    }

    #[test]
    fn test_debit_insufficient_balance_fails() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        // User has 0 balance
        let result = kernel.debit(&mut token, &caller, &user, 100, DebitReason::Transfer);
        assert_eq!(result, Err(KernelOpError::InsufficientBalance));
    }

    #[test]
    fn test_debit_unauthorized_fails() {
        let (mut kernel, mut token) = setup();
        let bad_caller = unauthorized_caller();
        let user = test_user();

        let result = kernel.debit(&mut token, &bad_caller, &user, 100, DebitReason::Transfer);
        assert_eq!(result, Err(KernelOpError::Unauthorized));
    }

    // ─── Lock/Release tests ─────────────────────────────────────────────

    #[test]
    fn test_lock_release_lifecycle() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        // Pre-fund
        token.mint_kernel_only(kernel.kernel_address(), &user, 1000).unwrap();

        // Lock 600
        let result = kernel.lock(&mut token, &caller, &user, 600, LockReason::Staking);
        assert!(result.is_ok());
        assert_eq!(token.available_balance(&user), 400);
        assert_eq!(token.balance_of(&user), 1000); // total unchanged

        // Release 300
        let result = kernel.release(&mut token, &caller, &user, 300, ReleaseReason::Unstaking);
        assert!(result.is_ok());
        assert_eq!(token.available_balance(&user), 700);

        // Release remaining 300
        let result = kernel.release(&mut token, &caller, &user, 300, ReleaseReason::Unstaking);
        assert!(result.is_ok());
        assert_eq!(token.available_balance(&user), 1000);
    }

    #[test]
    fn test_lock_exceeds_available_fails() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        token.mint_kernel_only(kernel.kernel_address(), &user, 500).unwrap();

        let result = kernel.lock(&mut token, &caller, &user, 600, LockReason::Staking);
        assert_eq!(result, Err(KernelOpError::InsufficientBalance));
    }

    #[test]
    fn test_release_exceeds_locked_fails() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        token.mint_kernel_only(kernel.kernel_address(), &user, 1000).unwrap();
        kernel.lock(&mut token, &caller, &user, 400, LockReason::Vesting).unwrap();

        let result = kernel.release(&mut token, &caller, &user, 500, ReleaseReason::VestingRelease);
        assert_eq!(result, Err(KernelOpError::InsufficientLockedBalance));
    }

    #[test]
    fn test_debit_respects_locked_balance() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let user = test_user();

        token.mint_kernel_only(kernel.kernel_address(), &user, 1000).unwrap();
        kernel.lock(&mut token, &caller, &user, 800, LockReason::Staking).unwrap();

        // Only 200 available — debit 300 should fail
        let result = kernel.debit(&mut token, &caller, &user, 300, DebitReason::Transfer);
        assert_eq!(result, Err(KernelOpError::InsufficientBalance));

        // Debit 200 should succeed
        let result = kernel.debit(&mut token, &caller, &user, 200, DebitReason::Transfer);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&user), 800);
    }

    // ─── Pause/Unpause tests ────────────────────────────────────────────

    #[test]
    fn test_pause_unpause_governance_only() {
        let (mut kernel, _) = setup();
        let gov = test_governance();
        let non_gov = test_kernel_address();

        // Non-governance cannot pause
        assert_eq!(kernel.pause(&non_gov), Err(KernelOpError::Unauthorized));

        // Governance can pause
        assert!(kernel.pause(&gov).is_ok());
        assert!(kernel.paused);

        // Non-governance cannot unpause
        assert_eq!(kernel.unpause(&non_gov), Err(KernelOpError::Unauthorized));

        // Governance can unpause
        assert!(kernel.unpause(&gov).is_ok());
        assert!(!kernel.paused);
    }

    #[test]
    fn test_operations_blocked_when_paused() {
        let (mut kernel, mut token) = setup();
        let gov = test_governance();
        let caller = test_kernel_address();
        let user = test_user();

        kernel.pause(&gov).unwrap();

        // All ops should fail with Paused
        assert_eq!(
            kernel.credit(&mut token, &caller, &user, 100, CreditReason::Mint),
            Err(KernelOpError::Paused)
        );
        assert_eq!(
            kernel.debit(&mut token, &caller, &user, 100, DebitReason::Transfer),
            Err(KernelOpError::Paused)
        );
        assert_eq!(
            kernel.lock(&mut token, &caller, &user, 100, LockReason::Staking),
            Err(KernelOpError::Paused)
        );
        assert_eq!(
            kernel.release(&mut token, &caller, &user, 100, ReleaseReason::Unstaking),
            Err(KernelOpError::Paused)
        );

        // Unpause and verify ops work again
        kernel.unpause(&gov).unwrap();
        token.mint_kernel_only(kernel.kernel_address(), &user, 1000).unwrap();
        assert!(kernel.debit(&mut token, &caller, &user, 100, DebitReason::Transfer).is_ok());
    }

    // ─── Transfer tests ─────────────────────────────────────────────────

    #[test]
    fn test_kernel_transfer() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let alice = test_user();
        let bob = test_recipient();

        token.mint_kernel_only(kernel.kernel_address(), &alice, 1000).unwrap();

        let result = kernel.transfer(&mut token, &caller, &alice, &bob, 400);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&alice), 600);
        assert_eq!(token.balance_of(&bob), 400);
        // Supply unchanged
        assert_eq!(token.total_supply, 1000);
    }

    #[test]
    fn test_kernel_transfer_respects_locked() {
        let (mut kernel, mut token) = setup();
        let caller = test_kernel_address();
        let alice = test_user();
        let bob = test_recipient();

        token.mint_kernel_only(kernel.kernel_address(), &alice, 1000).unwrap();
        kernel.lock(&mut token, &caller, &alice, 800, LockReason::Staking).unwrap();

        // Only 200 available — transfer 300 should fail
        let result = kernel.transfer(&mut token, &caller, &alice, &bob, 300);
        assert_eq!(result, Err(KernelOpError::InsufficientBalance));

        // Transfer 200 should succeed
        let result = kernel.transfer(&mut token, &caller, &alice, &bob, 200);
        assert!(result.is_ok());
    }

    // ─── M2: Governance-Gated Authorization Tests ───────────────────────

    use super::super::interface::{MintAuthorization, BurnAuthorization, MintReason};

    fn test_mint_auth(epoch: u64) -> MintAuthorization {
        MintAuthorization {
            proposal_id: [1u8; 32],
            reason: MintReason::TreasuryAllocation,
            authorized_amount: 500,
            recipient_key_id: [1u8; 32],
            authorized_at_epoch: epoch,
            executable_after_epoch: epoch + 1,
            consumed: false,
        }
    }

    fn test_burn_auth(epoch: u64) -> BurnAuthorization {
        BurnAuthorization {
            proposal_id: [2u8; 32],
            authorized_amount: 200,
            from_key_id: [1u8; 32],
            authorized_at_epoch: epoch,
            executable_after_epoch: epoch + 1,
            consumed: false,
        }
    }

    #[test]
    fn test_register_mint_authorization_succeeds() {
        let (mut kernel, _) = setup();
        let auth = test_mint_auth(0);
        let result = kernel.register_mint_authorization(auth);
        assert!(result.is_ok());
        assert_eq!(kernel.pending_mint_authorizations().len(), 1);
    }

    #[test]
    fn test_register_duplicate_authorization_rejected() {
        let (mut kernel, _) = setup();
        let auth = test_mint_auth(0);
        kernel.register_mint_authorization(auth.clone()).unwrap();

        // Simulate consumed by inserting into consumed set
        kernel.consumed_authorizations.insert(auth.proposal_id);

        // Re-register with same proposal_id should fail
        let auth2 = test_mint_auth(0);
        let result = kernel.register_mint_authorization(auth2);
        assert_eq!(result, Err(KernelOpError::AuthorizationConsumed));
    }

    #[test]
    fn test_execute_authorized_mint_after_delay_succeeds() {
        let (mut kernel, mut token) = setup();
        let auth = test_mint_auth(0); // executable_after_epoch = 1
        kernel.register_mint_authorization(auth).unwrap();

        // Execute at epoch 1 (delay elapsed)
        let result = kernel.execute_authorized_mint(&mut token, &[1u8; 32], 1);
        assert!(result.is_ok());

        // Balance is stored under the minimal PublicKey resolved from key_id.
        // In production, key resolution would map key_id to a full PublicKey.
        let recipient = PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: [1u8; 32],
        };
        assert_eq!(token.balance_of(&recipient), 500);
    }

    #[test]
    fn test_execute_authorized_mint_before_delay_fails() {
        let (mut kernel, mut token) = setup();
        let auth = test_mint_auth(0); // executable_after_epoch = 1
        kernel.register_mint_authorization(auth).unwrap();

        // Execute at epoch 0 (delay NOT elapsed)
        let result = kernel.execute_authorized_mint(&mut token, &[1u8; 32], 0);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
    }

    #[test]
    fn test_execute_authorized_mint_when_paused_fails() {
        let (mut kernel, mut token) = setup();
        let auth = test_mint_auth(0);
        kernel.register_mint_authorization(auth).unwrap();

        let gov = test_governance();
        kernel.pause(&gov).unwrap();

        let result = kernel.execute_authorized_mint(&mut token, &[1u8; 32], 1);
        assert_eq!(result, Err(KernelOpError::Paused));
    }

    #[test]
    fn test_execute_authorized_mint_missing_auth_fails() {
        let (mut kernel, mut token) = setup();
        let result = kernel.execute_authorized_mint(&mut token, &[99u8; 32], 1);
        assert_eq!(result, Err(KernelOpError::MissingAuthorization));
    }

    #[test]
    fn test_execute_authorized_mint_consumed_fails() {
        let (mut kernel, mut token) = setup();
        let auth = test_mint_auth(0);
        kernel.register_mint_authorization(auth).unwrap();

        // Execute once — succeeds
        kernel.execute_authorized_mint(&mut token, &[1u8; 32], 1).unwrap();

        // Execute again — consumed
        let result = kernel.execute_authorized_mint(&mut token, &[1u8; 32], 2);
        assert_eq!(result, Err(KernelOpError::AuthorizationConsumed));
    }

    #[test]
    fn test_execute_authorized_mint_exceeds_max_supply_fails() {
        let (mut kernel, mut token) = setup();
        let kernel_addr = test_kernel_address();
        let user = test_user();
        token.mint_kernel_only(&kernel_addr, &user, token.max_supply - 100).unwrap();

        // Now register authorization for 500 (exceeds remaining 100)
        let auth = test_mint_auth(0);
        kernel.register_mint_authorization(auth).unwrap();

        let result = kernel.execute_authorized_mint(&mut token, &[1u8; 32], 1);
        assert_eq!(result, Err(KernelOpError::ExceedsMaxSupply));
    }

    #[test]
    fn test_register_burn_authorization_succeeds() {
        let (mut kernel, _) = setup();
        let auth = test_burn_auth(0);
        let result = kernel.register_burn_authorization(auth);
        assert!(result.is_ok());
        assert_eq!(kernel.pending_burn_authorizations().len(), 1);
    }

    #[test]
    fn test_execute_authorized_burn_after_delay_succeeds() {
        let (mut kernel, mut token) = setup();
        let kernel_addr = test_kernel_address();

        // Pre-fund the minimal key that burn will resolve
        let from = PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: [1u8; 32],
        };
        token.mint_kernel_only(&kernel_addr, &from, 1000).unwrap();

        let auth = test_burn_auth(0); // burn 200, executable_after_epoch = 1
        kernel.register_burn_authorization(auth).unwrap();

        let result = kernel.execute_authorized_burn(&mut token, &[2u8; 32], 1);
        assert!(result.is_ok());
        assert_eq!(token.balance_of(&from), 800);
    }

    #[test]
    fn test_execute_authorized_burn_before_delay_fails() {
        let (mut kernel, mut token) = setup();
        let auth = test_burn_auth(0);
        kernel.register_burn_authorization(auth).unwrap();

        let result = kernel.execute_authorized_burn(&mut token, &[2u8; 32], 0);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
    }

    #[test]
    fn test_execute_authorized_burn_consumed_fails() {
        let (mut kernel, mut token) = setup();
        let kernel_addr = test_kernel_address();

        // Pre-fund the minimal key that burn will resolve
        let from = PublicKey {
            dilithium_pk: Vec::new(),
            kyber_pk: Vec::new(),
            key_id: [1u8; 32],
        };
        token.mint_kernel_only(&kernel_addr, &from, 1000).unwrap();

        let auth = test_burn_auth(0);
        kernel.register_burn_authorization(auth).unwrap();

        kernel.execute_authorized_burn(&mut token, &[2u8; 32], 1).unwrap();
        let result = kernel.execute_authorized_burn(&mut token, &[2u8; 32], 2);
        assert_eq!(result, Err(KernelOpError::AuthorizationConsumed));
    }

    #[test]
    fn test_set_mint_delay_governance_only() {
        let (mut kernel, _) = setup();
        let gov = test_governance();
        let user = test_user();

        // Governance can set delay
        let result = kernel.set_mint_delay_epochs(&gov, 3);
        assert!(result.is_ok());
        assert_eq!(kernel.mint_delay_epochs(), 3);

        // Non-governance cannot
        let result = kernel.set_mint_delay_epochs(&user, 5);
        assert_eq!(result, Err(KernelOpError::Unauthorized));
        assert_eq!(kernel.mint_delay_epochs(), 3); // unchanged
    }

    #[test]
    fn test_mint_delay_default() {
        let (kernel, _) = setup();
        assert_eq!(kernel.mint_delay_epochs(), 1);
    }

    #[test]
    fn test_register_mint_authorization_enforces_delay() {
        let (mut kernel, _) = setup();
        
        // Default delay is 1 epoch
        assert_eq!(kernel.mint_delay_epochs(), 1);
        
        // Try to register authorization with executable_after_epoch < authorized_at_epoch + delay
        let mut auth = test_mint_auth(10); // authorized_at_epoch = 10
        auth.executable_after_epoch = 10; // Should be at least 11
        
        let result = kernel.register_mint_authorization(auth);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
        
        // Verify authorization was not registered
        assert_eq!(kernel.pending_mint_authorizations().len(), 0);
    }

    #[test]
    fn test_register_mint_authorization_respects_delay() {
        let (mut kernel, _) = setup();
        
        // Default delay is 1 epoch
        assert_eq!(kernel.mint_delay_epochs(), 1);
        
        // Register authorization with correct delay
        let mut auth = test_mint_auth(10); // authorized_at_epoch = 10
        auth.executable_after_epoch = 11; // authorized_at_epoch + delay
        
        let result = kernel.register_mint_authorization(auth);
        assert!(result.is_ok());
        
        // Verify authorization was registered
        assert_eq!(kernel.pending_mint_authorizations().len(), 1);
    }

    #[test]
    fn test_register_burn_authorization_enforces_delay() {
        let (mut kernel, _) = setup();
        
        // Default delay is 1 epoch
        assert_eq!(kernel.mint_delay_epochs(), 1);
        
        // Try to register authorization with executable_after_epoch < authorized_at_epoch + delay
        let mut auth = test_burn_auth(10); // authorized_at_epoch = 10
        auth.executable_after_epoch = 10; // Should be at least 11
        
        let result = kernel.register_burn_authorization(auth);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
        
        // Verify authorization was not registered
        assert_eq!(kernel.pending_burn_authorizations().len(), 0);
    }

    #[test]
    fn test_register_burn_authorization_respects_delay() {
        let (mut kernel, _) = setup();
        
        // Default delay is 1 epoch
        assert_eq!(kernel.mint_delay_epochs(), 1);
        
        // Register authorization with correct delay
        let mut auth = test_burn_auth(10); // authorized_at_epoch = 10
        auth.executable_after_epoch = 11; // authorized_at_epoch + delay
        
        let result = kernel.register_burn_authorization(auth);
        assert!(result.is_ok());
        
        // Verify authorization was registered
        assert_eq!(kernel.pending_burn_authorizations().len(), 1);
    }

    #[test]
    fn test_mint_delay_configuration_affects_registration() {
        let (mut kernel, _) = setup();
        let gov = test_governance();
        
        // Set delay to 3 epochs
        kernel.set_mint_delay_epochs(&gov, 3).unwrap();
        assert_eq!(kernel.mint_delay_epochs(), 3);
        
        // Try to register with 1-epoch delay (should fail)
        let mut auth1 = test_mint_auth(10); // authorized_at_epoch = 10
        auth1.executable_after_epoch = 11; // Only 1 epoch delay
        let result = kernel.register_mint_authorization(auth1);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
        
        // Try to register with 2-epoch delay (should fail)
        let mut auth2 = test_mint_auth(10);
        auth2.proposal_id = [2u8; 32]; // Different proposal ID
        auth2.executable_after_epoch = 12; // Only 2 epoch delay
        let result = kernel.register_mint_authorization(auth2);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
        
        // Register with 3-epoch delay (should succeed)
        let mut auth3 = test_mint_auth(10);
        auth3.proposal_id = [3u8; 32]; // Different proposal ID
        auth3.executable_after_epoch = 13; // Exactly 3 epoch delay
        let result = kernel.register_mint_authorization(auth3);
        assert!(result.is_ok());
        
        // Register with > 3-epoch delay (should succeed)
        let mut auth4 = test_mint_auth(10);
        auth4.proposal_id = [4u8; 32]; // Different proposal ID
        auth4.executable_after_epoch = 15; // 5 epoch delay (more than required)
        let result = kernel.register_mint_authorization(auth4);
        assert!(result.is_ok());
        
        // Should have 2 authorizations registered
        assert_eq!(kernel.pending_mint_authorizations().len(), 2);
    }

    #[test]
    fn test_burn_delay_configuration_affects_registration() {
        let (mut kernel, _) = setup();
        let gov = test_governance();
        
        // Set delay to 2 epochs
        kernel.set_mint_delay_epochs(&gov, 2).unwrap();
        assert_eq!(kernel.mint_delay_epochs(), 2);
        
        // Try to register with insufficient delay (should fail)
        let mut auth1 = test_burn_auth(5); // authorized_at_epoch = 5
        auth1.executable_after_epoch = 6; // Only 1 epoch delay, needs 2
        let result = kernel.register_burn_authorization(auth1);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
        
        // Register with correct delay (should succeed)
        let mut auth2 = test_burn_auth(5);
        auth2.proposal_id = [3u8; 32]; // Different proposal ID
        auth2.executable_after_epoch = 7; // Exactly 2 epoch delay
        let result = kernel.register_burn_authorization(auth2);
        assert!(result.is_ok());
        
        assert_eq!(kernel.pending_burn_authorizations().len(), 1);
    }

    #[test]
    fn test_zero_epoch_delay_allowed() {
        let (mut kernel, _) = setup();
        let gov = test_governance();
        
        // Set delay to 0 epochs (immediate execution allowed)
        kernel.set_mint_delay_epochs(&gov, 0).unwrap();
        assert_eq!(kernel.mint_delay_epochs(), 0);
        
        // Register authorization with same epoch for authorization and execution
        let mut auth = test_mint_auth(10); // authorized_at_epoch = 10
        auth.executable_after_epoch = 10; // Same epoch (0 delay)
        
        let result = kernel.register_mint_authorization(auth);
        assert!(result.is_ok());
    }

    #[test]
    fn test_delay_validation_with_large_epochs() {
        let (mut kernel, _) = setup();
        let gov = test_governance();
        
        // Set a large delay
        kernel.set_mint_delay_epochs(&gov, 100).unwrap();
        
        // Register authorization at a large epoch number
        let mut auth = test_mint_auth(1000); // authorized_at_epoch = 1000
        auth.executable_after_epoch = 1100; // authorized_at_epoch + 100
        
        let result = kernel.register_mint_authorization(auth);
        assert!(result.is_ok());
        
        // Try with insufficient delay
        let mut auth2 = test_mint_auth(1000);
        auth2.proposal_id = [5u8; 32];
        auth2.executable_after_epoch = 1099; // Only 99 epochs delay
        
        let result = kernel.register_mint_authorization(auth2);
        assert_eq!(result, Err(KernelOpError::DelayNotElapsed));
    }
}
