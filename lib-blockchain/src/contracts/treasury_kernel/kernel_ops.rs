//! Treasury Kernel Operations — Implementation of the single balance mutation authority
//!
//! Every token balance mutation flows through these methods.
//! Authorization: only `governance_authority` or `kernel_address` may invoke.

use crate::contracts::tokens::core::TokenContract;
use crate::integration::crypto_integration::PublicKey;
use super::TreasuryKernel;
use super::interface::{
    KernelOpError, CreditReason, DebitReason, LockReason, ReleaseReason,
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
}
