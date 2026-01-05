//! Emergency Reserve Contract
//!
//! A custody boundary with audited ledger for protocol emergency funds.
//! Receives credits from fee distributor (15% of fees via canonical allocation).
//! Tracks accumulation per monthly economic period.
//! Allows withdrawals only via multisig approval with ON-CHAIN cryptographic verification.
//!
//! CRITICAL: This contract verifies signatures itself. No delegation to callers or runtime assumptions.
//! A vault is only as strong as its own verification boundary.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::{PublicKey, Signature, hash_data};
use lib_crypto::verify_signature;

/// Emergency Reserve: Multisig-protected custody with on-chain signature verification.
///
/// # Cryptographic Security
/// Withdrawals are authorized only with valid cryptographic signatures from threshold signers.
/// Each signature is verified against a canonical, unambiguous withdrawal message.
/// No public keys or caller trust assumptions—only verified signatures count.
///
/// # Hard Invariants (non-negotiable):
///
/// ## I1: Single Source of Truth for "15%"
/// EmergencyReserve never computes or enforces the 15% allocation.
/// Invariant: credited amounts are accepted as facts.
///
/// ## I2: Credit Authorization
/// Only the canonical fee collector can credit the reserve.
/// Invariant: if caller != authorized_fee_collector then fail with no state change.
///
/// ## I3: Conservation of Value
/// At all times: balance = total_received - total_withdrawn >= 0.
/// Invariant: no value creation, no overflow, no loss. Balance corruption is caught immediately.
///
/// ## I4: Period Monotonicity
/// Period accumulation must be monotonic (no backward time travel).
/// Invariant: reject period_id < last_period_id with no state change.
///
/// ## I5: Multisig Threshold Correctness
/// Withdrawals require valid cryptographic signatures from distinct signers.
/// Invariant: valid_unique_signers >= threshold. Duplicates don't count.
///
/// ## I6: Replay Protection
/// Each withdrawal is bound to a unique nonce that cannot be reused.
/// Invariant: nonce cannot be reused; reuse fails with no state change.
/// Mechanism: Monotonic next_nonce enforcement (cheaper than HashSet).
///
/// ## I7: Canonical Message Verification and Single Initialization
/// Every withdrawal signature is verified against a domain-separated, unambiguous message.
/// Invariant: Message includes (contract_id, to, amount, nonce, expiry_period_id).
/// No concatenation without framing; no ambiguity possible.
/// Invariant: Initialization (via init()) runs exactly once per contract instance.
/// Since init() is a constructor-like function that returns a new instance,
/// re-initialization is impossible by design (not stored with mutable state).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EmergencyReserve {
    // Initialization tracking (Invariant I7)
    initialized: bool,

    // Authorization (Invariant I2)
    authorized_fee_collector: PublicKey,

    // Multisig configuration (Invariant I5)
    signers: Vec<PublicKey>,
    threshold: u8,

    // Fund tracking (Invariant I3)
    total_received: u64,
    total_withdrawn: u64,

    // Period-based accounting (Invariant I4)
    received_by_period: HashMap<u64, u64>,
    last_period_id: u64,

    // Replay protection with monotonic nonce (Invariant I6)
    next_nonce: u64,
    
    // Contract identifier for message signing
    contract_id: [u8; 32],
}

/// Canonical withdrawal message for signature verification.
/// All fields are fixed-width to prevent ambiguity.
struct WithdrawalMessage {
    // Domain separation: "SOV_EMERGENCY_RESERVE_WITHDRAW_V1"
    domain: &'static str,
    // 32-byte contract identifier
    contract_id: [u8; 32],
    // Recipient address (1312 bytes)
    to: Vec<u8>,
    // Amount (u64, 8 bytes, big-endian)
    amount: u64,
    // Nonce (u64, 8 bytes, big-endian)
    nonce: u64,
    // Expiry period (u64, 8 bytes, big-endian)
    expiry_period_id: u64,
}

impl WithdrawalMessage {
    /// Encode the withdrawal message into a canonical byte sequence.
    /// Fixed-width encoding with domain separation prevents ambiguity.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        
        // Domain string (length-prefixed for safety)
        let domain_bytes = self.domain.as_bytes();
        buf.extend_from_slice(&(domain_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(domain_bytes);
        
        // Contract ID (fixed 32 bytes)
        buf.extend_from_slice(&self.contract_id);
        
        // Recipient address (length-prefixed)
        buf.extend_from_slice(&(self.to.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.to);
        
        // Amount (8 bytes, big-endian)
        buf.extend_from_slice(&self.amount.to_be_bytes());
        
        // Nonce (8 bytes, big-endian)
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        
        // Expiry period ID (8 bytes, big-endian)
        buf.extend_from_slice(&self.expiry_period_id.to_be_bytes());
        
        buf
    }
    
    /// Hash the canonical message to produce a message hash for signature verification.
    fn hash(&self) -> Vec<u8> {
        let encoded = self.encode();
        hash_data(&encoded).to_vec()
    }
}

impl EmergencyReserve {
    /// Initialize the emergency reserve with multisig configuration.
    ///
    /// # Parameters:
    /// - authorized_fee_collector: The only address allowed to credit this reserve
    /// - signers: List of addresses that can approve withdrawals
    /// - threshold: Minimum number of distinct signers required for withdrawal approval
    /// - contract_id: This contract's unique identifier (for message signing)
    ///
    /// # Invariants enforced:
    /// - Fee collector is non-zero (Invariant I2)
    /// - All signers are distinct and non-zero (Invariant I5)
    /// - Threshold is within valid range (Invariant I5)
    /// - Initialization runs exactly once (Invariant I7 enforced by constructor semantics)
    pub fn init(
        authorized_fee_collector: PublicKey,
        signers: Vec<PublicKey>,
        threshold: u8,
        contract_id: [u8; 32],
    ) -> Result<Self, String> {
        // Validate fee collector is non-zero
        if authorized_fee_collector.as_bytes().iter().all(|b| *b == 0) {
            return Err("Authorized fee collector cannot be zero address".to_string());
        }

        // Validate signers are non-empty
        if signers.is_empty() {
            return Err("At least one signer required".to_string());
        }

        // Validate all signers are non-zero
        for (idx, signer) in signers.iter().enumerate() {
            if signer.as_bytes().iter().all(|b| *b == 0) {
                return Err(format!("Signer {} cannot be zero address", idx));
            }
        }

        // Validate signers are distinct
        let mut unique_signers = HashSet::new();
        for signer in &signers {
            if !unique_signers.insert(signer.clone()) {
                return Err("Duplicate signer detected".to_string());
            }
        }

        // Validate threshold is within valid range
        if threshold == 0 || threshold > signers.len() as u8 {
            return Err(format!(
                "Threshold must be between 1 and {} (number of signers)",
                signers.len()
            ));
        }

        Ok(EmergencyReserve {
            initialized: true,
            authorized_fee_collector,
            signers,
            threshold,
            total_received: 0,
            total_withdrawn: 0,
            received_by_period: HashMap::new(),
            last_period_id: 0,
            next_nonce: 1,
            contract_id,
        })
    }

    /// Credit the emergency reserve with funds from the fee distributor.
    ///
    /// # Parameters:
    /// - caller: The address attempting to credit (must be authorized_fee_collector)
    /// - amount: The amount to credit (must be > 0)
    /// - period_id: The economic period this credit belongs to (must be >= last_period_id)
    ///
    /// # Invariants enforced:
    /// - Only authorized fee collector can credit (Invariant I2)
    /// - Period must be monotonic (Invariant I4)
    /// - Amount must be > 0
    /// - Total received is monotonically increasing (Invariant I3)
    /// - No percentage math (Invariant I1)
    pub fn credit(
        &mut self,
        caller: &PublicKey,
        amount: u64,
        period_id: u64,
    ) -> Result<(), String> {
        // PRE-VALIDATE: all checks before any mutation

        // Authorization check (Invariant I2)
        if caller != &self.authorized_fee_collector {
            return Err("Only authorized fee collector can credit reserve".to_string());
        }

        // Reject zero amounts
        if amount == 0 {
            return Err("Cannot credit zero amount".to_string());
        }

        // Check overflow
        if self.total_received.checked_add(amount).is_none() {
            return Err("Credit would cause total_received to overflow".to_string());
        }

        // Period monotonicity check (Invariant I4)
        if period_id < self.last_period_id {
            return Err(format!(
                "Period moved backwards: {} < {}",
                period_id, self.last_period_id
            ));
        }

        // MUTATE: only after all validations pass
        self.total_received += amount;
        self.last_period_id = period_id;

        // Track per-period accumulation (Invariant I4)
        let period_sum = self.received_by_period.entry(period_id).or_insert(0);
        *period_sum += amount;

        Ok(())
    }

    /// Withdraw funds via multisig approval with on-chain signature verification.
    ///
    /// # Parameters:
    /// - to: Recipient address (must be non-zero)
    /// - amount: Amount to withdraw (must be > 0 and <= balance)
    /// - nonce: Expected nonce value (must equal next_nonce for monotonic replay protection)
    /// - expiry_period_id: Withdrawal expires after this period (bounds the validity)
    /// - current_period_id: Current economic period (for expiry validation)
    /// - sigs: List of valid cryptographic signatures from signers
    ///
    /// # Invariants enforced:
    /// - Signatures are cryptographically verified (Invariant I7)
    /// - Withdrawal must be multisig-approved with valid signatures (Invariant I5)
    /// - Nonce must be monotonically increasing (Invariant I6: Replay Protection)
    /// - Amount <= balance (Invariant I3)
    /// - Only valid, distinct signers count (Invariant I5)
    /// - No value loss (Invariant I3)
    /// - All validations complete before any state mutation
    pub fn withdraw(
        &mut self,
        to: &PublicKey,
        amount: u64,
        nonce: u64,
        expiry_period_id: u64,
        current_period_id: u64,
        sigs: &[Signature],
    ) -> Result<(), String> {
        // PRE-VALIDATE: all checks before any mutation

        // Validate recipient is non-zero
        if to.as_bytes().iter().all(|b| *b == 0) {
            return Err("Recipient address cannot be zero".to_string());
        }

        // Validate amount > 0
        if amount == 0 {
            return Err("Cannot withdraw zero amount".to_string());
        }

        // Validate amount <= balance (Invariant I3: Conservation)
        let balance = self.balance()?;
        if amount > balance {
            return Err(format!(
                "Insufficient balance: {} > {}",
                amount, balance
            ));
        }

        // Monotonic nonce check (Invariant I6: Replay Protection)
        if nonce != self.next_nonce {
            return Err(format!(
                "Nonce mismatch: expected {}, got {}",
                self.next_nonce, nonce
            ));
        }

        // Check withdrawal not expired
        if current_period_id > expiry_period_id {
            return Err(format!(
                "Withdrawal expired: current_period {} > expiry_period {}",
                current_period_id, expiry_period_id
            ));
        }

        // Construct the canonical withdrawal message
        let message = WithdrawalMessage {
            domain: "SOV_EMERGENCY_RESERVE_WITHDRAW_V1",
            contract_id: self.contract_id,
            to: to.as_bytes().to_vec(),
            amount,
            nonce,
            expiry_period_id,
        };
        
        let message_hash = message.hash();

        // Verify signatures and collect valid signers (Invariant I5 + I7)
        // For each signature, try to verify it against all known signers
        // A signature is valid if exactly one signer can verify it
        // Only unique signers count toward the threshold
        let mut valid_signers = HashSet::new();
        
        for sig in sigs {
            // Try to find which signer created this signature
            for signer in &self.signers {
                let signer_bytes = signer.as_bytes();
                match verify_signature(&message_hash, &sig.signature, &signer_bytes) {
                    Ok(true) => {
                        // Valid signature from this signer - add to set (ensures uniqueness)
                        valid_signers.insert(signer.clone());
                        break; // Move to next signature
                    }
                    Ok(false) | Err(_) => {
                        // Invalid signature from this signer, try next signer
                        continue;
                    }
                }
            }
            
            // If no signer could verify this signature, the signature is invalid
            // We continue processing other signatures but the invalid ones don't count
            // This is intentional: garbage signatures don't reduce valid signature count
        }

        // Check threshold met (Invariant I5)
        if valid_signers.len() < self.threshold as usize {
            return Err(format!(
                "Insufficient valid signatures: {} < {} required",
                valid_signers.len(),
                self.threshold
            ));
        }

        // MUTATE: only after all validations pass (atomic update)
        self.total_withdrawn += amount;
        self.next_nonce += 1;

        Ok(())
    }

    /// Get the current balance of the reserve.
    /// Balance = total_received - total_withdrawn (Invariant I3)
    /// Returns error if balance would underflow (corruption detection)
    pub fn balance(&self) -> Result<u64, String> {
        self.total_received
            .checked_sub(self.total_withdrawn)
            .ok_or_else(|| {
                format!(
                    "CRITICAL: Balance corruption detected! total_received ({}) < total_withdrawn ({})",
                    self.total_received, self.total_withdrawn
                )
            })
    }

    /// Get total amount received by the reserve.
    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    /// Get total amount withdrawn from the reserve.
    pub fn total_withdrawn(&self) -> u64 {
        self.total_withdrawn
    }

    /// Get amount received in a specific period.
    pub fn received_for_period(&self, period_id: u64) -> u64 {
        *self.received_by_period.get(&period_id).unwrap_or(&0)
    }

    /// Get the last recorded period ID.
    pub fn last_period_id(&self) -> u64 {
        self.last_period_id
    }

    /// Get the multisig configuration.
    pub fn multisig_config(&self) -> (usize, u8) {
        (self.signers.len(), self.threshold)
    }

    /// Get the next expected nonce for withdrawals.
    pub fn next_nonce(&self) -> u64 {
        self.next_nonce
    }

    /// Get all signers (for testing).
    pub fn signers(&self) -> &[PublicKey] {
        &self.signers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    fn create_test_contract_id(id: u8) -> [u8; 32] {
        [id; 32]
    }

    /// Helper: Create a message to sign and return both the message bytes and the signature bytes
    /// This simulates what would be done during withdrawal authorization
    fn create_withdrawal_signature(
        keypair: &KeyPair,
        contract_id: &[u8; 32],
        to: &PublicKey,
        amount: u64,
        nonce: u64,
        expiry_period_id: u64,
    ) -> Result<Signature, String> {
        // Build the same message structure used in withdraw()
        let message = WithdrawalMessage {
            domain: "SOV_EMERGENCY_RESERVE_WITHDRAW_V1",
            contract_id: *contract_id,
            to: to.as_bytes().to_vec(),
            amount,
            nonce,
            expiry_period_id,
        };
        
        let message_hash = message.hash();
        
        // Sign the message hash using the keypair
        // keypair.sign() returns a Signature object, extract the signature bytes
        let signature_obj = keypair.sign(&message_hash)
            .map_err(|e| format!("Failed to sign message: {:?}", e))?;
        
        Ok(Signature {
            signature: signature_obj.signature,
            public_key: keypair.public_key,
            algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        })
    }

    // ============================================================================
    // INITIALIZATION TESTS
    // ============================================================================

    #[test]
    fn test_init_with_valid_config() {
        let fee_collector = create_test_public_key(1);
        let signer1 = create_test_public_key(10);
        let signer2 = create_test_public_key(11);
        let signer3 = create_test_public_key(12);
        let contract_id = create_test_contract_id(100);

        let reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer1, signer2, signer3],
            2,
            contract_id,
        )
        .expect("Should initialize");

        assert_eq!(reserve.total_received(), 0);
        assert_eq!(reserve.total_withdrawn(), 0);
        assert!(reserve.balance().is_ok());
        assert_eq!(reserve.balance().unwrap(), 0);
        assert_eq!(reserve.multisig_config(), (3, 2));
        assert_eq!(reserve.next_nonce(), 1);
    }

    #[test]
    fn test_init_rejects_zero_fee_collector() {
        let zero_fee_collector = PublicKey::new(vec![0u8; 1312]);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let result = EmergencyReserve::init(zero_fee_collector, vec![signer], 1, contract_id);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("fee collector"));
    }

    #[test]
    fn test_init_rejects_duplicate_signers() {
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let result = EmergencyReserve::init(
            fee_collector,
            vec![signer.clone(), signer.clone()],
            1,
            contract_id,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Duplicate"));
    }

    // ============================================================================
    // CREDIT TESTS
    // ============================================================================

    #[test]
    fn test_authorized_credit_succeeds() {
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        let amount = 1_000_000u64;
        reserve
            .credit(&fee_collector, amount, 1)
            .expect("Should credit");

        assert_eq!(reserve.total_received(), amount);
        assert_eq!(reserve.received_for_period(1), amount);
        assert_eq!(reserve.balance().unwrap(), amount);
    }

    #[test]
    fn test_unauthorized_credit_rejected() {
        let fee_collector = create_test_public_key(1);
        let unauthorized = create_test_public_key(2);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector, vec![signer], 1, contract_id)
                .expect("Should initialize");

        let result = reserve.credit(&unauthorized, 1_000_000, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("authorized"));
        assert_eq!(reserve.total_received(), 0); // No mutation
    }

    #[test]
    fn test_period_monotonicity_enforced() {
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        // Credit period 5
        reserve.credit(&fee_collector, 100, 5).expect("Should credit period 5");

        // Try to credit period 3 (earlier)
        let result = reserve.credit(&fee_collector, 100, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("backwards"));
        assert_eq!(reserve.total_received(), 100);
    }

    // ============================================================================
    // WITHDRAWAL TESTS - SIGNATURE VERIFICATION
    // ============================================================================

    #[test]
    fn test_withdraw_requires_valid_signatures() {
        // CRITICAL: Passing random bytes instead of valid signatures must fail
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);
        
        // Create an invalid signature (random bytes)
        let invalid_sig = Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey::new(vec![0u8; 1312]),
            algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };

        let result = reserve.withdraw(
            &recipient,
            500_000,
            1,
            10,
            5,
            &[invalid_sig],
        );

        // Invalid signatures must fail
        assert!(result.is_err());
        assert!(reserve.balance().unwrap() == 1_000_000); // No withdrawal
        assert_eq!(reserve.next_nonce(), 1); // Nonce not incremented
    }

    #[test]
    fn test_withdraw_nonce_monotonicity() {
        // CRITICAL: Nonce must match next_nonce exactly (Invariant I6)
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);
        let invalid_sig = Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey::new(vec![0u8; 1312]),
            algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };

        // Try nonce 5 when next_nonce is 1
        let result = reserve.withdraw(
            &recipient,
            500_000,
            5, // Wrong nonce
            10,
            5,
            &[invalid_sig],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Nonce mismatch"));
        assert_eq!(reserve.next_nonce(), 1); // Not incremented
    }

    #[test]
    fn test_withdraw_expired_fails() {
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);
        let invalid_sig = Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey::new(vec![0u8; 1312]),
            algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };

        let result = reserve.withdraw(
            &recipient,
            500_000,
            1,
            5,  // expiry_period_id = 5
            10, // current_period_id = 10 (expired!)
            &[invalid_sig],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
    }

    #[test]
    fn test_withdraw_insufficient_balance_fails() {
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        reserve
            .credit(&fee_collector, 500_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);
        let invalid_sig = Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey::new(vec![0u8; 1312]),
            algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };

        // Try to withdraw more than balance
        let result = reserve.withdraw(
            &recipient,
            1_000_000, // More than 500k balance
            1,
            10,
            5,
            &[invalid_sig],
        );

        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient balance"));
    }

    // ============================================================================
    // CONSERVATION INVARIANT TESTS
    // ============================================================================

    #[test]
    fn test_conservation_invariant_enforced() {
        // Invariant I3: balance() strictly checks total_received >= total_withdrawn
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        // Credit
        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");
        assert_eq!(reserve.balance().unwrap(), 1_000_000);

        // Manually corrupt total_withdrawn to trigger detection
        reserve.total_withdrawn = 2_000_000; // > total_received

        // balance() must catch this corruption
        let result = reserve.balance();
        assert!(result.is_err());
        let error_msg = result.unwrap_err();
        assert!(error_msg.contains("CRITICAL"));
        assert!(error_msg.contains("corruption"));
    }

    // ============================================================================
    // INTEGRATION TESTS
    // ============================================================================

    #[test]
    fn test_year_5_scenario_monthly_credit() {
        // Year 5: $5B monthly volume → $50M monthly fee → $7.5M monthly to reserve
        let fee_collector = create_test_public_key(1);
        let signer = create_test_public_key(10);
        let contract_id = create_test_contract_id(100);

        let mut reserve =
            EmergencyReserve::init(fee_collector.clone(), vec![signer], 1, contract_id)
                .expect("Should initialize");

        let monthly_amount = 7_500_000u64; // $7.5M per month

        // Simulate 3 months of Year 5
        for month in 1..=3 {
            reserve
                .credit(&fee_collector, monthly_amount, month)
                .expect(&format!("Should credit month {}", month));
        }

        // Verify accumulation
        assert_eq!(reserve.total_received(), monthly_amount * 3);
        assert_eq!(reserve.received_for_period(1), monthly_amount);
        assert_eq!(reserve.received_for_period(2), monthly_amount);
        assert_eq!(reserve.received_for_period(3), monthly_amount);
        assert_eq!(reserve.balance().unwrap(), monthly_amount * 3);
    }

    #[test]
    fn test_no_mutation_on_validation_failure() {
        // CRITICAL: Any validation failure leaves state completely unchanged
        let fee_collector = create_test_public_key(1);
        let signer1 = create_test_public_key(10);
        let signer2 = create_test_public_key(11);
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer1, signer2],
            2, // 2-of-2 multisig
            contract_id,
        )
        .expect("Should initialize");

        // Credit some funds
        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let initial_balance = reserve.balance().unwrap();
        let initial_nonce = reserve.next_nonce();
        let initial_withdrawn = reserve.total_withdrawn();

        let recipient = create_test_public_key(200);
        
        // Try invalid withdrawal (bad signatures)
        let _ = reserve.withdraw(
            &recipient,
            500_000,
            1,
            10,
            5,
            &[Signature { 
                signature: vec![0u8; 64],
                public_key: PublicKey::new(vec![0u8; 1312]),
                algorithm: lib_crypto::types::signatures::SignatureAlgorithm::Dilithium5,
                timestamp: 0,
            }], // Invalid
        );

        // Verify NO state changed
        assert_eq!(reserve.balance().unwrap(), initial_balance);
        assert_eq!(reserve.next_nonce(), initial_nonce);
        assert_eq!(reserve.total_withdrawn(), initial_withdrawn);
    }

    // ============================================================================
    // COMPREHENSIVE INTEGRATION TESTS WITH REAL SIGNATURES
    // ============================================================================

    #[test]
    fn test_valid_threshold_signatures_allow_withdrawal() {
        // Test that valid signatures from threshold signers authorize withdrawal
        let fee_collector = create_test_public_key(1);
        
        // Create keypairs for signers
        let signer1_keypair = KeyPair::generate()
            .expect("Should create keypair 1");
        let signer1_pubkey = signer1_keypair.public_key;
        
        let signer2_keypair = KeyPair::generate()
            .expect("Should create keypair 2");
        let signer2_pubkey = signer2_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        // Initialize with 2-of-2 multisig
        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer1_pubkey.clone(), signer2_pubkey.clone()],
            2, // 2-of-2 multisig
            contract_id,
        )
        .expect("Should initialize");

        // Credit funds
        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // Create valid signatures from both signers
        let sig1 = create_withdrawal_signature(
            &signer1_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            10,
        )
        .expect("Should create signature 1");

        let sig2 = create_withdrawal_signature(
            &signer2_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            10,
        )
        .expect("Should create signature 2");

        // Withdraw with valid signatures
        let result = reserve.withdraw(
            &recipient,
            500_000,
            1,
            10,
            5,
            &[sig1, sig2],
        );

        // Should succeed with threshold met
        assert!(result.is_ok(), "Withdrawal should succeed with 2-of-2 valid signatures");
        assert_eq!(reserve.total_withdrawn(), 500_000);
        assert_eq!(reserve.next_nonce(), 2); // Nonce incremented
        assert_eq!(reserve.balance().unwrap(), 500_000); // Half remaining
    }

    #[test]
    fn test_below_threshold_signatures_fail() {
        // Test that below-threshold valid signatures fail
        let fee_collector = create_test_public_key(1);
        
        let signer1_keypair = KeyPair::generate().expect("Should create keypair 1");
        let signer1_pubkey = signer1_keypair.public_key;
        
        let signer2_keypair = KeyPair::generate().expect("Should create keypair 2");
        let signer2_pubkey = signer2_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer1_pubkey.clone(), signer2_pubkey],
            2, // 2-of-2 multisig
            contract_id,
        )
        .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // Only one valid signature (need 2)
        let sig1 = create_withdrawal_signature(
            &signer1_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            10,
        )
        .expect("Should create signature");

        let result = reserve.withdraw(
            &recipient,
            500_000,
            1,
            10,
            5,
            &[sig1],
        );

        // Should fail - only 1 valid signature, need 2
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient valid signatures"));
        
        // State should be unchanged
        assert_eq!(reserve.balance().unwrap(), 1_000_000);
        assert_eq!(reserve.next_nonce(), 1);
    }

    #[test]
    fn test_signature_for_different_amount_fails() {
        // Test that signatures for a different amount are rejected
        let fee_collector = create_test_public_key(1);
        
        let signer_keypair = KeyPair::generate().expect("Should create keypair");
        let signer_pubkey = signer_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer_pubkey],
            1, // 1-of-1 multisig
            contract_id,
        )
        .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // Sign for 500_000
        let sig = create_withdrawal_signature(
            &signer_keypair,
            &contract_id,
            &recipient,
            500_000, // Signed for this amount
            1,
            10,
        )
        .expect("Should create signature");

        // Try to withdraw 300_000 (different amount)
        let result = reserve.withdraw(
            &recipient,
            300_000, // But trying to withdraw this amount
            1,
            10,
            5,
            &[sig],
        );

        // Should fail - signature is for different message
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient valid signatures"));
        
        // State unchanged
        assert_eq!(reserve.balance().unwrap(), 1_000_000);
        assert_eq!(reserve.next_nonce(), 1);
    }

    #[test]
    fn test_nonce_replay_protection() {
        // Test that the same nonce cannot be used twice
        let fee_collector = create_test_public_key(1);
        
        let signer_keypair = KeyPair::generate().expect("Should create keypair");
        let signer_pubkey = signer_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer_pubkey],
            1,
            contract_id,
        )
        .expect("Should initialize");

        reserve
            .credit(&fee_collector, 2_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // First withdrawal with nonce 1
        let sig1 = create_withdrawal_signature(
            &signer_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            10,
        )
        .expect("Should create signature");

        reserve
            .withdraw(&recipient, 500_000, 1, 10, 5, &[sig1])
            .expect("First withdrawal should succeed");

        assert_eq!(reserve.next_nonce(), 2);

        // Try to use same nonce again
        let sig2 = create_withdrawal_signature(
            &signer_keypair,
            &contract_id,
            &recipient,
            600_000,
            1, // Same nonce!
            10,
        )
        .expect("Should create second signature");

        let result = reserve.withdraw(
            &recipient,
            600_000,
            1, // This nonce is now invalid
            10,
            5,
            &[sig2],
        );

        // Should fail - nonce already used
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Nonce mismatch"));
        
        // State unchanged
        assert_eq!(reserve.total_withdrawn(), 500_000);
        assert_eq!(reserve.next_nonce(), 2);
    }

    #[test]
    fn test_duplicate_signer_counted_once() {
        // Test that passing the same signature twice doesn't double-count the signer
        let fee_collector = create_test_public_key(1);
        
        let signer_keypair = KeyPair::generate().expect("Should create keypair");
        let signer_pubkey = signer_keypair.public_key;
        
        let signer2_keypair = KeyPair::generate().expect("Should create keypair 2");
        let signer2_pubkey = signer2_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer_pubkey, signer2_pubkey],
            2, // 2-of-2 multisig
            contract_id,
        )
        .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // Create signature from signer1
        let sig1 = create_withdrawal_signature(
            &signer_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            10,
        )
        .expect("Should create signature");

        // Try to pass same signature twice (duplicate signer)
        let result = reserve.withdraw(
            &recipient,
            500_000,
            1,
            10,
            5,
            &[sig1.clone(), sig1], // Same signer twice
        );

        // Should fail - only 1 unique signer, need 2
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Insufficient valid signatures"));
        
        // State unchanged
        assert_eq!(reserve.balance().unwrap(), 1_000_000);
        assert_eq!(reserve.next_nonce(), 1);
    }

    #[test]
    fn test_expired_withdrawal_rejected() {
        // Test that withdrawals with expired expiry_period_id are rejected
        let fee_collector = create_test_public_key(1);
        
        let signer_keypair = KeyPair::generate().expect("Should create keypair");
        let signer_pubkey = signer_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer_pubkey],
            1,
            contract_id,
        )
        .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // Sign for expiry at period 5
        let sig = create_withdrawal_signature(
            &signer_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            5, // Expires at period 5
        )
        .expect("Should create signature");

        // But current period is 10 (expired!)
        let result = reserve.withdraw(
            &recipient,
            500_000,
            1,
            5, // expiry_period_id
            10, // current_period_id (past expiry)
            &[sig],
        );

        // Should fail - withdrawal expired
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("expired"));
        
        // State unchanged
        assert_eq!(reserve.balance().unwrap(), 1_000_000);
        assert_eq!(reserve.next_nonce(), 1);
    }

    #[test]
    fn test_atomic_failure_on_any_validation() {
        // CRITICAL: Verify that ANY validation failure leaves ALL state unchanged
        // This tests the atomicity guarantee: all checks before any mutation
        let fee_collector = create_test_public_key(1);
        
        let signer1_keypair = KeyPair::generate().expect("Should create keypair 1");
        let signer1_pubkey = signer1_keypair.public_key;
        
        let signer2_keypair = KeyPair::generate().expect("Should create keypair 2");
        let signer2_pubkey = signer2_keypair.public_key;
        
        let contract_id = create_test_contract_id(100);

        let mut reserve = EmergencyReserve::init(
            fee_collector.clone(),
            vec![signer1_pubkey.clone(), signer2_pubkey],
            2,
            contract_id,
        )
        .expect("Should initialize");

        reserve
            .credit(&fee_collector, 1_000_000, 1)
            .expect("Should credit");

        let recipient = create_test_public_key(200);

        // Create a valid signature from signer1 for nonce 1
        let valid_sig = create_withdrawal_signature(
            &signer1_keypair,
            &contract_id,
            &recipient,
            500_000,
            1,
            10,
        )
        .expect("Should create signature");

        let initial_balance = reserve.balance().unwrap();
        let initial_nonce = reserve.next_nonce();
        let initial_total_withdrawn = reserve.total_withdrawn();

        // Try withdrawal with only 1 signature (need 2)
        // This fails the threshold check, but the point is that even this
        // failure should not modify state
        let _ = reserve.withdraw(
            &recipient,
            500_000,
            1,
            10,
            5,
            &[valid_sig], // Only 1 valid signature, need 2
        );

        // Verify absolutely NO state changed
        assert_eq!(reserve.balance().unwrap(), initial_balance);
        assert_eq!(reserve.next_nonce(), initial_nonce);
        assert_eq!(reserve.total_withdrawn(), initial_total_withdrawn);
    }
}
