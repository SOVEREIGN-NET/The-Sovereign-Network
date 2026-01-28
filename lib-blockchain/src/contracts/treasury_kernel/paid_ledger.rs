//! Paid Ledger - Double Payment Prevention
//!
//! The Paid Ledger tracks completed payments to prevent double-payment.
//! Once a payment is recorded, it cannot be repeated.
//!
//! # Key Invariant
//! A (epoch, assignment_id) pair can only be paid ONCE.
//!
//! # Consensus-Critical
//! Uses BTreeMap for deterministic iteration.

use super::payout_types::{ComputationHash, PaymentError, PaymentRecord, TransactionId};
use super::role_types::AssignmentId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Key for payment lookup: (epoch, assignment_id)
type PaymentKey = (u64, AssignmentId);

/// Paid Ledger - prevents double payment
///
/// Stores completed payments keyed by (epoch, assignment_id).
/// Each combination can only be paid once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaidLedger {
    /// Payment records keyed by (epoch, assignment_id)
    payments: BTreeMap<PaymentKey, PaymentRecord>,

    /// Total amount paid across all time
    total_paid: u64,

    /// Total number of payments
    payment_count: u64,
}

impl PaidLedger {
    /// Create a new paid ledger
    pub fn new() -> Self {
        Self {
            payments: BTreeMap::new(),
            total_paid: 0,
            payment_count: 0,
        }
    }

    /// Record a payment - prevents double payment
    ///
    /// # Arguments
    /// * `epoch` - Epoch of the payment
    /// * `assignment_id` - Assignment that was paid
    /// * `amount` - Amount paid
    /// * `computation_hash` - Hash of the computation (for verification)
    /// * `paid_at_epoch` - Current epoch when recording
    /// * `transaction_id` - Transaction ID of the credit operation
    ///
    /// # Returns
    /// Ok(()) if recorded successfully
    /// Err(AlreadyPaid) if already paid for this epoch/assignment
    pub fn record_payment(
        &mut self,
        epoch: u64,
        assignment_id: &AssignmentId,
        amount: u64,
        computation_hash: ComputationHash,
        paid_at_epoch: u64,
        transaction_id: TransactionId,
    ) -> Result<(), PaymentError> {
        let key = (epoch, *assignment_id);

        // Check for existing payment
        if let Some(existing) = self.payments.get(&key) {
            return Err(PaymentError::AlreadyPaid {
                epoch,
                assignment_id: *assignment_id,
                existing_tx: existing.transaction_id,
            });
        }

        // Record payment
        let record = PaymentRecord::new(
            epoch,
            *assignment_id,
            amount,
            computation_hash,
            paid_at_epoch,
            transaction_id,
        );

        self.payments.insert(key, record);
        self.total_paid = self.total_paid.saturating_add(amount);
        self.payment_count += 1;

        Ok(())
    }

    /// Check if already paid for a given epoch/assignment
    pub fn is_paid(&self, epoch: u64, assignment_id: &AssignmentId) -> bool {
        self.payments.contains_key(&(epoch, *assignment_id))
    }

    /// Get payment record
    pub fn get_payment(
        &self,
        epoch: u64,
        assignment_id: &AssignmentId,
    ) -> Result<&PaymentRecord, PaymentError> {
        self.payments
            .get(&(epoch, *assignment_id))
            .ok_or(PaymentError::PaymentNotFound {
                epoch,
                assignment_id: *assignment_id,
            })
    }

    /// Get all payments for an assignment
    pub fn get_payments_for_assignment(&self, assignment_id: &AssignmentId) -> Vec<&PaymentRecord> {
        self.payments
            .iter()
            .filter(|(k, _)| &k.1 == assignment_id)
            .map(|(_, v)| v)
            .collect()
    }

    /// Get all payments for an epoch
    pub fn get_payments_for_epoch(&self, epoch: u64) -> Vec<&PaymentRecord> {
        self.payments
            .iter()
            .filter(|(k, _)| k.0 == epoch)
            .map(|(_, v)| v)
            .collect()
    }

    /// Get total paid to an assignment across all epochs
    pub fn total_paid_to_assignment(&self, assignment_id: &AssignmentId) -> u64 {
        self.payments
            .iter()
            .filter(|(k, _)| &k.1 == assignment_id)
            .map(|(_, v)| v.amount)
            .sum()
    }

    /// Get total paid in an epoch
    pub fn total_paid_in_epoch(&self, epoch: u64) -> u64 {
        self.payments
            .iter()
            .filter(|(k, _)| k.0 == epoch)
            .map(|(_, v)| v.amount)
            .sum()
    }

    /// Get total payments across all time
    pub fn total_paid(&self) -> u64 {
        self.total_paid
    }

    /// Get total payment count
    pub fn payment_count(&self) -> u64 {
        self.payment_count
    }

    /// Verify a payment matches expected hash
    pub fn verify_payment(
        &self,
        epoch: u64,
        assignment_id: &AssignmentId,
        expected_hash: &ComputationHash,
    ) -> Result<bool, PaymentError> {
        let record = self.get_payment(epoch, assignment_id)?;
        Ok(&record.computation_hash == expected_hash)
    }
}

impl Default for PaidLedger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_assignment_id(n: u8) -> AssignmentId {
        [n; 32]
    }

    fn test_tx_id(n: u8) -> TransactionId {
        [n; 32]
    }

    fn test_hash(n: u8) -> ComputationHash {
        [n; 32]
    }

    #[test]
    fn test_record_payment() {
        let mut ledger = PaidLedger::new();

        let result = ledger.record_payment(
            1,
            &test_assignment_id(10),
            50_000,
            test_hash(1),
            2,
            test_tx_id(1),
        );

        assert!(result.is_ok());
        assert!(ledger.is_paid(1, &test_assignment_id(10)));
        assert_eq!(ledger.total_paid(), 50_000);
        assert_eq!(ledger.payment_count(), 1);
    }

    #[test]
    fn test_double_payment_fails() {
        let mut ledger = PaidLedger::new();

        // First payment succeeds
        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();

        // Second payment for same epoch/assignment fails
        let result = ledger.record_payment(
            1,
            &test_assignment_id(10),
            50_000,
            test_hash(2),
            3,
            test_tx_id(2),
        );

        assert!(matches!(result, Err(PaymentError::AlreadyPaid { .. })));
    }

    #[test]
    fn test_different_epochs_allowed() {
        let mut ledger = PaidLedger::new();

        // Epoch 1
        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();

        // Epoch 2 - same assignment, different epoch - should succeed
        let result = ledger.record_payment(
            2,
            &test_assignment_id(10),
            60_000,
            test_hash(2),
            3,
            test_tx_id(2),
        );

        assert!(result.is_ok());
        assert_eq!(ledger.total_paid(), 110_000);
    }

    #[test]
    fn test_different_assignments_same_epoch() {
        let mut ledger = PaidLedger::new();

        // Alice
        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();

        // Bob - same epoch, different assignment - should succeed
        let result = ledger.record_payment(
            1,
            &test_assignment_id(11),
            60_000,
            test_hash(2),
            2,
            test_tx_id(2),
        );

        assert!(result.is_ok());
        assert_eq!(ledger.total_paid_in_epoch(1), 110_000);
    }

    #[test]
    fn test_get_payment() {
        let mut ledger = PaidLedger::new();

        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();

        let record = ledger.get_payment(1, &test_assignment_id(10)).unwrap();
        assert_eq!(record.amount, 50_000);
        assert_eq!(record.computation_hash, test_hash(1));
    }

    #[test]
    fn test_get_payment_not_found() {
        let ledger = PaidLedger::new();

        let result = ledger.get_payment(1, &test_assignment_id(10));
        assert!(matches!(result, Err(PaymentError::PaymentNotFound { .. })));
    }

    #[test]
    fn test_total_paid_to_assignment() {
        let mut ledger = PaidLedger::new();

        // Multiple epochs for same assignment
        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();
        ledger
            .record_payment(2, &test_assignment_id(10), 60_000, test_hash(2), 3, test_tx_id(2))
            .unwrap();
        ledger
            .record_payment(3, &test_assignment_id(10), 70_000, test_hash(3), 4, test_tx_id(3))
            .unwrap();

        assert_eq!(ledger.total_paid_to_assignment(&test_assignment_id(10)), 180_000);
    }

    #[test]
    fn test_get_payments_for_epoch() {
        let mut ledger = PaidLedger::new();

        // Multiple assignments in epoch 1
        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();
        ledger
            .record_payment(1, &test_assignment_id(11), 60_000, test_hash(2), 2, test_tx_id(2))
            .unwrap();
        ledger
            .record_payment(2, &test_assignment_id(10), 70_000, test_hash(3), 3, test_tx_id(3))
            .unwrap();

        let epoch1_payments = ledger.get_payments_for_epoch(1);
        assert_eq!(epoch1_payments.len(), 2);
    }

    #[test]
    fn test_verify_payment() {
        let mut ledger = PaidLedger::new();

        ledger
            .record_payment(1, &test_assignment_id(10), 50_000, test_hash(1), 2, test_tx_id(1))
            .unwrap();

        // Correct hash
        assert!(ledger
            .verify_payment(1, &test_assignment_id(10), &test_hash(1))
            .unwrap());

        // Wrong hash
        assert!(!ledger
            .verify_payment(1, &test_assignment_id(10), &test_hash(99))
            .unwrap());
    }
}
