//! UTXO Application Logic
//!
//! The `apply_native_transfer` function is the canonical way to execute
//! native UTXO transfers.

use std::collections::HashSet;

use lib_types::{Amount, BlockHeight, TxHash};

use crate::types::{OutPoint, TransferOutcome, TxInput, TxOutput, Utxo, UtxoStore};
use crate::errors::{UtxoError, UtxoResult};

/// Apply a native transfer transaction
///
/// # Rules
///
/// 1. **Inputs must exist**: All referenced UTXOs must be present in state
/// 2. **No double spend**: Each input can only appear once, UTXOs can't be spent twice
/// 3. **Outputs created before commit only**: New UTXOs are pending until block commit
/// 4. **Conservation**: sum(inputs) == sum(outputs) + fee
///
/// # Arguments
///
/// * `store` - UTXO storage backend
/// * `inputs` - Transaction inputs (UTXOs being spent)
/// * `outputs` - Transaction outputs (new UTXOs being created)
/// * `tx_hash` - Hash of the transaction (for creating new outpoints)
/// * `height` - Current block height
/// * `fee` - Transaction fee
///
/// # Returns
///
/// * `Ok(TransferOutcome)` - Transfer details on success
/// * `Err(UtxoError)` - Error describing failure
pub fn apply_native_transfer(
    store: &dyn UtxoStore,
    inputs: &[TxInput],
    outputs: &[TxOutput],
    tx_hash: TxHash,
    height: BlockHeight,
    fee: Amount,
) -> UtxoResult<TransferOutcome> {
    // =========================================================================
    // Validation: Non-empty inputs and outputs
    // =========================================================================
    if inputs.is_empty() {
        return Err(UtxoError::EmptyInputs);
    }
    if outputs.is_empty() {
        return Err(UtxoError::EmptyOutputs);
    }

    // =========================================================================
    // Rule 2: No duplicate inputs (double spend within tx)
    // =========================================================================
    let mut seen_inputs: HashSet<OutPoint> = HashSet::with_capacity(inputs.len());
    for input in inputs {
        if !seen_inputs.insert(input.outpoint) {
            return Err(UtxoError::DuplicateInput(input.outpoint));
        }
    }

    // =========================================================================
    // Rule 1: Inputs must exist - Spend all inputs and sum their values
    // =========================================================================
    let mut total_input: Amount = 0;

    for input in inputs {
        // Spend the UTXO (marks as consumed, returns error if not found)
        let utxo = store.spend_utxo(&input.outpoint)?;

        // Check if locked
        if !utxo.is_spendable(height) {
            return Err(UtxoError::Locked {
                outpoint: input.outpoint,
                lock_height: utxo.locked_until.unwrap_or(0),
                current_height: height,
            });
        }

        // Accumulate input value
        total_input = total_input
            .checked_add(utxo.amount)
            .ok_or(UtxoError::Overflow)?;
    }

    // =========================================================================
    // Conservation check: sum(inputs) >= sum(outputs) + fee
    // =========================================================================
    let mut total_output: Amount = 0;
    for output in outputs {
        if output.amount == 0 {
            return Err(UtxoError::InvalidAmount("Output amount cannot be zero".to_string()));
        }
        total_output = total_output
            .checked_add(output.amount)
            .ok_or(UtxoError::Overflow)?;
    }

    let required = total_output
        .checked_add(fee)
        .ok_or(UtxoError::Overflow)?;

    if total_input < required {
        return Err(UtxoError::InsufficientInput {
            have: total_input,
            need: required,
        });
    }

    // Strict conservation: inputs == outputs + fee (no dust left over)
    if total_input != required {
        return Err(UtxoError::ValueMismatch {
            inputs: total_input,
            outputs: total_output,
            fee,
        });
    }

    // =========================================================================
    // Rule 3: Create outputs (pending until commit)
    // =========================================================================
    for (index, output) in outputs.iter().enumerate() {
        let outpoint = OutPoint::new(tx_hash, index as u32);

        let utxo = match output.locked_until {
            Some(lock_height) => Utxo::new_locked(
                output.amount,
                output.recipient,
                height,
                lock_height,
            ),
            None => Utxo::new(output.amount, output.recipient, height),
        };

        store.create_utxo(&outpoint, &utxo)?;
    }

    Ok(TransferOutcome {
        inputs_spent: inputs.len(),
        outputs_created: outputs.len(),
        total_input,
        total_output,
        fee,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_types::Address;
    use std::cell::RefCell;
    use std::collections::HashMap;

    /// Mock UTXO store for testing
    struct MockUtxoStore {
        utxos: RefCell<HashMap<OutPoint, Utxo>>,
        spent: RefCell<HashSet<OutPoint>>,
    }

    impl MockUtxoStore {
        fn new() -> Self {
            Self {
                utxos: RefCell::new(HashMap::new()),
                spent: RefCell::new(HashSet::new()),
            }
        }

        fn add_utxo(&self, outpoint: OutPoint, utxo: Utxo) {
            self.utxos.borrow_mut().insert(outpoint, utxo);
        }
    }

    impl UtxoStore for MockUtxoStore {
        fn get_utxo(&self, outpoint: &OutPoint) -> UtxoResult<Option<Utxo>> {
            if self.spent.borrow().contains(outpoint) {
                return Ok(None); // Already spent
            }
            Ok(self.utxos.borrow().get(outpoint).cloned())
        }

        fn spend_utxo(&self, outpoint: &OutPoint) -> UtxoResult<Utxo> {
            if self.spent.borrow().contains(outpoint) {
                return Err(UtxoError::AlreadySpent(*outpoint));
            }

            let utxo = self.utxos.borrow().get(outpoint).cloned()
                .ok_or_else(|| UtxoError::NotFound(*outpoint))?;

            self.spent.borrow_mut().insert(*outpoint);
            Ok(utxo)
        }

        fn create_utxo(&self, outpoint: &OutPoint, utxo: &Utxo) -> UtxoResult<()> {
            self.utxos.borrow_mut().insert(*outpoint, utxo.clone());
            Ok(())
        }
    }

    fn create_input(tx_hash: TxHash, index: u32) -> TxInput {
        TxInput {
            outpoint: OutPoint::new(tx_hash, index),
            nullifier: [0u8; 32],
        }
    }

    fn create_output(amount: Amount, recipient: Address) -> TxOutput {
        TxOutput {
            amount,
            recipient,
            locked_until: None,
        }
    }

    #[test]
    fn test_basic_transfer() {
        let store = MockUtxoStore::new();

        // Setup: Create a UTXO to spend
        let prev_tx = TxHash::default();
        let prev_outpoint = OutPoint::new(prev_tx, 0);
        store.add_utxo(prev_outpoint, Utxo::new(1000, Address::default(), 0));

        // Create transfer: 1000 -> 900 + 100 fee
        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100).unwrap();

        assert_eq!(result.inputs_spent, 1);
        assert_eq!(result.outputs_created, 1);
        assert_eq!(result.total_input, 1000);
        assert_eq!(result.total_output, 900);
        assert_eq!(result.fee, 100);

        // Verify new UTXO was created
        let new_outpoint = OutPoint::new(tx_hash, 0);
        let new_utxo = store.get_utxo(&new_outpoint).unwrap().unwrap();
        assert_eq!(new_utxo.amount, 900);
    }

    #[test]
    fn test_multiple_inputs_outputs() {
        let store = MockUtxoStore::new();

        // Setup: Create two UTXOs
        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(500, Address::default(), 0));
        store.add_utxo(OutPoint::new(prev_tx, 1), Utxo::new(500, Address::default(), 0));

        // Transfer: 500 + 500 -> 400 + 400 + 200 fee
        let inputs = vec![
            create_input(prev_tx, 0),
            create_input(prev_tx, 1),
        ];
        let outputs = vec![
            create_output(400, Address::new([1u8; 32])),
            create_output(400, Address::new([2u8; 32])),
        ];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 200).unwrap();

        assert_eq!(result.inputs_spent, 2);
        assert_eq!(result.outputs_created, 2);
        assert_eq!(result.total_input, 1000);
        assert_eq!(result.total_output, 800);
        assert_eq!(result.fee, 200);
    }

    #[test]
    fn test_utxo_not_found() {
        let store = MockUtxoStore::new();

        let inputs = vec![create_input(TxHash::default(), 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100);
        assert!(matches!(result, Err(UtxoError::NotFound(_))));
    }

    #[test]
    fn test_double_spend_within_tx() {
        let store = MockUtxoStore::new();

        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));

        // Try to spend the same input twice
        let inputs = vec![
            create_input(prev_tx, 0),
            create_input(prev_tx, 0), // Duplicate!
        ];
        let outputs = vec![create_output(1800, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 200);
        assert!(matches!(result, Err(UtxoError::DuplicateInput(_))));
    }

    #[test]
    fn test_already_spent() {
        let store = MockUtxoStore::new();

        let prev_tx = TxHash::default();
        let outpoint = OutPoint::new(prev_tx, 0);
        store.add_utxo(outpoint, Utxo::new(1000, Address::default(), 0));

        // Spend it once
        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);
        apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100).unwrap();

        // Try to spend again
        let tx_hash2 = TxHash::new([2u8; 32]);
        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash2, 10, 100);
        assert!(matches!(result, Err(UtxoError::AlreadySpent(_))));
    }

    #[test]
    fn test_insufficient_input() {
        let store = MockUtxoStore::new();

        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(100, Address::default(), 0));

        // Try to transfer more than available
        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(200, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 10);
        assert!(matches!(result, Err(UtxoError::InsufficientInput { .. })));
    }

    #[test]
    fn test_locked_utxo() {
        let store = MockUtxoStore::new();

        let prev_tx = TxHash::default();
        // UTXO locked until height 100
        store.add_utxo(
            OutPoint::new(prev_tx, 0),
            Utxo::new_locked(1000, Address::default(), 0, 100),
        );

        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        // Should fail at height 50
        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 50, 100);
        assert!(matches!(result, Err(UtxoError::Locked { .. })));

        // Should succeed at height 100
        // Need fresh store since previous attempt spent the UTXO
        let store2 = MockUtxoStore::new();
        store2.add_utxo(
            OutPoint::new(prev_tx, 0),
            Utxo::new_locked(1000, Address::default(), 0, 100),
        );
        let result = apply_native_transfer(&store2, &inputs, &outputs, tx_hash, 100, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_empty_inputs() {
        let store = MockUtxoStore::new();

        let inputs: Vec<TxInput> = vec![];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100);
        assert!(matches!(result, Err(UtxoError::EmptyInputs)));
    }

    #[test]
    fn test_empty_outputs() {
        let store = MockUtxoStore::new();

        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));

        let inputs = vec![create_input(prev_tx, 0)];
        let outputs: Vec<TxOutput> = vec![];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100);
        assert!(matches!(result, Err(UtxoError::EmptyOutputs)));
    }

    #[test]
    fn test_value_mismatch() {
        let store = MockUtxoStore::new();

        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));

        // inputs (1000) != outputs (800) + fee (100) = 900
        // This leaves 100 unaccounted for
        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(800, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100);
        assert!(matches!(result, Err(UtxoError::ValueMismatch { .. })));
    }

    // =========================================================================
    // INVARIANT VIOLATION REJECTION TESTS
    // =========================================================================

    /// Invariant: Inputs must exist (no-create-from-nothing)
    #[test]
    fn invariant_inputs_must_exist() {
        let store = MockUtxoStore::new();
        // No UTXOs created

        let inputs = vec![create_input(TxHash::new([1u8; 32]), 0)];
        let outputs = vec![create_output(1000, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([2u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 0);
        assert!(result.is_err(), "Must reject transfer from non-existent UTXO");
    }

    /// Invariant: No double-spend (same input twice in single tx)
    #[test]
    fn invariant_no_double_spend_same_tx() {
        let store = MockUtxoStore::new();
        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));

        // Same input twice
        let inputs = vec![
            create_input(prev_tx, 0),
            create_input(prev_tx, 0),
        ];
        let outputs = vec![create_output(1900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100);
        assert!(matches!(result, Err(UtxoError::DuplicateInput(_))));
    }

    /// Invariant: No double-spend (across blocks)
    #[test]
    fn invariant_no_double_spend_across_blocks() {
        let store = MockUtxoStore::new();
        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));

        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];

        // First spend (block 10)
        let tx_hash1 = TxHash::new([1u8; 32]);
        apply_native_transfer(&store, &inputs, &outputs, tx_hash1, 10, 100).unwrap();

        // Second spend attempt (block 20)
        let tx_hash2 = TxHash::new([2u8; 32]);
        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash2, 20, 100);
        assert!(matches!(result, Err(UtxoError::AlreadySpent(_))));
    }

    /// Invariant: Conservation of value (inputs = outputs + fee)
    #[test]
    fn invariant_value_conservation() {
        let store = MockUtxoStore::new();
        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));

        let inputs = vec![create_input(prev_tx, 0)];
        let tx_hash = TxHash::new([1u8; 32]);

        // Case 1: outputs + fee > inputs (value creation - rejected)
        let outputs1 = vec![create_output(1001, Address::new([1u8; 32]))];
        let result = apply_native_transfer(&store, &inputs, &outputs1, tx_hash, 10, 0);
        assert!(result.is_err(), "Must reject value creation");

        // Case 2: outputs + fee < inputs (value destruction - rejected)
        let store2 = MockUtxoStore::new();
        store2.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));
        let outputs2 = vec![create_output(500, Address::new([1u8; 32]))];
        let result = apply_native_transfer(&store2, &inputs, &outputs2, tx_hash, 10, 100);
        assert!(matches!(result, Err(UtxoError::ValueMismatch { .. })));
    }

    /// Invariant: Output indices are sequential starting from 0
    #[test]
    fn invariant_output_indices_sequential() {
        let store = MockUtxoStore::new();
        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(3000, Address::default(), 0));

        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![
            create_output(1000, Address::new([1u8; 32])),
            create_output(1000, Address::new([2u8; 32])),
            create_output(900, Address::new([3u8; 32])),
        ];
        let tx_hash = TxHash::new([1u8; 32]);

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100).unwrap();

        // Verify outputs are at indices 0, 1, 2
        assert!(store.get_utxo(&OutPoint::new(tx_hash, 0)).unwrap().is_some());
        assert!(store.get_utxo(&OutPoint::new(tx_hash, 1)).unwrap().is_some());
        assert!(store.get_utxo(&OutPoint::new(tx_hash, 2)).unwrap().is_some());
        assert!(store.get_utxo(&OutPoint::new(tx_hash, 3)).unwrap().is_none());
    }

    /// Invariant: Locked UTXOs cannot be spent before unlock height
    #[test]
    fn invariant_time_lock_enforced() {
        let store = MockUtxoStore::new();
        let prev_tx = TxHash::default();
        store.add_utxo(
            OutPoint::new(prev_tx, 0),
            Utxo::new_locked(1000, Address::default(), 0, 1000), // Locked until height 1000
        );

        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        // Try at height 999 - must fail
        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 999, 100);
        assert!(matches!(result, Err(UtxoError::Locked { .. })));
    }

    // =========================================================================
    // GOLDEN VECTORS
    // =========================================================================

    /// Golden vector: Standard transfer outcome
    #[test]
    fn golden_standard_transfer() {
        let store = MockUtxoStore::new();
        let prev_tx = TxHash::default();
        store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(10_000, Address::default(), 0));

        let inputs = vec![create_input(prev_tx, 0)];
        let outputs = vec![
            create_output(5000, Address::new([1u8; 32])),
            create_output(4000, Address::new([2u8; 32])),
        ];
        let tx_hash = TxHash::new([1u8; 32]);
        let fee = 1000;

        let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 100, fee).unwrap();

        // GOLDEN VECTOR: These exact values MUST NOT change
        assert_eq!(result.total_input, 10_000);
        assert_eq!(result.total_output, 9_000);
        assert_eq!(result.fee, 1000);
        assert_eq!(result.inputs_spent, 1);
        assert_eq!(result.outputs_created, 2);
    }

    // =========================================================================
    // DETERMINISM TESTS
    // =========================================================================

    /// Verify transfer is deterministic
    #[test]
    fn determinism_transfer_outcome() {
        let create_scenario = || {
            let store = MockUtxoStore::new();
            let prev_tx = TxHash::default();
            store.add_utxo(OutPoint::new(prev_tx, 0), Utxo::new(1000, Address::default(), 0));
            store
        };

        let inputs = vec![create_input(TxHash::default(), 0)];
        let outputs = vec![create_output(900, Address::new([1u8; 32]))];
        let tx_hash = TxHash::new([1u8; 32]);

        // Run same transfer multiple times
        let mut results = Vec::new();
        for _ in 0..10 {
            let store = create_scenario();
            let result = apply_native_transfer(&store, &inputs, &outputs, tx_hash, 10, 100).unwrap();
            results.push((result.total_input, result.total_output, result.fee));
        }

        // All results must be identical
        let first = results[0];
        for result in &results {
            assert_eq!(*result, first, "Transfer must be deterministic");
        }
    }
}
