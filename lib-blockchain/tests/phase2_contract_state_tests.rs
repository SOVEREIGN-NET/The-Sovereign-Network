//! Phase 2: Contract State Management Tests
//!
//! Tests for contract state persistence and historical queries.

#[cfg(test)]
mod tests {
    use lib_blockchain::Blockchain;

    #[test]
    fn test_contract_state_update() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        let contract_id = [1u8; 32];
        let state = vec![42, 43, 44];

        // Update contract state
        blockchain
            .update_contract_state(contract_id, state.clone(), blockchain.get_height())
            .expect("Failed to update contract state");

        // Verify state was stored
        let retrieved = blockchain
            .get_contract_state(&contract_id)
            .expect("Contract state not found");
        assert_eq!(retrieved, state, "Contract state mismatch");
    }

    #[test]
    fn test_contract_state_multiple_contracts() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");

        let contract_1 = [1u8; 32];
        let contract_2 = [2u8; 32];
        let state_1 = vec![100];
        let state_2 = vec![200, 201];

        blockchain
            .update_contract_state(contract_1, state_1.clone(), 0)
            .expect("Failed to update contract 1");

        blockchain
            .update_contract_state(contract_2, state_2.clone(), 0)
            .expect("Failed to update contract 2");

        // Verify both states stored independently
        assert_eq!(
            blockchain.get_contract_state(&contract_1),
            Some(state_1),
            "Contract 1 state mismatch"
        );
        assert_eq!(
            blockchain.get_contract_state(&contract_2),
            Some(state_2),
            "Contract 2 state mismatch"
        );
    }

    #[test]
    fn test_contract_state_history() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        let contract_id = [5u8; 32];

        // Store different states at different heights
        let state_height_0 = vec![1, 2, 3];
        blockchain
            .update_contract_state(contract_id, state_height_0.clone(), 0)
            .expect("Failed to update at height 0");

        // Simulate block addition and height increase
        blockchain.height = 5;
        let state_height_5 = vec![10, 20, 30];
        blockchain
            .update_contract_state(contract_id, state_height_5.clone(), 5)
            .expect("Failed to update at height 5");

        blockchain.height = 10;
        let state_height_10 = vec![100, 200];
        blockchain
            .update_contract_state(contract_id, state_height_10.clone(), 10)
            .expect("Failed to update at height 10");

        // Verify historical state retrieval
        assert_eq!(
            blockchain.get_contract_state_at_height(&contract_id, 0),
            Some(state_height_0),
            "State at height 0 mismatch"
        );
        assert_eq!(
            blockchain.get_contract_state_at_height(&contract_id, 5),
            Some(state_height_5),
            "State at height 5 mismatch"
        );
        assert_eq!(
            blockchain.get_contract_state_at_height(&contract_id, 10),
            Some(state_height_10),
            "State at height 10 mismatch"
        );
    }

    #[test]
    fn test_contract_state_history_interpolation() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        let contract_id = [7u8; 32];

        // Store state at height 0
        let state_0 = vec![42];
        blockchain
            .update_contract_state(contract_id, state_0.clone(), 0)
            .expect("Failed to update at height 0");

        // Store state at height 10 (no update at heights 1-9)
        blockchain.height = 10;
        let state_10 = vec![100];
        blockchain
            .update_contract_state(contract_id, state_10.clone(), 10)
            .expect("Failed to update at height 10");

        // Querying height 5 should return state from height 0 (last known state)
        assert_eq!(
            blockchain.get_contract_state_at_height(&contract_id, 5),
            Some(state_0),
            "Should return last known state before height 5"
        );

        // Current state should be state_10
        assert_eq!(
            blockchain.get_contract_state(&contract_id),
            Some(state_10),
            "Current state should be latest"
        );
    }

    #[test]
    fn test_contract_state_nonexistent() {
        let blockchain = Blockchain::new().expect("Failed to create blockchain");
        let nonexistent_contract = [99u8; 32];

        // Querying nonexistent contract should return None
        assert_eq!(
            blockchain.get_contract_state(&nonexistent_contract),
            None,
            "Nonexistent contract should return None"
        );
    }

    #[test]
    fn test_contract_state_update_overwrites() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        let contract_id = [3u8; 32];

        let initial_state = vec![1, 2, 3];
        let updated_state = vec![4, 5, 6, 7];

        blockchain
            .update_contract_state(contract_id, initial_state, 0)
            .expect("Failed to store initial state");

        blockchain
            .update_contract_state(contract_id, updated_state.clone(), 0)
            .expect("Failed to update state");

        // Latest state should be the updated one
        assert_eq!(
            blockchain.get_contract_state(&contract_id),
            Some(updated_state),
            "State should be overwritten"
        );
    }

    #[test]
    fn test_contract_state_history_pruning() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        let contract_id = [8u8; 32];

        // Store state at multiple heights
        for height in 0..20 {
            blockchain.height = height;
            let state = vec![height as u8];
            blockchain
                .update_contract_state(contract_id, state, height)
                .expect("Failed to update contract state");
        }

        // History should have 20 entries
        assert_eq!(
            blockchain.contract_state_history.len(),
            20,
            "Should have 20 historical entries"
        );

        blockchain.height = 19;
        // Prune history, keeping only last 5 blocks
        blockchain.prune_contract_history(5);

        // Should only keep blocks 15-19 (5 blocks)
        assert_eq!(
            blockchain.contract_state_history.len(),
            5,
            "Should prune to keep only 5 recent blocks"
        );

        // Verify recent blocks are kept
        assert!(
            blockchain.contract_state_history.contains_key(&19),
            "Most recent block should be kept"
        );

        // Verify old blocks are removed
        assert!(
            !blockchain.contract_state_history.contains_key(&5),
            "Old blocks should be pruned"
        );
    }

    #[test]
    fn test_contract_state_empty_initialization() {
        let blockchain = Blockchain::new().expect("Failed to create blockchain");

        // New blockchain should have empty contract states
        assert_eq!(
            blockchain.contract_states.len(),
            0,
            "Should start with empty contract states"
        );
        assert_eq!(
            blockchain.contract_state_history.len(),
            0,
            "Should start with empty history"
        );
    }

    #[test]
    fn test_contract_state_large_payloads() {
        let mut blockchain = Blockchain::new().expect("Failed to create blockchain");
        let contract_id = [10u8; 32];

        // Create a large state (1MB)
        let large_state: Vec<u8> = vec![42u8; 1024 * 1024];

        blockchain
            .update_contract_state(contract_id, large_state.clone(), 0)
            .expect("Failed to store large state");

        // Verify large state retrieved correctly
        let retrieved = blockchain
            .get_contract_state(&contract_id)
            .expect("Large state not found");
        assert_eq!(retrieved.len(), 1024 * 1024, "Large state size mismatch");
        assert_eq!(retrieved, large_state, "Large state content mismatch");
    }
}
