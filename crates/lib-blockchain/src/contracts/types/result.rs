use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Result of contract execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractResult {
    /// Whether the contract execution was successful
    pub success: bool,
    /// Return data from the contract function
    pub return_data: Vec<u8>,
    /// Amount of gas consumed during execution
    pub gas_used: u64,
    /// Events logged during execution
    pub logs: Vec<super::ContractLog>,
    /// State changes to be applied to contract storage
    pub state_changes: HashMap<Vec<u8>, Vec<u8>>,
}

impl ContractResult {
    /// Create a new successful contract result
    pub fn success() -> Self {
        Self {
            success: true,
            return_data: Vec::new(),
            gas_used: 0,
            logs: Vec::new(),
            state_changes: HashMap::new(),
        }
    }

    /// Create a new failed contract result
    pub fn failure(gas_used: u64) -> Self {
        Self {
            success: false,
            return_data: Vec::new(),
            gas_used,
            logs: Vec::new(),
            state_changes: HashMap::new(),
        }
    }

    /// Create a contract result with specific gas usage
    pub fn with_gas(gas_used: u64) -> Self {
        Self {
            success: true,
            return_data: Vec::new(),
            gas_used,
            logs: Vec::new(),
            state_changes: HashMap::new(),
        }
    }

    /// Create a contract result with return data
    pub fn with_return_data<T: Serialize>(data: &T, gas_used: u64) -> Result<Self, bincode::Error> {
        Ok(Self {
            success: true,
            return_data: bincode::serialize(data)?,
            gas_used,
            logs: Vec::new(),
            state_changes: HashMap::new(),
        })
    }

    /// Set return data for the result
    pub fn set_return_data<T: Serialize>(&mut self, data: &T) -> Result<(), bincode::Error> {
        self.return_data = bincode::serialize(data)?;
        Ok(())
    }

    /// Get return data as a specific type
    pub fn get_return_data<T: for<'de> Deserialize<'de>>(&self) -> Result<T, bincode::Error> {
        bincode::deserialize(&self.return_data)
    }

    /// Add a log entry to the result
    pub fn add_log(&mut self, log: super::ContractLog) {
        self.logs.push(log);
    }

    /// Add a state change to the result
    pub fn add_state_change(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.state_changes.insert(key, value);
    }

    /// Remove a state entry (set to empty for deletion)
    pub fn remove_state(&mut self, key: Vec<u8>) {
        self.state_changes.insert(key, Vec::new());
    }

    /// Check if the result has any state changes
    pub fn has_state_changes(&self) -> bool {
        !self.state_changes.is_empty()
    }

    /// Check if the result has any logs
    pub fn has_logs(&self) -> bool {
        !self.logs.is_empty()
    }

    /// Check if the result has return data
    pub fn has_return_data(&self) -> bool {
        !self.return_data.is_empty()
    }

    /// Calculate total cost (gas used plus any additional fees)
    pub fn total_cost(&self, gas_price: u64) -> u64 {
        self.gas_used * gas_price
    }

    /// Mark the result as failed
    pub fn mark_failed(&mut self) {
        self.success = false;
        // Clear state changes on failure (rollback)
        self.state_changes.clear();
    }

    /// Merge another result into this one (for complex operations)
    pub fn merge(&mut self, other: ContractResult) {
        if !other.success {
            self.mark_failed();
            return;
        }

        self.gas_used += other.gas_used;
        self.logs.extend(other.logs);
        self.state_changes.extend(other.state_changes);

        // If other has return data, it overrides ours
        if !other.return_data.is_empty() {
            self.return_data = other.return_data;
        }
    }

    /// Create a summary of the execution result
    pub fn summary(&self) -> String {
        format!(
            "ContractResult {{ success: {}, gas_used: {}, logs: {}, state_changes: {}, return_data_size: {} }}",
            self.success,
            self.gas_used,
            self.logs.len(),
            self.state_changes.len(),
            self.return_data.len()
        )
    }
}

impl Default for ContractResult {
    fn default() -> Self {
        Self::success()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::types::ContractLog;

    #[test]
    fn test_contract_result_creation() {
        let success_result = ContractResult::success();
        assert!(success_result.success);
        assert_eq!(success_result.gas_used, 0);
        assert!(success_result.logs.is_empty());
        assert!(success_result.state_changes.is_empty());

        let failure_result = ContractResult::failure(1000);
        assert!(!failure_result.success);
        assert_eq!(failure_result.gas_used, 1000);

        let gas_result = ContractResult::with_gas(2000);
        assert!(gas_result.success);
        assert_eq!(gas_result.gas_used, 2000);
    }

    #[test]
    fn test_return_data_handling() {
        let mut result = ContractResult::success();
        let test_value: u64 = 12345;

        result.set_return_data(&test_value).unwrap();
        assert!(result.has_return_data());

        let retrieved_value: u64 = result.get_return_data().unwrap();
        assert_eq!(retrieved_value, test_value);

        // Test with_return_data constructor
        let result2 = ContractResult::with_return_data(&test_value, 500).unwrap();
        assert_eq!(result2.gas_used, 500);
        let retrieved_value2: u64 = result2.get_return_data().unwrap();
        assert_eq!(retrieved_value2, test_value);
    }

    #[test]
    fn test_log_handling() {
        let mut result = ContractResult::success();
        assert!(!result.has_logs());

        let log = ContractLog {
            contract_id: [1u8; 32],
            event: "Transfer".to_string(),
            data: vec![1, 2, 3],
            indexed_fields: vec![vec![4, 5, 6]],
        };

        result.add_log(log.clone());
        assert!(result.has_logs());
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0], log);
    }

    #[test]
    fn test_state_changes() {
        let mut result = ContractResult::success();
        assert!(!result.has_state_changes());

        let key = b"test_key".to_vec();
        let value = b"test_value".to_vec();

        result.add_state_change(key.clone(), value.clone());
        assert!(result.has_state_changes());
        assert_eq!(result.state_changes.get(&key), Some(&value));

        // Test removal
        result.remove_state(key.clone());
        assert_eq!(result.state_changes.get(&key), Some(&Vec::new()));
    }

    #[test]
    fn test_result_merging() {
        let mut result1 = ContractResult::with_gas(1000);
        result1.add_state_change(b"key1".to_vec(), b"value1".to_vec());

        let mut result2 = ContractResult::with_gas(500);
        result2.add_state_change(b"key2".to_vec(), b"value2".to_vec());
        result2.set_return_data(&42u64).unwrap();

        result1.merge(result2);

        assert_eq!(result1.gas_used, 1500);
        assert_eq!(result1.state_changes.len(), 2);
        assert!(result1.has_return_data());
        let return_value: u64 = result1.get_return_data().unwrap();
        assert_eq!(return_value, 42);
    }

    #[test]
    fn test_failure_handling() {
        let mut result = ContractResult::success();
        result.add_state_change(b"key".to_vec(), b"value".to_vec());
        assert!(result.has_state_changes());

        result.mark_failed();
        assert!(!result.success);
        assert!(!result.has_state_changes()); // State changes should be cleared on failure
    }

    #[test]
    fn test_cost_calculation() {
        let result = ContractResult::with_gas(1000);
        assert_eq!(result.total_cost(2), 2000);
        assert_eq!(result.total_cost(5), 5000);
    }

    #[test]
    fn test_summary() {
        let mut result = ContractResult::with_gas(1500);
        result.set_return_data(&"test".to_string()).unwrap();
        result.add_state_change(b"key".to_vec(), b"value".to_vec());

        let summary = result.summary();
        assert!(summary.contains("success: true"));
        assert!(summary.contains("gas_used: 1500"));
        assert!(summary.contains("state_changes: 1"));
    }
}
