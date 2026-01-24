//! ABI registry for contract lookups
//!
//! Provides a central registry to manage and query contract ABIs.

use super::schema::ContractAbi;
use std::collections::HashMap;
use anyhow::Result;

/// Registry of contract ABIs
///
/// Manages the mapping from contract names to their ABI definitions.
pub struct AbiRegistry {
    abis: HashMap<String, ContractAbi>,
}

impl AbiRegistry {
    /// Create a new ABI registry
    pub fn new() -> Self {
        Self {
            abis: HashMap::new(),
        }
    }

    /// Register a contract ABI
    pub fn register(&mut self, abi: ContractAbi) -> Result<()> {
        self.abis.insert(abi.contract.clone(), abi);
        Ok(())
    }

    /// Look up a contract ABI by name
    pub fn get(&self, contract: &str) -> Option<&ContractAbi> {
        self.abis.get(contract)
    }

    /// List all registered contracts
    pub fn list(&self) -> Vec<&str> {
        self.abis.keys().map(|s| s.as_str()).collect()
    }

    /// Get the count of registered ABIs
    pub fn len(&self) -> usize {
        self.abis.len()
    }

    /// Check if registry is empty
    pub fn is_empty(&self) -> bool {
        self.abis.is_empty()
    }
}

impl Default for AbiRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_operations() {
        let mut registry = AbiRegistry::new();
        assert!(registry.is_empty());

        let abi = ContractAbi::new("Test", "1.0.0");
        registry.register(abi).expect("Should register");

        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
        assert!(registry.get("Test").is_some());
    }
}
