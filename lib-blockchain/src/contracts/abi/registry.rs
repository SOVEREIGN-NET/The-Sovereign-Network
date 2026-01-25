//! ABI registry for contract lookups
//!
//! Provides a central registry to manage and query contract ABIs.

use super::schema::ContractAbi;
use std::collections::HashMap;
use anyhow::{Result, anyhow};

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
    ///
    /// Returns an error if a contract with this name already exists.
    /// To update an ABI, you must first remove the old one and register the new one.
    pub fn register(&mut self, abi: ContractAbi) -> Result<()> {
        if self.abis.contains_key(&abi.contract) {
            return Err(anyhow!(
                "Contract ABI for '{}' is already registered. Use a different version or remove the existing one.",
                abi.contract
            ));
        }
        self.abis.insert(abi.contract.clone(), abi);
        Ok(())
    }

    /// Look up a contract ABI by name
    pub fn get(&self, contract: &str) -> Option<&ContractAbi> {
        self.abis.get(contract)
    }

    /// Remove a contract ABI from the registry
    pub fn unregister(&mut self, contract: &str) -> Option<ContractAbi> {
        self.abis.remove(contract)
    }

    /// Update an existing contract ABI (register with overwrite permission)
    pub fn update(&mut self, abi: ContractAbi) -> Result<()> {
        self.abis.insert(abi.contract.clone(), abi);
        Ok(())
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

    #[test]
    fn test_registry_rejects_duplicates() {
        let mut registry = AbiRegistry::new();
        let abi1 = ContractAbi::new("Test", "1.0.0");
        let abi2 = ContractAbi::new("Test", "2.0.0");

        // First registration should succeed
        assert!(registry.register(abi1).is_ok());
        assert_eq!(registry.len(), 1);

        // Duplicate registration should fail
        assert!(registry.register(abi2).is_err());
        assert_eq!(registry.len(), 1); // Still just one
    }

    #[test]
    fn test_registry_update_and_unregister() {
        let mut registry = AbiRegistry::new();
        let abi1 = ContractAbi::new("Test", "1.0.0");
        let abi2 = ContractAbi::new("Test", "2.0.0");

        registry.register(abi1).expect("Should register v1");

        // Update should work (overwrites)
        registry.update(abi2).expect("Should update");
        assert_eq!(registry.get("Test").unwrap().version, "2.0.0");

        // Unregister should work
        let removed = registry.unregister("Test");
        assert!(removed.is_some());
        assert!(registry.get("Test").is_none());
    }
}
