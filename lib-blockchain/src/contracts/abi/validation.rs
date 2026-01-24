//! ABI validation and type checking
//!
//! Validates ABI schemas for correctness and type safety.

use super::schema::*;
use anyhow::{Result, anyhow};

/// ABI validator
pub struct AbiValidator;

impl AbiValidator {
    /// Validate that an ABI is well-formed
    pub fn validate(abi: &ContractAbi) -> Result<()> {
        // Validate contract name
        if abi.contract.is_empty() {
            return Err(anyhow!("Contract name cannot be empty"));
        }

        // Validate version format
        if !Self::is_valid_version(&abi.version) {
            return Err(anyhow!("Invalid version format: {}", abi.version));
        }

        // Validate methods
        Self::validate_methods(&abi.methods)?;

        // Validate events
        if let Some(events) = &abi.events {
            Self::validate_events(events)?;
        }

        // Validate type references
        if let Some(types) = &abi.types {
            Self::validate_types(types, abi)?;
        }

        Ok(())
    }

    fn is_valid_version(version: &str) -> bool {
        // Simple semver check: X.Y.Z
        let parts: Vec<_> = version.split('.').collect();
        parts.len() == 3 && parts.iter().all(|p| p.parse::<u32>().is_ok())
    }

    fn validate_methods(methods: &[MethodSchema]) -> Result<()> {
        // Check for duplicate method names
        let mut names = std::collections::HashSet::new();
        for method in methods {
            if !names.insert(&method.name) {
                return Err(anyhow!("Duplicate method name: {}", method.name));
            }

            // Validate method name format
            if !method.name.chars().all(|c| c.is_alphanumeric() || c == '_') {
                return Err(anyhow!("Invalid method name: {}", method.name));
            }

            // Validate parameter names are unique
            let mut param_names = std::collections::HashSet::new();
            for param in &method.parameters {
                if !param_names.insert(&param.name) {
                    return Err(anyhow!(
                        "Duplicate parameter name '{}' in method '{}'",
                        param.name,
                        method.name
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_events(events: &[EventSchema]) -> Result<()> {
        // Check for duplicate event names
        let mut names = std::collections::HashSet::new();
        for event in events {
            if !names.insert(&event.name) {
                return Err(anyhow!("Duplicate event name: {}", event.name));
            }

            // Validate field names are unique
            let mut field_names = std::collections::HashSet::new();
            for field in &event.fields {
                if !field_names.insert(&field.name) {
                    return Err(anyhow!(
                        "Duplicate field name '{}' in event '{}'",
                        field.name,
                        event.name
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_types(types: &std::collections::HashMap<String, TypeDefinition>, abi: &ContractAbi) -> Result<()> {
        for (name, typedef) in types {
            match typedef {
                TypeDefinition::Enum { variants, .. } => {
                    if variants.is_empty() {
                        return Err(anyhow!("Enum '{}' has no variants", name));
                    }
                }
                TypeDefinition::Struct { fields } => {
                    if fields.is_empty() {
                        return Err(anyhow!("Struct '{}' has no fields", name));
                    }
                }
            }
        }

        // Check that custom type references are defined
        // This would recursively check ParameterType and FieldType references

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_contract() {
        let abi = ContractAbi {
            contract: String::new(),
            version: "1.0.0".to_string(),
            description: None,
            methods: vec![],
            events: None,
            types: None,
            deprecated: None,
            references: None,
        };
        assert!(AbiValidator::validate(&abi).is_err());
    }

    #[test]
    fn test_validate_invalid_version() {
        let abi = ContractAbi {
            contract: "Test".to_string(),
            version: "1.0".to_string(), // Invalid: missing patch
            description: None,
            methods: vec![],
            events: None,
            types: None,
            deprecated: None,
            references: None,
        };
        assert!(AbiValidator::validate(&abi).is_err());
    }

    #[test]
    fn test_validate_valid_abi() {
        let abi = ContractAbi::new("Test", "1.0.0");
        assert!(AbiValidator::validate(&abi).is_ok());
    }
}
