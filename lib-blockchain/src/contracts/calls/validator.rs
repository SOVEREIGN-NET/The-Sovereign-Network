//! Parameter and return type validation for cross-contract calls
//!
//! Ensures that cross-contract calls match the called contract's ABI,
//! providing type safety across contract boundaries.

use super::call::CrossContractCall;
use anyhow::{anyhow, Result};

/// Validates cross-contract call parameters and return types
///
/// This validator is responsible for:
/// - Checking that methods exist in the callee's ABI
/// - Verifying parameter count matches
/// - Validating return types match expected interface
/// - Detecting version incompatibilities
///
/// # Design Notes
/// - Works with serialized arguments (agnostic to format)
/// - Relies on ABI registry for contract ABIs
/// - Performs early validation (fail-fast principle)
pub struct CallValidator;

/// Method signature information (from ABI)
#[derive(Debug, Clone)]
pub struct MethodSignature {
    /// Method name
    pub name: String,
    /// Number of parameters expected
    pub parameter_count: usize,
    /// Return type identifier (for compatibility checking)
    pub return_type: String,
    /// ABI version this signature is from
    pub abi_version: String,
}

/// Result of validation
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// Parameters and method exist and are valid
    Valid {
        method: String,
        parameter_count: usize,
    },
    /// Validation failed with a reason
    Invalid {
        reason: String,
    },
}

impl CallValidator {
    /// Validate that a method exists in the ABI
    ///
    /// # Arguments
    /// - `call`: The cross-contract call
    /// - `abi_methods`: Available methods in the callee's ABI
    ///
    /// # Returns
    /// Ok if method exists, Err with ValidationFailed if not
    pub fn validate_method_exists(
        call: &CrossContractCall,
        abi_methods: &[MethodSignature],
    ) -> Result<()> {
        if abi_methods.iter().any(|m| m.name == call.method) {
            Ok(())
        } else {
            Err(anyhow!(
                "Method '{}' not found in callee's ABI",
                call.method
            ))
        }
    }

    /// Validate that the number of parameters matches the method signature
    ///
    /// # Arguments
    /// - `call`: The cross-contract call
    /// - `method_sig`: The method signature from callee's ABI
    /// - `actual_param_count`: Actual number of parameters provided
    ///
    /// # Returns
    /// Ok if parameter count matches, Err otherwise
    pub fn validate_parameter_count(
        call: &CrossContractCall,
        method_sig: &MethodSignature,
        actual_param_count: usize,
    ) -> Result<()> {
        if method_sig.parameter_count == actual_param_count {
            Ok(())
        } else {
            Err(anyhow!(
                "Method '{}' expects {} parameters but got {}",
                call.method,
                method_sig.parameter_count,
                actual_param_count
            ))
        }
    }

    /// Validate return type compatibility
    ///
    /// # Arguments
    /// - `method_sig`: The method signature from callee's ABI
    /// - `expected_return_type`: Expected return type at call site
    ///
    /// # Returns
    /// Ok if return types are compatible, Err otherwise
    pub fn validate_return_type(
        method_sig: &MethodSignature,
        expected_return_type: &str,
    ) -> Result<()> {
        if method_sig.return_type == expected_return_type
            || expected_return_type == "*" // Wildcard: accept any return type
            || Self::is_compatible_type(&method_sig.return_type, expected_return_type)
        {
            Ok(())
        } else {
            Err(anyhow!(
                "Return type mismatch: method returns '{}' but caller expects '{}'",
                method_sig.return_type,
                expected_return_type
            ))
        }
    }

    /// Check if two types are compatible (for subtyping, coercion, etc.)
    ///
    /// # Examples
    /// - "u64" is compatible with "u64"
    /// - "Result<u64>" might be compatible with "u64" with error handling
    fn is_compatible_type(method_type: &str, expected_type: &str) -> bool {
        // Exact match
        if method_type == expected_type {
            return true;
        }

        // Result<T> can be used where T is expected (with error handling)
        if method_type.starts_with("Result<") && method_type.ends_with(">") {
            let inner = &method_type[7..method_type.len() - 1];
            if inner == expected_type {
                return true;
            }
        }

        // Option<T> can be used where T is expected (with None handling)
        if method_type.starts_with("Option<") && method_type.ends_with(">") {
            let inner = &method_type[7..method_type.len() - 1];
            if inner == expected_type {
                return true;
            }
        }

        false
    }

    /// Validate version compatibility between caller and callee ABIs
    ///
    /// # Arguments
    /// - `caller_abi_version`: ABI version at the call site
    /// - `callee_abi_version`: ABI version in the callee
    ///
    /// # Returns
    /// Ok if versions are compatible, Err if incompatible
    pub fn validate_version_compatibility(
        caller_abi_version: &str,
        callee_abi_version: &str,
    ) -> Result<()> {
        // Parse semantic versions (e.g., "1.2.3")
        let caller_parts = Self::parse_version(caller_abi_version)?;
        let callee_parts = Self::parse_version(callee_abi_version)?;

        // Major version must match (breaking changes)
        if caller_parts.0 != callee_parts.0 {
            return Err(anyhow!(
                "ABI version incompatibility: caller expects {}.x.x but callee is {}.x.x",
                caller_parts.0,
                callee_parts.0
            ));
        }

        // Minor version: callee must be >= caller (backward compatibility)
        if callee_parts.1 < caller_parts.1 {
            return Err(anyhow!(
                "ABI version incompatibility: caller expects {}.{}.x but callee is {}.{}.x",
                caller_parts.0, caller_parts.1, callee_parts.0, callee_parts.1
            ));
        }

        Ok(())
    }

    /// Parse semantic version string "major.minor.patch"
    fn parse_version(version: &str) -> Result<(u32, u32, u32)> {
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() != 3 {
            return Err(anyhow!(
                "Invalid version format: expected 'major.minor.patch', got '{}'",
                version
            ));
        }

        let major = parts[0]
            .parse::<u32>()
            .map_err(|_| anyhow!("Invalid major version: '{}'", parts[0]))?;
        let minor = parts[1]
            .parse::<u32>()
            .map_err(|_| anyhow!("Invalid minor version: '{}'", parts[1]))?;
        let patch = parts[2]
            .parse::<u32>()
            .map_err(|_| anyhow!("Invalid patch version: '{}'", parts[2]))?;

        Ok((major, minor, patch))
    }

    /// Comprehensive validation of a call
    ///
    /// Performs all validation checks in sequence:
    /// 1. Method exists
    /// 2. Parameter count matches
    /// 3. Return type is compatible
    /// 4. ABI versions are compatible
    pub fn validate_call(
        call: &CrossContractCall,
        available_methods: &[MethodSignature],
        actual_param_count: usize,
        expected_return_type: &str,
        caller_abi_version: &str,
    ) -> Result<ValidationResult> {
        // Find the method signature
        let method_sig = available_methods
            .iter()
            .find(|m| m.name == call.method)
            .ok_or_else(|| anyhow!("Method '{}' not found", call.method))?;

        // Validate parameter count
        Self::validate_parameter_count(call, method_sig, actual_param_count)?;

        // Validate return type
        Self::validate_return_type(method_sig, expected_return_type)?;

        // Validate version compatibility
        Self::validate_version_compatibility(caller_abi_version, &method_sig.abi_version)?;

        Ok(ValidationResult::Valid {
            method: call.method.clone(),
            parameter_count: method_sig.parameter_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_call(method: &str) -> CrossContractCall {
        let caller = [1u8; 32];
        let callee = [2u8; 32];
        CrossContractCall::new(caller, callee, method.to_string(), vec![])
    }

    fn create_test_signature(name: &str, param_count: usize) -> MethodSignature {
        MethodSignature {
            name: name.to_string(),
            parameter_count: param_count,
            return_type: "u64".to_string(),
            abi_version: "1.0.0".to_string(),
        }
    }

    #[test]
    fn test_validate_method_exists_found() {
        let call = create_test_call("transfer");
        let methods = vec![
            create_test_signature("transfer", 2),
            create_test_signature("approve", 2),
        ];

        let result = CallValidator::validate_method_exists(&call, &methods);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_method_exists_not_found() {
        let call = create_test_call("unknown_method");
        let methods = vec![
            create_test_signature("transfer", 2),
            create_test_signature("approve", 2),
        ];

        let result = CallValidator::validate_method_exists(&call, &methods);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not found"));
    }

    #[test]
    fn test_validate_method_exists_empty_abi() {
        let call = create_test_call("transfer");
        let methods = vec![];

        let result = CallValidator::validate_method_exists(&call, &methods);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_parameter_count_match() {
        let call = create_test_call("transfer");
        let sig = create_test_signature("transfer", 2);

        let result = CallValidator::validate_parameter_count(&call, &sig, 2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_parameter_count_mismatch_too_few() {
        let call = create_test_call("transfer");
        let sig = create_test_signature("transfer", 2);

        let result = CallValidator::validate_parameter_count(&call, &sig, 1);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expects 2"));
    }

    #[test]
    fn test_validate_parameter_count_mismatch_too_many() {
        let call = create_test_call("transfer");
        let sig = create_test_signature("transfer", 2);

        let result = CallValidator::validate_parameter_count(&call, &sig, 3);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("expects 2"));
    }

    #[test]
    fn test_validate_parameter_count_zero() {
        let call = create_test_call("balance_of");
        let sig = MethodSignature {
            name: "balance_of".to_string(),
            parameter_count: 0,
            return_type: "u64".to_string(),
            abi_version: "1.0.0".to_string(),
        };

        let result = CallValidator::validate_parameter_count(&call, &sig, 0);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_return_type_exact_match() {
        let sig = MethodSignature {
            name: "test".to_string(),
            parameter_count: 0,
            return_type: "u64".to_string(),
            abi_version: "1.0.0".to_string(),
        };

        let result = CallValidator::validate_return_type(&sig, "u64");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_return_type_wildcard() {
        let sig = MethodSignature {
            name: "test".to_string(),
            parameter_count: 0,
            return_type: "bytes32".to_string(),
            abi_version: "1.0.0".to_string(),
        };

        let result = CallValidator::validate_return_type(&sig, "*");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_return_type_mismatch() {
        let sig = MethodSignature {
            name: "test".to_string(),
            parameter_count: 0,
            return_type: "u64".to_string(),
            abi_version: "1.0.0".to_string(),
        };

        let result = CallValidator::validate_return_type(&sig, "u32");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[test]
    fn test_is_compatible_type_result() {
        assert!(CallValidator::is_compatible_type(
            "Result<u64>",
            "u64"
        ));
        assert!(!CallValidator::is_compatible_type(
            "Result<u32>",
            "u64"
        ));
    }

    #[test]
    fn test_is_compatible_type_option() {
        assert!(CallValidator::is_compatible_type(
            "Option<u64>",
            "u64"
        ));
        assert!(!CallValidator::is_compatible_type(
            "Option<u32>",
            "u64"
        ));
    }

    #[test]
    fn test_parse_version_valid() {
        let result = CallValidator::parse_version("1.2.3");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (1, 2, 3));
    }

    #[test]
    fn test_parse_version_zeros() {
        let result = CallValidator::parse_version("0.0.0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (0, 0, 0));
    }

    #[test]
    fn test_parse_version_large_numbers() {
        let result = CallValidator::parse_version("256.512.1024");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), (256, 512, 1024));
    }

    #[test]
    fn test_parse_version_invalid_format() {
        let result = CallValidator::parse_version("1.2");
        assert!(result.is_err());

        let result = CallValidator::parse_version("1.2.3.4");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_version_invalid_numbers() {
        let result = CallValidator::parse_version("a.b.c");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_version_compatibility_matching() {
        let result =
            CallValidator::validate_version_compatibility("1.0.0", "1.0.0");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_version_compatibility_minor_upgrade() {
        let result =
            CallValidator::validate_version_compatibility("1.0.0", "1.1.0");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_version_compatibility_patch_upgrade() {
        let result =
            CallValidator::validate_version_compatibility("1.0.0", "1.0.5");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_version_compatibility_major_mismatch() {
        let result =
            CallValidator::validate_version_compatibility("1.0.0", "2.0.0");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .to_lowercase()
            .contains("incompatibility"));
    }

    #[test]
    fn test_validate_version_compatibility_minor_downgrade() {
        let result =
            CallValidator::validate_version_compatibility("1.1.0", "1.0.0");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_call_comprehensive_valid() {
        let call = create_test_call("transfer");
        let methods = vec![create_test_signature("transfer", 2)];

        let result = CallValidator::validate_call(
            &call,
            &methods,
            2,           // param count
            "u64",       // return type
            "1.0.0",     // caller version
        );

        assert!(result.is_ok());
        match result.unwrap() {
            ValidationResult::Valid { method, parameter_count } => {
                assert_eq!(method, "transfer");
                assert_eq!(parameter_count, 2);
            }
            _ => panic!("Expected Valid result"),
        }
    }

    #[test]
    fn test_validate_call_method_not_found() {
        let call = create_test_call("unknown");
        let methods = vec![create_test_signature("transfer", 2)];

        let result = CallValidator::validate_call(
            &call,
            &methods,
            2,
            "u64",
            "1.0.0",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_call_parameter_mismatch() {
        let call = create_test_call("transfer");
        let methods = vec![create_test_signature("transfer", 2)];

        let result = CallValidator::validate_call(
            &call,
            &methods,
            3,  // Wrong count
            "u64",
            "1.0.0",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_call_return_type_mismatch() {
        let call = create_test_call("transfer");
        let methods = vec![create_test_signature("transfer", 2)];

        let result = CallValidator::validate_call(
            &call,
            &methods,
            2,
            "u32", // Wrong type
            "1.0.0",
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_validate_call_version_mismatch() {
        let call = create_test_call("transfer");
        let methods = vec![MethodSignature {
            name: "transfer".to_string(),
            parameter_count: 2,
            return_type: "u64".to_string(),
            abi_version: "2.0.0".to_string(), // Different major version
        }];

        let result = CallValidator::validate_call(
            &call,
            &methods,
            2,
            "u64",
            "1.0.0", // Caller expects v1
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_method_signature_creation() {
        let sig = MethodSignature {
            name: "test".to_string(),
            parameter_count: 3,
            return_type: "bool".to_string(),
            abi_version: "1.2.3".to_string(),
        };

        assert_eq!(sig.name, "test");
        assert_eq!(sig.parameter_count, 3);
        assert_eq!(sig.return_type, "bool");
        assert_eq!(sig.abi_version, "1.2.3");
    }

    #[test]
    fn test_validation_result_valid() {
        let result = ValidationResult::Valid {
            method: "transfer".to_string(),
            parameter_count: 2,
        };

        match result {
            ValidationResult::Valid { method, parameter_count } => {
                assert_eq!(method, "transfer");
                assert_eq!(parameter_count, 2);
            }
            _ => panic!("Expected Valid"),
        }
    }
}
