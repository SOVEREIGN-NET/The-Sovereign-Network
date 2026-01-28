//! Integration tests for ABI system
//!
//! Tests the complete ABI workflow including schema creation, validation,
//! encoding, and registry operations.

#[cfg(test)]
mod abi_tests {
    use crate::contracts::abi::schema::*;
    use crate::contracts::abi::{
        codec, registry, validation, privilege, codegen
    };

    /// Test complete UBI contract ABI
    #[test]
    fn test_ubi_abi_creation() {
        let abi = ContractAbi::new("UBI", "1.0.0");

        // Create claim method
        let claim_method = MethodSchema::new(
            "claim",
            ReturnType::Value {
                r#type: Box::new(ParameterType::U64),
            },
        )
        .kernel_only();

        let abi_with_method = abi.with_method(claim_method);

        // Create events
        let claim_recorded_event = EventSchema {
            name: "ClaimRecorded".to_string(),
            fields: vec![
                EventField {
                    name: "citizen".to_string(),
                    r#type: FieldType::Bytes32,
                    indexed: true,
                    description: None,
                },
                EventField {
                    name: "amount".to_string(),
                    r#type: FieldType::U64,
                    indexed: false,
                    description: None,
                },
            ],
            description: None,
            indexed: false,
        };

        let final_abi = abi_with_method.with_events(vec![claim_recorded_event]);

        assert_eq!(final_abi.contract, "UBI");
        assert_eq!(final_abi.version, "1.0.0");
        assert_eq!(final_abi.methods.len(), 1);
        assert_eq!(final_abi.methods[0].name, "claim");
        assert!(final_abi.events.is_some());
    }

    /// Test ABI validation
    #[test]
    fn test_abi_validation() {
        let valid_abi = ContractAbi::new("Test", "1.0.0");
        assert!(validation::AbiValidator::validate(&valid_abi).is_ok());
    }

    /// Test ABI encoding and decoding
    #[test]
    fn test_abi_serialization_round_trip() {
        let original = ContractAbi::new("TestContract", "2.0.0")
            .with_method(MethodSchema::new("test", ReturnType::Void));

        let json = codec::AbiEncoder::encode_abi(&original)
            .expect("Should encode ABI");

        let decoded = codec::AbiDecoder::decode_abi(&json)
            .expect("Should decode ABI");

        assert_eq!(decoded.contract, "TestContract");
        assert_eq!(decoded.version, "2.0.0");
        assert_eq!(decoded.methods.len(), 1);
    }

    /// Test deterministic hashing
    #[test]
    fn test_abi_hash_consistency() {
        let abi = ContractAbi::new("Immutable", "1.0.0");

        let hash1 = codec::AbiEncoder::abi_hash(&abi)
            .expect("Should hash");
        let hash2 = codec::AbiEncoder::abi_hash(&abi)
            .expect("Should hash");

        assert_eq!(hash1, hash2, "Hashes should be deterministic");
    }

    /// Test ABI registry
    #[test]
    fn test_registry_management() {
        let mut registry = registry::AbiRegistry::new();

        let abi1 = ContractAbi::new("UBI", "1.0.0");
        let abi2 = ContractAbi::new("DevGrants", "1.0.0");

        registry.register(abi1).expect("Should register UBI");
        registry.register(abi2).expect("Should register DevGrants");

        assert_eq!(registry.len(), 2);
        assert!(registry.get("UBI").is_some());
        assert!(registry.get("DevGrants").is_some());
        assert!(registry.get("NonExistent").is_none());
    }

    /// Test privilege markers
    #[test]
    fn test_privilege_authorization() {
        let kernel_marker = privilege::PrivilegeMarker::kernel_only();

        assert!(!kernel_marker.can_execute(privilege::PrivilegeLevel::Public));
        assert!(kernel_marker.can_execute(privilege::PrivilegeLevel::Kernel));

        let public_marker = privilege::PrivilegeMarker::public();
        assert!(public_marker.can_execute(privilege::PrivilegeLevel::Public));
        assert!(public_marker.can_execute(privilege::PrivilegeLevel::Kernel));
    }

    /// Test that design respects ADR-0017 (Execution Boundary)
    #[test]
    fn test_execution_boundary_semantics() {
        // All methods should default to "intent" semantics
        let method = MethodSchema::new("test", ReturnType::Void);
        assert_eq!(method.semantics, ExecutionSemantics::Intent);

        // Query methods should have query semantics
        let query_method = MethodSchema {
            name: "balance".to_string(),
            parameters: vec![],
            returns: ReturnType::Value {
                r#type: Box::new(ParameterType::U64),
            },
            privilege: None,
            semantics: ExecutionSemantics::Query,
            description: None,
            deprecated: None,
        };
        assert_eq!(query_method.semantics, ExecutionSemantics::Query);
    }

    /// Test kernel-only privilege enforcement
    #[test]
    fn test_kernel_only_enforcement() {
        let abi = ContractAbi::new("TreasuryTest", "1.0.0").with_method(
            MethodSchema::new("mint", ReturnType::Void)
                .with_privilege(PrivilegeRequirement {
                    kernel_only: true,
                    governance_gated: false,
                    require_role: None,
                    custom_check: None,
                })
        );

        // Verify kernel_only flag is set
        assert!(abi.methods[0].privilege.as_ref().unwrap().kernel_only);
    }

    /// Test Rust code generation
    #[test]
    fn test_rust_codegen() {
        let abi = ContractAbi::new("UBI", "1.0.0").with_method(
            MethodSchema::new("claim", ReturnType::Value {
                r#type: Box::new(ParameterType::U64),
            })
        );

        let rust_code = codegen::AbiCodegen::generate_rust(&abi)
            .expect("Should generate Rust code");

        assert!(rust_code.contains("struct CallClaim"));
        assert!(rust_code.contains("pub fn new("));
        assert!(rust_code.contains("Auto-generated Rust bindings"));
    }

    /// Test TypeScript code generation
    #[test]
    fn test_ts_codegen() {
        let abi = ContractAbi::new("UBI", "1.0.0").with_method(
            MethodSchema::new("claim", ReturnType::Value {
                r#type: Box::new(ParameterType::U64),
            })
        );

        let ts_code = codegen::AbiCodegen::generate_typescript(&abi)
            .expect("Should generate TypeScript code");

        assert!(ts_code.contains("interface CallClaim"));
        assert!(ts_code.contains("interface IUBI"));
        assert!(ts_code.contains("Auto-generated TypeScript bindings"));
    }

    /// Test that generated code respects type mapping
    #[test]
    fn test_codegen_type_mapping() {
        let abi = ContractAbi::new("Types", "1.0.0").with_method(
            MethodSchema::new("complex_call", ReturnType::Void)
                .with_parameter(Parameter {
                    name: "amount".to_string(),
                    r#type: ParameterType::U64,
                    description: None,
                    optional: None,
                })
                .with_parameter(Parameter {
                    name: "data".to_string(),
                    r#type: ParameterType::Bytes32,
                    description: None,
                    optional: None,
                })
        );

        let rust_code = codegen::AbiCodegen::generate_rust(&abi)
            .expect("Should generate Rust");

        // Verify Rust type mappings
        assert!(rust_code.contains("amount: u64"));
        assert!(rust_code.contains("data: [u8; 32]"));

        let ts_code = codegen::AbiCodegen::generate_typescript(&abi)
            .expect("Should generate TypeScript");

        // Verify TypeScript type mappings
        assert!(ts_code.contains("amount: bigint"));
        assert!(ts_code.contains("data: Uint8Array"));
    }
}
