//! Core ABI type definitions and schema format
//!
//! Defines the canonical structure for contract ABIs, including methods, events,
//! parameters, and type definitions.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Complete contract ABI definition
///
/// Describes all public methods, events, and types for a contract.
/// Serves as the interface specification for Treasury Kernel integration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractAbi {
    /// Contract name (e.g., "UBI", "DevGrants", "ZHTP")
    pub contract: String,

    /// Semantic version of the ABI (e.g., "1.0.0")
    /// Incremented when interface changes
    pub version: String,

    /// Human-readable contract description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// All methods this contract exposes
    pub methods: Vec<MethodSchema>,

    /// All events this contract can emit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub events: Option<Vec<EventSchema>>,

    /// Custom type definitions (enums, structs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub types: Option<HashMap<String, TypeDefinition>>,

    /// Deprecation notice if contract is deprecated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<String>,

    /// Related ADRs or design documents
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<String>>,
}

/// Method signature definition
///
/// Describes a callable method on a contract, including:
/// - Parameter names and types
/// - Return type
/// - Privilege requirements
/// - Execution semantics
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MethodSchema {
    /// Method name (e.g., "claim", "transfer", "vote")
    pub name: String,

    /// Method parameters in order
    pub parameters: Vec<Parameter>,

    /// Return type from this method
    pub returns: ReturnType,

    /// Privilege requirements for this method
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privilege: Option<PrivilegeRequirement>,

    /// Execution semantics (intent vs immediate)
    #[serde(default)]
    pub semantics: ExecutionSemantics,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether this method is deprecated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deprecated: Option<bool>,
}

/// Method parameter definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Parameter {
    /// Parameter name
    pub name: String,

    /// Parameter type
    pub r#type: ParameterType,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether parameter is optional
    #[serde(skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
}

/// Event signature definition
///
/// Describes an event that can be emitted by a contract.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventSchema {
    /// Event name (e.g., "ClaimRecorded", "Transfer")
    pub name: String,

    /// Event fields in order
    pub fields: Vec<EventField>,

    /// Human-readable description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Whether event is indexed (searchable)
    #[serde(default)]
    pub indexed: bool,
}

/// Event field definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventField {
    /// Field name
    pub name: String,

    /// Field type
    pub r#type: FieldType,

    /// Whether field is indexed for efficient lookup
    #[serde(default)]
    pub indexed: bool,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// Parameter type definition
///
/// Supports primitives, arrays, and references to custom types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ParameterType {
    /// 32-byte fixed-size byte array
    #[serde(rename = "bytes32")]
    Bytes32,

    /// 64-bit unsigned integer
    #[serde(rename = "u64")]
    U64,

    /// 32-bit unsigned integer
    #[serde(rename = "u32")]
    U32,

    /// UTF-8 string
    #[serde(rename = "string")]
    String,

    /// Boolean
    #[serde(rename = "bool")]
    Bool,

    /// Array of items
    #[serde(rename = "array")]
    Array {
        /// Item type in array
        item: Box<ParameterType>,
    },

    /// Optional/nullable value
    #[serde(rename = "optional")]
    Optional {
        /// Inner type that can be None
        inner: Box<ParameterType>,
    },

    /// Reference to a custom type
    #[serde(rename = "type")]
    Custom {
        /// Name of the custom type
        name: String,
    },
}

/// Return type definition
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum ReturnType {
    /// No return value (unit type)
    #[serde(rename = "void")]
    Void,

    /// Returns a value of this type
    #[serde(rename = "value")]
    Value {
        /// The return type
        r#type: Box<ParameterType>,
    },

    /// Returns a result (success or error)
    #[serde(rename = "result")]
    Result {
        /// Success type
        ok: Box<ParameterType>,
        /// Error type
        err: Box<ParameterType>,
    },
}

/// Field type for events
///
/// Similar to parameter types but may include additional metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum FieldType {
    #[serde(rename = "bytes32")]
    Bytes32,

    #[serde(rename = "u64")]
    U64,

    #[serde(rename = "u32")]
    U32,

    #[serde(rename = "string")]
    String,

    #[serde(rename = "bool")]
    Bool,

    #[serde(rename = "address")]
    Address,

    #[serde(rename = "array")]
    Array {
        item: Box<FieldType>,
    },

    #[serde(rename = "type")]
    Custom {
        name: String,
    },
}

/// Privilege requirement for a method
///
/// Specifies what authorization is required to call this method.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegeRequirement {
    /// Only Treasury Kernel can call this method
    #[serde(default)]
    pub kernel_only: bool,

    /// Requires governance approval
    #[serde(default)]
    pub governance_gated: bool,

    /// Requires specific role
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_role: Option<String>,

    /// Custom privilege check (e.g., "caller == owner")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_check: Option<String>,
}

/// Execution semantics for a method
///
/// Indicates whether the method executes immediately or records intent
/// for deferred execution by Treasury Kernel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionSemantics {
    /// Intent: Method records intent, Treasury Kernel executes effects
    Intent,

    /// Immediate: Method executes immediately (legacy, not recommended)
    Immediate,

    /// Query: Method only reads state, has no side effects
    Query,
}

impl Default for ExecutionSemantics {
    fn default() -> Self {
        ExecutionSemantics::Intent
    }
}

/// Custom type definition (enum or struct)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
pub enum TypeDefinition {
    /// Enumeration type
    #[serde(rename = "enum")]
    Enum {
        /// Variant names
        variants: Vec<String>,
        /// Optional variant descriptions
        #[serde(skip_serializing_if = "Option::is_none")]
        descriptions: Option<HashMap<String, String>>,
    },

    /// Struct type with named fields
    #[serde(rename = "struct")]
    Struct {
        /// Field definitions
        fields: HashMap<String, ParameterType>,
    },
}

impl ContractAbi {
    /// Create a new contract ABI
    pub fn new(contract: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            contract: contract.into(),
            version: version.into(),
            description: None,
            methods: Vec::new(),
            events: None,
            types: None,
            deprecated: None,
            references: None,
        }
    }

    /// Add a method to this ABI
    pub fn with_method(mut self, method: MethodSchema) -> Self {
        self.methods.push(method);
        self
    }

    /// Set the events for this ABI
    pub fn with_events(mut self, events: Vec<EventSchema>) -> Self {
        self.events = Some(events);
        self
    }

    /// Set custom type definitions
    pub fn with_types(mut self, types: HashMap<String, TypeDefinition>) -> Self {
        self.types = Some(types);
        self
    }

    /// Validate the ABI for consistency
    pub fn validate(&self) -> Result<(), String> {
        // Check for duplicate method names
        let mut names = std::collections::HashSet::new();
        for method in &self.methods {
            if !names.insert(&method.name) {
                return Err(format!("Duplicate method name: {}", method.name));
            }
        }

        // Check for duplicate event names
        if let Some(events) = &self.events {
            let mut event_names = std::collections::HashSet::new();
            for event in events {
                if !event_names.insert(&event.name) {
                    return Err(format!("Duplicate event name: {}", event.name));
                }
            }
        }

        // Validate parameter types reference defined custom types if needed
        // This would be expanded in validation.rs

        Ok(())
    }
}

impl MethodSchema {
    /// Create a new method schema
    pub fn new(name: impl Into<String>, returns: ReturnType) -> Self {
        Self {
            name: name.into(),
            parameters: Vec::new(),
            returns,
            privilege: None,
            semantics: ExecutionSemantics::Intent,
            description: None,
            deprecated: None,
        }
    }

    /// Add a parameter to this method
    pub fn with_parameter(mut self, param: Parameter) -> Self {
        self.parameters.push(param);
        self
    }

    /// Set privilege requirement
    pub fn with_privilege(mut self, privilege: PrivilegeRequirement) -> Self {
        self.privilege = Some(privilege);
        self
    }

    /// Mark as kernel-only
    pub fn kernel_only(mut self) -> Self {
        self.privilege = Some(PrivilegeRequirement {
            kernel_only: true,
            governance_gated: false,
            require_role: None,
            custom_check: None,
        });
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_abi_creation() {
        let abi = ContractAbi::new("TestContract", "1.0.0");
        assert_eq!(abi.contract, "TestContract");
        assert_eq!(abi.version, "1.0.0");
        assert!(abi.methods.is_empty());
    }

    #[test]
    fn test_method_creation() {
        let method = MethodSchema::new(
            "test_method",
            ReturnType::Value {
                r#type: Box::new(ParameterType::U64),
            },
        )
        .kernel_only();

        assert_eq!(method.name, "test_method");
        assert!(method.privilege.is_some());
        assert!(method.privilege.unwrap().kernel_only);
    }

    #[test]
    fn test_abi_serialization() {
        let abi = ContractAbi::new("UBI", "1.0.0");
        let json = serde_json::to_string(&abi).expect("Should serialize");
        let _restored: ContractAbi = serde_json::from_str(&json).expect("Should deserialize");
    }

    #[test]
    fn test_duplicate_method_validation() {
        let mut abi = ContractAbi::new("Test", "1.0.0");
        let method1 = MethodSchema::new("claim", ReturnType::Void);
        let method2 = MethodSchema::new("claim", ReturnType::Void);

        abi = abi.with_method(method1).with_method(method2);
        assert!(abi.validate().is_err());
    }
}
