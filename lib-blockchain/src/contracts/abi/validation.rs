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
        // Rust and TypeScript reserved keywords that cannot be used as identifiers
        let reserved_keywords = std::collections::HashSet::from([
            "abstract", "arguments", "await", "boolean", "break", "byte", "case", "catch",
            "char", "class", "const", "continue", "debugger", "default", "delete", "do",
            "double", "else", "enum", "eval", "export", "extends", "false", "final",
            "finally", "float", "for", "function", "goto", "if", "implements", "import",
            "in", "instanceof", "int", "interface", "let", "long", "native", "new",
            "null", "package", "private", "protected", "public", "return", "short",
            "static", "super", "switch", "synchronized", "this", "throw", "throws",
            "transient", "true", "try", "typeof", "var", "void", "volatile", "while",
            "with", "yield",
        ]);

        // Check for duplicate method names
        let mut names = std::collections::HashSet::new();
        for method in methods {
            if !names.insert(&method.name) {
                return Err(anyhow!("Duplicate method name: {}", method.name));
            }

            // Validate method name format (must be valid identifier)
            Self::validate_identifier(&method.name, "method")?;

            // Validate parameter names are unique and valid identifiers
            let mut param_names = std::collections::HashSet::new();
            for param in &method.parameters {
                if !param_names.insert(&param.name) {
                    return Err(anyhow!(
                        "Duplicate parameter name '{}' in method '{}'",
                        param.name,
                        method.name
                    ));
                }

                // Validate parameter name is a valid identifier and not a reserved keyword
                Self::validate_identifier(&param.name, "parameter")?;
                if reserved_keywords.contains(param.name.as_str()) {
                    return Err(anyhow!(
                        "Parameter name '{}' is a reserved keyword and cannot be used",
                        param.name
                    ));
                }
            }
        }
        Ok(())
    }

    /// Validate that a name is a valid Rust/TypeScript identifier
    fn validate_identifier(name: &str, kind: &str) -> Result<()> {
        if name.is_empty() {
            return Err(anyhow!("{} name cannot be empty", kind));
        }

        // Must start with letter or underscore
        if !name.chars().next().unwrap().is_alphabetic() && !name.starts_with('_') {
            return Err(anyhow!(
                "Invalid {} name '{}': must start with letter or underscore",
                kind,
                name
            ));
        }

        // Must contain only alphanumeric and underscore
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err(anyhow!(
                "Invalid {} name '{}': must contain only alphanumeric and underscore characters",
                kind,
                name
            ));
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
        // First validate the type definitions themselves
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
                    // Validate field types in struct
                    for (_field_name, field_type) in fields {
                        Self::validate_parameter_type_references(field_type, types, "struct field")?;
                    }
                }
            }
        }

        // Validate all custom type references in methods and events
        for method in &abi.methods {
            // Check method parameters
            for param in &method.parameters {
                Self::validate_parameter_type_references(&param.r#type, types, "method parameter")?;
            }

            // Check method return type
            if let ReturnType::Value { r#type } = &method.returns {
                Self::validate_parameter_type_references(r#type, types, "method return type")?;
            }
        }

        // Check event field types
        if let Some(events) = &abi.events {
            for event in events {
                for field in &event.fields {
                    Self::validate_field_type_references(&field.r#type, types, "event field")?;
                }
            }
        }

        Ok(())
    }

    /// Recursively validate that all custom type references exist in the types map
    fn validate_parameter_type_references(
        param_type: &ParameterType,
        types: &std::collections::HashMap<String, TypeDefinition>,
        context: &str,
    ) -> Result<()> {
        match param_type {
            ParameterType::Custom { name } => {
                if !types.contains_key(name) {
                    return Err(anyhow!(
                        "Undefined custom type '{}' referenced in {}",
                        name,
                        context
                    ));
                }
            }
            ParameterType::Array { item } => {
                Self::validate_parameter_type_references(item, types, context)?;
            }
            ParameterType::Optional { inner } => {
                Self::validate_parameter_type_references(inner, types, context)?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Recursively validate that all custom type references exist for field types
    fn validate_field_type_references(
        field_type: &FieldType,
        types: &std::collections::HashMap<String, TypeDefinition>,
        context: &str,
    ) -> Result<()> {
        match field_type {
            FieldType::Custom { name } => {
                if !types.contains_key(name) {
                    return Err(anyhow!(
                        "Undefined custom type '{}' referenced in {}",
                        name,
                        context
                    ));
                }
            }
            FieldType::Array { item } => {
                Self::validate_field_type_references(item, types, context)?;
            }
            _ => {}
        }
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
