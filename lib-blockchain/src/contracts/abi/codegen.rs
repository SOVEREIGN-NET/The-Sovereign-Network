//! ABI code generation for Rust and TypeScript bindings
//!
//! Generates type-safe bindings and validators from ABI schemas,
//! enabling developers to write safe contract interactions.

use super::schema::*;
use anyhow::Result;

/// Code generator for ABI schemas
pub struct AbiCodegen;

impl AbiCodegen {
    /// Generate Rust type-safe bindings from ABI
    ///
    /// Produces Rust module with:
    /// - Method call structs
    /// - Event emission structs
    /// - Type definitions
    /// - Validation helpers
    pub fn generate_rust(abi: &ContractAbi) -> Result<String> {
        let mut output = String::new();

        // Module header
        output.push_str(&format!(
            "//! Auto-generated Rust bindings for {} contract v{}\n",
            abi.contract, abi.version
        ));
        output.push_str("//! This module is auto-generated from the contract ABI.\n");
        output.push_str("//! Do not edit manually.\n\n");

        // Add use statements
        output.push_str("use serde::{Serialize, Deserialize};\n");
        output.push_str("use anyhow::Result;\n\n");

        // Generate method types
        output.push_str("// ===== Method Types =====\n\n");
        for method in &abi.methods {
            output.push_str(&Self::generate_rust_method(method, &abi.contract)?);
            output.push_str("\n");
        }

        // Generate event types
        if let Some(events) = &abi.events {
            output.push_str("// ===== Event Types =====\n\n");
            for event in events {
                output.push_str(&Self::generate_rust_event(event)?);
                output.push_str("\n");
            }
        }

        // Generate custom types
        if let Some(types) = &abi.types {
            output.push_str("// ===== Custom Types =====\n\n");
            for (name, typedef) in types {
                output.push_str(&Self::generate_rust_type(name, typedef)?);
                output.push_str("\n");
            }
        }

        // Generate validator trait
        output.push_str(&Self::generate_rust_validator(&abi.contract)?);

        Ok(output)
    }

    fn generate_rust_method(method: &MethodSchema, contract: &str) -> Result<String> {
        let mut output = String::new();
        let struct_name = Self::to_pascal_case(&method.name);

        // Struct definition
        output.push_str(&format!("/// Call to {}.{}\n", contract, method.name));
        if let Some(desc) = &method.description {
            output.push_str(&format!("/// \n/// {}\n", desc));
        }

        output.push_str("#[derive(Debug, Clone, Serialize, Deserialize)]\n");
        output.push_str(&format!("pub struct Call{} {{\n", struct_name));

        // Add fields for each parameter
        for param in &method.parameters {
            let param_type = Self::rust_type_from_param(&param.r#type)?;
            output.push_str(&format!("    pub {}: {},\n", param.name, param_type));
        }

        output.push_str("}\n\n");

        // Builder implementation
        output.push_str(&format!("impl Call{} {{\n", struct_name));
        output.push_str(&format!("    /// Create a new call to {}\n", method.name));
        output.push_str("    pub fn new(");

        for (i, param) in method.parameters.iter().enumerate() {
            let param_type = Self::rust_type_from_param(&param.r#type)?;
            if i > 0 {
                output.push_str(", ");
            }
            output.push_str(&format!("{}: {}", param.name, param_type));
        }

        output.push_str(") -> Self {\n");
        output.push_str("        Self {\n");
        for param in &method.parameters {
            output.push_str(&format!("            {},\n", param.name));
        }
        output.push_str("        }\n");
        output.push_str("    }\n");
        output.push_str("}\n");

        Ok(output)
    }

    fn generate_rust_event(event: &EventSchema) -> Result<String> {
        let mut output = String::new();
        let struct_name = Self::to_pascal_case(&event.name);

        output.push_str(&format!("/// Event: {}\n", event.name));
        if let Some(desc) = &event.description {
            output.push_str(&format!("/// {}\n", desc));
        }

        output.push_str("#[derive(Debug, Clone, Serialize, Deserialize)]\n");
        output.push_str(&format!("pub struct Event{} {{\n", struct_name));

        for field in &event.fields {
            let field_type = Self::rust_type_from_field(&field.r#type)?;
            output.push_str(&format!("    pub {}: {},\n", field.name, field_type));
        }

        output.push_str("}\n");

        Ok(output)
    }

    fn generate_rust_type(name: &str, typedef: &TypeDefinition) -> Result<String> {
        match typedef {
            TypeDefinition::Enum { variants, descriptions } => {
                let mut output = String::new();
                output.push_str("#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]\n");
                output.push_str(&format!("pub enum {} {{\n", name));

                for variant in variants {
                    if let Some(descs) = descriptions {
                        if let Some(desc) = descs.get(variant) {
                            output.push_str(&format!("    /// {}\n", desc));
                        }
                    }
                    output.push_str(&format!("    {},\n", variant));
                }

                output.push_str("}\n");
                Ok(output)
            }
            TypeDefinition::Struct { fields } => {
                let mut output = String::new();
                output.push_str("#[derive(Debug, Clone, Serialize, Deserialize)]\n");
                output.push_str(&format!("pub struct {} {{\n", name));

                for (field_name, field_type) in fields {
                    let rust_type = Self::rust_type_from_param(field_type)?;
                    output.push_str(&format!("    pub {}: {},\n", field_name, rust_type));
                }

                output.push_str("}\n");
                Ok(output)
            }
        }
    }

    fn generate_rust_validator(contract: &str) -> Result<String> {
        let mut output = String::new();

        output.push_str("// ===== Validator =====\n\n");
        output.push_str(&format!("/// Validator for {} contract calls\n", contract));
        output.push_str(&format!("pub struct {}Validator;\n\n", Self::to_pascal_case(contract)));
        output.push_str(&format!("impl {}Validator {{\n", Self::to_pascal_case(contract)));
        output.push_str("    /// Validate contract state\n");
        output.push_str("    pub fn validate() -> Result<()> {\n");
        output.push_str("        // Validation logic would go here\n");
        output.push_str("        Ok(())\n");
        output.push_str("    }\n");
        output.push_str("}\n");

        Ok(output)
    }

    /// Generate TypeScript bindings
    pub fn generate_typescript(abi: &ContractAbi) -> Result<String> {
        let mut output = String::new();

        // Header
        output.push_str(&format!(
            "// Auto-generated TypeScript bindings for {} contract v{}\n",
            abi.contract, abi.version
        ));
        output.push_str("// This file is auto-generated from the contract ABI.\n");
        output.push_str("// Do not edit manually.\n\n");

        // Method types
        output.push_str("// ===== Method Types =====\n\n");
        for method in &abi.methods {
            output.push_str(&Self::generate_ts_method(method)?);
            output.push_str("\n");
        }

        // Event types
        if let Some(events) = &abi.events {
            output.push_str("// ===== Event Types =====\n\n");
            for event in events {
                output.push_str(&Self::generate_ts_event(event)?);
                output.push_str("\n");
            }
        }

        // Custom types
        if let Some(types) = &abi.types {
            output.push_str("// ===== Custom Types =====\n\n");
            for (name, typedef) in types {
                output.push_str(&Self::generate_ts_type(name, typedef)?);
                output.push_str("\n");
            }
        }

        // Contract interface
        output.push_str(&format!("export interface I{} {{\n", Self::to_pascal_case(&abi.contract)));
        for method in &abi.methods {
            output.push_str(&format!(
                "  {}(args: Call{}): Promise<any>;\n",
                method.name,
                Self::to_pascal_case(&method.name)
            ));
        }
        output.push_str("}\n");

        Ok(output)
    }

    fn generate_ts_method(method: &MethodSchema) -> Result<String> {
        let mut output = String::new();
        let interface_name = format!("Call{}", Self::to_pascal_case(&method.name));

        output.push_str(&format!("export interface {} {{\n", interface_name));
        for param in &method.parameters {
            let param_type = Self::ts_type_from_param(&param.r#type)?;
            output.push_str(&format!("  {}: {};\n", param.name, param_type));
        }
        output.push_str("}\n");

        Ok(output)
    }

    fn generate_ts_event(event: &EventSchema) -> Result<String> {
        let mut output = String::new();
        let interface_name = format!("Event{}", Self::to_pascal_case(&event.name));

        output.push_str(&format!("export interface {} {{\n", interface_name));
        for field in &event.fields {
            let field_type = Self::ts_type_from_field(&field.r#type)?;
            output.push_str(&format!("  {}: {};\n", field.name, field_type));
        }
        output.push_str("}\n");

        Ok(output)
    }

    fn generate_ts_type(name: &str, typedef: &TypeDefinition) -> Result<String> {
        match typedef {
            TypeDefinition::Enum { variants, .. } => {
                let mut output = String::new();
                output.push_str(&format!("export enum {} {{\n", name));
                for variant in variants {
                    output.push_str(&format!("  {} = '{}',\n", variant, variant));
                }
                output.push_str("}\n");
                Ok(output)
            }
            TypeDefinition::Struct { fields } => {
                let mut output = String::new();
                output.push_str(&format!("export interface {} {{\n", name));
                for (field_name, field_type) in fields {
                    let ts_type = Self::ts_type_from_param(field_type)?;
                    output.push_str(&format!("  {}: {};\n", field_name, ts_type));
                }
                output.push_str("}\n");
                Ok(output)
            }
        }
    }

    // Helper functions
    fn rust_type_from_param(param: &ParameterType) -> Result<String> {
        match param {
            ParameterType::Bytes32 => Ok("[u8; 32]".to_string()),
            ParameterType::U64 => Ok("u64".to_string()),
            ParameterType::U32 => Ok("u32".to_string()),
            ParameterType::String => Ok("String".to_string()),
            ParameterType::Bool => Ok("bool".to_string()),
            ParameterType::Array { item } => {
                let item_type = Self::rust_type_from_param(item)?;
                Ok(format!("Vec<{}>", item_type))
            }
            ParameterType::Optional { inner } => {
                let inner_type = Self::rust_type_from_param(inner)?;
                Ok(format!("Option<{}>", inner_type))
            }
            ParameterType::Custom { name } => Ok(name.clone()),
        }
    }

    fn rust_type_from_field(field: &FieldType) -> Result<String> {
        match field {
            FieldType::Bytes32 => Ok("[u8; 32]".to_string()),
            FieldType::U64 => Ok("u64".to_string()),
            FieldType::U32 => Ok("u32".to_string()),
            FieldType::String => Ok("String".to_string()),
            FieldType::Bool => Ok("bool".to_string()),
            FieldType::Address => Ok("Vec<u8>".to_string()),
            FieldType::Array { item } => {
                let item_type = Self::rust_type_from_field(item)?;
                Ok(format!("Vec<{}>", item_type))
            }
            FieldType::Custom { name } => Ok(name.clone()),
        }
    }

    fn ts_type_from_param(param: &ParameterType) -> Result<String> {
        match param {
            ParameterType::Bytes32 => Ok("Uint8Array".to_string()),
            ParameterType::U64 => Ok("bigint".to_string()),
            ParameterType::U32 => Ok("number".to_string()),
            ParameterType::String => Ok("string".to_string()),
            ParameterType::Bool => Ok("boolean".to_string()),
            ParameterType::Array { item } => {
                let item_type = Self::ts_type_from_param(item)?;
                Ok(format!("{}[]", item_type))
            }
            ParameterType::Optional { inner } => {
                let inner_type = Self::ts_type_from_param(inner)?;
                Ok(format!("{}?", inner_type))
            }
            ParameterType::Custom { name } => Ok(name.clone()),
        }
    }

    fn ts_type_from_field(field: &FieldType) -> Result<String> {
        match field {
            FieldType::Bytes32 => Ok("Uint8Array".to_string()),
            FieldType::U64 => Ok("bigint".to_string()),
            FieldType::U32 => Ok("number".to_string()),
            FieldType::String => Ok("string".to_string()),
            FieldType::Bool => Ok("boolean".to_string()),
            FieldType::Address => Ok("string".to_string()),
            FieldType::Array { item } => {
                let item_type = Self::ts_type_from_field(item)?;
                Ok(format!("{}[]", item_type))
            }
            FieldType::Custom { name } => Ok(name.clone()),
        }
    }

    fn to_pascal_case(snake_case: &str) -> String {
        snake_case
            .split('_')
            .map(|word| {
                let mut chars = word.chars();
                match chars.next() {
                    None => String::new(),
                    Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_codegen() {
        let abi = ContractAbi::new("Test", "1.0.0")
            .with_method(MethodSchema::new("claim", ReturnType::Void));

        let rust_code = AbiCodegen::generate_rust(&abi).expect("Should generate Rust");
        assert!(rust_code.contains("struct CallClaim"));
        assert!(rust_code.contains("impl CallClaim"));
    }

    #[test]
    fn test_ts_codegen() {
        let abi = ContractAbi::new("Test", "1.0.0")
            .with_method(MethodSchema::new("claim", ReturnType::Void));

        let ts_code = AbiCodegen::generate_typescript(&abi).expect("Should generate TypeScript");
        assert!(ts_code.contains("interface CallClaim"));
        assert!(ts_code.contains("interface ITest"));
    }

    #[test]
    fn test_pascal_case_conversion() {
        assert_eq!(AbiCodegen::to_pascal_case("claim_ubi"), "ClaimUbi");
        assert_eq!(AbiCodegen::to_pascal_case("test"), "Test");
        assert_eq!(AbiCodegen::to_pascal_case("multi_word_name"), "MultiWordName");
    }
}
