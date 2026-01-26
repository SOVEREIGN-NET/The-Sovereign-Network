//! Extended type validation for cross-contract call parameters
//!
//! Provides comprehensive type checking beyond basic signatures,
//! including primitive types, arrays, custom structs, and recursive validation.

use anyhow::{anyhow, Result};
use std::collections::HashMap;

/// Represents a type in the ABI type system
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TypeSpec {
    /// Primitive unsigned integer types
    U8,
    U16,
    U32,
    U64,
    U128,
    /// Primitive signed integer types
    I8,
    I16,
    I32,
    I64,
    I128,
    /// Boolean type
    Bool,
    /// String type (UTF-8)
    String,
    /// Raw bytes
    Bytes,
    /// Array of fixed size
    Array {
        element_type: Box<TypeSpec>,
        size: usize,
    },
    /// Dynamic vector
    Vec {
        element_type: Box<TypeSpec>,
    },
    /// Option/nullable type
    Option {
        inner_type: Box<TypeSpec>,
    },
    /// Result with success and error types
    Result {
        ok_type: Box<TypeSpec>,
        err_type: Box<TypeSpec>,
    },
    /// Custom struct type (referenced by name)
    Struct {
        name: String,
        fields: Vec<(String, TypeSpec)>,
    },
    /// Hash/bytes32
    Hash,
    /// Any type (wildcard)
    Any,
}

impl TypeSpec {
    /// Parse a type string into TypeSpec
    ///
    /// # Examples
    /// - "u64" → TypeSpec::U64
    /// - "Vec<u32>" → TypeSpec::Vec { element_type: U32 }
    /// - "Option<String>" → TypeSpec::Option { inner_type: String }
    /// - "[u8; 32]" → TypeSpec::Array { element_type: U8, size: 32 }
    pub fn parse(type_str: &str) -> Result<Self> {
        let trimmed = type_str.trim();

        // Primitive types
        match trimmed {
            "u8" => return Ok(TypeSpec::U8),
            "u16" => return Ok(TypeSpec::U16),
            "u32" => return Ok(TypeSpec::U32),
            "u64" => return Ok(TypeSpec::U64),
            "u128" => return Ok(TypeSpec::U128),
            "i8" => return Ok(TypeSpec::I8),
            "i16" => return Ok(TypeSpec::I16),
            "i32" => return Ok(TypeSpec::I32),
            "i64" => return Ok(TypeSpec::I64),
            "i128" => return Ok(TypeSpec::I128),
            "bool" => return Ok(TypeSpec::Bool),
            "String" => return Ok(TypeSpec::String),
            "bytes" => return Ok(TypeSpec::Bytes),
            "Hash" => return Ok(TypeSpec::Hash),
            "*" => return Ok(TypeSpec::Any),
            _ => {}
        }

        // Array [T; N]
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            return Self::parse_array(trimmed);
        }

        // Vec<T>
        if trimmed.starts_with("Vec<") && trimmed.ends_with('>') {
            let inner = trimmed[4..trimmed.len() - 1].trim();
            if inner.is_empty() {
                return Err(anyhow!("Vec<> requires an element type"));
            }
            let element_type = Box::new(Self::parse(inner)?);
            return Ok(TypeSpec::Vec { element_type });
        }

        // Option<T>
        if trimmed.starts_with("Option<") && trimmed.ends_with('>') {
            let inner = trimmed[7..trimmed.len() - 1].trim();
            let inner_type = Box::new(Self::parse(inner)?);
            return Ok(TypeSpec::Option { inner_type });
        }

        // Result<T, E>
        if trimmed.starts_with("Result<") && trimmed.ends_with('>') {
            let inner = trimmed[7..trimmed.len() - 1].trim();
            let parts: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
            if parts.len() != 2 {
                return Err(anyhow!(
                    "Invalid Result type: expected Result<T, E>, got {}",
                    type_str
                ));
            }
            let ok_type = Box::new(Self::parse(parts[0])?);
            let err_type = Box::new(Self::parse(parts[1])?);
            return Ok(TypeSpec::Result { ok_type, err_type });
        }

        // Custom struct (assume anything else is a struct name)
        if trimmed.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Ok(TypeSpec::Struct {
                name: trimmed.to_string(),
                fields: vec![],
            });
        }

        Err(anyhow!("Unable to parse type: {}", type_str))
    }

    /// Parse array type like "[u32; 10]"
    fn parse_array(type_str: &str) -> Result<Self> {
        let inner = &type_str[1..type_str.len() - 1]; // Remove brackets
        let parts: Vec<&str> = inner.split(';').map(|s| s.trim()).collect();

        if parts.len() != 2 {
            return Err(anyhow!(
                "Invalid array type format: expected [T; N], got {}",
                type_str
            ));
        }

        let element_type = Box::new(Self::parse(parts[0])?);
        let size = parts[1]
            .parse::<usize>()
            .map_err(|_| anyhow!("Invalid array size: {}", parts[1]))?;

        Ok(TypeSpec::Array { element_type, size })
    }

    /// Check if this type is compatible with another type
    ///
    /// Compatibility rules:
    /// - Exact match is compatible
    /// - Any (*) is compatible with everything
    /// - Covariant types (Vec<T> with Vec<U> where T compatible with U)
    pub fn is_compatible_with(&self, other: &TypeSpec) -> bool {
        // Wildcard matches anything
        if self == &TypeSpec::Any || other == &TypeSpec::Any {
            return true;
        }

        // Exact match
        if self == other {
            return true;
        }

        // Check structural compatibility
        match (self, other) {
            // Vec<T> compatible with Vec<U> if T compatible with U
            (
                TypeSpec::Vec { element_type: t1 },
                TypeSpec::Vec { element_type: t2 },
            ) => t1.is_compatible_with(t2),

            // Option<T> compatible with Option<U> if T compatible with U
            (
                TypeSpec::Option { inner_type: t1 },
                TypeSpec::Option { inner_type: t2 },
            ) => t1.is_compatible_with(t2),

            // Result<T, E1> compatible with Result<U, E2> if T compatible with U, E1 compatible with E2
            (
                TypeSpec::Result {
                    ok_type: ok1,
                    err_type: err1,
                },
                TypeSpec::Result {
                    ok_type: ok2,
                    err_type: err2,
                },
            ) => ok1.is_compatible_with(ok2) && err1.is_compatible_with(err2),

            // Array<T, N> compatible with Array<U, N> if T compatible with U and same size
            (
                TypeSpec::Array {
                    element_type: t1,
                    size: n1,
                },
                TypeSpec::Array {
                    element_type: t2,
                    size: n2,
                },
            ) => n1 == n2 && t1.is_compatible_with(t2),

            // Unsigned integers have implicit promotion rules
            // u8 → u16 → u32 → u64 → u128
            (TypeSpec::U8, TypeSpec::U16 | TypeSpec::U32 | TypeSpec::U64 | TypeSpec::U128) => {
                true
            }
            (TypeSpec::U16, TypeSpec::U32 | TypeSpec::U64 | TypeSpec::U128) => true,
            (TypeSpec::U32, TypeSpec::U64 | TypeSpec::U128) => true,
            (TypeSpec::U64, TypeSpec::U128) => true,

            // Signed integers have implicit promotion rules
            // i8 → i16 → i32 → i64 → i128
            (TypeSpec::I8, TypeSpec::I16 | TypeSpec::I32 | TypeSpec::I64 | TypeSpec::I128) => {
                true
            }
            (TypeSpec::I16, TypeSpec::I32 | TypeSpec::I64 | TypeSpec::I128) => true,
            (TypeSpec::I32, TypeSpec::I64 | TypeSpec::I128) => true,
            (TypeSpec::I64, TypeSpec::I128) => true,

            _ => false,
        }
    }

    /// Get string representation of this type
    pub fn to_string_representation(&self) -> String {
        match self {
            TypeSpec::U8 => "u8".to_string(),
            TypeSpec::U16 => "u16".to_string(),
            TypeSpec::U32 => "u32".to_string(),
            TypeSpec::U64 => "u64".to_string(),
            TypeSpec::U128 => "u128".to_string(),
            TypeSpec::I8 => "i8".to_string(),
            TypeSpec::I16 => "i16".to_string(),
            TypeSpec::I32 => "i32".to_string(),
            TypeSpec::I64 => "i64".to_string(),
            TypeSpec::I128 => "i128".to_string(),
            TypeSpec::Bool => "bool".to_string(),
            TypeSpec::String => "String".to_string(),
            TypeSpec::Bytes => "bytes".to_string(),
            TypeSpec::Hash => "Hash".to_string(),
            TypeSpec::Any => "*".to_string(),
            TypeSpec::Array { element_type, size } => {
                format!("[{}; {}]", element_type.to_string_representation(), size)
            }
            TypeSpec::Vec { element_type } => {
                format!("Vec<{}>", element_type.to_string_representation())
            }
            TypeSpec::Option { inner_type } => {
                format!("Option<{}>", inner_type.to_string_representation())
            }
            TypeSpec::Result { ok_type, err_type } => {
                format!(
                    "Result<{}, {}>",
                    ok_type.to_string_representation(),
                    err_type.to_string_representation()
                )
            }
            TypeSpec::Struct { name, .. } => name.clone(),
        }
    }
}

/// Extended type validator for cross-contract calls
pub struct TypeValidator;

impl TypeValidator {
    /// Validate that provided argument matches expected parameter type
    pub fn validate_argument_type(
        arg_type: &str,
        param_type: &str,
    ) -> Result<()> {
        let arg_spec = TypeSpec::parse(arg_type)?;
        let param_spec = TypeSpec::parse(param_type)?;

        if arg_spec.is_compatible_with(&param_spec) {
            Ok(())
        } else {
            Err(anyhow!(
                "Type mismatch: argument is {} but parameter expects {}",
                arg_type,
                param_type
            ))
        }
    }

    /// Validate multiple arguments against parameter types
    pub fn validate_arguments(
        arg_types: &[&str],
        param_types: &[&str],
    ) -> Result<()> {
        if arg_types.len() != param_types.len() {
            return Err(anyhow!(
                "Argument count mismatch: {} provided, {} expected",
                arg_types.len(),
                param_types.len()
            ));
        }

        for (i, (arg_type, param_type)) in arg_types.iter().zip(param_types.iter()).enumerate() {
            Self::validate_argument_type(arg_type, param_type).map_err(|e| {
                anyhow!("Argument {} type error: {}", i, e)
            })?;
        }

        Ok(())
    }

    /// Validate struct field types
    pub fn validate_struct_fields(
        actual_fields: &[(String, String)],
        expected_fields: &[(String, String)],
    ) -> Result<()> {
        if actual_fields.len() != expected_fields.len() {
            return Err(anyhow!(
                "Struct field count mismatch: {} provided, {} expected",
                actual_fields.len(),
                expected_fields.len()
            ));
        }

        let expected_map: HashMap<_, _> = expected_fields.iter().cloned().collect();

        for (name, actual_type) in actual_fields {
            let expected_type = expected_map
                .get(name)
                .ok_or_else(|| anyhow!("Unexpected field: {}", name))?;

            Self::validate_argument_type(actual_type, expected_type)
                .map_err(|e| anyhow!("Field '{}': {}", name, e))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_primitives() {
        assert_eq!(TypeSpec::parse("u8").unwrap(), TypeSpec::U8);
        assert_eq!(TypeSpec::parse("u32").unwrap(), TypeSpec::U32);
        assert_eq!(TypeSpec::parse("u64").unwrap(), TypeSpec::U64);
        assert_eq!(TypeSpec::parse("bool").unwrap(), TypeSpec::Bool);
        assert_eq!(TypeSpec::parse("String").unwrap(), TypeSpec::String);
    }

    #[test]
    fn test_parse_vec() {
        let vec_u32 = TypeSpec::parse("Vec<u32>").unwrap();
        match vec_u32 {
            TypeSpec::Vec { element_type } => {
                assert_eq!(*element_type, TypeSpec::U32);
            }
            _ => panic!("Expected Vec type"),
        }
    }

    #[test]
    fn test_parse_vec_nested() {
        let vec_vec_u8 = TypeSpec::parse("Vec<Vec<u8>>").unwrap();
        match vec_vec_u8 {
            TypeSpec::Vec { element_type } => {
                match *element_type {
                    TypeSpec::Vec { .. } => {}, // correct
                    _ => panic!("Expected nested Vec"),
                }
            }
            _ => panic!("Expected Vec type"),
        }
    }

    #[test]
    fn test_parse_array() {
        let arr = TypeSpec::parse("[u8; 32]").unwrap();
        match arr {
            TypeSpec::Array {
                element_type,
                size,
            } => {
                assert_eq!(*element_type, TypeSpec::U8);
                assert_eq!(size, 32);
            }
            _ => panic!("Expected Array type"),
        }
    }

    #[test]
    fn test_parse_option() {
        let opt = TypeSpec::parse("Option<u64>").unwrap();
        match opt {
            TypeSpec::Option { inner_type } => {
                assert_eq!(*inner_type, TypeSpec::U64);
            }
            _ => panic!("Expected Option type"),
        }
    }

    #[test]
    fn test_parse_result() {
        let result = TypeSpec::parse("Result<u64, String>").unwrap();
        match result {
            TypeSpec::Result { ok_type, err_type } => {
                assert_eq!(*ok_type, TypeSpec::U64);
                assert_eq!(*err_type, TypeSpec::String);
            }
            _ => panic!("Expected Result type"),
        }
    }

    #[test]
    fn test_parse_custom_struct() {
        let custom = TypeSpec::parse("TokenContract").unwrap();
        match custom {
            TypeSpec::Struct { name, .. } => {
                assert_eq!(name, "TokenContract");
            }
            _ => panic!("Expected Struct type"),
        }
    }

    #[test]
    fn test_parse_invalid() {
        assert!(TypeSpec::parse("invalid!!!").is_err());
        assert!(TypeSpec::parse("[u32; abc]").is_err());
        assert!(TypeSpec::parse("Vec<>").is_err());
    }

    #[test]
    fn test_compatibility_exact_match() {
        let u64 = TypeSpec::U64;
        assert!(u64.is_compatible_with(&u64));
    }

    #[test]
    fn test_compatibility_wildcard() {
        let any = TypeSpec::Any;
        let u32 = TypeSpec::U32;

        assert!(any.is_compatible_with(&u32));
        assert!(u32.is_compatible_with(&any));
    }

    #[test]
    fn test_compatibility_unsigned_promotion() {
        let u8 = TypeSpec::U8;
        let u32 = TypeSpec::U32;
        let u64 = TypeSpec::U64;

        assert!(u8.is_compatible_with(&u32));
        assert!(u8.is_compatible_with(&u64));
        assert!(u32.is_compatible_with(&u64));
        assert!(!u64.is_compatible_with(&u32)); // No demotion
    }

    #[test]
    fn test_compatibility_signed_promotion() {
        let i16 = TypeSpec::I16;
        let i32 = TypeSpec::I32;
        let i64 = TypeSpec::I64;

        assert!(i16.is_compatible_with(&i32));
        assert!(i16.is_compatible_with(&i64));
        assert!(i32.is_compatible_with(&i64));
        assert!(!i64.is_compatible_with(&i32)); // No demotion
    }

    #[test]
    fn test_compatibility_no_cross_sign_promotion() {
        let u32 = TypeSpec::U32;
        let i32 = TypeSpec::I32;

        assert!(!u32.is_compatible_with(&i32));
        assert!(!i32.is_compatible_with(&u32));
    }

    #[test]
    fn test_compatibility_vec_covariance() {
        let vec_u8 = TypeSpec::Vec {
            element_type: Box::new(TypeSpec::U8),
        };
        let vec_u32 = TypeSpec::Vec {
            element_type: Box::new(TypeSpec::U32),
        };

        assert!(vec_u8.is_compatible_with(&vec_u32));
        assert!(!vec_u32.is_compatible_with(&vec_u8));
    }

    #[test]
    fn test_compatibility_array_size_mismatch() {
        let arr32 = TypeSpec::Array {
            element_type: Box::new(TypeSpec::U8),
            size: 32,
        };
        let arr64 = TypeSpec::Array {
            element_type: Box::new(TypeSpec::U8),
            size: 64,
        };

        assert!(!arr32.is_compatible_with(&arr64));
    }

    #[test]
    fn test_compatibility_option_covariance() {
        let opt_u8 = TypeSpec::Option {
            inner_type: Box::new(TypeSpec::U8),
        };
        let opt_u32 = TypeSpec::Option {
            inner_type: Box::new(TypeSpec::U32),
        };

        assert!(opt_u8.is_compatible_with(&opt_u32));
    }

    #[test]
    fn test_validate_argument_type_success() {
        let result = TypeValidator::validate_argument_type("u32", "u64");
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_argument_type_failure() {
        let result = TypeValidator::validate_argument_type("u64", "u32");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_arguments_success() {
        let args = vec!["u32", "String", "bool"];
        let params = vec!["u64", "String", "bool"];
        let result = TypeValidator::validate_arguments(&args, &params);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_arguments_count_mismatch() {
        let args = vec!["u32", "String"];
        let params = vec!["u64", "String", "bool"];
        let result = TypeValidator::validate_arguments(&args, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_arguments_type_mismatch() {
        let args = vec!["u64", "String"];
        let params = vec!["u32", "String"];
        let result = TypeValidator::validate_arguments(&args, &params);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_struct_fields_success() {
        let actual = vec![
            ("amount".to_string(), "u64".to_string()),
            ("recipient".to_string(), "Hash".to_string()),
        ];
        let expected = vec![
            ("amount".to_string(), "u64".to_string()),
            ("recipient".to_string(), "Hash".to_string()),
        ];

        let result = TypeValidator::validate_struct_fields(&actual, &expected);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_struct_fields_missing_field() {
        let actual = vec![("amount".to_string(), "u64".to_string())];
        let expected = vec![
            ("amount".to_string(), "u64".to_string()),
            ("recipient".to_string(), "Hash".to_string()),
        ];

        let result = TypeValidator::validate_struct_fields(&actual, &expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_struct_fields_type_mismatch() {
        let actual = vec![
            ("amount".to_string(), "String".to_string()),
            ("recipient".to_string(), "Hash".to_string()),
        ];
        let expected = vec![
            ("amount".to_string(), "u64".to_string()),
            ("recipient".to_string(), "Hash".to_string()),
        ];

        let result = TypeValidator::validate_struct_fields(&actual, &expected);
        assert!(result.is_err());
    }

    #[test]
    fn test_to_string_representation_primitives() {
        assert_eq!(TypeSpec::U64.to_string_representation(), "u64");
        assert_eq!(TypeSpec::Bool.to_string_representation(), "bool");
        assert_eq!(TypeSpec::String.to_string_representation(), "String");
    }

    #[test]
    fn test_to_string_representation_complex() {
        let vec_u32 = TypeSpec::Vec {
            element_type: Box::new(TypeSpec::U32),
        };
        assert_eq!(vec_u32.to_string_representation(), "Vec<u32>");

        let arr = TypeSpec::Array {
            element_type: Box::new(TypeSpec::U8),
            size: 32,
        };
        assert_eq!(arr.to_string_representation(), "[u8; 32]");
    }

    #[test]
    fn test_parse_whitespace_handling() {
        assert_eq!(TypeSpec::parse("  u64  ").unwrap(), TypeSpec::U64);
        let result = TypeSpec::parse("Vec< u32 >").unwrap();
        match result {
            TypeSpec::Vec { element_type } => {
                assert_eq!(*element_type, TypeSpec::U32);
            }
            _ => panic!("Expected Vec"),
        }
    }

    #[test]
    fn test_deeply_nested_types() {
        let nested = TypeSpec::parse("Vec<Option<Vec<u32>>>").unwrap();
        match nested {
            TypeSpec::Vec { .. } => {}, // Success
            _ => panic!("Failed to parse deeply nested type"),
        }
    }

    #[test]
    fn test_array_with_large_size() {
        let arr = TypeSpec::parse("[u8; 1000000]").unwrap();
        match arr {
            TypeSpec::Array { size, .. } => {
                assert_eq!(size, 1000000);
            }
            _ => panic!("Expected Array"),
        }
    }
}
