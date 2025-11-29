# Validation Module

This module provides comprehensive validation for ZHTP requests, responses, and Web4 components, including zero-knowledge proof validation, economic model validation, content integrity, and protocol compliance checks.

## Main Types
- `ZhtpValidator`: Main validation system with config and context.
- `ValidationConfig`: Configures strict mode, size limits, ZK proofs, DAO fees, rate limits.
- `ValidationResult`: Detailed validation result with errors, warnings, and metadata.
- `RateLimitConfig`: Rate limiting per IP and identity.

## Key Features
- Zero-knowledge proof validation
- Economic model validation with DAO fee checks
- Content integrity checks (hashing, signatures)
- Protocol compliance validation
- Rate limiting and bandwidth throttling

## Example Usage
```rust
let validator = ZhtpValidator::new(ValidationConfig::default());
let result = validator.validate_request(&request).await?;
if !result.valid {
    // Handle validation errors
}
```
