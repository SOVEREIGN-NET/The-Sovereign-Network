# CLI Refactoring Guide: Functional Core, Imperative Shell (FCIS)

## Overview

This guide documents the architectural refactoring of the ZHTP CLI to follow the **Functional Core, Imperative Shell** (FCIS) pattern. This refactoring was done to address technical debt, improve testability, and establish proper separation of concerns before implementing Phase 2 distribution features.

## Architecture Principles

### Functional Core - Pure Business Logic

**Location**: `src/logic/` module

The functional core contains pure functions that:
- Have **no side effects** (no I/O, no printing, no state mutation)
- Depend **only on their inputs** (deterministic)
- Are **easily testable** (no mocks needed)
- **Compose cleanly** into higher-level operations

**Examples**:
- `logic::paths::normalize_path()` - pure path normalization
- `logic::identity::validate_identity_name()` - pure validation
- `logic::wallet::validate_transaction_amount()` - pure business rule checking
- `logic::deploy::validate_domain()` - pure domain validation

### Imperative Shell - Side Effects

**Location**: `src/commands/` module

The imperative shell contains functions that orchestrate side effects:
- **HTTP requests** via reqwest client
- **Printing/Output** via Output trait
- **Error handling** and user feedback
- **Coordination** of multiple operations

**Pattern**:
```rust
pub async fn handle_command(args: Args, cli: &ZhtpCli) -> Result<()> {
    let output = ConsoleOutput; // or inject mock in tests

    // 1. Validate inputs (pure)
    validate_input(&args)?;

    // 2. Make HTTP requests (side effect)
    let response = client.get(url).send().await?;

    // 3. Print results (side effect)
    output.print(&formatted)?;

    Ok(())
}
```

### Error Handling - Domain-Specific Types

**Location**: `src/error.rs`

Use `CliError` instead of generic `anyhow::Error`:

```rust
pub enum CliError {
    #[error("Identity creation failed: {0}")]
    IdentityCreationFailed { name: String, reason: String },

    #[error("API call to {endpoint} failed: {status} - {reason}")]
    ApiCallFailed { endpoint: String, status: u16, reason: String },

    // ... more domain-specific errors
}

pub type CliResult<T> = Result<T, CliError>;
```

**Benefits**:
- Clear error semantics
- Better error messages
- Structured error information
- Pattern matching on errors

### Output Abstraction - Testable Printing

**Location**: `src/output.rs`

Use the `Output` trait instead of `println!()` directly:

```rust
pub trait Output: Send + Sync {
    fn print(&self, msg: &str) -> CliResult<()>;
    fn error(&self, msg: &str) -> CliResult<()>;
    fn success(&self, msg: &str) -> CliResult<()>;
    fn header(&self, title: &str) -> CliResult<()>;
}

pub struct ConsoleOutput;  // Real output
pub struct MockOutput;     // For testing
```

**Benefits**:
- Handlers are testable without capturing stdout
- Output behavior can be verified in tests
- Easy to switch output implementations

## Module Structure

```
src/
├── lib.rs                      # Library root with FCIS documentation
├── main.rs                     # Simple entry point
├── error.rs                    # Domain-specific error types (NEW)
├── output.rs                   # Output abstraction trait (NEW)
├── logic/                      # Functional Core (NEW)
│   ├── mod.rs
│   ├── paths.rs               # Path normalization
│   ├── identity.rs            # Identity validation & building
│   ├── wallet.rs              # Wallet validation & rules
│   ├── config.rs              # Configuration building
│   └── deploy.rs              # Deployment validation & manifest building
├── commands/                   # Imperative Shell
│   ├── mod.rs
│   ├── blockchain.rs          # ✅ REFACTORED (pattern example)
│   ├── monitor.rs             # TODO: Refactor
│   ├── network.rs             # TODO: Refactor
│   ├── wallet.rs              # TODO: Refactor
│   ├── identity.rs            # TODO: Refactor
│   ├── node.rs                # TODO: Refactor
│   ├── deploy.rs              # TODO: Refactor
│   └── ... (other commands)
├── argument_parsing.rs        # CLI argument parsing & dispatch
└── banner.rs                  # ASCII banner
```

## Refactoring Pattern

### Step 1: Extract Pure Logic

Create pure functions in `src/logic/` that have no side effects.

**Example** (from `logic/identity.rs`):
```rust
/// Pure function - no side effects, fully testable
pub fn validate_identity_name(name: &str) -> CliResult<()> {
    if name.len() < 3 {
        return Err(CliError::IdentityError(
            "Identity name must be at least 3 characters".to_string(),
        ));
    }
    // ... more validation
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_validate_identity_name_valid() {
        assert!(validate_identity_name("alice").is_ok());
    }

    #[test]
    fn test_validate_identity_name_too_short() {
        let result = validate_identity_name("ab");
        assert!(result.is_err());
    }
}
```

### Step 2: Create Internal Handler with Dependency Injection

Inside the command handler, create an internal `_impl` function that accepts the `Output` trait:

```rust
// Public API - backward compatible
pub async fn handle_command(
    args: CommandArgs,
    cli: &ZhtpCli,
) -> Result<()> {
    let output = ConsoleOutput;
    handle_command_impl(args, cli, &output).await
        .map_err(|e| anyhow::Error::msg(e.to_string()))
}

// Internal implementation - fully testable
async fn handle_command_impl(
    args: CommandArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    // Implementation here
}
```

### Step 3: Separate HTTP Calls

Create helper functions for each API operation:

```rust
async fn fetch_and_display_status(
    client: &reqwest::Client,
    base_url: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.print("Fetching status...")?;

    let response = client
        .get(&format!("{}/status", base_url))
        .send()
        .await
        .map_err(|e| CliError::ApiCallFailed {
            endpoint: "status".to_string(),
            status: 0,
            reason: e.to_string(),
        })?;

    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        output.header("Status")?;
        output.print(&formatted)?;
        Ok(())
    } else {
        Err(CliError::ApiCallFailed {
            endpoint: "status".to_string(),
            status: response.status().as_u16(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}
```

### Step 4: Add Tests

Test pure logic without side effects, mock output for imperative shell:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::testing::MockOutput;

    #[test]
    fn test_pure_validation() {
        // No output needed, no HTTP mocks needed
        assert!(validate_amount(1000).is_ok());
        assert!(validate_amount(0).is_err());
    }

    #[tokio::test]
    async fn test_handler_with_mock_output() {
        let output = MockOutput::new();
        let args = CommandArgs { /* ... */ };
        let cli = ZhtpCli { /* ... */ };

        let result = handle_command_impl(args, &cli, &output).await;

        // Verify behavior through output mock
        output.assert_contains_message("some text");
    }
}
```

## Refactoring Checklist

For each handler file:

- [ ] Identify pure validation/building logic
- [ ] Create pure functions in `src/logic/`
- [ ] Add unit tests for pure logic
- [ ] Create `handle_command_impl()` with Output parameter
- [ ] Separate HTTP operations into helper functions
- [ ] Update error handling to use `CliError`
- [ ] Update output to use Output trait instead of `println!`
- [ ] Add integration tests with MockOutput
- [ ] Verify backward compatibility with public API
- [ ] Build and test the handler

## Before and After Example

### Before (Mixed Concerns)

```rust
pub async fn handle_wallet_command(args: WalletArgs, cli: &ZhtpCli) -> Result<()> {
    match args.action {
        WalletAction::Create { name, wallet_type } => {
            // All mixed together:
            println!("💳 Creating wallet: {}", name);  // Side effect

            // No validation
            let client = reqwest::Client::new();       // Side effect
            let response = client
                .post(&format!("http://{}/api/v1/wallet/create", cli.server))
                .json(&json!({ "name": name, "type": wallet_type }))
                .send()
                .await?;

            if response.status().is_success() {
                println!("✅ Wallet created");
            } else {
                println!("❌ Failed");
            }
            Ok(())
        }
        // ...
    }
}
```

**Problems**:
- Business logic mixed with I/O
- No validation before API call
- Untestable (println! required stdout capture)
- Generic error handling
- No output abstraction

### After (FCIS Pattern)

```rust
// Pure logic in src/logic/wallet.rs
pub fn validate_wallet_name(name: &str) -> CliResult<()> {
    if name.len() < 3 {
        return Err(CliError::WalletError(
            "Wallet name must be at least 3 characters".to_string(),
        ));
    }
    // ... more validation
    Ok(())
}

// Imperative shell in src/commands/wallet.rs
pub async fn handle_wallet_command(
    args: WalletArgs,
    cli: &ZhtpCli,
) -> Result<()> {
    let output = ConsoleOutput;
    handle_wallet_command_impl(args, cli, &output).await
        .map_err(|e| anyhow::Error::msg(e.to_string()))
}

async fn handle_wallet_command_impl(
    args: WalletArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        WalletAction::Create { name, wallet_type } => {
            // Pure validation first
            logic::wallet::validate_wallet_name(&name)?;

            // Then imperative: HTTP call and output
            create_wallet(&name, &wallet_type, cli, output).await
        }
        // ...
    }
}

async fn create_wallet(
    name: &str,
    wallet_type: &str,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.print(&format!("💳 Creating wallet: {}", name))?;

    let client = reqwest::Client::new();
    let response = client
        .post(&format!("http://{}/api/v1/wallet/create", cli.server))
        .json(&json!({ "name": name, "type": wallet_type }))
        .send()
        .await
        .map_err(|e| CliError::WalletError(e.to_string()))?;

    if response.status().is_success() {
        output.success("Wallet created")?;
        Ok(())
    } else {
        Err(CliError::WalletCreationFailed {
            name: name.to_string(),
            reason: format!("HTTP {}", response.status()),
        })
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_validate_wallet_name() {
        assert!(validate_wallet_name("my-wallet").is_ok());
        assert!(validate_wallet_name("ab").is_err());
    }

    #[tokio::test]
    async fn test_create_wallet_with_mock_output() {
        let output = MockOutput::new();
        // Test with mock output - no actual HTTP calls
        // Verify behavior through output assertions
    }
}
```

**Benefits**:
- ✅ Pure logic separated and testable
- ✅ Proper validation before API calls
- ✅ Testable without stdout capture
- ✅ Domain-specific error handling
- ✅ Output abstraction for testing
- ✅ Clear separation of concerns

## Testing Strategy

### Pure Logic Tests

Test logic functions directly:
```rust
#[test]
fn test_validate_identity_name() {
    assert!(validate_identity_name("alice").is_ok());
    assert!(validate_identity_name("ab").is_err());
}
```

### Handler Tests with Mock Output

Test handlers with MockOutput:
```rust
#[tokio::test]
async fn test_handler_creates_correct_output() {
    let output = MockOutput::new();
    let result = handle_command_impl(args, &cli, &output).await;
    output.assert_contains_message("expected text");
}
```

### Integration Tests

Integration tests in `tests/` directory that test through the public API.

## Migrating Remaining Handlers

Priority order (complexity):
1. `monitor.rs` - Simple HTTP-only operations ✅
2. `blockchain.rs` - Simple HTTP operations ✅
3. `network.rs` - Some local logic + HTTP
4. `wallet.rs` - More business logic
5. `identity.rs` - Complex crypto + file I/O
6. `node.rs` - Complex configuration
7. `deploy.rs` - Very complex, file processing + HTTP

## Current Status

**Refactored** ✅:
- `blockchain.rs` - Demonstration refactor showing the pattern

**In Progress**:
- Establishing refactoring pattern
- Building supporting infrastructure (error types, output trait)

**Not Yet Started**:
- `monitor.rs`, `network.rs`, `wallet.rs`, `identity.rs`, `node.rs`, `deploy.rs`

## Next Steps

1. ✅ Set up error types and output trait
2. ✅ Refactor `blockchain.rs` as pattern demonstration
3. Refactor remaining simple handlers (`monitor.rs`, `network.rs`)
4. Refactor complex handlers (`wallet.rs`, `identity.rs`, `node.rs`)
5. Refactor most complex handler (`deploy.rs`)
6. Add comprehensive test coverage
7. Update documentation and migration guide

## Questions & Notes

### Why FCIS?

FCIS (Functional Core, Imperative Shell) provides:
- **Testability**: Pure logic is easily testable
- **Reasoning**: Pure functions are easier to understand
- **Composability**: Functions compose cleanly
- **Maintainability**: Clear separation makes changes easier
- **Robustness**: Fewer side effects = fewer bugs

### Why Output Trait?

Instead of direct `println!()`:
- **Testability**: Can mock output in tests
- **Flexibility**: Easy to change output implementation
- **Correctness**: Output errors are properly handled
- **Consistency**: Uniform output interface

### Why CliError?

Instead of generic `anyhow::Error`:
- **Semantics**: Errors carry domain meaning
- **Context**: Rich error information
- **Handling**: Can pattern match specific errors
- **Messages**: Better user-facing error messages

## Resources

- [Functional Core, Imperative Shell](https://www.destroyallsoftware.com/screencasts/show/functional-core-imperative-shell) by Gary Bernhardt
- [Architecture without an end goal](https://www.destroyallsoftware.com/talks/architecture-without-an-end-goal) by Gary Bernhardt
- Rust patterns: [Type-safe builders](https://docs.rust-embedded.org/book/static-guarantees/), [Result-based error handling](https://doc.rust-lang.org/book/ch09-00-error-handling.html)

---

**Version**: 1.0
**Last Updated**: 2025-12-26
**Status**: Active - Refactoring in progress
