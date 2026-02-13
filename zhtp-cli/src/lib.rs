//! ZHTP CLI Library
//!
//! Provides the command-line interface for the ZHTP network node,
//! enabling users to manage nodes, wallets, identities, and monitor network status.
//!
//! ## Architecture
//!
//! This crate follows the **Functional Core, Imperative Shell** (FCIS) architecture pattern:
//!
//! - **Functional Core** (`logic/` module): Pure functions for business logic
//! - **Imperative Shell** (`commands/` module): Side effects, I/O, and command orchestration
//! - **Error Handling** (`error/` module): Structured, domain-specific error types
//! - **Output Abstraction** (`output/` module): Testable printing interface

// Core modules
pub mod commands;
pub mod argument_parsing;
pub mod banner;
pub mod cli_config;

// Architecture modules (new)
pub mod error;
pub mod output;
pub mod logic;

// Legacy modules (disabled for refactoring)
// pub mod execution;  // Disabled for now - old implementation not used
// pub mod handler;    // Disabled for now - old implementation not used
// pub mod interactive;  // Disabled for now - needs refactoring
// pub mod interactive_shell;  // Disabled for now - needs refactoring

// Re-export main types for public use
pub use argument_parsing::{ZhtpCli, ZhtpCommand, run_cli, format_output};
pub use error::{CliError, CliResult};
pub use output::Output;

/// ZHTP CLI version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// ZHTP CLI author information
pub const AUTHOR: &str = "Sovereign Network Team";
