//! Command Line Interface
//! 
//! Handles argument parsing, banner display, and interactive CLI features

pub mod argument_parsing;
pub mod banner;
pub mod interactive;

use anyhow::Result;
use super::config::{CliArgs, Environment};
use std::path::PathBuf;

// Re-export key functions
pub use argument_parsing::parse_cli_arguments;
pub use banner::show_lib_banner;
pub use interactive::InteractiveShell;

/// Parse command line arguments and return structured configuration
pub async fn parse_arguments() -> Result<CliArgs> {
    argument_parsing::parse_cli_arguments().await
}

/// Display the ZHTP startup banner with version and mode information
pub fn display_startup_banner() {
    banner::show_lib_banner();
}

/// Start interactive shell for runtime commands
pub async fn start_interactive_shell() -> Result<InteractiveShell> {
    interactive::InteractiveShell::new().await
}
