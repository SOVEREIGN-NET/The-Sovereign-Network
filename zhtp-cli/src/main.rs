//! ZHTP Command-Line Interface
//!
//! Entry point for the zhtp-cli binary. Parses command-line arguments
//! and delegates to the appropriate command handler.

use zhtp_cli::run_cli;
use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_cli().await
}
