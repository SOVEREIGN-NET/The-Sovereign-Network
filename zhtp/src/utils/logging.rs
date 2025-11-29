//! Logging Utilities
//! 
//! Provides logging initialization and configuration

use anyhow::{Result, Context};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initialize the logging system
pub fn initialize_logging() -> Result<()> {
    // Set up structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_thread_ids(true)
                .with_line_number(true)
                .compact()
        )
        .with(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .try_init()
        .context("Failed to initialize logging")?;

    Ok(())
}

/// Set logging level dynamically
pub fn set_log_level(level: &str) -> Result<()> {
    // This would require more complex setup to change dynamically
    // For now, just validate the level
    match level {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        _ => Err(anyhow::anyhow!("Invalid log level: {}", level)),
    }
}

/// Get current log level
pub fn get_log_level() -> String {
    // This would need more complex implementation to get actual level
    "info".to_string()
}
