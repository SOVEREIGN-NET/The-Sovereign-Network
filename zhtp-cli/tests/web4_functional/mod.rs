//! Support module for Web4 CLI functional tests
//!
//! Provides common utilities and infrastructure for testing:
//! - TestEnv: Isolated test environment management
//! - CliExecutor: CLI command execution wrapper
//! - SiteGenerator: Automated test site creation
//! - StateVerifier: State verification and assertion

pub mod test_env;
pub mod cli_executor;
pub mod site_generator;
pub mod state_verifier;

pub use test_env::TestEnv;
pub use cli_executor::CliExecutor;
pub use site_generator::SiteGenerator;
pub use state_verifier::StateVerifier;
