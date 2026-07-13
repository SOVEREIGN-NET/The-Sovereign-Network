//! Version command for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Version string construction, metadata formatting
//! - **Imperative Shell**: Output printing, environment variable reading
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::VersionArgs;
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_consensus_core::CONSENSUS_BUILD_ID;
use lib_protocols::types::ZhtpStatus;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Version information structure
#[derive(Debug, Clone)]
pub struct VersionInfo {
    pub version: String,
    pub git_hash: String,
    pub git_branch: String,
    pub git_dirty: bool,
    pub build_timestamp: String,
    pub build_profile: String,
    pub platform: String,
    pub consensus_build_id: String,
}

impl VersionInfo {
    /// Format version info for display
    pub fn format_brief(&self) -> String {
        format!(
            "zhtp-cli {}\n  Consensus build: {}\n  Release: {} build on {}",
            self.version, self.consensus_build_id, self.build_profile, self.platform
        )
    }

    /// Format full version info with all details
    pub fn format_full(&self) -> String {
        format!(
            "zhtp-cli {}\n  \
            Consensus build: {}\n  \
            Git: {} on {} ({})\n  \
            Built: {} ({} profile)\n  \
            Platform: {}",
            self.version,
            self.consensus_build_id,
            &self.git_hash[..8.min(self.git_hash.len())],
            self.git_branch,
            if self.git_dirty { "dirty" } else { "clean" },
            self.build_timestamp,
            self.build_profile,
            self.platform
        )
    }
}

/// Capture environment variables set by build.rs
///
/// Pure function - only reads environment variables
pub fn capture_version_info() -> VersionInfo {
    VersionInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        git_hash: env!("GIT_HASH").to_string(),
        git_branch: env!("GIT_BRANCH").to_string(),
        git_dirty: env!("GIT_DIRTY") == "true",
        build_timestamp: env!("BUILD_TIMESTAMP").to_string(),
        build_profile: env!("BUILD_PROFILE").to_string(),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        consensus_build_id: CONSENSUS_BUILD_ID.to_string(),
    }
}

/// Fetch consensus build id from a running node via `/api/v1/protocol/version`.
pub async fn fetch_remote_consensus_build_id(server: &str) -> CliResult<String> {
    let client = crate::commands::web4_utils::connect_default(server)
        .await
        .map_err(|e| CliError::NetworkError(format!("cannot connect to {server}: {e}")))?;

    let response = client
        .get("/api/v1/protocol/version")
        .await
        .map_err(|e| CliError::NetworkError(format!("version request failed: {e}")))?;

    if response.status != ZhtpStatus::Ok {
        return Err(CliError::NetworkError(format!(
            "version endpoint returned {} ({})",
            response.status, response.status_message
        )));
    }

    let body: serde_json::Value = lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::NetworkError(format!("invalid version JSON: {e}")))?;

    body.get("consensus_build_id")
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| {
            CliError::NetworkError(
                "remote node did not report consensus_build_id (upgrade required)".into(),
            )
        })
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (output)
// ============================================================================

/// Handle version command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_version_command(args: VersionArgs, server: &str) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_version_command_impl(args, server, &output).await
}

/// Internal implementation with dependency injection
async fn handle_version_command_impl(
    args: VersionArgs,
    server: &str,
    output: &dyn Output,
) -> CliResult<()> {
    if args.remote {
        let remote_id = fetch_remote_consensus_build_id(server).await?;
        if args.build_id_only {
            output.print(&remote_id)?;
        } else {
            output.print(&format!("consensus build: {remote_id} (remote @ {server})"))?;
        }
        return Ok(());
    }

    let info = capture_version_info();

    if args.build_id_only {
        output.print(&info.consensus_build_id)?;
        return Ok(());
    }

    if args.full {
        output.print(&info.format_full())?;
    } else {
        output.print(&info.format_brief())?;
    }

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_info_format_brief() {
        let info = VersionInfo {
            version: "0.1.0".to_string(),
            git_hash: "abc123def456".to_string(),
            git_branch: "main".to_string(),
            git_dirty: false,
            build_timestamp: "2024-12-26T10:00:00Z".to_string(),
            build_profile: "release".to_string(),
            platform: "linux-x86_64".to_string(),
            consensus_build_id: "abc123def456".to_string(),
        };

        let formatted = info.format_brief();
        assert!(formatted.contains("0.1.0"));
        assert!(formatted.contains("abc123def456"));
        assert!(formatted.contains("release"));
        assert!(formatted.contains("linux-x86_64"));
    }

    #[test]
    fn test_version_info_format_full() {
        let info = VersionInfo {
            version: "0.1.0".to_string(),
            git_hash: "abc123def456".to_string(),
            git_branch: "main".to_string(),
            git_dirty: false,
            build_timestamp: "2024-12-26T10:00:00Z".to_string(),
            build_profile: "release".to_string(),
            platform: "linux-x86_64".to_string(),
            consensus_build_id: "abc123def456".to_string(),
        };

        let formatted = info.format_full();
        assert!(formatted.contains("0.1.0"));
        assert!(formatted.contains("abc123"));
        assert!(formatted.contains("main"));
        assert!(formatted.contains("clean"));
        assert!(formatted.contains("release"));
        assert!(formatted.contains("linux-x86_64"));
        assert!(formatted.contains("Consensus build: abc123def456"));
    }

    #[test]
    fn test_version_info_format_full_dirty() {
        let info = VersionInfo {
            version: "0.1.0".to_string(),
            git_hash: "abc123def456".to_string(),
            git_branch: "dev".to_string(),
            git_dirty: true,
            build_timestamp: "2024-12-26T10:00:00Z".to_string(),
            build_profile: "debug".to_string(),
            platform: "darwin-aarch64".to_string(),
            consensus_build_id: "abc123def456-dirty".to_string(),
        };

        let formatted = info.format_full();
        assert!(formatted.contains("dirty"));
        assert!(formatted.contains("debug"));
        assert!(formatted.contains("darwin-aarch64"));
    }

    #[test]
    fn test_capture_version_info_includes_consensus_build_id() {
        let info = capture_version_info();
        assert_eq!(info.consensus_build_id, CONSENSUS_BUILD_ID);
    }
}