//! Version command for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)

use crate::argument_parsing::VersionArgs;
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_consensus_core::{BUILD_REVISION, CONSENSUS_BUILD_ID};
use lib_protocols::types::ZhtpStatus;

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
    /// Human-bumped binary epoch (gated at consensus admission).
    pub consensus_build_id: String,
    /// Git revision embedded at compile time (advisory telemetry).
    pub build_revision: String,
}

impl VersionInfo {
    pub fn format_brief(&self) -> String {
        format!(
            "zhtp-cli {}\n  Consensus epoch: {}\n  Build revision: {}\n  Release: {} build on {}",
            self.version, self.consensus_build_id, self.build_revision, self.build_profile, self.platform
        )
    }

    pub fn format_full(&self) -> String {
        format!(
            "zhtp-cli {}\n  \
            Consensus epoch: {}\n  \
            Build revision: {}\n  \
            Git: {} on {} ({})\n  \
            Built: {} ({} profile)\n  \
            Platform: {}",
            self.version,
            self.consensus_build_id,
            self.build_revision,
            &self.git_hash[..8.min(self.git_hash.len())],
            self.git_branch,
            if self.git_dirty { "dirty" } else { "clean" },
            self.build_timestamp,
            self.build_profile,
            self.platform
        )
    }
}

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
        build_revision: BUILD_REVISION.to_string(),
    }
}

/// Fetch consensus epoch from a running node via `/api/v1/protocol/version`.
pub async fn fetch_remote_consensus_build_id(server: &str) -> CliResult<String> {
    let body = fetch_remote_version_json(server).await?;
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

async fn fetch_remote_version_json(server: &str) -> CliResult<serde_json::Value> {
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

    lib_network::client::ZhtpClient::parse_json(&response)
        .map_err(|e| CliError::NetworkError(format!("invalid version JSON: {e}")))
}

pub async fn handle_version_command(args: VersionArgs, server: &str) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_version_command_impl(args, server, &output).await
}

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
            output.print(&format!(
                "consensus epoch: {remote_id} (remote @ {server})"
            ))?;
        }
        return Ok(());
    }

    let info = capture_version_info();

    if args.build_id_only {
        if info.consensus_build_id.is_empty() {
            return Err(CliError::ConfigError(
                "consensus build id unavailable — rebuild from a git checkout".into(),
            ));
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capture_version_info_includes_epoch_and_revision() {
        let info = capture_version_info();
        assert_eq!(info.consensus_build_id, CONSENSUS_BUILD_ID);
        assert_eq!(info.build_revision, BUILD_REVISION);
        assert!(!info.build_revision.is_empty());
    }

    #[test]
    fn test_version_info_format_brief_includes_epoch() {
        let info = VersionInfo {
            version: "0.1.0".to_string(),
            git_hash: "abc123def456".to_string(),
            git_branch: "main".to_string(),
            git_dirty: false,
            build_timestamp: "2024-12-26T10:00:00Z".to_string(),
            build_profile: "release".to_string(),
            platform: "linux-x86_64".to_string(),
            consensus_build_id: "1".to_string(),
            build_revision: "abc123def456".to_string(),
        };
        let formatted = info.format_brief();
        assert!(formatted.contains("Consensus epoch: 1"));
        assert!(formatted.contains("abc123def456"));
    }
}