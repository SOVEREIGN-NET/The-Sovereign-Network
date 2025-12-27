//! Version command for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Version string construction, metadata formatting
//! - **Imperative Shell**: Output printing, environment variable reading
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::VersionArgs;
use crate::error::CliResult;
use crate::output::Output;

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
}

impl VersionInfo {
    /// Format version info for display
    pub fn format_brief(&self) -> String {
        format!(
            "zhtp-cli {}\n  Release: {} build on {}",
            self.version, self.build_profile, self.platform
        )
    }

    /// Format full version info with all details
    pub fn format_full(&self) -> String {
        format!(
            "zhtp-cli {}\n  \
            Git: {} on {} ({})\n  \
            Built: {} ({} profile)\n  \
            Platform: {}",
            self.version,
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
        platform: format!(
            "{}-{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    }
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (output)
// ============================================================================

/// Handle version command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_version_command(args: VersionArgs) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_version_command_impl(args, &output).await
}

/// Internal implementation with dependency injection
async fn handle_version_command_impl(
    args: VersionArgs,
    output: &dyn Output,
) -> CliResult<()> {
    let info = capture_version_info();

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
        };

        let formatted = info.format_brief();
        assert!(formatted.contains("0.1.0"));
        assert!(formatted.contains("release"));
        assert!(formatted.contains("linux-x86_64"));
        assert!(!formatted.contains("abc123"));
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
        };

        let formatted = info.format_full();
        assert!(formatted.contains("0.1.0"));
        assert!(formatted.contains("abc123"));
        assert!(formatted.contains("main"));
        assert!(formatted.contains("clean"));
        assert!(formatted.contains("release"));
        assert!(formatted.contains("linux-x86_64"));
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
        };

        let formatted = info.format_full();
        assert!(formatted.contains("dirty"));
        assert!(formatted.contains("debug"));
        assert!(formatted.contains("darwin-aarch64"));
    }

    #[test]
    fn test_version_info_hash_truncation() {
        let info = VersionInfo {
            version: "0.1.0".to_string(),
            git_hash: "a1b2c3d4e5f6g7h8i9j0".to_string(),
            git_branch: "main".to_string(),
            git_dirty: false,
            build_timestamp: "2024-12-26T10:00:00Z".to_string(),
            build_profile: "release".to_string(),
            platform: "linux-x86_64".to_string(),
        };

        let formatted = info.format_full();
        // Should show only first 8 characters of hash
        assert!(formatted.contains("a1b2c3d4"));
        assert!(!formatted.contains("a1b2c3d4e5f6g7h8"));
    }

    #[test]
    fn test_version_info_creation() {
        let info = VersionInfo {
            version: "0.1.0".to_string(),
            git_hash: "abc123".to_string(),
            git_branch: "main".to_string(),
            git_dirty: false,
            build_timestamp: "2024-12-26T10:00:00Z".to_string(),
            build_profile: "release".to_string(),
            platform: "linux-x86_64".to_string(),
        };

        assert_eq!(info.version, "0.1.0");
        assert_eq!(info.build_profile, "release");
        assert!(!info.git_dirty);
    }
}
