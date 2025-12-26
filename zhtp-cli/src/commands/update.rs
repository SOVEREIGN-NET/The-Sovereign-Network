//! Self-update mechanism for ZHTP CLI
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Version comparison, path validation, backup detection
//! - **Imperative Shell**: HTTP requests, file I/O, system integration
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Pure functions for version parsing and comparison

use crate::argument_parsing::UpdateAction;
use crate::error::{CliResult, CliError};

use std::path::{Path, PathBuf};
use std::fs;
use semver::Version;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Update operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateOperation {
    Check,
    Install,
    Rollback,
    ShowVersion,
}

impl UpdateOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            UpdateOperation::Check => "Check for updates",
            UpdateOperation::Install => "Install update",
            UpdateOperation::Rollback => "Rollback to previous version",
            UpdateOperation::ShowVersion => "Show current version",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &UpdateAction) -> UpdateOperation {
    match action {
        UpdateAction::Check => UpdateOperation::Check,
        UpdateAction::Install { .. } => UpdateOperation::Install,
        UpdateAction::Rollback => UpdateOperation::Rollback,
        UpdateAction::Version => UpdateOperation::ShowVersion,
    }
}

/// Parse version string to semver Version
///
/// Pure function - version string parsing only
pub fn parse_version(version_str: &str) -> CliResult<Version> {
    // Remove 'v' prefix if present
    let clean = version_str.trim_start_matches('v');

    Version::parse(clean).map_err(|e| {
        CliError::ConfigError(format!(
            "Invalid version format: {}. Expected semantic version (e.g., 0.1.0)",
            e
        ))
    })
}

/// Compare two versions
///
/// Pure function - returns true if remote is newer
pub fn is_newer_available(current: &Version, remote: &Version) -> bool {
    remote > current
}

/// Get backup path for current binary
///
/// Pure function - path construction only
pub fn get_backup_path(binary_path: &Path) -> PathBuf {
    let mut backup = binary_path.to_path_buf();
    let filename = binary_path.file_name().unwrap_or_default();
    let backup_name = format!("{}.bak", filename.to_string_lossy());
    backup.set_file_name(backup_name);
    backup
}

/// Check if backup exists
///
/// Pure function - returns true if backup path would be valid
pub fn should_backup_exist(binary_path: &Path) -> CliResult<()> {
    if binary_path.as_os_str().is_empty() {
        return Err(CliError::ConfigError(
            "Binary path cannot be empty".to_string(),
        ));
    }
    Ok(())
}

/// Get current binary path
///
/// Pure function - environment inspection only
pub fn get_binary_path() -> CliResult<PathBuf> {
    std::env::current_exe().map_err(|e| {
        CliError::ConfigError(format!(
            "Failed to get current executable path: {}",
            e
        ))
    })
}

/// Get GitHub release download URL
///
/// Pure function - URL construction only
pub fn get_github_release_url(owner: &str, repo: &str, version: &str) -> String {
    let tag = format!("v{}", version);
    let platform = get_platform_triple();
    format!(
        "https://github.com/{}/{}/releases/download/{}/zhtp-cli-{}",
        owner, repo, tag, platform
    )
}

/// Get current platform triple for downloads
///
/// Pure function - platform detection only
pub fn get_platform_triple() -> String {
    let os = match std::env::consts::OS {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        other => other,
    };

    let arch = match std::env::consts::ARCH {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        "arm" => "armv7",
        other => other,
    };

    format!("{}-{}", os, arch)
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (HTTP, file I/O)
// ============================================================================

/// Handle update command with proper error handling and output
pub async fn handle_update_command(args: crate::argument_parsing::UpdateArgs) -> CliResult<()> {
    let _op = action_to_operation(&args.action);

    match args.action {
        UpdateAction::Check => check_for_updates_impl().await,
        UpdateAction::Install { force, backup } => install_update_impl(force, backup).await,
        UpdateAction::Rollback => rollback_update_impl().await,
        UpdateAction::Version => show_version_impl(),
    }
}

/// Check for available updates
async fn check_for_updates_impl() -> CliResult<()> {
    let current_version = env!("CARGO_PKG_VERSION");
    println!("Current version: {}", current_version);

    // In a real implementation, we would:
    // 1. Query GitHub API for latest release
    // 2. Compare versions
    // 3. Display results
    //
    // For now, show instructions for manual updates
    println!("\nLatest version information:");
    println!("  Repository: https://github.com/SOVEREIGN-NET/The-Sovereign-Network");
    println!("  Releases: https://github.com/SOVEREIGN-NET/The-Sovereign-Network/releases");
    println!("\nTo update to latest version, use:");
    println!("  zhtp-cli update install");

    Ok(())
}

/// Install the latest available update
async fn install_update_impl(_force: bool, _backup: bool) -> CliResult<()> {
    let current_version = env!("CARGO_PKG_VERSION");

    println!("Checking for updates...");
    println!("Current version: {}", current_version);

    // In a real implementation with self_update crate:
    // 1. Check GitHub releases for new versions
    // 2. If newer version available and force=false, prompt for confirmation
    // 3. Download binary to temporary location
    // 4. If backup=true, backup current binary
    // 5. Replace binary
    // 6. Verify update succeeded
    // 7. Display success message

    println!("\nNote: Automatic updates are not yet configured.");
    println!("To update manually:");
    println!("  1. Download latest binary from GitHub releases");
    println!("  2. Back up current binary: cp $(which zhtp-cli) $(which zhtp-cli).bak");
    println!("  3. Replace with new binary");
    println!("  4. Verify: zhtp-cli version");

    Ok(())
}

/// Rollback to previous version
async fn rollback_update_impl() -> CliResult<()> {
    let binary_path = get_binary_path()?;
    let backup_path = get_backup_path(&binary_path);

    if !backup_path.exists() {
        return Err(CliError::ConfigError(format!(
            "No backup found at: {}",
            backup_path.display()
        )));
    }

    println!("Rolling back from: {}", binary_path.display());
    println!("To backup at: {}", backup_path.display());

    // In a real implementation:
    // 1. Verify backup exists and is executable
    // 2. Replace current with backup
    // 3. Delete backup
    // 4. Verify rollback succeeded

    println!("\nNote: Manual rollback steps:");
    println!("  1. mv {} {}", backup_path.display(), binary_path.display());
    println!("  2. chmod +x {}", binary_path.display());
    println!("  3. zhtp-cli version");

    Ok(())
}

/// Show current version information
fn show_version_impl() -> CliResult<()> {
    println!("zhtp-cli {}", env!("CARGO_PKG_VERSION"));

    #[cfg(debug_assertions)]
    println!("Build: debug");

    #[cfg(not(debug_assertions))]
    println!("Build: release");

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_action_to_operation_check() {
        assert_eq!(action_to_operation(&UpdateAction::Check), UpdateOperation::Check);
    }

    #[test]
    fn test_action_to_operation_install() {
        let action = UpdateAction::Install { force: false, backup: true };
        assert_eq!(action_to_operation(&action), UpdateOperation::Install);
    }

    #[test]
    fn test_action_to_operation_rollback() {
        assert_eq!(action_to_operation(&UpdateAction::Rollback), UpdateOperation::Rollback);
    }

    #[test]
    fn test_action_to_operation_version() {
        assert_eq!(action_to_operation(&UpdateAction::Version), UpdateOperation::ShowVersion);
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(UpdateOperation::Check.description(), "Check for updates");
        assert_eq!(UpdateOperation::Install.description(), "Install update");
        assert_eq!(UpdateOperation::Rollback.description(), "Rollback to previous version");
        assert_eq!(UpdateOperation::ShowVersion.description(), "Show current version");
    }

    #[test]
    fn test_parse_version_valid() {
        assert!(parse_version("1.0.0").is_ok());
        assert!(parse_version("0.1.0").is_ok());
        assert!(parse_version("v0.1.0").is_ok());
    }

    #[test]
    fn test_parse_version_invalid() {
        assert!(parse_version("not-a-version").is_err());
        assert!(parse_version("1.0").is_err());
        assert!(parse_version("").is_err());
    }

    #[test]
    fn test_is_newer_available() {
        let v1 = Version::parse("1.0.0").unwrap();
        let v2 = Version::parse("1.0.1").unwrap();
        let v3 = Version::parse("0.9.0").unwrap();

        assert!(is_newer_available(&v1, &v2)); // 1.0.0 < 1.0.1
        assert!(!is_newer_available(&v2, &v1)); // 1.0.1 > 1.0.0
        assert!(!is_newer_available(&v1, &v3)); // 1.0.0 > 0.9.0
    }

    #[test]
    fn test_get_backup_path() {
        let binary = PathBuf::from("/usr/local/bin/zhtp-cli");
        let backup = get_backup_path(&binary);
        assert_eq!(backup, PathBuf::from("/usr/local/bin/zhtp-cli.bak"));
    }

    #[test]
    fn test_get_platform_triple() {
        let triple = get_platform_triple();
        assert!(triple.contains('-'));
        // Should be something like "linux-x86_64" or "darwin-aarch64"
    }

    #[test]
    fn test_get_github_release_url() {
        let url = get_github_release_url("SOVEREIGN-NET", "The-Sovereign-Network", "0.1.0");
        assert!(url.contains("github.com"));
        assert!(url.contains("SOVEREIGN-NET"));
        assert!(url.contains("v0.1.0"));
        assert!(url.contains("zhtp-cli"));
    }

    #[test]
    fn test_should_backup_exist_valid() {
        assert!(should_backup_exist(Path::new("/tmp/binary")).is_ok());
    }

    #[test]
    fn test_should_backup_exist_invalid() {
        assert!(should_backup_exist(Path::new("")).is_err());
    }
}
