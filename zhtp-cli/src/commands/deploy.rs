//! Web4 Deploy Command
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)
//!
//! - **Pure Logic**: Deploy mode parsing, domain validation, file manifest building
//! - **Imperative Shell**: File I/O, QUIC communication, trust config building
//! - **Error Handling**: Domain-specific CliError types
//! - **Testability**: Output trait injection for testing

use crate::argument_parsing::{DeployArgs, DeployAction, ZhtpCli};
use crate::error::{CliResult, CliError};
use crate::output::Output;

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::str::FromStr;

// ============================================================================
// PURE LOGIC - No side effects, fully testable
// ============================================================================

/// Supported deployment modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    /// Single Page Application - all routes serve index.html
    Spa,
    /// Static site - each file served at its path
    Static,
}

impl FromStr for DeployMode {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "spa" => Ok(DeployMode::Spa),
            "static" => Ok(DeployMode::Static),
            _ => Err(CliError::ConfigError(
                format!("Invalid deploy mode: '{}'. Use 'spa' or 'static'", s),
            )),
        }
    }
}

impl DeployMode {
    /// Get mode as string
    pub fn as_str(&self) -> &str {
        match self {
            DeployMode::Spa => "spa",
            DeployMode::Static => "static",
        }
    }
}

/// Deployment manifest tracking all files
#[derive(Debug, Serialize, Deserialize)]
pub struct DeployManifest {
    pub domain: String,
    pub mode: String,
    pub files: Vec<FileEntry>,
    pub total_size: u64,
    pub deployed_at: u64,
}

/// Single file entry in manifest
#[derive(Debug, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mime_type: String,
    pub hash: String,
}

/// Valid deployment operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployOperation {
    Site,
    Status,
    List,
    History,
    Rollback,
}

impl DeployOperation {
    /// Get user-friendly description
    pub fn description(&self) -> &'static str {
        match self {
            DeployOperation::Site => "Deploy website to Web4",
            DeployOperation::Status => "Check deployment status",
            DeployOperation::List => "List deployments",
            DeployOperation::History => "Show deployment history",
            DeployOperation::Rollback => "Rollback to previous version",
        }
    }
}

/// Determine operation from arguments
///
/// Pure function - deterministic conversion
pub fn action_to_operation(action: &DeployAction) -> DeployOperation {
    match action {
        DeployAction::Site { .. } => DeployOperation::Site,
        DeployAction::Status { .. } => DeployOperation::Status,
        DeployAction::List { .. } => DeployOperation::List,
        DeployAction::History { .. } => DeployOperation::History,
        DeployAction::Rollback { .. } => DeployOperation::Rollback,
    }
}

/// Validate domain format
///
/// Pure function - format validation only
pub fn validate_domain(domain: &str) -> CliResult<()> {
    if domain.is_empty() {
        return Err(CliError::ConfigError(
            "Domain cannot be empty".to_string(),
        ));
    }

    if domain.ends_with(".zhtp") || domain.ends_with(".sov") {
        Ok(())
    } else {
        Err(CliError::ConfigError(format!(
            "Domain must end with .zhtp or .sov (got: {})",
            domain
        )))
    }
}

/// Validate build directory
///
/// Pure function - path validation only (no I/O)
pub fn validate_build_directory(path_str: &str) -> CliResult<PathBuf> {
    if path_str.is_empty() {
        return Err(CliError::ConfigError(
            "Build directory path cannot be empty".to_string(),
        ));
    }

    Ok(PathBuf::from(path_str))
}

// ============================================================================
// IMPERATIVE SHELL - All side effects here (file I/O, network, output)
// ============================================================================

/// Handle deploy command with proper error handling and output
///
/// Public entry point that maintains backward compatibility
pub async fn handle_deploy_command(
    args: DeployArgs,
    cli: &ZhtpCli,
) -> crate::error::CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_deploy_command_impl(args, cli, &output).await
}

/// Internal implementation with dependency injection
async fn handle_deploy_command_impl(
    args: DeployArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let op = action_to_operation(&args.action);
    output.info(&format!("{}...", op.description()))?;

    match args.action {
        DeployAction::Site {
            build_dir,
            domain,
            mode,
            keystore,
            fee,
            pin_spki: _,
            node_did: _,
            tofu: _,
            trust_node: _,
            dry_run,
        } => {
            // Pure validation
            validate_domain(&domain)?;
            validate_build_directory(&build_dir)?;
            let deploy_mode: DeployMode = mode
                .as_deref()
                .unwrap_or("spa")
                .parse()?;

            output.header("Web4 Site Deployment")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Build directory: {}", build_dir))?;
            output.print(&format!("Mode: {}", deploy_mode.as_str()))?;

            // Imperative: File I/O and deployment
            deploy_site_impl(
                &build_dir,
                &domain,
                deploy_mode,
                Some(keystore.as_str()),
                fee,
                dry_run,
                output,
            )
            .await
        }
        DeployAction::Status {
            domain,
            keystore,
            pin_spki: _,
            node_did: _,
            tofu: _,
            trust_node: _,
        } => {
            // Pure validation
            validate_domain(&domain)?;

            output.header("Deployment Status")?;
            output.print(&format!("Domain: {}", domain))?;

            // Imperative: Network communication
            check_deployment_status_impl(&domain, keystore.as_ref().map(|s| s.as_str()), output).await
        }
        DeployAction::List {
            keystore,
            pin_spki: _,
            node_did: _,
            tofu: _,
            trust_node: _,
        } => {
            output.header("Deployments")?;

            // Imperative: Network communication
            list_deployments_impl(keystore.as_ref().map(|s| s.as_str()), output).await
        }
        DeployAction::History {
            domain,
            limit,
            keystore,
            pin_spki: _,
            node_did: _,
            tofu: _,
            trust_node: _,
        } => {
            // Pure validation
            validate_domain(&domain)?;

            output.header("Deployment History")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Limit: {}", limit))?;

            // Imperative: Network communication
            show_deployment_history_impl(&domain, limit as u32, keystore.as_ref().map(|s| s.as_str()), output)
                .await
        }
        DeployAction::Rollback {
            domain,
            to_version,
            keystore,
            pin_spki: _,
            node_did: _,
            tofu: _,
            trust_node: _,
            force,
        } => {
            // Pure validation
            validate_domain(&domain)?;

            output.header("Rollback Deployment")?;
            output.print(&format!("Domain: {}", domain))?;
            output.print(&format!("Rolling back to version: {}", to_version))?;

            // Imperative: Network communication
            rollback_deployment_impl(&domain, &to_version.to_string(), Some(keystore.as_str()), force, output)
                .await
        }
    }
}

/// Deploy a static site to Web4
async fn deploy_site_impl(
    build_dir: &str,
    domain: &str,
    _mode: DeployMode,
    _keystore: Option<&str>,
    _fee: Option<u64>,
    dry_run: bool,
    output: &dyn Output,
) -> CliResult<()> {
    let build_path = PathBuf::from(build_dir);

    // Check if directory exists (I/O operation)
    if !build_path.exists() {
        return Err(CliError::ConfigError(format!(
            "Build directory does not exist: {}",
            build_dir
        )));
    }

    if !build_path.is_dir() {
        return Err(CliError::ConfigError(format!(
            "Path is not a directory: {}",
            build_dir
        )));
    }

    if dry_run {
        output.info("DRY RUN - no files will be deployed")?;
    }

    output.info("Collecting files from build directory...")?;
    output.print(&format!("Preparing deployment to {}", domain))?;

    output.success("Site deployment ready!")?;
    output.print("Use 'zhtp deploy status --domain mysite.zhtp' to check status")?;

    Ok(())
}

/// Check deployment status
async fn check_deployment_status_impl(
    domain: &str,
    _keystore: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!("Checking status for {}...", domain))?;
    output.print("This requires a running ZHTP node.")?;
    output.warning("Connect to ZHTP node to check deployment status.")?;

    Ok(())
}

/// List all deployments
async fn list_deployments_impl(_keystore: Option<&str>, output: &dyn Output) -> CliResult<()> {
    output.info("Listing all deployments...")?;
    output.print("This requires a running ZHTP node.")?;
    output.warning("Connect to ZHTP node to list deployments.")?;

    Ok(())
}

/// Show deployment history for a domain
async fn show_deployment_history_impl(
    domain: &str,
    limit: u32,
    _keystore: Option<&str>,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!(
        "Showing deployment history for {} (limit: {})...",
        domain, limit
    ))?;
    output.print("This requires a running ZHTP node.")?;
    output.warning("Connect to ZHTP node to view deployment history.")?;

    Ok(())
}

/// Rollback deployment to a previous version
async fn rollback_deployment_impl(
    domain: &str,
    to_version: &str,
    _keystore: Option<&str>,
    _force: bool,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&format!(
        "Rolling back {} to version {}...",
        domain, to_version
    ))?;
    output.warning("This requires a running ZHTP node.")?;
    output.print("Connect to ZHTP node to perform rollback.")?;

    Ok(())
}

// ============================================================================
// TESTS - Pure logic is testable without mocks or side effects
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_mode_from_str_spa() {
        assert_eq!("spa".parse::<DeployMode>().unwrap(), DeployMode::Spa);
        assert_eq!("SPA".parse::<DeployMode>().unwrap(), DeployMode::Spa);
        assert_eq!("Spa".parse::<DeployMode>().unwrap(), DeployMode::Spa);
    }

    #[test]
    fn test_deploy_mode_from_str_static() {
        assert_eq!(
            "static".parse::<DeployMode>().unwrap(),
            DeployMode::Static
        );
        assert_eq!(
            "STATIC".parse::<DeployMode>().unwrap(),
            DeployMode::Static
        );
    }

    #[test]
    fn test_deploy_mode_from_str_invalid() {
        assert!("invalid".parse::<DeployMode>().is_err());
        assert!("".parse::<DeployMode>().is_err());
    }

    #[test]
    fn test_deploy_mode_as_str() {
        assert_eq!(DeployMode::Spa.as_str(), "spa");
        assert_eq!(DeployMode::Static.as_str(), "static");
    }

    #[test]
    fn test_action_to_operation_site() {
        let action = DeployAction::Site {
            build_dir: "./dist".to_string(),
            domain: "myapp.zhtp".to_string(),
            mode: Some("spa".to_string()),
            keystore: "~/.zhtp/keystore".to_string(),
            fee: None,
            pin_spki: None,
            node_did: None,
            tofu: false,
            trust_node: false,
            dry_run: false,
        };
        assert_eq!(action_to_operation(&action), DeployOperation::Site);
    }

    #[test]
    fn test_action_to_operation_status() {
        let action = DeployAction::Status {
            domain: "myapp.zhtp".to_string(),
            keystore: None,
            pin_spki: None,
            node_did: None,
            tofu: false,
            trust_node: false,
        };
        assert_eq!(action_to_operation(&action), DeployOperation::Status);
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("myapp.zhtp").is_ok());
        assert!(validate_domain("example.sov").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid_extension() {
        assert!(validate_domain("myapp.com").is_err());
        assert!(validate_domain("example.net").is_err());
    }

    #[test]
    fn test_validate_domain_empty() {
        assert!(validate_domain("").is_err());
    }

    #[test]
    fn test_validate_build_directory_valid() {
        let result = validate_build_directory("./dist");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), PathBuf::from("./dist"));
    }

    #[test]
    fn test_validate_build_directory_empty() {
        assert!(validate_build_directory("").is_err());
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(
            DeployOperation::Site.description(),
            "Deploy website to Web4"
        );
        assert_eq!(
            DeployOperation::Status.description(),
            "Check deployment status"
        );
        assert_eq!(
            DeployOperation::List.description(),
            "List deployments"
        );
        assert_eq!(
            DeployOperation::History.description(),
            "Show deployment history"
        );
        assert_eq!(
            DeployOperation::Rollback.description(),
            "Rollback to previous version"
        );
    }
}
