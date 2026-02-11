//! Pure deployment logic
//!
//! Handles deployment manifest building, validation, and calculations.
//! File I/O is separated from logic - this module provides pure functions.

use crate::error::{CliError, CliResult};
use std::path::Path;

/// Deployment mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeployMode {
    Spa,
    Static,
}

impl DeployMode {
    pub fn as_str(&self) -> &str {
        match self {
            DeployMode::Spa => "spa",
            DeployMode::Static => "static",
        }
    }

    pub fn from_str(s: &str) -> CliResult<Self> {
        match s.to_lowercase().as_str() {
            "spa" => Ok(DeployMode::Spa),
            "static" => Ok(DeployMode::Static),
            other => Err(CliError::DeploymentFailed {
                domain: "unknown".to_string(),
                reason: format!(
                    "Unknown deploy mode: '{}'. Supported: spa, static",
                    other
                ),
            }),
        }
    }
}

/// File manifest entry
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mime_type: String,
    pub hash: String,
}

/// Complete deployment manifest
#[derive(Debug, Clone)]
pub struct FileManifest {
    pub domain: String,
    pub mode: DeployMode,
    pub files: Vec<FileEntry>,
    pub total_size: u64,
    pub created_at: u64,
}

/// Deployment configuration
#[derive(Debug, Clone)]
pub struct DeploymentConfig {
    pub domain: String,
    pub mode: DeployMode,
    pub owner_did: Option<String>,
    pub fee: u64,
    pub dry_run: bool,
}

/// Validate domain name
pub fn validate_domain(domain: &str) -> CliResult<()> {
    if domain.is_empty() {
        return Err(CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: "Domain cannot be empty".to_string(),
        });
    }

    // Must end with .zhtp
    if !domain.ends_with(".zhtp") {
        return Err(CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: "Domain must end with '.zhtp'".to_string(),
        });
    }

    // Minimum length: x.zhtp
    if domain.len() < 6 {
        return Err(CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: "Domain must be at least 2 characters before '.zhtp'".to_string(),
        });
    }

    // Check subdomain validity
    let subdomain = &domain[..domain.len() - 5]; // Remove .zhtp
    if !is_valid_subdomain(subdomain) {
        return Err(CliError::DeploymentFailed {
            domain: domain.to_string(),
            reason: "Invalid domain format".to_string(),
        });
    }

    Ok(())
}

/// Validate subdomain (part before .zhtp)
fn is_valid_subdomain(subdomain: &str) -> bool {
    if subdomain.is_empty() {
        return false;
    }

    // Must start with alphanumeric
    if !subdomain.chars().next().unwrap().is_alphanumeric() {
        return false;
    }

    // Must end with alphanumeric
    if !subdomain.chars().last().unwrap().is_alphanumeric() {
        return false;
    }

    // Only allow alphanumeric, dash, dot
    subdomain
        .chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '.')
}

/// Validate deployment fee
pub fn validate_deployment_fee(fee: u64) -> CliResult<()> {
    // Minimum fee: 1000 satoshis
    if fee < 1000 {
        return Err(CliError::DeploymentFailed {
            domain: "unknown".to_string(),
            reason: "Deployment fee must be at least 1000 satoshis".to_string(),
        });
    }

    // Maximum fee: 1 SOV
    const MAX_FEE: u64 = 100_000_000;
    if fee > MAX_FEE {
        return Err(CliError::DeploymentFailed {
            domain: "unknown".to_string(),
            reason: format!("Deployment fee cannot exceed {}", MAX_FEE),
        });
    }

    Ok(())
}

/// Calculate deployment fee based on total size
pub fn calculate_deployment_fee(total_size: u64) -> u64 {
    // Base fee: 10,000 satoshis
    // Plus 1 satoshi per byte
    let base_fee = 10_000u64;
    let per_byte_fee = 1u64;
    base_fee + (total_size * per_byte_fee)
}

/// Validate MIME type
pub fn validate_mime_type(mime_type: &str) -> CliResult<()> {
    if mime_type.is_empty() {
        return Err(CliError::DeploymentFailed {
            domain: "unknown".to_string(),
            reason: "MIME type cannot be empty".to_string(),
        });
    }

    // Basic MIME type validation: type/subtype
    if !mime_type.contains('/') {
        return Err(CliError::DeploymentFailed {
            domain: "unknown".to_string(),
            reason: "Invalid MIME type format".to_string(),
        });
    }

    Ok(())
}

/// Check if a file path is safe to deploy
pub fn is_safe_file_path(path: &str) -> bool {
    // Don't allow absolute paths
    if Path::new(path).is_absolute() {
        return false;
    }

    // Don't allow path traversal attempts
    if path.contains("..") {
        return false;
    }

    // Don't allow hidden files (starting with .)
    if path.starts_with('.') {
        return false;
    }

    true
}

/// Get file extension
pub fn get_file_extension(path: &str) -> String {
    Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_string())
        .unwrap_or_default()
}

/// Guess MIME type from file extension
pub fn guess_mime_type(extension: &str) -> &'static str {
    match extension.to_lowercase().as_str() {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "svg" => "image/svg+xml",
        "webp" => "image/webp",
        "txt" | "text" => "text/plain",
        "md" => "text/markdown",
        "woff" => "font/woff",
        "woff2" => "font/woff2",
        "ttf" => "font/ttf",
        "otf" => "font/otf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deploy_mode_as_str() {
        assert_eq!(DeployMode::Spa.as_str(), "spa");
        assert_eq!(DeployMode::Static.as_str(), "static");
    }

    #[test]
    fn test_deploy_mode_from_str() {
        assert_eq!(DeployMode::from_str("spa").unwrap(), DeployMode::Spa);
        assert_eq!(DeployMode::from_str("static").unwrap(), DeployMode::Static);
        assert!(DeployMode::from_str("invalid").is_err());
    }

    #[test]
    fn test_validate_domain_valid() {
        assert!(validate_domain("myapp.zhtp").is_ok());
        assert!(validate_domain("my-app.zhtp").is_ok());
        assert!(validate_domain("my.app.zhtp").is_ok());
    }

    #[test]
    fn test_validate_domain_invalid_suffix() {
        assert!(validate_domain("myapp.com").is_err());
    }

    #[test]
    fn test_validate_domain_empty() {
        assert!(validate_domain("").is_err());
    }

    #[test]
    fn test_validate_domain_too_short() {
        assert!(validate_domain(".zhtp").is_err());
    }

    #[test]
    fn test_is_valid_subdomain() {
        assert!(is_valid_subdomain("app"));
        assert!(is_valid_subdomain("my-app"));
        assert!(is_valid_subdomain("my.app"));
        assert!(!is_valid_subdomain(""));
        assert!(!is_valid_subdomain("-app"));
        assert!(!is_valid_subdomain("app-"));
    }

    #[test]
    fn test_validate_deployment_fee_valid() {
        assert!(validate_deployment_fee(1000).is_ok());
        assert!(validate_deployment_fee(50_000_000).is_ok());
    }

    #[test]
    fn test_validate_deployment_fee_too_low() {
        assert!(validate_deployment_fee(999).is_err());
    }

    #[test]
    fn test_validate_deployment_fee_too_high() {
        assert!(validate_deployment_fee(100_000_001).is_err());
    }

    #[test]
    fn test_calculate_deployment_fee() {
        let fee = calculate_deployment_fee(1000);
        assert_eq!(fee, 10_000 + 1000);
    }

    #[test]
    fn test_is_safe_file_path_valid() {
        assert!(is_safe_file_path("index.html"));
        assert!(is_safe_file_path("src/app.js"));
        assert!(is_safe_file_path("styles/main.css"));
    }

    #[test]
    fn test_is_safe_file_path_absolute() {
        assert!(!is_safe_file_path("/etc/passwd"));
    }

    #[test]
    fn test_is_safe_file_path_traversal() {
        assert!(!is_safe_file_path("../../../etc/passwd"));
    }

    #[test]
    fn test_is_safe_file_path_hidden() {
        assert!(!is_safe_file_path(".hidden"));
    }

    #[test]
    fn test_get_file_extension() {
        assert_eq!(get_file_extension("app.js"), "js");
        assert_eq!(get_file_extension("style.css"), "css");
        assert_eq!(get_file_extension("index.html"), "html");
    }

    #[test]
    fn test_guess_mime_type() {
        assert_eq!(guess_mime_type("html"), "text/html");
        assert_eq!(guess_mime_type("js"), "application/javascript");
        assert_eq!(guess_mime_type("png"), "image/png");
        assert_eq!(guess_mime_type("unknown"), "application/octet-stream");
    }
}
