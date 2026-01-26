//! CLI executor for running Web4 CLI commands and parsing results

use std::process::{Command, Stdio};
use std::path::Path;
use std::collections::HashMap;

/// Result of a CLI command execution
#[derive(Debug, Clone)]
pub struct CliResult {
    pub success: bool,
    pub output: String,
    pub exit_code: i32,
}

/// Wrapper for executing Web4 CLI commands
pub struct CliExecutor {
    cli_path: String,
}

impl CliExecutor {
    /// Create a new CLI executor
    pub fn new(_env: &super::TestEnv) -> Self {
        // In production, would locate the built CLI binary
        // For tests, we use the installed zhtp-cli
        CliExecutor {
            cli_path: "zhtp-cli".to_string(),
        }
    }
    
    /// Execute a raw CLI command
    fn execute(&self, args: &[&str]) -> CliResult {
        let output = Command::new(&self.cli_path)
            .args(args)
            .output();
        
        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let combined = format!("{}\n{}", stdout, stderr);
                
                CliResult {
                    success: output.status.success(),
                    output: combined,
                    exit_code: output.status.code().unwrap_or(-1),
                }
            }
            Err(e) => {
                CliResult {
                    success: false,
                    output: format!("Execution error: {}", e),
                    exit_code: -1,
                }
            }
        }
    }
    
    // ========================================================================
    // Domain Registration Commands
    // ========================================================================
    
    /// Register a new domain
    pub fn register_domain(&self, domain: &str, description: Option<&str>) -> CliResult {
        let mut args = vec!["domain", "register", domain];
        let desc_string = description.map(|d| d.to_string());
        
        if let Some(ref desc) = desc_string {
            args.push("--description");
            args.push(desc);
        }
        
        self.execute(&args)
    }
    
    /// Register domain with metadata
    pub fn register_domain_with_metadata(
        &self,
        domain: &str,
        metadata: Vec<(&str, &str)>,
    ) -> CliResult {
        let mut args = vec!["domain", "register", domain];
        
        for (key, value) in metadata {
            args.push("--metadata");
            args.push(key);
            args.push(value);
        }
        
        self.execute(&args)
    }
    
    /// List all registered domains
    pub fn list_domains(&self) -> CliResult {
        self.execute(&["domain", "list"])
    }
    
    /// Get domain information
    pub fn get_domain_info(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "info", domain])
    }
    
    // ========================================================================
    // Deployment Commands
    // ========================================================================
    
    /// Deploy a site to a domain
    pub fn deploy_site(&self, domain: &str, site_path: &str) -> CliResult {
        self.execute(&["domain", "deploy", domain, site_path])
    }
    
    /// Deploy with specific version
    pub fn deploy_site_with_version(
        &self,
        domain: &str,
        site_path: &str,
        version: &str,
    ) -> CliResult {
        self.execute(&["domain", "deploy", domain, site_path, "--version", version])
    }
    
    // ========================================================================
    // Version Management Commands
    // ========================================================================
    
    /// Get version history for a domain
    pub fn get_version_history(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "versions", domain])
    }
    
    /// Rollback to a specific version
    pub fn rollback_to_version(&self, domain: &str, version: &str) -> CliResult {
        self.execute(&["domain", "rollback", domain, version])
    }
    
    /// Get current version of a domain
    pub fn get_current_version(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "version", domain])
    }
    
    // ========================================================================
    // Deletion Commands
    // ========================================================================
    
    /// Delete a domain
    pub fn delete_domain(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "delete", domain, "--force"])
    }
    
    /// Delete domain with confirmation
    pub fn delete_domain_with_confirmation(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "delete", domain])
    }
    
    // ========================================================================
    // State and Status Commands
    // ========================================================================
    
    /// Get domain status
    pub fn get_domain_status(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "status", domain])
    }
    
    /// Get manifest for a domain
    pub fn get_manifest(&self, domain: &str) -> CliResult {
        self.execute(&["domain", "manifest", domain])
    }
    
    /// Get manifest for specific version
    pub fn get_manifest_version(&self, domain: &str, version: &str) -> CliResult {
        self.execute(&["domain", "manifest", domain, "--version", version])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cli_result_parsing() {
        let result = CliResult {
            success: true,
            output: "Domain registered successfully".to_string(),
            exit_code: 0,
        };
        
        assert!(result.success);
        assert!(result.output.contains("Domain"));
        assert_eq!(result.exit_code, 0);
    }
}
