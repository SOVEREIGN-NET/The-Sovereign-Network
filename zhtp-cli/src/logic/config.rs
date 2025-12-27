//! Pure configuration logic
//!
//! Configuration building, validation, and merging.
//! All functions are pure - no I/O or side effects.

use crate::error::{CliError, CliResult};

/// Configuration profile for different deployment scenarios
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigProfile {
    Development,
    Staging,
    Production,
}

impl ConfigProfile {
    pub fn as_str(&self) -> &str {
        match self {
            ConfigProfile::Development => "development",
            ConfigProfile::Staging => "staging",
            ConfigProfile::Production => "production",
        }
    }

    pub fn from_str(s: &str) -> CliResult<Self> {
        match s.to_lowercase().as_str() {
            "development" | "dev" => Ok(ConfigProfile::Development),
            "staging" => Ok(ConfigProfile::Staging),
            "production" | "prod" => Ok(ConfigProfile::Production),
            other => Err(CliError::ConfigError(format!(
                "Unknown config profile: '{}'. Supported: development, staging, production",
                other
            ))),
        }
    }
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
    pub use_tls: bool,
}

impl ServerConfig {
    /// Get full server URL
    pub fn url(&self) -> String {
        let protocol = if self.use_tls { "https" } else { "http" };
        format!("{}://{}:{}", protocol, self.address, self.port)
    }
}

/// Validate server address
pub fn validate_server_address(address: &str) -> CliResult<()> {
    if address.is_empty() {
        return Err(CliError::ConfigError(
            "Server address cannot be empty".to_string(),
        ));
    }

    // Basic validation: either IP or hostname
    if address.contains("://") {
        return Err(CliError::ConfigError(
            "Server address should not include protocol".to_string(),
        ));
    }

    Ok(())
}

/// Validate server port
pub fn validate_server_port(port: u16) -> CliResult<()> {
    if port == 0 {
        return Err(CliError::ConfigError("Server port cannot be 0".to_string()));
    }

    // Ports below 1024 require root/admin
    if port < 1024 {
        return Err(CliError::ConfigError(
            "Server port must be 1024 or higher".to_string(),
        ));
    }

    Ok(())
}

/// Build server configuration from components
pub fn build_server_config(
    address: &str,
    port: u16,
    use_tls: bool,
) -> CliResult<ServerConfig> {
    validate_server_address(address)?;
    validate_server_port(port)?;

    Ok(ServerConfig {
        address: address.to_string(),
        port,
        use_tls,
    })
}

/// Validate output format
pub fn validate_output_format(format: &str) -> CliResult<()> {
    match format.to_lowercase().as_str() {
        "json" | "yaml" | "table" | "text" => Ok(()),
        other => Err(CliError::ConfigError(format!(
            "Unknown output format: '{}'. Supported: json, yaml, table, text",
            other
        ))),
    }
}

/// Validate log level
pub fn validate_log_level(level: &str) -> CliResult<()> {
    match level.to_lowercase().as_str() {
        "trace" | "debug" | "info" | "warn" | "error" => Ok(()),
        other => Err(CliError::ConfigError(format!(
            "Unknown log level: '{}'. Supported: trace, debug, info, warn, error",
            other
        ))),
    }
}

/// Check if configuration is valid for a given profile
pub fn validate_for_profile(profile: &ConfigProfile) -> CliResult<()> {
    match profile {
        ConfigProfile::Production => {
            // Production config requires TLS
            // This check happens at a higher level when we have actual config
        }
        ConfigProfile::Development | ConfigProfile::Staging => {
            // Less strict validation
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_profile_as_str() {
        assert_eq!(ConfigProfile::Development.as_str(), "development");
        assert_eq!(ConfigProfile::Staging.as_str(), "staging");
        assert_eq!(ConfigProfile::Production.as_str(), "production");
    }

    #[test]
    fn test_config_profile_from_str() {
        assert_eq!(ConfigProfile::from_str("dev").unwrap(), ConfigProfile::Development);
        assert_eq!(ConfigProfile::from_str("staging").unwrap(), ConfigProfile::Staging);
        assert_eq!(ConfigProfile::from_str("prod").unwrap(), ConfigProfile::Production);
    }

    #[test]
    fn test_server_config_url() {
        let config = ServerConfig {
            address: "localhost".to_string(),
            port: 8080,
            use_tls: false,
        };
        assert_eq!(config.url(), "http://localhost:8080");

        let config_tls = ServerConfig {
            address: "example.com".to_string(),
            port: 443,
            use_tls: true,
        };
        assert_eq!(config_tls.url(), "https://example.com:443");
    }

    #[test]
    fn test_validate_server_address_valid() {
        assert!(validate_server_address("localhost").is_ok());
        assert!(validate_server_address("127.0.0.1").is_ok());
        assert!(validate_server_address("example.com").is_ok());
    }

    #[test]
    fn test_validate_server_address_empty() {
        assert!(validate_server_address("").is_err());
    }

    #[test]
    fn test_validate_server_address_with_protocol() {
        assert!(validate_server_address("http://localhost").is_err());
    }

    #[test]
    fn test_validate_server_port_valid() {
        assert!(validate_server_port(8080).is_ok());
        assert!(validate_server_port(1024).is_ok());
        assert!(validate_server_port(65535).is_ok());
    }

    #[test]
    fn test_validate_server_port_zero() {
        assert!(validate_server_port(0).is_err());
    }

    #[test]
    fn test_validate_server_port_too_low() {
        assert!(validate_server_port(80).is_err());
    }

    #[test]
    fn test_validate_output_format_valid() {
        assert!(validate_output_format("json").is_ok());
        assert!(validate_output_format("yaml").is_ok());
        assert!(validate_output_format("table").is_ok());
        assert!(validate_output_format("text").is_ok());
    }

    #[test]
    fn test_validate_output_format_invalid() {
        assert!(validate_output_format("xml").is_err());
    }

    #[test]
    fn test_validate_log_level_valid() {
        assert!(validate_log_level("debug").is_ok());
        assert!(validate_log_level("info").is_ok());
        assert!(validate_log_level("error").is_ok());
    }

    #[test]
    fn test_build_server_config() {
        let config = build_server_config("localhost", 8080, false);
        assert!(config.is_ok());
        let cfg = config.unwrap();
        assert_eq!(cfg.address, "localhost");
        assert_eq!(cfg.port, 8080);
    }
}
