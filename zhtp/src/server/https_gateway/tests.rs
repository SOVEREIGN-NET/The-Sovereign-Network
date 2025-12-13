//! Tests for HTTPS Gateway

use super::config::{GatewayTlsConfig, TlsMode};
use std::path::PathBuf;

#[test]
fn test_config_default() {
    let config = GatewayTlsConfig::default();
    assert_eq!(config.mode, TlsMode::SelfSigned);
    assert_eq!(config.https_port, 8443);
    assert_eq!(config.http_port, Some(8080));
    assert_eq!(config.gateway_suffix, ".localhost");
    assert!(config.allow_bare_sovereign_domains);
}

#[test]
fn test_config_development() {
    let config = GatewayTlsConfig::development();
    assert_eq!(config.mode, TlsMode::SelfSigned);
    assert_eq!(config.https_port, 8443);
    assert!(!config.enable_http_redirect);
}

#[test]
fn test_config_production() {
    let config = GatewayTlsConfig::production("gateway.example.com");
    assert_eq!(config.mode, TlsMode::StandardCa);
    assert_eq!(config.https_port, 443);
    assert_eq!(config.http_port, Some(80));
    assert_eq!(config.gateway_suffix, ".gateway.example.com");
    assert!(config.enable_http_redirect);
    assert!(!config.allow_bare_sovereign_domains);
}

#[test]
fn test_config_private_ca() {
    let config = GatewayTlsConfig::private_ca(
        PathBuf::from("/etc/pki/ca.crt"),
        PathBuf::from("/etc/pki/server.crt"),
        PathBuf::from("/etc/pki/server.key"),
    );
    assert_eq!(config.mode, TlsMode::PrivateCa);
    assert!(config.allow_bare_sovereign_domains);
    assert!(config.gateway_suffix.is_empty());
}

#[test]
fn test_config_builder_pattern() {
    let config = GatewayTlsConfig::default()
        .with_https_port(8443)
        .with_http_port(8080)
        .with_gateway_suffix(".test.local")
        .with_data_dir(PathBuf::from("/tmp/gateway"));

    assert_eq!(config.https_port, 8443);
    assert_eq!(config.http_port, Some(8080));
    assert_eq!(config.gateway_suffix, ".test.local");
    assert_eq!(config.data_dir, PathBuf::from("/tmp/gateway"));
}

#[test]
fn test_config_without_http() {
    let config = GatewayTlsConfig::default().without_http();
    assert!(config.http_port.is_none());
}

#[test]
fn test_effective_paths_with_explicit() {
    let config = GatewayTlsConfig::default()
        .with_certs(
            PathBuf::from("/custom/cert.pem"),
            PathBuf::from("/custom/key.pem"),
        );

    assert_eq!(config.effective_cert_path(), PathBuf::from("/custom/cert.pem"));
    assert_eq!(config.effective_key_path(), PathBuf::from("/custom/key.pem"));
}

#[test]
fn test_effective_paths_fallback() {
    let config = GatewayTlsConfig::default()
        .with_data_dir(PathBuf::from("/var/lib/gateway"));

    assert_eq!(config.effective_cert_path(), PathBuf::from("/var/lib/gateway/server.crt"));
    assert_eq!(config.effective_key_path(), PathBuf::from("/var/lib/gateway/server.key"));
}

#[test]
fn test_config_validate_success() {
    let config = GatewayTlsConfig::default();
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_port_conflict() {
    let config = GatewayTlsConfig {
        https_port: 8443,
        http_port: Some(8443), // Same as HTTPS!
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validate_standard_ca_requires_certs() {
    let config = GatewayTlsConfig {
        mode: TlsMode::StandardCa,
        cert_path: None, // Missing!
        key_path: None,  // Missing!
        ..Default::default()
    };
    assert!(config.validate().is_err());
}

#[test]
fn test_config_validate_private_ca_requires_ca_cert() {
    let config = GatewayTlsConfig {
        mode: TlsMode::PrivateCa,
        cert_path: Some(PathBuf::from("/etc/pki/server.crt")),
        key_path: Some(PathBuf::from("/etc/pki/server.key")),
        ca_cert_path: None, // Missing!
        ..Default::default()
    };
    let result = config.validate();
    assert!(result.is_err(), "PrivateCa without ca_cert_path should fail validation");
    assert!(result.unwrap_err().contains("ca_cert_path"));
}

#[test]
fn test_config_validate_private_ca_requires_cert_path() {
    let config = GatewayTlsConfig {
        mode: TlsMode::PrivateCa,
        cert_path: None, // Missing!
        key_path: Some(PathBuf::from("/etc/pki/server.key")),
        ca_cert_path: Some(PathBuf::from("/etc/pki/ca.crt")),
        ..Default::default()
    };
    let result = config.validate();
    assert!(result.is_err(), "PrivateCa without cert_path should fail validation");
    assert!(result.unwrap_err().contains("cert_path"));
}

#[test]
fn test_config_validate_private_ca_success() {
    let config = GatewayTlsConfig {
        mode: TlsMode::PrivateCa,
        cert_path: Some(PathBuf::from("/etc/pki/server.crt")),
        key_path: Some(PathBuf::from("/etc/pki/server.key")),
        ca_cert_path: Some(PathBuf::from("/etc/pki/ca.crt")),
        ..Default::default()
    };
    assert!(config.validate().is_ok(), "PrivateCa with all paths should pass validation");
}

#[test]
fn test_tls_mode_default() {
    assert_eq!(TlsMode::default(), TlsMode::SelfSigned);
}

#[test]
fn test_config_cors_origins() {
    let config = GatewayTlsConfig::default();
    assert_eq!(config.cors_origins, vec!["*".to_string()]);
}

#[test]
fn test_config_hsts() {
    let config = GatewayTlsConfig::default();
    assert_eq!(config.hsts_max_age, 31536000); // 1 year
}
