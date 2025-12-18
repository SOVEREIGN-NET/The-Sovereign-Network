//! TLS Configuration for HTTPS Gateway
//!
//! Supports multiple TLS modes:
//! - Standard CA certificates (Let's Encrypt, commercial CAs)
//! - Private CA for .zhtp/.sov domains (enterprise deployments)
//! - Self-signed certificates (development)

use std::path::PathBuf;
use std::net::{IpAddr, Ipv4Addr};
use serde::{Deserialize, Serialize};

/// TLS mode for the gateway
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TlsMode {
    /// Standard CA certificates (Let's Encrypt, commercial CAs)
    /// Recommended for production with standard domain names
    StandardCa,
    /// Private CA for .zhtp/.sov domains
    /// Requires CA cert installation on client devices
    PrivateCa,
    /// Self-signed certificate for development/testing
    SelfSigned,
    /// No TLS (HTTP only) - NOT recommended for production
    Disabled,
}

impl Default for TlsMode {
    fn default() -> Self {
        TlsMode::SelfSigned // Safe default for development
    }
}

/// Configuration for the HTTPS gateway
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayTlsConfig {
    /// TLS mode
    pub mode: TlsMode,

    /// Port for HTTPS (default: 8443 for non-root, 443 for root)
    pub https_port: u16,

    /// Port for HTTP redirect (default: 8080, or 80 for root)
    pub http_port: Option<u16>,

    /// Bind address (default: 0.0.0.0)
    pub bind_addr: IpAddr,

    /// Path to TLS certificate (PEM format)
    /// For StandardCa: fullchain.pem from Let's Encrypt
    /// For PrivateCa: server certificate signed by private CA
    /// For SelfSigned: auto-generated if not provided
    pub cert_path: Option<PathBuf>,

    /// Path to TLS private key (PEM format)
    pub key_path: Option<PathBuf>,

    /// Path to CA certificate (for PrivateCa mode)
    /// Clients must install this CA to trust .zhtp/.sov domains
    pub ca_cert_path: Option<PathBuf>,

    /// Gateway suffix to strip from Host header
    /// e.g., ".gateway.example.com" or ".localhost"
    pub gateway_suffix: String,

    /// Allow bare .zhtp/.sov domains (without gateway suffix)
    /// Only works when DNS resolves .zhtp to gateway IP
    pub allow_bare_sovereign_domains: bool,

    /// CORS allowed origins (default: *)
    pub cors_origins: Vec<String>,

    /// Enable HTTP to HTTPS redirect
    pub enable_http_redirect: bool,

    /// HSTS max-age in seconds (default: 1 year)
    pub hsts_max_age: u64,

    /// Certificate/key data directory (for self-signed cert generation)
    pub data_dir: PathBuf,
}

impl Default for GatewayTlsConfig {
    fn default() -> Self {
        Self {
            mode: TlsMode::SelfSigned,
            https_port: 8443,
            http_port: Some(8080),
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
            gateway_suffix: ".localhost".to_string(),
            allow_bare_sovereign_domains: true,
            cors_origins: vec!["*".to_string()],
            enable_http_redirect: true,
            hsts_max_age: 31536000, // 1 year
            data_dir: PathBuf::from("./data/gateway"),
        }
    }
}

impl GatewayTlsConfig {
    /// Create production configuration with standard CA
    pub fn production(domain: &str) -> Self {
        Self {
            mode: TlsMode::StandardCa,
            https_port: 443,
            http_port: Some(80),
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            cert_path: Some(PathBuf::from("/etc/letsencrypt/live").join(domain).join("fullchain.pem")),
            key_path: Some(PathBuf::from("/etc/letsencrypt/live").join(domain).join("privkey.pem")),
            ca_cert_path: None,
            gateway_suffix: format!(".{}", domain),
            allow_bare_sovereign_domains: false,
            cors_origins: vec!["*".to_string()],
            enable_http_redirect: true,
            hsts_max_age: 31536000,
            data_dir: PathBuf::from("/var/lib/zhtp/gateway"),
        }
    }

    /// Create local development configuration
    pub fn development() -> Self {
        Self {
            mode: TlsMode::SelfSigned,
            https_port: 8443,
            http_port: Some(8080),
            bind_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            cert_path: None, // Will be auto-generated
            key_path: None,
            ca_cert_path: None,
            gateway_suffix: ".localhost".to_string(),
            allow_bare_sovereign_domains: true,
            cors_origins: vec!["*".to_string()],
            enable_http_redirect: false,
            hsts_max_age: 0,
            data_dir: PathBuf::from("./data/gateway"),
        }
    }

    /// Create private CA configuration for enterprise .zhtp/.sov deployment
    pub fn private_ca(ca_cert: PathBuf, server_cert: PathBuf, server_key: PathBuf) -> Self {
        Self {
            mode: TlsMode::PrivateCa,
            https_port: 443,
            http_port: Some(80),
            bind_addr: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            cert_path: Some(server_cert),
            key_path: Some(server_key),
            ca_cert_path: Some(ca_cert),
            gateway_suffix: String::new(), // Bare .zhtp domains
            allow_bare_sovereign_domains: true,
            cors_origins: vec!["*".to_string()],
            enable_http_redirect: true,
            hsts_max_age: 31536000,
            data_dir: PathBuf::from("/var/lib/zhtp/gateway"),
        }
    }

    /// Builder: Set HTTPS port
    pub fn with_https_port(mut self, port: u16) -> Self {
        self.https_port = port;
        self
    }

    /// Builder: Set HTTP port
    pub fn with_http_port(mut self, port: u16) -> Self {
        self.http_port = Some(port);
        self
    }

    /// Builder: Disable HTTP port
    pub fn without_http(mut self) -> Self {
        self.http_port = None;
        self
    }

    /// Builder: Set bind address
    pub fn with_bind_addr(mut self, addr: IpAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Builder: Set certificate paths
    pub fn with_certs(mut self, cert_path: PathBuf, key_path: PathBuf) -> Self {
        self.cert_path = Some(cert_path);
        self.key_path = Some(key_path);
        self
    }

    /// Builder: Set gateway suffix
    pub fn with_gateway_suffix(mut self, suffix: &str) -> Self {
        self.gateway_suffix = suffix.to_string();
        self
    }

    /// Builder: Set data directory
    pub fn with_data_dir(mut self, dir: PathBuf) -> Self {
        self.data_dir = dir;
        self
    }

    /// Get effective certificate path (with fallback to auto-generated)
    pub fn effective_cert_path(&self) -> PathBuf {
        self.cert_path.clone().unwrap_or_else(|| {
            self.data_dir.join("server.crt")
        })
    }

    /// Get effective key path (with fallback to auto-generated)
    pub fn effective_key_path(&self) -> PathBuf {
        self.key_path.clone().unwrap_or_else(|| {
            self.data_dir.join("server.key")
        })
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Check port conflicts
        if let Some(http_port) = self.http_port {
            if http_port == self.https_port {
                return Err("HTTP and HTTPS ports cannot be the same".to_string());
            }
        }

        // Check certificate paths for non-self-signed modes
        match self.mode {
            TlsMode::StandardCa => {
                if self.cert_path.is_none() {
                    return Err("StandardCa mode requires cert_path".to_string());
                }
                if self.key_path.is_none() {
                    return Err("StandardCa mode requires key_path".to_string());
                }
            }
            TlsMode::PrivateCa => {
                if self.cert_path.is_none() {
                    return Err("PrivateCa mode requires cert_path".to_string());
                }
                if self.key_path.is_none() {
                    return Err("PrivateCa mode requires key_path".to_string());
                }
                if self.ca_cert_path.is_none() {
                    return Err("PrivateCa mode requires ca_cert_path".to_string());
                }
            }
            TlsMode::SelfSigned | TlsMode::Disabled => {
                // No certificate paths required
            }
        }

        // Validate CORS origins
        if self.cors_origins.is_empty() {
            return Err("cors_origins cannot be empty".to_string());
        }

        Ok(())
    }
}
