use anyhow::{Context, Result};
use lib_network::web4::TrustConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_NAME: &str = "config.toml";
const DEFAULT_ROOT_DIR: &str = ".zhtp-daemon";
const DEFAULT_LISTEN_ADDR: &str = "127.0.0.1:7840";
const DEFAULT_NODE_ADDR: &str = "127.0.0.1:443";
const ENV_ROOT_DIR: &str = "ZHTP_DAEMON_ROOT_DIR";
const ENV_CONFIG_PATH: &str = "ZHTP_DAEMON_CONFIG";

/// Backend selection policy for the gateway.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BackendSelectionPolicy {
    RoundRobin,
    LowestLatency,
    LeastInflight,
}

impl Default for BackendSelectionPolicy {
    fn default() -> Self {
        BackendSelectionPolicy::LowestLatency
    }
}

/// Gateway-specific configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Public listen address for incoming client connections.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// QUIC listen address for incoming native ZHTP connections.
    /// Defaults to the same value as `listen_addr` so UDP and TCP share the port.
    #[serde(default = "default_listen_addr")]
    pub quic_listen_addr: String,
    /// Total request timeout in milliseconds.
    #[serde(default = "default_request_timeout_ms")]
    pub request_timeout_ms: u64,
    /// Backend connect timeout in milliseconds.
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    /// How to select a backend from the healthy pool.
    #[serde(default)]
    pub backend_selection: BackendSelectionPolicy,
    /// Whether to retry idempotent requests on backend failure.
    #[serde(default = "default_retry_idempotent")]
    pub retry_idempotent_requests: bool,
    /// Statically configured backend addresses (bedrock fallback).
    #[serde(default)]
    pub static_backends: Vec<String>,
    /// Whether to discover dynamic backend candidates from PeerRegistry.
    #[serde(default)]
    pub dynamic_backend_discovery: bool,
    /// Whether to actually route traffic to dynamically discovered backends.
    #[serde(default)]
    pub dynamic_backend_routing: bool,
    /// How often to run health probes in milliseconds.
    #[serde(default = "default_health_check_interval_ms")]
    pub health_check_interval_ms: u64,
    /// Consecutive failures before marking a backend unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    /// Consecutive successes in HalfOpen before promoting to Healthy.
    #[serde(default = "default_recovery_threshold")]
    pub recovery_threshold: u32,
    /// Cooldown duration before moving Unhealthy -> HalfOpen in milliseconds.
    #[serde(default = "default_cooldown_ms")]
    pub cooldown_ms: u64,
    /// Maximum concurrent requests per backend.
    #[serde(default = "default_max_in_flight_per_backend")]
    pub max_in_flight_per_backend: usize,
}

fn default_listen_addr() -> String {
    DEFAULT_LISTEN_ADDR.to_string()
}

fn default_request_timeout_ms() -> u64 {
    8000
}

fn default_connect_timeout_ms() -> u64 {
    1500
}

fn default_retry_idempotent() -> bool {
    true
}

fn default_health_check_interval_ms() -> u64 {
    5000
}

fn default_unhealthy_threshold() -> u32 {
    3
}

fn default_recovery_threshold() -> u32 {
    2
}

fn default_cooldown_ms() -> u64 {
    15000
}

fn default_max_in_flight_per_backend() -> usize {
    200
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            quic_listen_addr: default_listen_addr(),
            request_timeout_ms: default_request_timeout_ms(),
            connect_timeout_ms: default_connect_timeout_ms(),
            backend_selection: BackendSelectionPolicy::default(),
            retry_idempotent_requests: default_retry_idempotent(),
            static_backends: Vec::new(),
            dynamic_backend_discovery: false,
            dynamic_backend_routing: false,
            health_check_interval_ms: default_health_check_interval_ms(),
            unhealthy_threshold: default_unhealthy_threshold(),
            recovery_threshold: default_recovery_threshold(),
            cooldown_ms: default_cooldown_ms(),
            max_in_flight_per_backend: default_max_in_flight_per_backend(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustMode {
    Strict,
    Tofu,
    Bootstrap,
}

impl Default for TrustMode {
    fn default() -> Self {
        Self::Tofu
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustSettings {
    #[serde(default)]
    pub mode: TrustMode,
    #[serde(default)]
    pub node_did: Option<String>,
    #[serde(default)]
    pub pin_spki: Option<String>,
    #[serde(default)]
    pub trustdb_path: Option<String>,
    #[serde(default)]
    pub audit_log_path: Option<String>,
}

impl Default for TrustSettings {
    fn default() -> Self {
        Self {
            mode: TrustMode::Tofu,
            node_did: None,
            pin_spki: None,
            trustdb_path: None,
            audit_log_path: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    /// Legacy static backend list. Used as fallback when `gateway` block is absent.
    #[serde(default)]
    pub backend_nodes: Vec<String>,
    #[serde(default)]
    pub trust: TrustSettings,
    /// Optional gateway configuration. When present, the daemon runs in gateway mode.
    #[serde(default)]
    pub gateway: Option<GatewayConfig>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            backend_nodes: vec![DEFAULT_NODE_ADDR.to_string()],
            trust: TrustSettings::default(),
            gateway: None,
        }
    }
}

impl DaemonConfig {
    pub fn config_path() -> Result<PathBuf> {
        if let Some(path) = std::env::var_os(ENV_CONFIG_PATH) {
            return Ok(PathBuf::from(path));
        }
        if let Some(root_dir) = std::env::var_os(ENV_ROOT_DIR) {
            return Ok(PathBuf::from(root_dir).join(DEFAULT_CONFIG_NAME));
        }
        let home = dirs::home_dir().context("Cannot determine home directory")?;
        Ok(home.join(DEFAULT_ROOT_DIR).join(DEFAULT_CONFIG_NAME))
    }

    pub fn root_dir() -> Result<PathBuf> {
        Ok(Self::config_path()?
            .parent()
            .context("Invalid config path")?
            .to_path_buf())
    }

    pub fn load_or_create() -> Result<(Self, PathBuf)> {
        let config_path = Self::config_path()?;
        if config_path.exists() {
            let raw = std::fs::read_to_string(&config_path)
                .with_context(|| format!("Failed to read {}", config_path.display()))?;
            let config: Self = toml::from_str(&raw)
                .with_context(|| format!("Failed to parse {}", config_path.display()))?;
            return Ok((config, config_path));
        }

        let config = Self::default();
        config.save(&config_path)?;
        Ok((config, config_path))
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create {}", parent.display()))?;
        }

        let rendered = toml::to_string_pretty(self).context("Failed to serialize config")?;
        std::fs::write(path, rendered)
            .with_context(|| format!("Failed to write {}", path.display()))?;
        Ok(())
    }

    /// Return the effective static backend addresses.
    /// If a gateway config exists, uses `gateway.static_backends`.
    /// Otherwise falls back to the legacy `backend_nodes` list.
    pub fn static_backends(&self) -> Vec<String> {
        if let Some(ref gw) = self.gateway {
            if !gw.static_backends.is_empty() {
                return gw.static_backends.clone();
            }
        }
        self.backend_nodes.clone()
    }

    /// Return the effective gateway config, constructing one from legacy fields if necessary.
    pub fn effective_gateway_config(&self) -> GatewayConfig {
        self.gateway.clone().unwrap_or_else(|| {
            let mut cfg = GatewayConfig::default();
            cfg.listen_addr = self.listen_addr.clone();
            cfg.static_backends = self.backend_nodes.clone();
            cfg
        })
    }

    pub fn trust_config(&self) -> Result<TrustConfig> {
        let root_dir = Self::root_dir()?;
        let default_trustdb = root_dir.join("trustdb.json");
        let default_audit = root_dir.join("trust-audit.log");

        let trustdb_path = self
            .trust
            .trustdb_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or(default_trustdb);
        let audit_log_path = self
            .trust
            .audit_log_path
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or(default_audit);

        let mut config = TrustConfig {
            pin_spki: self.trust.pin_spki.clone(),
            node_did: self.trust.node_did.clone(),
            allow_tofu: matches!(self.trust.mode, TrustMode::Tofu),
            bootstrap_mode: matches!(self.trust.mode, TrustMode::Bootstrap),
            trustdb_path: Some(trustdb_path),
            audit_log_path: Some(audit_log_path),
        };

        if matches!(self.trust.mode, TrustMode::Bootstrap) {
            config.allow_tofu = false;
        }

        Ok(config)
    }
}
