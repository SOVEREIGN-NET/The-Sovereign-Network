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
    pub listen_addr: String,
    pub backend_nodes: Vec<String>,
    #[serde(default)]
    pub trust: TrustSettings,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            backend_nodes: vec![DEFAULT_NODE_ADDR.to_string()],
            trust: TrustSettings::default(),
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
