//! CLI configuration loader and runtime defaults.

use crate::error::{CliError, CliResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Default CLI config filename under ~/.zhtp/
pub const DEFAULT_CONFIG_FILENAME: &str = "cli.toml";

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct CliConfig {
    pub defaults: Option<CliDefaults>,
    pub default_profile: Option<String>,
    #[serde(default)]
    pub servers: HashMap<String, ServerSpec>,
    #[serde(default)]
    pub profiles: HashMap<String, ProfileConfig>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct CliDefaults {
    pub server: Option<String>,
    pub keystore: Option<String>,
    pub identity: Option<String>,
    pub api_key: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ServerSpec {
    Address(String),
    Detailed(ServerProfile),
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ServerProfile {
    pub address: String,
    pub keystore: Option<String>,
    pub identity: Option<String>,
    pub api_key: Option<String>,
    pub user_id: Option<String>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct ProfileConfig {
    pub server: Option<String>,
    pub keystore: Option<String>,
    pub identity: Option<String>,
    pub api_key: Option<String>,
    pub user_id: Option<String>,
    pub trust: Option<TrustProfile>,
}

#[derive(Debug, Default, Clone, Deserialize, Serialize)]
pub struct TrustProfile {
    pub pin_spki: Option<String>,
    pub node_did: Option<String>,
    pub tofu: Option<bool>,
    pub trust_node: Option<bool>,
}

impl ServerSpec {
    pub fn address(&self) -> &str {
        match self {
            ServerSpec::Address(addr) => addr.as_str(),
            ServerSpec::Detailed(profile) => profile.address.as_str(),
        }
    }

    pub fn profile(&self) -> Option<&ServerProfile> {
        match self {
            ServerSpec::Detailed(profile) => Some(profile),
            _ => None,
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct RuntimeDefaults {
    pub keystore: Option<String>,
    pub identity: Option<String>,
    pub api_key: Option<String>,
    pub user_id: Option<String>,
    pub trust: Option<TrustProfile>,
}

static RUNTIME_DEFAULTS: OnceLock<RuntimeDefaults> = OnceLock::new();

pub fn set_runtime_defaults(defaults: RuntimeDefaults) {
    let _ = RUNTIME_DEFAULTS.set(defaults);
}

pub fn runtime_defaults() -> RuntimeDefaults {
    RUNTIME_DEFAULTS.get().cloned().unwrap_or_default()
}

pub fn default_config_path() -> PathBuf {
    if let Some(home) = dirs::home_dir() {
        home.join(".zhtp").join(DEFAULT_CONFIG_FILENAME)
    } else {
        PathBuf::from("./zhtp-cli.toml")
    }
}

pub fn load_config(path: Option<&str>) -> CliResult<CliConfig> {
    let config_path = path
        .map(PathBuf::from)
        .unwrap_or_else(default_config_path);

    if !config_path.exists() {
        if path.is_some() {
            return Err(CliError::ConfigError(format!(
                "Configuration file not found: {}",
                config_path.display()
            )));
        }
        return Ok(CliConfig::default());
    }

    let raw = fs::read_to_string(&config_path)
        .map_err(|e| CliError::ConfigError(format!("Failed to read config: {}", e)))?;

    toml::from_str(&raw)
        .map_err(|e| CliError::ConfigError(format!("Invalid CLI config: {}", e)))
}

pub fn load_config_strict(path: &Path) -> CliResult<CliConfig> {
    if !path.exists() {
        return Err(CliError::ConfigError(format!(
            "Configuration file not found: {}",
            path.display()
        )));
    }

    let raw = fs::read_to_string(path)
        .map_err(|e| CliError::ConfigError(format!("Failed to read config: {}", e)))?;

    toml::from_str(&raw)
        .map_err(|e| CliError::ConfigError(format!("Invalid CLI config: {}", e)))
}

pub fn resolve_server_alias<'a>(
    config: &'a CliConfig,
    name: &str,
) -> Option<&'a ServerSpec> {
    config.servers.get(name)
}

pub fn resolve_profile<'a>(
    config: &'a CliConfig,
    name: &str,
) -> Option<&'a ProfileConfig> {
    config.profiles.get(name)
}

pub fn merge_defaults(
    base: RuntimeDefaults,
    overrides: &CliDefaults,
) -> RuntimeDefaults {
    RuntimeDefaults {
        keystore: overrides.keystore.clone().or(base.keystore),
        identity: overrides.identity.clone().or(base.identity),
        api_key: overrides.api_key.clone().or(base.api_key),
        user_id: overrides.user_id.clone().or(base.user_id),
        trust: base.trust,
    }
}

pub fn merge_profile_defaults(
    base: RuntimeDefaults,
    profile: &ServerProfile,
) -> RuntimeDefaults {
    RuntimeDefaults {
        keystore: profile.keystore.clone().or(base.keystore),
        identity: profile.identity.clone().or(base.identity),
        api_key: profile.api_key.clone().or(base.api_key),
        user_id: profile.user_id.clone().or(base.user_id),
        trust: base.trust,
    }
}

pub fn merge_profile_config(
    base: RuntimeDefaults,
    profile: &ProfileConfig,
) -> RuntimeDefaults {
    RuntimeDefaults {
        keystore: profile.keystore.clone().or(base.keystore),
        identity: profile.identity.clone().or(base.identity),
        api_key: profile.api_key.clone().or(base.api_key),
        user_id: profile.user_id.clone().or(base.user_id),
        trust: profile.trust.clone().or(base.trust),
    }
}

pub fn config_path(path: Option<&str>) -> PathBuf {
    path.map(PathBuf::from).unwrap_or_else(default_config_path)
}

pub fn save_config(path: Option<&str>, config: &CliConfig) -> CliResult<()> {
    let config_path = config_path(path);
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            CliError::ConfigError(format!("Failed to create config directory: {}", e))
        })?;
    }

    let data = toml::to_string_pretty(config)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize config: {}", e)))?;
    fs::write(&config_path, data)
        .map_err(|e| CliError::ConfigError(format!("Failed to write config: {}", e)))?;
    Ok(())
}
}
