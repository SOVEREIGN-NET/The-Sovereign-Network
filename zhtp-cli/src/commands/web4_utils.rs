//! Shared Web4 CLI helpers (identity loading, trust config, validation).

use crate::error::{CliError, CliResult};
use base64::{engine::general_purpose, Engine as _};
use lib_crypto::keypair::KeyPair;
use lib_crypto::types::PrivateKey;
use lib_identity::ZhtpIdentity;
use lib_network::client::{ZhtpClient, ZhtpClientConfig};
use lib_network::web4::TrustConfig;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct LoadedIdentity {
    pub identity: ZhtpIdentity,
    pub keypair: KeyPair,
}

#[derive(Deserialize)]
struct KeystorePrivateKey {
    dilithium_sk: Vec<u8>,
    kyber_sk: Vec<u8>,
    master_seed: Vec<u8>,
}

pub fn load_identity_from_keystore(keystore_path: &Path) -> CliResult<LoadedIdentity> {
    // Load USER identity for domain/content operations (has wallets)
    // NODE identity is for mesh networking operations only
    let identity_file = keystore_path.join(zhtp::keystore_names::USER_IDENTITY_FILENAME);
    let private_key_file = keystore_path.join(zhtp::keystore_names::USER_PRIVATE_KEY_FILENAME);

    if !identity_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Identity file not found in keystore: {:?}",
            identity_file
        )));
    }
    if !private_key_file.exists() {
        return Err(CliError::IdentityError(format!(
            "Private key file not found in keystore: {:?}",
            private_key_file
        )));
    }

    let identity_json = std::fs::read_to_string(&identity_file)
        .map_err(|e| CliError::IdentityError(format!("Failed to read identity: {}", e)))?;
    let private_key_json = std::fs::read_to_string(&private_key_file)
        .map_err(|e| CliError::IdentityError(format!("Failed to read private key: {}", e)))?;

    let keystore_key: KeystorePrivateKey = serde_json::from_str(&private_key_json)
        .map_err(|e| CliError::IdentityError(format!("Failed to parse private key: {}", e)))?;

    let private_key = PrivateKey {
        dilithium_sk: keystore_key.dilithium_sk,
        kyber_sk: keystore_key.kyber_sk,
        master_seed: keystore_key.master_seed,
    };

    let identity = ZhtpIdentity::from_serialized(&identity_json, &private_key)
        .map_err(|e| CliError::IdentityError(format!("Failed to restore identity: {}", e)))?;

    let keypair = KeyPair {
        public_key: identity.public_key.clone(),
        private_key,
    };

    Ok(LoadedIdentity { identity, keypair })
}

pub fn build_trust_config(
    pin_spki: Option<&str>,
    node_did: Option<&str>,
    tofu: bool,
    trust_node: bool,
) -> CliResult<TrustConfig> {
    if trust_node && pin_spki.is_some() {
        return Err(CliError::ConfigError(
            "Cannot use --trust-node (bootstrap mode) with --pin-spki (pinning mode)".to_string(),
        ));
    }

    if trust_node && tofu {
        return Err(CliError::ConfigError(
            "Cannot use --trust-node (bootstrap mode) with --tofu (TOFU mode)".to_string(),
        ));
    }

    if pin_spki.is_some() && tofu {
        return Err(CliError::ConfigError(
            "Cannot use --pin-spki with --tofu - choose one trust mode".to_string(),
        ));
    }

    let mut config = if trust_node {
        TrustConfig::bootstrap()
    } else if let Some(pin) = pin_spki {
        TrustConfig::with_pin(pin.to_string())
    } else if tofu {
        let trustdb_path = TrustConfig::default_trustdb_path()
            .map_err(|e| CliError::ConfigError(format!("Failed to resolve trustdb path: {}", e)))?;
        TrustConfig::with_tofu(trustdb_path)
    } else {
        TrustConfig::default()
    };

    if let Some(did) = node_did {
        config = config.expect_node_did(did.to_string());
    }

    Ok(config)
}

pub async fn connect_client(
    identity: ZhtpIdentity,
    trust_config: TrustConfig,
    server: &str,
) -> CliResult<ZhtpClient> {
    let config = ZhtpClientConfig {
        allow_bootstrap: trust_config.bootstrap_mode,
    };

    let mut client = ZhtpClient::new_with_config(identity, trust_config, config)
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to create client: {}", e)))?;
    client
        .connect(server)
        .await
        .map_err(|e| CliError::ConfigError(format!("Failed to connect: {}", e)))?;
    Ok(client)
}

pub fn validate_domain(domain: &str) -> CliResult<String> {
    if domain.is_empty() {
        return Err(CliError::ConfigError("Domain cannot be empty".to_string()));
    }
    if domain.len() > 253 {
        return Err(CliError::ConfigError(
            "Domain cannot exceed 253 characters".to_string(),
        ));
    }
    if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
        return Err(CliError::ConfigError(
            "Domain contains empty labels".to_string(),
        ));
    }
    if domain.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(CliError::ConfigError(
            "Domain must be lowercase ASCII".to_string(),
        ));
    }

    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() < 2 {
        return Err(CliError::ConfigError(
            "Domain must include a TLD".to_string(),
        ));
    }

    let tld = parts.last().unwrap_or(&"");
    if *tld != "zhtp" && *tld != "sov" {
        return Err(CliError::ConfigError(
            "Domain must end with .zhtp or .sov".to_string(),
        ));
    }

    let mut seen = HashSet::new();
    for label in &parts[..parts.len() - 1] {
        if label.is_empty() {
            return Err(CliError::ConfigError(
                "Domain contains empty label".to_string(),
            ));
        }
        if label.len() > 63 {
            return Err(CliError::ConfigError(
                "Domain label exceeds 63 characters".to_string(),
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(CliError::ConfigError(
                "Domain label cannot start or end with '-'".to_string(),
            ));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        {
            return Err(CliError::ConfigError(
                "Domain labels may only contain a-z, 0-9, and '-'".to_string(),
            ));
        }
        if !seen.insert(label.to_string()) {
            return Err(CliError::ConfigError(
                "Domain contains duplicate labels".to_string(),
            ));
        }
    }

    Ok(domain.to_string())
}

pub fn decode_base64(data: &str) -> CliResult<Vec<u8>> {
    general_purpose::STANDARD
        .decode(data)
        .map_err(|e| CliError::ConfigError(format!("Invalid base64 data: {}", e)))
}

pub fn default_trust_paths() -> (PathBuf, PathBuf) {
    let trustdb = TrustConfig::default_trustdb_path()
        .unwrap_or_else(|_| PathBuf::from("trustdb.json"));
    let audit = TrustConfig::default_audit_path();
    (trustdb, audit)
}
