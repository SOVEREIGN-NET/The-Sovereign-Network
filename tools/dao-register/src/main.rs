/// Generate, register, and persist the 5 sector DAO identities.
///
/// Outputs keys/dao-wallets.json — a permanent credential backup.
/// The key_ids printed at the end must be wired into FeeRouter initialization.
use anyhow::{Context, Result};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use lib_network::{
    client::{ZhtpClient, ZhtpClientConfig},
    web4::trust::TrustConfig,
    ZhtpIdentity,
};
use zhtp_client::{
    generate_identity, get_seed_phrase, sign_registration_proof, Identity,
};

const SERVER: &str = "91.98.113.188:9334"; // g3

#[derive(Debug, Serialize, Deserialize)]
struct DaoWallet {
    /// DAO sector name
    pub sector: String,
    /// DID — did:zhtp:<hex(key_id)>
    pub did: String,
    /// key_id as hex (32 bytes)
    pub key_id: String,
    /// BIP39 recovery phrase (24 words) — KEEP SECRET
    pub recovery_phrase: String,
    /// Dilithium5 public key as hex (2592 bytes)
    pub dilithium_pk_hex: String,
    /// Kyber1024 public key as hex (1568 bytes)
    pub kyber_pk_hex: String,
    /// device_id used at registration
    pub device_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DaoWalletsFile {
    pub note: String,
    pub created_at: u64,
    pub server: String,
    pub wallets: Vec<DaoWallet>,
}

async fn load_transport_identity() -> Result<ZhtpIdentity> {
    let keystore = PathBuf::from(
        std::env::var("HOME").context("HOME not set")?
    ).join(".zhtp").join("keystore");

    let identity_json = std::fs::read_to_string(keystore.join("user_identity.json"))
        .context("read user_identity.json")?;
    let private_key_json = std::fs::read_to_string(keystore.join("user_private_key.json"))
        .context("read user_private_key.json")?;

    #[derive(Deserialize)]
    struct KsPk {
        #[serde(with = "hex_serde_4896")]
        dilithium_sk: [u8; 4896],
        #[serde(with = "hex_serde_2592")]
        dilithium_pk: [u8; 2592],
        #[serde(with = "hex_serde_3168")]
        kyber_sk: [u8; 3168],
        #[serde(with = "hex_serde_64")]
        master_seed: [u8; 64],
    }

    mod hex_serde_4896 {
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 4896], D::Error> {
            let s = String::deserialize(d)?;
            let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
            b.try_into().map_err(|_| serde::de::Error::custom("bad len"))
        }
        use serde::Deserialize;
    }
    mod hex_serde_2592 {
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 2592], D::Error> {
            let s = String::deserialize(d)?;
            let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
            b.try_into().map_err(|_| serde::de::Error::custom("bad len"))
        }
        use serde::Deserialize;
    }
    mod hex_serde_3168 {
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 3168], D::Error> {
            let s = String::deserialize(d)?;
            let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
            b.try_into().map_err(|_| serde::de::Error::custom("bad len"))
        }
        use serde::Deserialize;
    }
    mod hex_serde_64 {
        pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
            let s = String::deserialize(d)?;
            let b = hex::decode(&s).map_err(serde::de::Error::custom)?;
            b.try_into().map_err(|_| serde::de::Error::custom("bad len"))
        }
        use serde::Deserialize;
    }

    let ks: KsPk = serde_json::from_str(&private_key_json).context("parse private key")?;
    let pk = lib_crypto::PrivateKey {
        dilithium_sk: ks.dilithium_sk,
        dilithium_pk: ks.dilithium_pk,
        kyber_sk: ks.kyber_sk,
        master_seed: ks.master_seed,
    };
    ZhtpIdentity::from_serialized(&identity_json, &pk).context("restore identity")
}

async fn register_one(client: &ZhtpClient, identity: &Identity, display_name: &str, device_id: &str) -> Result<String> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    let sig = sign_registration_proof(identity, timestamp)
        .context("sign registration proof")?;

    let b64 = base64::engine::general_purpose::STANDARD;
    let body = serde_json::json!({
        "public_key": b64.encode(&identity.public_key),
        "kyber_public_key": b64.encode(&identity.kyber_public_key),
        "device_id": device_id,
        "display_name": display_name,
        "identity_type": "organization",
        "registration_proof": b64.encode(&sig),
        "timestamp": timestamp,
    });

    println!("  → Registering {}...", display_name);
    let resp = client
        .post_json("/api/v1/identity/register", &body)
        .await
        .context("POST /api/v1/identity/register")?;

    let result: serde_json::Value = ZhtpClient::parse_json(&resp)
        .context("parse registration response")?;

    let did = result
        .get("did")
        .or_else(|| result.get("identity_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| identity.did.clone());

    println!("    ✓ DID: {}", &did);
    Ok(did)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("warn")
        .init();

    let sectors = [
        ("healthcare", "DAO: Healthcare",   "dao-healthcare"),
        ("education",  "DAO: Education",    "dao-education"),
        ("energy",     "DAO: Energy",       "dao-energy"),
        ("housing",    "DAO: Housing",      "dao-housing"),
        ("food",       "DAO: Food",         "dao-food"),
    ];

    // Connect using local transport identity
    println!("Connecting to {}...", SERVER);
    let transport_identity = load_transport_identity().await?;
    let trust_config = TrustConfig::bootstrap();
    let config = ZhtpClientConfig { allow_bootstrap: true };
    let mut client = ZhtpClient::new_with_config(transport_identity, trust_config, config)
        .await
        .context("create client")?;
    client.connect(SERVER).await.context("connect")?;
    println!("Connected.\n");

    let mut wallets: Vec<DaoWallet> = Vec::new();
    let created_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    for (sector, display_name, device_id) in &sectors {
        println!("Generating identity for {} ({})...", display_name, device_id);
        let identity = generate_identity(device_id.to_string())
            .context("generate identity")?;

        let phrase = get_seed_phrase(&identity)
            .context("get seed phrase")?;

        // key_id is blake3(dilithium_pk) on the server side (DID derivation)
        // but on client side it's blake3(dilithium_pk || kyber_pk). Use DID for consistency.
        let did_result = register_one(&client, &identity, display_name, device_id).await;

        let did = match did_result {
            Ok(d) => d,
            Err(e) => {
                eprintln!("  ✗ Registration failed for {}: {}", sector, e);
                eprintln!("    Saving credentials anyway for manual registration.");
                identity.did.clone()
            }
        };

        // key_id from DID: did:zhtp:<hex> → strip prefix
        let key_id_hex = did.strip_prefix("did:zhtp:").unwrap_or(&did).to_string();

        wallets.push(DaoWallet {
            sector: sector.to_string(),
            did: did.clone(),
            key_id: key_id_hex,
            recovery_phrase: phrase,
            dilithium_pk_hex: hex::encode(&identity.public_key),
            kyber_pk_hex: hex::encode(&identity.kyber_public_key),
            device_id: device_id.to_string(),
        });
    }

    // Save permanent backup
    let out = DaoWalletsFile {
        note: "PERMANENT — DO NOT DELETE. These are the 5 sector DAO wallet credentials. \
               Keep offline copies. The recovery_phrase can restore the private keys. \
               The key_ids must be wired into FeeRouter initialization in lib-blockchain."
            .to_string(),
        created_at,
        server: SERVER.to_string(),
        wallets,
    };

    let keys_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent().unwrap()   // tools/
        .parent().unwrap()   // repo root
        .join("keys");
    std::fs::create_dir_all(&keys_dir)?;
    let out_path = keys_dir.join("dao-wallets.json");
    let json = serde_json::to_string_pretty(&out)?;
    std::fs::write(&out_path, &json)?;

    println!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("✅ DAO wallets saved to: {}", out_path.display());
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    println!("Key IDs for FeeRouter initialization:");
    for w in &out.wallets {
        println!("  {}: {}", w.sector, w.key_id);
    }
    println!("\nWire these into lib-blockchain/src/contracts/economics/fee_router.rs");

    Ok(())
}
