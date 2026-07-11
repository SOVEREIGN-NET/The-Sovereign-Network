//! D3: enable on-chain `RewardsModuleState` for legacy testnet BUBL via `AssetModuleUpgrade`.
//!
//! Usage:
//!   cargo run -p tools --bin seed_bubl_rewards_upgrade -- \
//!     --keystore-dir /opt/zhtp/keystores/bubl-creator \
//!     --asset-id 6948e43dea1fa98ac4f0d2b713774f9ca3f70d63365ad17ad12ffa0b5394050d \
//!     --rewards-delegate-dir /opt/zhtp/keystores/bubl-creator \
//!     --chain-id 2

use anyhow::{Context, Result};
use clap::Parser;
use lib_blockchain::{
    integration::crypto_integration::{Signature, SignatureAlgorithm},
    rewards_policy::{policy_hash, validate_rewards_policy},
    transaction::{
        asset_tx::{AssetModuleUpgradePayloadV1, AssetUpgradeModule, RewardsLaunchConfig},
        Transaction,
    },
};
use lib_crypto::{KeyPair, PrivateKey, PublicKey};
use lib_identity::identity::ZhtpIdentity;
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct KeystorePrivateKey {
    #[serde(with = "hex_bytes")]
    dilithium_sk: [u8; 4896],
    #[serde(default = "default_dilithium_pk", with = "hex_bytes")]
    dilithium_pk: [u8; 2592],
    #[serde(with = "hex_bytes")]
    kyber_sk: [u8; 3168],
    #[serde(with = "hex_bytes")]
    master_seed: [u8; 64],
}

fn default_dilithium_pk() -> [u8; 2592] {
    [0u8; 2592]
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != N {
            return Err(serde::de::Error::custom(format!(
                "expected {N} bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

const USER_IDENTITY_FILENAME: &str = "user_identity.json";
const USER_PRIVATE_KEY_FILENAME: &str = "user_private_key.json";

#[derive(Parser)]
#[command(name = "seed_bubl_rewards_upgrade")]
struct Args {
    /// Creator keystore (signs the upgrade tx).
    #[arg(long)]
    keystore_dir: PathBuf,
    /// Legacy BUBL token_id / asset_id (32-byte hex).
    #[arg(long)]
    asset_id: String,
    /// Spend-delegate keystore whose key_id is written on-chain.
    #[arg(long)]
    rewards_delegate_dir: PathBuf,
    #[arg(long, default_value = "schemas/zhtp/rewards-policy/examples/bubl-v1.json")]
    policy_file: PathBuf,
    #[arg(long, default_value_t = 0x02)]
    chain_id: u8,
    #[arg(long, default_value_t = 0)]
    fee: u64,
}

fn load_keypair(keystore_dir: &std::path::Path) -> Result<KeyPair> {
    let identity_file = keystore_dir.join(USER_IDENTITY_FILENAME);
    let priv_file = keystore_dir.join(USER_PRIVATE_KEY_FILENAME);
    let identity_json = std::fs::read_to_string(&identity_file)
        .with_context(|| format!("read {}", identity_file.display()))?;
    let priv_json = std::fs::read_to_string(&priv_file)
        .with_context(|| format!("read {}", priv_file.display()))?;
    let stored: KeystorePrivateKey = serde_json::from_str(&priv_json).context("parse private key")?;
    let private_key = PrivateKey {
        dilithium_sk: stored.dilithium_sk,
        dilithium_pk: stored.dilithium_pk,
        kyber_sk: stored.kyber_sk,
        master_seed: stored.master_seed,
    };
    let identity = ZhtpIdentity::from_serialized(&identity_json, &private_key)
        .context("restore identity from keystore")?;
    Ok(KeyPair {
        public_key: identity.public_key,
        private_key,
    })
}

fn parse_asset_id(hex_str: &str) -> Result<[u8; 32]> {
    let trimmed = hex_str.trim();
    let bytes = hex::decode(trimmed).context("asset_id hex")?;
    anyhow::ensure!(bytes.len() == 32, "asset_id must be 32 bytes");
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn load_rewards_policy_bundle(
    policy_path: &std::path::Path,
    asset_id: &[u8; 32],
) -> Result<([u8; 32], [u8; 32], Vec<u8>)> {
    let raw = std::fs::read(policy_path)
        .with_context(|| format!("read rewards policy {}", policy_path.display()))?;
    let mut doc: serde_json::Value =
        serde_json::from_slice(&raw).context("parse rewards policy json")?;
    if let Some(obj) = doc.as_object_mut() {
        obj.insert("asset_id".into(), serde_json::Value::String(hex::encode(asset_id)));
    }
    let bytes = serde_json::to_vec(&doc).context("canonicalize policy json")?;
    let policy = validate_rewards_policy(&bytes).context("validate rewards policy")?;
    let hash = policy_hash(&policy).context("hash rewards policy")?;
    let policy_hash = hash.as_array();
    let mut cid_input = b"zhtp/rewards-policy/cid/v1\0".to_vec();
    cid_input.extend_from_slice(&bytes);
    let policy_cid = lib_crypto::hash_blake3(&cid_input);
    Ok((policy_cid, policy_hash, bytes))
}

fn build_signed_upgrade(
    keypair: &KeyPair,
    asset_id: [u8; 32],
    rewards: RewardsLaunchConfig,
    chain_id: u8,
    fee: u64,
) -> Result<Transaction> {
    let payload = AssetModuleUpgradePayloadV1 {
        asset_id,
        module: AssetUpgradeModule::Rewards(rewards),
        transfer_authority: false,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| anyhow::anyhow!("encode asset upgrade memo: {e}"))?;

    let mut tx = Transaction::new_asset_module_upgrade_with_chain_id(
        chain_id,
        Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(keypair.public_key.dilithium_pk),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        memo,
    );
    tx.fee = fee;

    let sig = keypair
        .sign(tx.signing_hash().as_bytes())
        .context("sign AssetModuleUpgrade")?;
    tx.signature = sig;
    Ok(tx)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let asset_id = parse_asset_id(&args.asset_id)?;
    let creator = load_keypair(&args.keystore_dir)?;
    let delegate = load_keypair(&args.rewards_delegate_dir)?;
    let (policy_cid, policy_hash, policy_document) =
        load_rewards_policy_bundle(&args.policy_file, &asset_id)?;

    let rewards = RewardsLaunchConfig {
        spend_delegate_key_id: delegate.public_key.key_id,
        policy_cid,
        policy_hash,
        policy_document: Some(policy_document),
    };

    let tx = build_signed_upgrade(&creator, asset_id, rewards, args.chain_id, args.fee)?;
    let signed_hex = hex::encode(bincode::serialize(&tx)?);

    let output = serde_json::json!({
        "migration": "D3-legacy-bubl-rewards-upgrade",
        "asset_id": hex::encode(asset_id),
        "creator_key_id": hex::encode(creator.public_key.key_id),
        "spend_delegate_key_id": hex::encode(delegate.public_key.key_id),
        "tx_hash": hex::encode(tx.hash().as_bytes()),
        "signed_tx": signed_hex,
        "broadcast_hint": "zhtp-cli -s <validator>:9334 blockchain ... or POST /api/v1/blockchain/transaction/broadcast",
        "activation_hint": {
            "rewards_activation.toml": {
                "asset_id": hex::encode(asset_id),
                "delegate_keystore_dir": args.rewards_delegate_dir.display().to_string(),
            }
        }
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}