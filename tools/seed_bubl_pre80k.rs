//! BUBL pre-80k readiness migration (#2864): treasury bind, delegate rotate, governance enable.
//!
//! Emits signed `AssetModuleUpgrade` / `AssetRewardsDelegateRotate` txs as JSON.
//! Fund-delegate still uses `zhtp-cli asset rewards fund-delegate` (needs live nonce).
//!
//! Usage:
//!   cargo run -p tools --bin seed_bubl_pre80k -- treasury-bind \
//!     --keystore-dir /opt/zhtp/keystores/bubl-creator \
//!     --treasury-dir /opt/zhtp/keystores/bubl-treasury \
//!     --asset-id 6948e43dea1fa98ac4f0d2b713774f9ca3f70d63365ad17ad12ffa0b5394050d \
//!     --chain-id 2

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use lib_blockchain::{
    integration::crypto_integration::{Signature, SignatureAlgorithm},
    transaction::{
        asset_tx::{
            AssetAuthorityProof, AssetModuleUpgradePayloadV1, AssetRewardsDelegateRotatePayloadV1,
            AssetUpgradeModule, GovernanceLaunchConfig,
        },
        Transaction,
    },
};
use lib_blockchain::contracts::sovereign_asset::GovernanceVerifierState;
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
#[command(name = "seed_bubl_pre80k")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Bind `treasury_key_id` on a legacy sovereign asset (one-time).
    TreasuryBind(TreasuryBindArgs),
    /// Rotate rewards spend delegate (creator-signed pre-handoff).
    RotateDelegate(RotateDelegateArgs),
    /// Enable governance module with creator as initial single signer.
    EnableGovernance(EnableGovernanceArgs),
}

#[derive(Parser)]
struct SharedArgs {
    #[arg(long)]
    keystore_dir: PathBuf,
    #[arg(long)]
    asset_id: String,
    #[arg(long, default_value_t = 0x02)]
    chain_id: u8,
    #[arg(long, default_value_t = 0)]
    fee: u64,
}

#[derive(Parser)]
struct TreasuryBindArgs {
    #[command(flatten)]
    shared: SharedArgs,
    #[arg(long)]
    treasury_dir: PathBuf,
}

#[derive(Parser)]
struct RotateDelegateArgs {
    #[command(flatten)]
    shared: SharedArgs,
    #[arg(long)]
    new_delegate_dir: PathBuf,
}

#[derive(Parser)]
struct EnableGovernanceArgs {
    #[command(flatten)]
    shared: SharedArgs,
    /// Queue creator→governance handoff via module-upgrade timelock (default: true).
    #[arg(long, default_value_t = true)]
    queue_authority_transfer: bool,
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

fn sign_module_upgrade(
    keypair: &KeyPair,
    payload: AssetModuleUpgradePayloadV1,
    chain_id: u8,
    fee: u64,
) -> Result<Transaction> {
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
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .context("sign AssetModuleUpgrade")?;
    Ok(tx)
}

fn sign_delegate_rotate(
    keypair: &KeyPair,
    payload: AssetRewardsDelegateRotatePayloadV1,
    chain_id: u8,
    fee: u64,
) -> Result<Transaction> {
    let memo = payload
        .encode_memo()
        .map_err(|e| anyhow::anyhow!("encode delegate rotate memo: {e}"))?;
    let mut tx = Transaction::new_asset_rewards_delegate_rotate_with_chain_id(
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
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .context("sign AssetRewardsDelegateRotate")?;
    Ok(tx)
}

fn emit_tx(step: &str, tx: &Transaction, extra: serde_json::Value) -> Result<()> {
    let signed_hex = hex::encode(bincode::serialize(tx)?);
    let mut output = serde_json::json!({
        "step": step,
        "tx_hash": hex::encode(tx.hash().as_bytes()),
        "signed_tx": signed_hex,
        "broadcast_hint": "POST /api/v1/blockchain/transaction/broadcast or zhtp-cli blockchain broadcast",
    });
    if let Some(obj) = output.as_object_mut() {
        if let Some(map) = extra.as_object() {
            for (k, v) in map {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::TreasuryBind(args) => {
            let asset_id = parse_asset_id(&args.shared.asset_id)?;
            let creator = load_keypair(&args.shared.keystore_dir)?;
            let treasury = load_keypair(&args.treasury_dir)?;
            if creator.public_key.key_id == treasury.public_key.key_id {
                anyhow::bail!("treasury keystore must differ from creator");
            }
            let payload = AssetModuleUpgradePayloadV1 {
                asset_id,
                module: AssetUpgradeModule::TreasuryBind {
                    treasury_key_id: treasury.public_key.key_id,
                },
                transfer_authority: false,
            };
            let tx = sign_module_upgrade(
                &creator,
                payload,
                args.shared.chain_id,
                args.shared.fee,
            )?;
            emit_tx(
                "treasury-bind",
                &tx,
                serde_json::json!({
                    "migration": "2864-treasury-bind",
                    "asset_id": hex::encode(asset_id),
                    "creator_key_id": hex::encode(creator.public_key.key_id),
                    "treasury_key_id": hex::encode(treasury.public_key.key_id),
                }),
            )?;
        }
        Command::RotateDelegate(args) => {
            let asset_id = parse_asset_id(&args.shared.asset_id)?;
            let creator = load_keypair(&args.shared.keystore_dir)?;
            let delegate = load_keypair(&args.new_delegate_dir)?;
            if creator.public_key.key_id == delegate.public_key.key_id {
                anyhow::bail!("new delegate must differ from creator");
            }
            let payload = AssetRewardsDelegateRotatePayloadV1 {
                asset_id,
                new_delegate_key_id: delegate.public_key.key_id,
                authority_proof: AssetAuthorityProof::CreatorSig,
            };
            let tx = sign_delegate_rotate(&creator, payload, args.shared.chain_id, args.shared.fee)?;
            emit_tx(
                "rotate-delegate",
                &tx,
                serde_json::json!({
                    "migration": "2864-rotate-delegate",
                    "asset_id": hex::encode(asset_id),
                    "new_delegate_key_id": hex::encode(delegate.public_key.key_id),
                }),
            )?;
        }
        Command::EnableGovernance(args) => {
            let asset_id = parse_asset_id(&args.shared.asset_id)?;
            let creator = load_keypair(&args.shared.keystore_dir)?;
            let gov = GovernanceLaunchConfig {
                verifier: GovernanceVerifierState::Single {
                    signer_key_id: creator.public_key.key_id,
                },
                threshold: None,
            };
            let payload = AssetModuleUpgradePayloadV1 {
                asset_id,
                module: AssetUpgradeModule::Governance(gov),
                transfer_authority: args.queue_authority_transfer,
            };
            let tx = sign_module_upgrade(
                &creator,
                payload,
                args.shared.chain_id,
                args.shared.fee,
            )?;
            emit_tx(
                "enable-governance",
                &tx,
                serde_json::json!({
                    "migration": "2864-enable-governance",
                    "asset_id": hex::encode(asset_id),
                    "queue_authority_transfer": args.queue_authority_transfer,
                    "initial_verifier": hex::encode(creator.public_key.key_id),
                }),
            )?;
        }
    }
    Ok(())
}