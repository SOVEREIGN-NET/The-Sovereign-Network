//! SA-3: build signed founding `AssetLaunch` transactions for post-reset testnet.
//!
//! Usage:
//!   cargo run -p tools --bin seed_asset_launch -- \
//!     --keystore-dir /opt/zhtp/keystores/bubl-creator \
//!     --token bubl \
//!     --supply-atoms 1000000000000000000000000000 \
//!     --rewards-delegate-dir /opt/zhtp/keystores/bubl-rewards-hot

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use lib_blockchain::{
    contracts::sovereign_asset::{DaoClass, SupplyMode},
    integration::crypto_integration::{Signature, SignatureAlgorithm},
    protocol::ProtocolParams,
    rewards_policy::{policy_hash, validate_rewards_policy},
    transaction::{
        asset_tx::{AssetLaunchPayloadV1, RewardsLaunchConfig},
        hash_transaction, Transaction,
    },
    TransactionType,
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

#[derive(Clone, ValueEnum)]
enum FoundingToken {
    Bubl,
    Cbe,
}

#[derive(Parser)]
#[command(name = "seed_asset_launch")]
struct Args {
    #[arg(long)]
    keystore_dir: PathBuf,
    #[arg(long, value_enum, default_value = "bubl")]
    token: FoundingToken,
    #[arg(long)]
    supply_atoms: u128,
    #[arg(long)]
    treasury_key_id: Option<String>,
    /// Keystore for rewards spend delegate (BUBL only).
    #[arg(long)]
    rewards_delegate_dir: Option<PathBuf>,
    /// Rewards policy JSON (`zhtp/rewards-policy/v1`). Hashed for on-chain `policy_hash`.
    #[arg(long, default_value = "schemas/zhtp/rewards-policy/examples/bubl-v1.json")]
    policy_file: PathBuf,
    #[arg(long, default_value_t = 0x03)]
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

fn treasury_key_id(args: &Args) -> Result<[u8; 32]> {
    if let Some(hex_str) = &args.treasury_key_id {
        let bytes = hex::decode(hex_str).context("treasury_key_id hex")?;
        anyhow::ensure!(bytes.len() == 32, "treasury_key_id must be 32 bytes");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        return Ok(out);
    }
    Ok(ProtocolParams::default().fee_sink_address().0)
}

fn token_meta(token: &FoundingToken) -> (&'static str, &'static str, u8, SupplyMode) {
    match token {
        FoundingToken::Bubl => ("Bubble", "BUBL", 18, SupplyMode::Fixed),
        FoundingToken::Cbe => {
            use lib_blockchain::contracts::bonding_curve::canonical::{
                CBE_DECIMALS, CBE_NAME, CBE_SYMBOL,
            };
            (CBE_NAME, CBE_SYMBOL, CBE_DECIMALS, SupplyMode::Elastic)
        }
    }
}

fn load_rewards_policy_bundle(
    policy_path: &std::path::Path,
) -> Result<([u8; 32], [u8; 32], Vec<u8>)> {
    let bytes = std::fs::read(policy_path)
        .with_context(|| format!("read rewards policy {}", policy_path.display()))?;
    let policy = validate_rewards_policy(&bytes).context("validate rewards policy")?;
    let hash = policy_hash(&policy).context("hash rewards policy")?;
    let policy_hash = hash.as_array();
    let mut cid_input = b"zhtp/rewards-policy/cid/v1\0".to_vec();
    cid_input.extend_from_slice(&bytes);
    let policy_cid = lib_crypto::hash_blake3(&cid_input);
    Ok((policy_cid, policy_hash, bytes))
}

fn placeholder_manifest() -> ([u8; 32], [u8; 32]) {
    let manifest = serde_json::json!({
        "schema": "zhtp/asset-manifest/v1",
        "interface": { "version": "1.0.0", "tx_kinds": ["TokenTransfer", "RewardsClaim"] }
    });
    let bytes = serde_json::to_vec(&manifest).expect("manifest json");
    let hash = lib_crypto::hash_blake3(&bytes);
    let mut cid = [0u8; 32];
    cid[..16].copy_from_slice(&hash[..16]);
    (cid, hash)
}

fn build_signed_asset_launch(
    keypair: &KeyPair,
    name: &str,
    symbol: &str,
    supply_atoms: u128,
    decimals: u8,
    supply_mode: SupplyMode,
    treasury_key_id: [u8; 32],
    rewards: Option<RewardsLaunchConfig>,
    chain_id: u8,
    fee: u64,
) -> Result<Transaction> {
    let (manifest_cid, manifest_hash) = placeholder_manifest();
    let payload = AssetLaunchPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        initial_supply: supply_atoms,
        treasury_key_id,
        treasury_bps: 2_000,
        supply_mode,
        manifest_cid,
        manifest_hash,
        curve: None,
        rewards,
        governance: None,
        transfer_authority: false,
        // Seeded assets are for-profit class: treasury_bps 2_000 == FP_TREASURY_BPS.
        dao_class: DaoClass::Fp,
        burn_bps: 0,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| anyhow::anyhow!("encode asset launch memo: {e}"))?;

    let mut tx = Transaction::new_asset_launch_with_chain_id(
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
        .context("sign AssetLaunch")?;
    tx.signature = sig;

    anyhow::ensure!(
        tx.transaction_type == TransactionType::AssetLaunch,
        "built tx is not AssetLaunch"
    );
    Ok(tx)
}

fn main() -> Result<()> {
    let args = Args::parse();
    let keypair = load_keypair(&args.keystore_dir)?;
    let treasury = treasury_key_id(&args)?;
    if treasury == keypair.public_key.key_id {
        anyhow::bail!("treasury_key_id must differ from creator key_id");
    }

    let (name, symbol, decimals, supply_mode) = token_meta(&args.token);

    let rewards = match (&args.token, &args.rewards_delegate_dir) {
        (FoundingToken::Bubl, Some(dir)) => {
            let delegate_kp = load_keypair(dir)?;
            let (policy_cid, policy_hash, policy_document) =
                load_rewards_policy_bundle(&args.policy_file)?;
            Some(RewardsLaunchConfig {
                spend_delegate_key_id: delegate_kp.public_key.key_id,
                policy_cid,
                policy_hash,
                policy_document: Some(policy_document),
            })
        }
        (FoundingToken::Bubl, None) => {
            anyhow::bail!("BUBL launch requires --rewards-delegate-dir");
        }
        _ => None,
    };

    let tx = build_signed_asset_launch(
        &keypair,
        name,
        symbol,
        args.supply_atoms,
        decimals,
        supply_mode,
        treasury,
        rewards,
        args.chain_id,
        args.fee,
    )?;

    let asset_id = hash_transaction(&tx).as_array();
    let signed_hex = hex::encode(bincode::serialize(&tx)?);
    let (creator_alloc, treasury_alloc) = AssetLaunchPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        decimals,
        initial_supply: args.supply_atoms,
        treasury_key_id: treasury,
        treasury_bps: 2_000,
        supply_mode,
        manifest_cid: [0u8; 32],
        manifest_hash: [0u8; 32],
        curve: None,
        rewards: None,
        governance: None,
        transfer_authority: false,
        dao_class: DaoClass::Fp,
        burn_bps: 0,
    }
    .split_initial_supply();

    let output = serde_json::json!({
        "genesis_phase": "SA-3",
        "token": symbol,
        "asset_id": hex::encode(asset_id),
        "creator_key_id": hex::encode(keypair.public_key.key_id),
        "treasury_key_id": hex::encode(treasury),
        "creator_allocation_atoms": creator_alloc.to_string(),
        "treasury_allocation_atoms": treasury_alloc.to_string(),
        "tx_hash": hex::encode(tx.hash().as_bytes()),
        "signed_tx": signed_hex,
        "submit_hint": "Broadcast AssetLaunch tx via zhtp-cli or mempool",
        "configure_rewards": {
            "asset_id": hex::encode(asset_id),
            "delegate_keystore": args.rewards_delegate_dir.as_ref().map(|p| p.display().to_string()),
            "hint": "zhtp-cli node configure-rewards --asset-id <asset_id> --delegate-keystore <path>"
        }
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}