//! GENESIS-6 (#2734): build signed founding `TokenCreation` transactions for
//! post-reset DAO token deployment (BUBL rewards treasury, future CBE migration).
//!
//! Usage (after coordinated testnet reset, block 1..k seeding):
//!   cargo run -p tools --bin seed_founding_dao -- \
//!     --keystore-dir /opt/zhtp/keystores/bubl-creator \
//!     --token bubl \
//!     --supply-atoms 1000000000000000000000000000
//!
//! Submit the printed `signed_tx` hex via:
//!   zhtp-cli token create  (or POST /api/v1/token/create with signed_tx body)
//!
//! The keystore MUST be the entity that will fund `/api/v1/rewards/*` transfers
//! (`ZHTP_REWARDS_TREASURY_KEYSTORE` on validators).

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use lib_blockchain::{
    integration::crypto_integration::{Signature, SignatureAlgorithm},
    protocol::ProtocolParams,
    transaction::{
        token_creation::TokenCreationPayloadV1, Transaction, DEFAULT_TOKEN_CREATION_FEE,
    },
    TransactionType,
};
use lib_crypto::{KeyPair, PrivateKey, PublicKey};
use lib_identity::identity::ZhtpIdentity;
use serde::Deserialize;
use std::path::PathBuf;

/// Keystore private key JSON (matches `zhtp/src/keyfile_names.rs`).
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
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

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

const BUBL_TOKEN_NAME: &str = "Bubble";
const BUBL_TOKEN_SYMBOL: &str = "BUBL";

#[derive(Clone, ValueEnum)]
enum FoundingToken {
    /// Bubble / BUBL — rewards distribution token.
    Bubl,
    /// CBE Equity / CBE — DAO bonding-curve token (GENESIS-6 migration; block-0 seed must be retired first).
    Cbe,
}

#[derive(Parser)]
#[command(name = "seed_founding_dao")]
struct Args {
    /// Directory containing `user_identity.json` + `user_private_key.json`.
    #[arg(long)]
    keystore_dir: PathBuf,

    /// Which founding DAO token to build.
    #[arg(long, value_enum, default_value = "bubl")]
    token: FoundingToken,

    /// Total initial supply in atomic units (18-decimal atoms for BUBL/CBE).
    #[arg(long)]
    supply_atoms: u128,

    /// Treasury recipient key_id (hex). Defaults to protocol fee-sink address.
    #[arg(long)]
    treasury_key_id: Option<String>,

    /// Chain id byte (development testnet default 0x03).
    #[arg(long, default_value_t = 0x03)]
    chain_id: u8,

    /// TokenCreation fee (atoms). Use 0 only on subsidised testnet bootstrap.
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

fn token_meta(token: &FoundingToken) -> (&'static str, &'static str, u8) {
    match token {
        FoundingToken::Bubl => (BUBL_TOKEN_NAME, BUBL_TOKEN_SYMBOL, 18),
        FoundingToken::Cbe => {
            use lib_blockchain::contracts::bonding_curve::canonical::{CBE_DECIMALS, CBE_NAME, CBE_SYMBOL};
            (CBE_NAME, CBE_SYMBOL, CBE_DECIMALS)
        }
    }
}

fn build_signed_token_creation(
    keypair: &KeyPair,
    name: &str,
    symbol: &str,
    supply_atoms: u128,
    decimals: u8,
    treasury_recipient: [u8; 32],
    chain_id: u8,
    fee: u64,
) -> Result<(Transaction, [u8; 32])> {
    let expected_id = lib_blockchain::contracts::utils::generate_custom_token_id(name, symbol);
    let payload = TokenCreationPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply: supply_atoms,
        decimals,
        treasury_allocation_bps: 2_000,
        treasury_recipient,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| anyhow::anyhow!("encode token creation memo: {e}"))?;

    let mut tx = Transaction::new_token_creation_with_chain_id(
        chain_id,
        Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(keypair.public_key.dilithium_pk),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        },
        memo,
    );
    tx.fee = if fee == 0 { 0 } else { fee.max(DEFAULT_TOKEN_CREATION_FEE) };

    let sig = keypair
        .sign(tx.signing_hash().as_bytes())
        .context("sign TokenCreation")?;
    tx.signature = sig;

    anyhow::ensure!(
        tx.transaction_type == TransactionType::TokenCreation,
        "built tx is not TokenCreation"
    );
    Ok((tx, expected_id))
}

fn validate_canonical_rewards_policy() -> Result<lib_blockchain::types::Hash> {
    use lib_blockchain::rewards_policy::{policy_hash, validate_rewards_policy};
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../schemas/zhtp/rewards-policy/examples/bubl-v1.json"
    );
    let bytes = std::fs::read(path).context("read canonical BUBL rewards policy example")?;
    let policy = validate_rewards_policy(&bytes).context("validate rewards policy")?;
    policy_hash(&policy).map_err(|e| anyhow::anyhow!("policy_hash: {e}"))
}

fn main() -> Result<()> {
    let args = Args::parse();
    if matches!(args.token, FoundingToken::Bubl) {
        let policy_hash = validate_canonical_rewards_policy()?;
        eprintln!(
            "rewards policy validated (zhtp/rewards-policy/v1); policy_hash={}",
            hex::encode(policy_hash.as_bytes())
        );
    }
    let keypair = load_keypair(&args.keystore_dir)?;
    let treasury = treasury_key_id(&args)?;
    if treasury == keypair.public_key.key_id {
        anyhow::bail!("treasury_recipient must differ from creator key_id");
    }

    let (name, symbol, decimals) = token_meta(&args.token);
    let (tx, expected_id) = build_signed_token_creation(
        &keypair,
        name,
        symbol,
        args.supply_atoms,
        decimals,
        treasury,
        args.chain_id,
        args.fee,
    )?;

    let signed_hex = hex::encode(bincode::serialize(&tx)?);
    let (creator_alloc, treasury_alloc) = TokenCreationPayloadV1 {
        name: name.to_string(),
        symbol: symbol.to_string(),
        initial_supply: args.supply_atoms,
        decimals,
        treasury_allocation_bps: 2_000,
        treasury_recipient: treasury,
    }
    .split_initial_supply();

    let output = serde_json::json!({
        "genesis_phase": "GENESIS-6",
        "token": symbol,
        "expected_token_id": hex::encode(expected_id),
        "creator_key_id": hex::encode(keypair.public_key.key_id),
        "treasury_key_id": hex::encode(treasury),
        "creator_allocation_atoms": creator_alloc.to_string(),
        "treasury_allocation_atoms": treasury_alloc.to_string(),
        "tx_hash": hex::encode(tx.hash().as_bytes()),
        "signed_tx": signed_hex,
        "submit_hint": "POST /api/v1/token/create with {\"signed_tx\": <signed_tx>}",
    });

    if matches!(args.token, FoundingToken::Cbe) {
        eprintln!(
            "NOTE: CBE founding via TokenCreation requires retiring block-0 CBE treasury seed (GENESIS-6 #2734)."
        );
        eprintln!(
            "      Until executor migration lands, block 0 still seeds {} CBE atoms to the fee sink.",
            lib_blockchain::contracts::bonding_curve::canonical::GENESIS_TREASURY_ALLOCATION
        );
    }

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bubl_token_id_is_deterministic() {
        let a = lib_blockchain::contracts::utils::generate_custom_token_id(
            BUBL_TOKEN_NAME,
            BUBL_TOKEN_SYMBOL,
        );
        let b = lib_blockchain::contracts::utils::generate_custom_token_id(
            BUBL_TOKEN_NAME,
            BUBL_TOKEN_SYMBOL,
        );
        assert_eq!(a, b);
    }
}