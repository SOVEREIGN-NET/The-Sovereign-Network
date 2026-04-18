//! Standalone tool to register a gateway node on-chain.
//!
//! Usage:
//!   register_gateway --identity-dir /root/.zhtp/keystore \
//!                    --endpoint 91.98.113.188:7840 \
//!                    --stake 10000 \
//!                    --validator 77.42.37.161:9334

use anyhow::{Context, Result};
use std::path::PathBuf;

fn main() -> Result<()> {
    let args = parse_args();

    // Load identity
    let identity_path = args.identity_dir.join("daemon_identity.json");
    let private_key_path = args.identity_dir.join("daemon_private_key.json");

    let identity_json = std::fs::read_to_string(&identity_path)
        .with_context(|| format!("Failed to read {}", identity_path.display()))?;
    let key_json = std::fs::read_to_string(&private_key_path)
        .with_context(|| format!("Failed to read {}", private_key_path.display()))?;

    let stored_key: zhtp_daemon::identity::StoredPrivateKey = serde_json::from_str(&key_json)
        .context("Failed to parse private key")?;
    let private_key = lib_crypto::types::PrivateKey::try_from(stored_key)
        .context("Failed to decode private key")?;

    let identity = lib_identity::ZhtpIdentity::from_serialized(&identity_json, &private_key)
        .context("Failed to restore identity")?;

    println!("Identity loaded: {}", identity.did);

    // Build gateway registration transaction
    let gateway_key = identity.public_key.dilithium_pk;
    if gateway_key.len() != 2592 {
        anyhow::bail!("Gateway key must be 2592 bytes (Dilithium5), got {}", gateway_key.len());
    }

    let gateway_data = lib_blockchain::transaction::GatewayTransactionData {
        identity_id: identity.did.clone(),
        stake: args.stake,
        gateway_key: gateway_key.to_vec(),
        endpoints: args.endpoint,
        commission_rate: args.commission_rate,
        operation: lib_blockchain::transaction::GatewayOperation::Register,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    };

    let signature = lib_crypto::sign_message(
        &private_key,
        format!("gateway_register:{}", identity.did).as_bytes(),
    )
    .context("Failed to sign registration")?;

    let tx = lib_blockchain::transaction::Transaction::new_gateway_registration(
        gateway_data,
        vec![], // outputs — stake locking would go here
        lib_blockchain::transaction::Signature {
            signature: signature.signature.clone(),
            public_key: lib_crypto::PublicKey::new(identity.public_key.dilithium_pk),
            algorithm: lib_blockchain::transaction::SignatureAlgorithm::DEFAULT,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        },
        format!("Gateway registration for {}", identity.did).into_bytes(),
    );

    println!("Transaction created: hash={}", hex::encode(tx.hash().as_bytes()));
    println!("Broadcasting to validator {}...", args.validator);

    // TODO: Broadcast via Web4Client to validator
    // For now, just serialize and print
    let tx_bytes = bincode::serialize(&tx).context("Failed to serialize transaction")?;
    println!("Transaction bytes ({} bytes): {}", tx_bytes.len(), hex::encode(&tx_bytes));

    Ok(())
}

#[derive(Debug)]
struct Args {
    identity_dir: PathBuf,
    endpoint: String,
    stake: u64,
    commission_rate: u8,
    validator: String,
}

fn parse_args() -> Args {
    let mut identity_dir = PathBuf::from(".");
    let mut endpoint = String::new();
    let mut stake = 10_000u64;
    let mut commission_rate = 5u8;
    let mut validator = String::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--identity-dir" => identity_dir = PathBuf::from(args.next().expect("--identity-dir requires a value")),
            "--endpoint" => endpoint = args.next().expect("--endpoint requires a value"),
            "--stake" => stake = args.next().expect("--stake requires a value").parse().expect("invalid number"),
            "--commission-rate" => commission_rate = args.next().expect("--commission-rate requires a value").parse().expect("invalid number"),
            "--validator" => validator = args.next().expect("--validator requires a value"),
            _ => {}
        }
    }

    if endpoint.is_empty() {
        eprintln!("Usage: register_gateway --identity-dir <dir> --endpoint <host:port> --validator <host:port> [--stake <micro-SOV>] [--commission-rate <0-100>]");
        std::process::exit(1);
    }
    if validator.is_empty() {
        eprintln!("Usage: register_gateway --identity-dir <dir> --endpoint <host:port> --validator <host:port> [--stake <micro-SOV>] [--commission-rate <0-100>]");
        std::process::exit(1);
    }

    Args { identity_dir, endpoint, stake, commission_rate, validator }
}
