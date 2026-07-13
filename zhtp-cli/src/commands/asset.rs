//! Sovereign asset CLI commands (DAO Launch C4 #2819).
//!
//! ## Authority paths
//!
//! **Pre-handoff (creator authority):** While `SovereignAsset.authority` is still
//! `Creator`, privileged rewards operations — including delegate rotation — are
//! signed by the creator keystore with `AssetAuthorityProof::CreatorSig`. This CLI
//! implements that path.
//!
//! **Post-handoff (governance authority):** After `AssetAuthorityTransfer` moves
//! authority to `Governance`, delegate rotation requires `AssetAuthorityProof::Governance`
//! (multisig approval). That path is not exposed here yet; use governance tooling
//! when the asset has completed authority transfer.

use crate::argument_parsing::{format_output, AssetRewardsAction, AssetRewardsArgs, ZhtpCli};
use crate::commands::node::normalize_keystore_path;
use crate::commands::transaction_utils::broadcast_signed_tx;
use crate::commands::web4_utils::{connect_default, default_keystore_path, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::transaction::asset_tx::{
    AssetAuthorityProof, AssetRewardsDelegateRotatePayloadV1,
};
use lib_blockchain::transaction::TokenTransferData;
use lib_blockchain::Transaction;
use lib_crypto::keypair::KeyPair;
use lib_network::client::ZhtpClient;
use std::path::Path;

fn resolve_keystore_dir(keystore: Option<&str>) -> CliResult<std::path::PathBuf> {
    match keystore {
        Some(path) => normalize_keystore_path(path)
            .ok_or_else(|| CliError::ConfigError(format!("invalid keystore path: {path}"))),
        None => default_keystore_path(),
    }
}

fn load_keypair_from_keystore_dir(dir: &Path) -> CliResult<KeyPair> {
    let loaded = load_identity_from_keystore(dir)?;
    Ok(loaded.keypair)
}

fn parse_asset_id(asset_id: &str) -> CliResult<[u8; 32]> {
    zhtp::rewards_activation::parse_asset_id_hex(asset_id)
        .map_err(|e| CliError::ConfigError(format!("invalid --asset-id: {e}")))
}

fn build_signed_delegate_rotate_tx(
    keypair: &KeyPair,
    chain_id: u8,
    asset_id: [u8; 32],
    new_delegate_key_id: [u8; 32],
) -> CliResult<Transaction> {
    if new_delegate_key_id == [0u8; 32] {
        return Err(CliError::ConfigError(
            "new delegate key_id must be non-zero".to_string(),
        ));
    }

    let payload = AssetRewardsDelegateRotatePayloadV1 {
        asset_id,
        new_delegate_key_id,
        authority_proof: AssetAuthorityProof::CreatorSig,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| CliError::ConfigError(format!("encode delegate rotate payload: {e}")))?;

    let mut tx = Transaction::new_asset_rewards_delegate_rotate_with_chain_id(
        chain_id,
        lib_crypto::Signature::default(),
        memo,
    );
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("sign delegate rotate tx: {e}")))?;
    Ok(tx)
}

fn build_signed_fund_delegate_tx(
    keypair: &KeyPair,
    chain_id: u8,
    asset_id: [u8; 32],
    delegate_key_id: [u8; 32],
    amount: u128,
    nonce: u64,
) -> CliResult<Transaction> {
    if amount == 0 {
        return Err(CliError::ConfigError("--amount must be non-zero".to_string()));
    }
    if delegate_key_id == [0u8; 32] {
        return Err(CliError::ConfigError(
            "delegate key_id must be non-zero".to_string(),
        ));
    }

    let transfer_data = TokenTransferData {
        token_id: asset_id,
        from: keypair.public_key.key_id,
        to: delegate_key_id,
        amount,
        nonce,
    };

    let mut tx = Transaction::new_token_transfer_with_chain_id(
        chain_id,
        transfer_data,
        lib_crypto::Signature::default(),
        b"token:transfer:v1".to_vec(),
    );
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("sign fund-delegate transfer: {e}")))?;
    Ok(tx)
}

async fn fetch_token_nonce(
    client: &ZhtpClient,
    token_id: &[u8; 32],
    holder_key_id: &[u8; 32],
) -> CliResult<u64> {
    let path = format!(
        "/api/v1/token/{}/nonce/{}",
        hex::encode(token_id),
        hex::encode(holder_key_id)
    );
    let response = client.get(&path).await.map_err(|e| CliError::ApiCallFailed {
        endpoint: path.clone(),
        status: 0,
        reason: e.to_string(),
    })?;
    let json: serde_json::Value = ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint: path.clone(),
        status: 0,
        reason: format!("parse nonce response: {e}"),
    })?;
    json.get("nonce")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| CliError::ApiCallFailed {
            endpoint: path,
            status: 0,
            reason: "missing or invalid nonce in response".to_string(),
        })
}

pub async fn handle_asset_command(args: crate::argument_parsing::AssetArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_asset_command_impl(args, cli, &output).await
}

async fn handle_asset_command_impl(
    args: crate::argument_parsing::AssetArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        crate::argument_parsing::AssetAction::Rewards(rewards_args) => {
            handle_asset_rewards_command_impl(rewards_args, cli, output).await
        }
    }
}

async fn handle_asset_rewards_command_impl(
    args: AssetRewardsArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match args.action {
        AssetRewardsAction::RotateDelegate {
            asset_id,
            new_keystore,
            keystore,
            chain_id,
        } => {
            handle_rotate_delegate(cli, output, &asset_id, &new_keystore, keystore.as_deref(), chain_id)
                .await
        }
        AssetRewardsAction::FundDelegate {
            asset_id,
            amount,
            delegate_keystore,
            keystore,
            chain_id,
        } => {
            handle_fund_delegate(
                cli,
                output,
                &asset_id,
                amount,
                &delegate_keystore,
                keystore.as_deref(),
                chain_id,
            )
            .await
        }
    }
}

async fn handle_rotate_delegate(
    cli: &ZhtpCli,
    output: &dyn Output,
    asset_id: &str,
    new_keystore: &str,
    creator_keystore: Option<&str>,
    chain_id: u8,
) -> CliResult<()> {
    output.header("Rotate Rewards Spend Delegate")?;
    output.info(
        "Pre-handoff path: creator signs AssetRewardsDelegateRotate with CreatorSig.",
    )?;
    output.info(
        "Post-handoff (governance authority) requires GovernanceProof — not supported by this command.",
    )?;

    let asset_id_bytes = parse_asset_id(asset_id)?;
    let new_keystore_dir = resolve_keystore_dir(Some(new_keystore))?;
    if !new_keystore_dir.is_dir() {
        return Err(CliError::ConfigError(format!(
            "--new-keystore is not a directory: {}",
            new_keystore_dir.display()
        )));
    }
    let new_delegate = load_keypair_from_keystore_dir(&new_keystore_dir)?;
    let creator_dir = resolve_keystore_dir(creator_keystore)?;
    let creator = load_keypair_from_keystore_dir(&creator_dir)?;

    let tx = build_signed_delegate_rotate_tx(
        &creator,
        chain_id,
        asset_id_bytes,
        new_delegate.public_key.key_id,
    )?;
    let tx_hash = tx.hash();

    let client = connect_default(&cli.server).await?;
    let result = broadcast_signed_tx(&client, &tx).await?;

    output.print(&format!("Signed tx hash: {tx_hash}"))?;
    output.print(&format!(
        "New delegate key_id: {}",
        hex::encode(new_delegate.public_key.key_id)
    ))?;
    output.print(&format_output(&result, &cli.format)?)?;
    output.success("Delegate rotation broadcast submitted.")?;
    Ok(())
}

async fn handle_fund_delegate(
    cli: &ZhtpCli,
    output: &dyn Output,
    asset_id: &str,
    amount: u128,
    delegate_keystore: &str,
    creator_keystore: Option<&str>,
    chain_id: u8,
) -> CliResult<()> {
    output.header("Fund Rewards Spend Delegate")?;
    output.info(&format!(
        "Transferring {amount} token atoms from creator to delegate (token_id = asset_id)."
    ))?;

    let asset_id_bytes = parse_asset_id(asset_id)?;
    let delegate_dir = resolve_keystore_dir(Some(delegate_keystore))?;
    if !delegate_dir.is_dir() {
        return Err(CliError::ConfigError(format!(
            "--delegate-keystore is not a directory: {}",
            delegate_dir.display()
        )));
    }
    let delegate = load_keypair_from_keystore_dir(&delegate_dir)?;
    let creator_dir = resolve_keystore_dir(creator_keystore)?;
    let creator = load_keypair_from_keystore_dir(&creator_dir)?;

    if creator.public_key.key_id == delegate.public_key.key_id {
        return Err(CliError::ConfigError(
            "creator and delegate keystores must differ".to_string(),
        ));
    }

    let client = connect_default(&cli.server).await?;
    let nonce =
        fetch_token_nonce(&client, &asset_id_bytes, &creator.public_key.key_id).await?;
    output.info(&format!("Using transfer nonce: {nonce}"))?;

    let tx = build_signed_fund_delegate_tx(
        &creator,
        chain_id,
        asset_id_bytes,
        delegate.public_key.key_id,
        amount,
        nonce,
    )?;
    let tx_hash = tx.hash();
    let result = broadcast_signed_tx(&client, &tx).await?;

    output.print(&format!("Signed tx hash: {tx_hash}"))?;
    output.print(&format!(
        "Delegate key_id: {}",
        hex::encode(delegate.public_key.key_id)
    ))?;
    output.print(&format_output(&result, &cli.format)?)?;
    output.success("Fund-delegate transfer broadcast submitted.")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_delegate_rotate_tx_encodes_creator_proof() {
        let keypair = KeyPair::generate().expect("keypair");
        let new_delegate = KeyPair::generate().expect("delegate");
        let asset_id = [7u8; 32];
        let tx = build_signed_delegate_rotate_tx(
            &keypair,
            0x03,
            asset_id,
            new_delegate.public_key.key_id,
        )
        .expect("tx");

        assert_eq!(tx.transaction_type, lib_blockchain::types::TransactionType::AssetRewardsDelegateRotate);
        let payload = AssetRewardsDelegateRotatePayloadV1::decode_memo(&tx.memo).expect("memo");
        assert_eq!(payload.asset_id, asset_id);
        assert_eq!(payload.new_delegate_key_id, new_delegate.public_key.key_id);
        assert_eq!(payload.authority_proof, AssetAuthorityProof::CreatorSig);
    }

    #[test]
    fn build_fund_delegate_tx_uses_asset_id_as_token_id() {
        let creator = KeyPair::generate().expect("creator");
        let delegate = KeyPair::generate().expect("delegate");
        let asset_id = [9u8; 32];
        let tx = build_signed_fund_delegate_tx(
            &creator,
            0x02,
            asset_id,
            delegate.public_key.key_id,
            1_000_000,
            0,
        )
        .expect("tx");

        let transfer = match &tx.payload {
            lib_blockchain::transaction::TransactionPayload::TokenTransfer(data) => data.clone(),
            _ => panic!("expected TokenTransfer payload"),
        };
        assert_eq!(transfer.token_id, asset_id);
        assert_eq!(transfer.from, creator.public_key.key_id);
        assert_eq!(transfer.to, delegate.public_key.key_id);
        assert_eq!(transfer.amount, 1_000_000);
    }

    #[test]
    fn parse_asset_id_rejects_short_hex() {
        assert!(parse_asset_id("abcd").is_err());
    }

    #[test]
    fn build_delegate_rotate_rejects_zero_delegate() {
        let keypair = KeyPair::generate().expect("keypair");
        let err = build_signed_delegate_rotate_tx(&keypair, 0x03, [1u8; 32], [0u8; 32])
            .expect_err("zero delegate");
        assert!(err.to_string().contains("non-zero"));
    }
}