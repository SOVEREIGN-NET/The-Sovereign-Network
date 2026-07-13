//! Sovereign asset governance CLI (DAO C5 #2820).
//!
//! - `dao governance propose` — build a rewards policy update proposal (CID/hash)
//! - `dao governance vote` — collect multisig approvals and optionally submit
//! - `dao governance status` — pending authority transfer / rewards policy timelocks

use crate::argument_parsing::{format_output, DaoGovernanceAction, ZhtpCli};
use crate::commands::rewards::{
    apply_asset_id_to_policy, build_rewards_policy_bundle, load_policy_bytes_from_file,
    normalize_asset_id_hex,
};
use crate::commands::transaction_utils::{broadcast_signed_tx, parse_hex_32};
use crate::commands::web4_utils::{connect_default, default_keystore_path, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::contracts::approval_verifier::traits::Signature64;
use lib_blockchain::contracts::approval_verifier::ApprovalProof;
use lib_blockchain::transaction::asset_tx::{
    AssetAuthorityProof, AssetRewardsPolicyUpdatePayloadV1, RewardsPolicyUpdateConfig,
};
use lib_blockchain::Transaction;
use lib_crypto::keypair::KeyPair;
use lib_network::client::ZhtpClient;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const PROPOSAL_SCHEMA: &str = "zhtp/governance-proposal/v1";
const PROPOSAL_TYPE_REWARDS_POLICY_UPDATE: &str = "rewards_policy_update";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceApproval {
    pub signer_key_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GovernanceProposal {
    pub schema: String,
    pub proposal_id: String,
    pub proposal_type: String,
    pub asset_id: String,
    pub policy_cid: String,
    pub policy_hash: String,
    pub message_hash: String,
    pub policy_document_hex: String,
    pub threshold: u8,
    #[serde(default)]
    pub signers: Vec<String>,
    #[serde(default)]
    pub approvals: Vec<GovernanceApproval>,
}

pub fn parse_proposal_type(value: &str) -> CliResult<&'static str> {
    match value.to_ascii_lowercase().as_str() {
        "rewards_policy_update" | "rewards-policy-update" => {
            Ok(PROPOSAL_TYPE_REWARDS_POLICY_UPDATE)
        }
        other => Err(CliError::ConfigError(format!(
            "unsupported proposal type '{other}'; supported: rewards_policy_update"
        ))),
    }
}

pub fn governance_message_hash(
    asset_id: &[u8; 32],
    proposal_type: &str,
    policy_hash: &[u8; 32],
) -> [u8; 32] {
    lib_crypto::hash_blake3(
        &[
            b"zhtp/governance-proposal/v1\0",
            proposal_type.as_bytes(),
            asset_id.as_slice(),
            policy_hash.as_slice(),
        ]
        .concat(),
    )
}

pub fn build_rewards_policy_update_proposal(
    asset_id: &str,
    policy_file: &Path,
) -> CliResult<GovernanceProposal> {
    let asset_id_norm = normalize_asset_id_hex(asset_id).map_err(CliError::ConfigError)?;
    let asset_id_bytes = parse_hex_32("asset_id", &asset_id_norm)?;

    let policy_bytes = load_policy_bytes_from_file(policy_file)?;
    let policy = lib_blockchain::rewards_policy::validate_rewards_policy(&policy_bytes)
        .map_err(|e| CliError::ConfigError(format!("rewards policy: {e}")))?;
    let policy = apply_asset_id_to_policy(policy, &asset_id_norm)?;
    let bundle = build_rewards_policy_bundle(&policy)
        .map_err(|e| CliError::ConfigError(format!("rewards policy: {e}")))?;

    let message_hash = governance_message_hash(
        &asset_id_bytes,
        PROPOSAL_TYPE_REWARDS_POLICY_UPDATE,
        &bundle.policy_hash,
    );

    Ok(GovernanceProposal {
        schema: PROPOSAL_SCHEMA.to_string(),
        proposal_id: hex::encode(message_hash),
        proposal_type: PROPOSAL_TYPE_REWARDS_POLICY_UPDATE.to_string(),
        asset_id: asset_id_norm,
        policy_cid: hex::encode(bundle.policy_cid),
        policy_hash: hex::encode(bundle.policy_hash),
        message_hash: hex::encode(message_hash),
        policy_document_hex: hex::encode(&bundle.document_bytes),
        threshold: 1,
        signers: Vec::new(),
        approvals: Vec::new(),
    })
}

fn parse_governance_approval_pairs(raw: &[String]) -> CliResult<Vec<([u8; 32], Vec<u8>)>> {
    raw.iter()
        .map(|s| {
            let (key_hex, sig_hex) = s.split_once(':').ok_or_else(|| {
                CliError::ConfigError(format!("--approval must be <key_id_hex>:<sig_hex>, got: {s}"))
            })?;
            let key_id = parse_hex_32("approval key_id", key_hex)?;
            let sig = hex::decode(sig_hex.strip_prefix("0x").unwrap_or(sig_hex))
                .map_err(|_| CliError::ConfigError(format!("invalid approval signature hex: {sig_hex}")))?;
            Ok((key_id, sig))
        })
        .collect()
}

fn signature64_from_dilithium(sig: &[u8]) -> Signature64 {
    let h1 = lib_crypto::hash_blake3(sig);
    let h2 = lib_crypto::hash_blake3(&[h1.as_slice(), b"sig64"].concat());
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&h1);
    out[32..].copy_from_slice(&h2);
    Signature64::new(out)
}

fn merge_approvals(
    proposal: &mut GovernanceProposal,
    pairs: Vec<([u8; 32], Vec<u8>)>,
) -> CliResult<()> {
    for (key_id, sig) in pairs {
        let key_hex = hex::encode(key_id);
        if proposal.approvals.iter().any(|a| a.signer_key_id == key_hex) {
            return Err(CliError::ConfigError(format!(
                "duplicate approval for signer {key_hex}"
            )));
        }
        proposal.approvals.push(GovernanceApproval {
            signer_key_id: key_hex,
            signature_hex: hex::encode(sig),
        });
    }
    Ok(())
}

fn sign_proposal_with_keypair(
    proposal: &mut GovernanceProposal,
    keypair: &KeyPair,
) -> CliResult<()> {
    let message_hash = parse_hex_32("message_hash", &proposal.message_hash)?;
    let key_hex = hex::encode(keypair.public_key.key_id);
    if proposal.approvals.iter().any(|a| a.signer_key_id == key_hex) {
        return Err(CliError::ConfigError(format!(
            "keystore already approved as {key_hex}"
        )));
    }
    let sig = keypair
        .sign(&message_hash)
        .map_err(|e| CliError::ConfigError(format!("failed to sign proposal: {e}")))?;
    proposal.approvals.push(GovernanceApproval {
        signer_key_id: key_hex,
        signature_hex: hex::encode(sig.signature),
    });
    Ok(())
}

fn enrich_proposal_from_asset_detail(proposal: &mut GovernanceProposal, asset: &Value) -> CliResult<()> {
    let gov_status = asset
        .get("governance_status")
        .ok_or_else(|| CliError::ConfigError("asset response missing governance_status".into()))?;
    if let Some(verifier) = gov_status.get("verifier") {
        if let Some(threshold) = verifier.get("threshold").and_then(|v| v.as_u64()) {
            proposal.threshold = threshold as u8;
        }
        if let Some(signers) = verifier.get("signers").and_then(|v| v.as_array()) {
            proposal.signers = signers
                .iter()
                .filter_map(|s| s.as_str().map(str::to_string))
                .collect();
        }
    }
    Ok(())
}

fn build_policy_update_tx(
    proposal: &GovernanceProposal,
    keypair: &KeyPair,
    chain_id: u8,
    use_governance_proof: bool,
) -> CliResult<Transaction> {
    let asset_id = parse_hex_32("asset_id", &proposal.asset_id)?;
    let policy_cid = parse_hex_32("policy_cid", &proposal.policy_cid)?;
    let policy_hash = parse_hex_32("policy_hash", &proposal.policy_hash)?;
    let message_hash = parse_hex_32("message_hash", &proposal.message_hash)?;
    let policy_document = hex::decode(&proposal.policy_document_hex)
        .map_err(|e| CliError::ConfigError(format!("invalid policy_document_hex: {e}")))?;

    let authority_proof = if use_governance_proof {
        if proposal.approvals.len() < proposal.threshold as usize {
            return Err(CliError::ConfigError(format!(
                "need {} approvals, have {}",
                proposal.threshold,
                proposal.approvals.len()
            )));
        }
        let mut signers = Vec::new();
        let mut signatures = Vec::new();
        for approval in &proposal.approvals {
            let key_id = parse_hex_32("signer", &approval.signer_key_id)?;
            let sig_bytes = hex::decode(&approval.signature_hex)
                .map_err(|e| CliError::ConfigError(format!("invalid approval sig: {e}")))?;
            signers.push(key_id);
            signatures.push(signature64_from_dilithium(&sig_bytes));
        }
        AssetAuthorityProof::Governance(ApprovalProof::Multisig {
            signatures,
            signers,
            threshold: proposal.threshold,
            message_hash,
        })
    } else {
        AssetAuthorityProof::CreatorSig
    };

    let payload = AssetRewardsPolicyUpdatePayloadV1 {
        asset_id,
        policy: RewardsPolicyUpdateConfig {
            policy_cid,
            policy_hash,
            policy_document: Some(policy_document),
        },
        authority_proof,
    };
    let memo = payload
        .encode_memo()
        .map_err(|e| CliError::ConfigError(format!("encode policy update payload: {e}")))?;

    let mut tx = Transaction::new_asset_rewards_policy_update_with_chain_id(
        chain_id,
        lib_crypto::Signature::default(),
        memo,
    );
    tx.signature = keypair
        .sign(tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("sign policy update tx: {e}")))?;
    Ok(tx)
}

async fn fetch_asset_detail(client: &ZhtpClient, asset_id: &str) -> CliResult<Value> {
    let endpoint = format!("/api/v1/assets/{}", asset_id.trim_start_matches("0x"));
    let response = client.get(&endpoint).await.map_err(|e| CliError::ApiCallFailed {
        endpoint: endpoint.clone(),
        status: 0,
        reason: e.to_string(),
    })?;
    ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint,
        status: 0,
        reason: format!("Failed to parse asset detail: {e}"),
    })
}

pub async fn handle_dao_governance_command(
    action: DaoGovernanceAction,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    match action {
        DaoGovernanceAction::Propose {
            asset_id,
            proposal_type,
            policy_file,
            out,
        } => {
            let ty = parse_proposal_type(&proposal_type)?;
            if ty != PROPOSAL_TYPE_REWARDS_POLICY_UPDATE {
                return Err(CliError::ConfigError(format!(
                    "proposal type '{ty}' not implemented"
                )));
            }
            output.header("Governance Proposal (rewards_policy_update)")?;
            let mut proposal =
                build_rewards_policy_update_proposal(&asset_id, Path::new(&policy_file))?;

            let client = connect_default(&cli.server).await?;
            if let Ok(asset) = fetch_asset_detail(&client, &proposal.asset_id).await {
                enrich_proposal_from_asset_detail(&mut proposal, &asset)?;
            }

            let formatted = format_output(&serde_json::to_value(&proposal)?, &cli.format)?;
            output.print(&formatted)?;

            if let Some(path) = out {
                let bytes = serde_json::to_vec_pretty(&proposal)
                    .map_err(|e| CliError::ConfigError(format!("serialize proposal: {e}")))?;
                std::fs::write(&path, bytes).map_err(|e| {
                    CliError::ConfigError(format!("write {}: {e}", path.display()))
                })?;
                output.info(&format!("Proposal written to {}", path.display()))?;
            }
            output.success("Proposal ready — share message_hash with signers; run `dao governance vote`.")?;
            Ok(())
        }
        DaoGovernanceAction::Vote {
            proposal_file,
            keystore,
            approvals,
            submit,
            chain_id,
        } => {
            output.header("Governance Vote")?;
            let bytes = std::fs::read(&proposal_file).map_err(|e| {
                CliError::ConfigError(format!("read {}: {e}", proposal_file.display()))
            })?;
            let mut proposal: GovernanceProposal = serde_json::from_slice(&bytes)
                .map_err(|e| CliError::ConfigError(format!("invalid proposal file: {e}")))?;
            if proposal.schema != PROPOSAL_SCHEMA {
                return Err(CliError::ConfigError(format!(
                    "proposal schema must be {PROPOSAL_SCHEMA}"
                )));
            }

            let client = connect_default(&cli.server).await?;
            let asset_id = proposal.asset_id.clone();
            let asset = fetch_asset_detail(&client, &asset_id).await?;
            enrich_proposal_from_asset_detail(&mut proposal, &asset)?;

            if !approvals.is_empty() {
                merge_approvals(&mut proposal, parse_governance_approval_pairs(&approvals)?)?;
            }

            let keystore_dir = match keystore {
                Some(path) => PathBuf::from(path),
                None => default_keystore_path()?,
            };
            let loaded = load_identity_from_keystore(&keystore_dir)?;
            sign_proposal_with_keypair(&mut proposal, &loaded.keypair)?;

            output.info(&format!(
                "Approvals: {}/{} (threshold {})",
                proposal.approvals.len(),
                proposal.signers.len().max(proposal.threshold as usize),
                proposal.threshold
            ))?;

            if submit {
                let asset = fetch_asset_detail(&client, &proposal.asset_id).await?;
                let authority_kind = asset
                    .get("governance_status")
                    .and_then(|g| g.get("authority"))
                    .and_then(|a| a.get("kind"))
                    .and_then(|k| k.as_str())
                    .unwrap_or("creator");
                let use_governance = authority_kind == "governance";
                let tx = build_policy_update_tx(
                    &proposal,
                    &loaded.keypair,
                    chain_id,
                    use_governance,
                )?;
                let result = broadcast_signed_tx(&client, &tx).await?;
                output.print(&format!("Signed tx hash: {}", tx.hash()))?;
                output.print(&format_output(&result, &cli.format)?)?;
                output.success("Rewards policy update submitted.")?;
            } else {
                std::fs::write(
                    &proposal_file,
                    serde_json::to_vec_pretty(&proposal)
                        .map_err(|e| CliError::ConfigError(format!("serialize proposal: {e}")))?,
                )
                .map_err(|e| {
                    CliError::ConfigError(format!("write {}: {e}", proposal_file.display()))
                })?;
                output.info(&format!(
                    "Updated proposal saved to {} (re-run with --submit when threshold met)",
                    proposal_file.display()
                ))?;
            }
            Ok(())
        }
        DaoGovernanceAction::Status { asset_id } => {
            output.header("Governance Status")?;
            let client = connect_default(&cli.server).await?;
            let asset = fetch_asset_detail(&client, &asset_id).await?;
            let status = asset
                .get("governance_status")
                .cloned()
                .unwrap_or(json!({}));
            output.print(&format_output(&status, &cli.format)?)?;
            if let Some(pending) = status.get("pending_authority_transfer") {
                if let Some(remaining) = pending.get("blocks_remaining").and_then(|v| v.as_u64()) {
                    output.info(&format!(
                        "Authority transfer timelock: {remaining} blocks remaining"
                    ))?;
                }
            }
            if let Some(pending) = status.get("pending_rewards_policy") {
                if let Some(remaining) = pending.get("blocks_remaining").and_then(|v| v.as_u64()) {
                    output.info(&format!(
                        "Rewards policy decrease timelock: {remaining} blocks remaining"
                    ))?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_proposal_type_accepts_aliases() {
        assert_eq!(
            parse_proposal_type("rewards_policy_update").unwrap(),
            PROPOSAL_TYPE_REWARDS_POLICY_UPDATE
        );
        assert_eq!(
            parse_proposal_type("rewards-policy-update").unwrap(),
            PROPOSAL_TYPE_REWARDS_POLICY_UPDATE
        );
        assert!(parse_proposal_type("manifest_update").is_err());
    }

    #[test]
    fn governance_message_hash_is_deterministic() {
        let asset_id = [0xab; 32];
        let policy_hash = [0xcd; 32];
        let h1 = governance_message_hash(&asset_id, PROPOSAL_TYPE_REWARDS_POLICY_UPDATE, &policy_hash);
        let h2 = governance_message_hash(&asset_id, PROPOSAL_TYPE_REWARDS_POLICY_UPDATE, &policy_hash);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    #[test]
    fn merge_approvals_rejects_duplicate_signer() {
        let mut proposal = GovernanceProposal {
            schema: PROPOSAL_SCHEMA.to_string(),
            proposal_id: "00".repeat(32),
            proposal_type: PROPOSAL_TYPE_REWARDS_POLICY_UPDATE.to_string(),
            asset_id: "11".repeat(32),
            policy_cid: "22".repeat(32),
            policy_hash: "33".repeat(32),
            message_hash: "44".repeat(32),
            policy_document_hex: "7b7d".to_string(),
            threshold: 2,
            signers: vec![],
            approvals: vec![GovernanceApproval {
                signer_key_id: "aa".repeat(32),
                signature_hex: "bb".to_string(),
            }],
        };
        let key = parse_hex_32("k", &"aa".repeat(32)).unwrap();
        assert!(merge_approvals(&mut proposal, vec![(key, vec![1, 2])]).is_err());
    }
}