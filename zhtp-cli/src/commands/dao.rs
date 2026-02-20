//! DAO commands for ZHTP orchestrator
//!
//! Architecture: Functional Core, Imperative Shell (FCIS)

use crate::argument_parsing::{DaoAction, DaoArgs, ZhtpCli, format_output};
use crate::commands::transaction_utils::{broadcast_signed_tx, parse_hex_32};
use crate::commands::web4_utils::{connect_default, default_keystore_path, load_identity_from_keystore};
use crate::error::{CliError, CliResult};
use crate::output::Output;
use lib_blockchain::contracts::derive_dao_id;
use lib_blockchain::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
use lib_blockchain::transaction::DaoExecutionData;
use lib_blockchain::types::Hash as BcHash;
use lib_blockchain::types::dao::DAOType;
use lib_blockchain::Transaction;
use lib_network::client::ZhtpClient;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaoOperation {
    Info,
    Propose,
    Vote,
    Balance,
    RegistryList,
    RegistryGet,
}

impl DaoOperation {
    pub fn description(&self) -> &'static str {
        match self {
            DaoOperation::Info => "Get DAO information",
            DaoOperation::Propose => "Create proposal",
            DaoOperation::Vote => "Vote on proposal",
            DaoOperation::Balance => "Get DAO treasury balance",
            DaoOperation::RegistryList => "List DAO registry entries",
            DaoOperation::RegistryGet => "Get DAO registry entry",
        }
    }

    pub fn method(&self) -> &'static str {
        match self {
            DaoOperation::Info | DaoOperation::Balance | DaoOperation::RegistryList | DaoOperation::RegistryGet => "GET",
            DaoOperation::Propose | DaoOperation::Vote => "POST",
        }
    }

    pub fn endpoint_path(&self) -> &'static str {
        match self {
            DaoOperation::Info => "/api/v1/dao/data",
            DaoOperation::Propose => "/api/v1/dao/proposal/create",
            DaoOperation::Vote => "/api/v1/dao/vote/cast",
            DaoOperation::Balance => "/api/v1/dao/treasury/status",
            DaoOperation::RegistryList => "/api/v1/dao/registry/list",
            DaoOperation::RegistryGet => "/api/v1/dao/registry",
        }
    }

    pub fn title(&self) -> &'static str {
        match self {
            DaoOperation::Info => "DAO Information",
            DaoOperation::Propose => "Proposal Creation",
            DaoOperation::Vote => "Vote Submission",
            DaoOperation::Balance => "Treasury Status",
            DaoOperation::RegistryList => "DAO Registry",
            DaoOperation::RegistryGet => "DAO Registry Entry",
        }
    }
}

pub fn action_to_operation(action: &DaoAction) -> Option<DaoOperation> {
    match action {
        DaoAction::Info => Some(DaoOperation::Info),
        DaoAction::Propose { .. } => Some(DaoOperation::Propose),
        DaoAction::Vote { .. } => Some(DaoOperation::Vote),
        DaoAction::Balance | DaoAction::TreasuryBalance => Some(DaoOperation::Balance),
        DaoAction::RegistryList => Some(DaoOperation::RegistryList),
        DaoAction::RegistryGet { .. } => Some(DaoOperation::RegistryGet),
        DaoAction::RegistryRegister { .. } | DaoAction::FactoryCreate { .. } => None,
    }
}

pub fn validate_proposal_id(id: &str) -> CliResult<()> {
    if id.is_empty() {
        return Err(CliError::ConfigError("Proposal ID cannot be empty".to_string()));
    }
    if !id.chars().all(|c| c.is_alphanumeric() || c == '-') {
        return Err(CliError::ConfigError(format!(
            "Invalid proposal ID: {}. Use only alphanumeric characters and hyphens",
            id
        )));
    }
    Ok(())
}

pub fn validate_vote_choice(choice: &str) -> CliResult<()> {
    let lower = choice.to_lowercase();
    if !["yes", "no", "abstain"].contains(&lower.as_str()) {
        return Err(CliError::ConfigError(format!(
            "Invalid vote choice: {}. Must be 'yes', 'no', or 'abstain'",
            choice
        )));
    }
    Ok(())
}

pub fn validate_proposal_title(title: &str) -> CliResult<()> {
    if title.is_empty() {
        return Err(CliError::ConfigError("Proposal title cannot be empty".to_string()));
    }
    if title.len() > 255 {
        return Err(CliError::ConfigError(format!(
            "Proposal title too long: {} (max 255 characters)",
            title.len()
        )));
    }
    Ok(())
}

fn parse_dao_class(value: &str) -> CliResult<DAOType> {
    let normalized = value.trim().to_ascii_lowercase();
    if let Some(class) = DAOType::from_str(&normalized) {
        return Ok(class);
    }

    match normalized.as_str() {
        "nonprofit" => Ok(DAOType::NP),
        "forprofit" => Ok(DAOType::FP),
        _ => Err(CliError::ConfigError(
            "Invalid DAO class. Use one of: np, non_profit, non-profit, nonprofit, fp, for_profit, for-profit, forprofit"
                .to_string(),
        )),
    }
}

fn build_request_body(
    operation: DaoOperation,
    title: Option<&str>,
    description: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
) -> Value {
    match operation {
        DaoOperation::Info | DaoOperation::Balance | DaoOperation::RegistryList | DaoOperation::RegistryGet => json!({}),
        DaoOperation::Propose => json!({
            "title": title,
            "description": description,
            "orchestrated": true
        }),
        DaoOperation::Vote => json!({
            "proposal_id": proposal_id,
            "choice": choice,
            "orchestrated": true
        }),
    }
}

pub fn get_operation_message(
    operation: DaoOperation,
    title: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
) -> String {
    match operation {
        DaoOperation::Info => "Fetching DAO information...".to_string(),
        DaoOperation::Propose => format!("Creating proposal: {}", title.unwrap_or("unknown")),
        DaoOperation::Vote => format!(
            "Submitting vote: {} on proposal {}",
            choice.unwrap_or("unknown"),
            proposal_id.unwrap_or("unknown")
        ),
        DaoOperation::Balance => "Fetching DAO treasury balance...".to_string(),
        DaoOperation::RegistryList => "Listing DAO registry entries...".to_string(),
        DaoOperation::RegistryGet => "Fetching DAO registry entry...".to_string(),
    }
}

fn public_key_from_key_id(key_id: [u8; 32]) -> PublicKey {
    // This key-id-only placeholder is used strictly for deterministic DAO ID derivation.
    // It must never be used for signature verification.
    PublicKey {
        dilithium_pk: Vec::new(),
        kyber_pk: Vec::new(),
        key_id,
    }
}

fn build_signed_dao_registry_tx(
    execution_type: &str,
    identity_did: &str,
    signer_pubkey: PublicKey,
    signer_private: lib_crypto::types::PrivateKey,
    token_id: [u8; 32],
    class: DAOType,
    metadata_hash: [u8; 32],
) -> CliResult<(Transaction, [u8; 32])> {
    let treasury_key_id = signer_pubkey.key_id;
    let token_addr = public_key_from_key_id(token_id);
    let treasury = public_key_from_key_id(treasury_key_id);
    let dao_id = derive_dao_id(&token_addr, class, &treasury);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| CliError::ConfigError(format!("System time error: {e}")))?
        .as_secs();

    let event = json!({
        "token_id": hex::encode(token_id),
        "class": class.as_str(),
        "metadata_hash": hex::encode(metadata_hash),
        "treasury_key_id": hex::encode(treasury_key_id),
    });
    let event_bytes = serde_json::to_vec(&event)
        .map_err(|e| CliError::ConfigError(format!("Failed to serialize event payload: {e}")))?;

    let execution_data = DaoExecutionData {
        proposal_id: BcHash::from_slice(&lib_crypto::hash_blake3(
            &[execution_type.as_bytes(), identity_did.as_bytes(), &now.to_le_bytes(), &token_id].concat(),
        )),
        executor: identity_did.to_string(),
        execution_type: execution_type.to_string(),
        recipient: Some(hex::encode(dao_id)),
        amount: None,
        executed_at: now,
        // CLI tx construction does not know inclusion height; node sets canonical height.
        executed_at_height: 0,
        multisig_signatures: vec![event_bytes],
    };

    let mut tx = Transaction::new_dao_execution(
        execution_data,
        Vec::new(),
        Vec::new(),
        0,
        Signature {
            signature: Vec::new(),
            public_key: signer_pubkey.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: now,
        },
        format!("dao:{execution_type}").into_bytes(),
    );

    let keypair = lib_crypto::KeyPair {
        public_key: signer_pubkey,
        private_key: signer_private,
    };
    let sig = lib_crypto::sign_message(&keypair, tx.signing_hash().as_bytes())
        .map_err(|e| CliError::ConfigError(format!("Failed to sign DAO tx: {e}")))?;
    tx.signature.signature = sig.signature;

    Ok((tx, dao_id))
}

pub async fn handle_dao_command(args: DaoArgs, cli: &ZhtpCli) -> CliResult<()> {
    let output = crate::output::ConsoleOutput;
    handle_dao_command_impl(args, cli, &output).await
}

fn build_registry_get_endpoint(dao_id: &str) -> String {
    format!("/api/v1/dao/registry/{}", dao_id.trim_start_matches("0x"))
}

async fn handle_dao_command_impl(
    args: DaoArgs,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    let client = connect_default(&cli.server).await?;

    match args.action {
        DaoAction::Info => {
            let operation = DaoOperation::Info;
            handle_dao_operation_impl(&client, operation, None, None, None, None, cli, output).await
        }
        DaoAction::Propose { title, description } => {
            validate_proposal_title(&title)?;
            let operation = DaoOperation::Propose;
            handle_dao_operation_impl(&client, operation, Some(&title), Some(&description), None, None, cli, output).await
        }
        DaoAction::Vote { proposal_id, choice } => {
            validate_proposal_id(&proposal_id)?;
            validate_vote_choice(&choice)?;
            let operation = DaoOperation::Vote;
            handle_dao_operation_impl(&client, operation, None, None, Some(&proposal_id), Some(&choice), cli, output).await
        }
        DaoAction::Balance | DaoAction::TreasuryBalance => {
            let operation = DaoOperation::Balance;
            handle_dao_operation_impl(&client, operation, None, None, None, None, cli, output).await
        }
        DaoAction::RegistryList => {
            let operation = DaoOperation::RegistryList;
            handle_dao_operation_impl(&client, operation, None, None, None, None, cli, output).await
        }
        DaoAction::RegistryGet { dao_id } => {
            parse_hex_32("dao_id", &dao_id)?;
            let endpoint = build_registry_get_endpoint(&dao_id);
            output.info("Fetching DAO registry entry...")?;
            let response = client.get(&endpoint).await.map_err(|e| CliError::ApiCallFailed {
                endpoint: endpoint.clone(),
                status: 0,
                reason: e.to_string(),
            })?;
            let result: Value = ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
                endpoint: endpoint.clone(),
                status: 0,
                reason: format!("Failed to parse response: {e}"),
            })?;
            output.header("DAO Registry Entry")?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        DaoAction::RegistryRegister { token_id, class, metadata_hash } => {
            let token_id = parse_hex_32("token_id", &token_id)?;
            let class = parse_dao_class(&class)?;
            let metadata_hash = parse_hex_32("metadata_hash", &metadata_hash)?;
            let loaded = load_identity_from_keystore(&default_keystore_path()?)?;
            let (tx, dao_id) = build_signed_dao_registry_tx(
                "dao_registry_register_v1",
                &loaded.identity.did,
                loaded.keypair.public_key.clone(),
                loaded.keypair.private_key.clone(),
                token_id,
                class,
                metadata_hash,
            )?;
            let tx_hash = tx.hash();
            let result = broadcast_signed_tx(&client, &tx).await?;
            output.header("DAO Registry Register Broadcast")?;
            output.print(&format!("Signed tx hash: {tx_hash}"))?;
            output.print(&format!("Derived dao_id: {}", hex::encode(dao_id)))?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
        DaoAction::FactoryCreate { token_id, class, metadata_hash } => {
            let token_id = parse_hex_32("token_id", &token_id)?;
            let class = parse_dao_class(&class)?;
            let metadata_hash = parse_hex_32("metadata_hash", &metadata_hash)?;
            let loaded = load_identity_from_keystore(&default_keystore_path()?)?;
            let (tx, dao_id) = build_signed_dao_registry_tx(
                "dao_factory_create_v1",
                &loaded.identity.did,
                loaded.keypair.public_key.clone(),
                loaded.keypair.private_key.clone(),
                token_id,
                class,
                metadata_hash,
            )?;
            let tx_hash = tx.hash();
            let result = broadcast_signed_tx(&client, &tx).await?;
            output.header("DAO Factory Create Broadcast")?;
            output.print(&format!("Signed tx hash: {tx_hash}"))?;
            output.print(&format!("Derived dao_id: {}", hex::encode(dao_id)))?;
            output.print(&format_output(&result, &cli.format)?)?;
            Ok(())
        }
    }
}

async fn handle_dao_operation_impl(
    client: &ZhtpClient,
    operation: DaoOperation,
    title: Option<&str>,
    description: Option<&str>,
    proposal_id: Option<&str>,
    choice: Option<&str>,
    cli: &ZhtpCli,
    output: &dyn Output,
) -> CliResult<()> {
    output.info(&get_operation_message(operation, title, proposal_id, choice))?;

    let request_body = build_request_body(operation, title, description, proposal_id, choice);
    let response = match operation.method() {
        "GET" => client.get(operation.endpoint_path()).await,
        "POST" => client.post_json(operation.endpoint_path(), &request_body).await,
        _ => client.get(operation.endpoint_path()).await,
    }
    .map_err(|e| CliError::ApiCallFailed {
        endpoint: operation.endpoint_path().to_string(),
        status: 0,
        reason: e.to_string(),
    })?;

    let result: Value = ZhtpClient::parse_json(&response).map_err(|e| CliError::ApiCallFailed {
        endpoint: operation.endpoint_path().to_string(),
        status: 0,
        reason: format!("Failed to parse response: {}", e),
    })?;
    let formatted = format_output(&result, &cli.format)?;
    output.header(operation.title())?;
    output.print(&formatted)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::keypair::KeyPair;

    #[test]
    fn test_action_to_operation_info() {
        assert_eq!(action_to_operation(&DaoAction::Info), Some(DaoOperation::Info));
    }

    #[test]
    fn test_action_to_operation_propose() {
        let action = DaoAction::Propose {
            title: "test".to_string(),
            description: "test".to_string(),
        };
        assert_eq!(action_to_operation(&action), Some(DaoOperation::Propose));
    }

    #[test]
    fn test_action_to_operation_vote() {
        let action = DaoAction::Vote {
            proposal_id: "1".to_string(),
            choice: "yes".to_string(),
        };
        assert_eq!(action_to_operation(&action), Some(DaoOperation::Vote));
    }

    #[test]
    fn test_action_to_operation_registry_and_factory() {
        assert_eq!(action_to_operation(&DaoAction::RegistryList), Some(DaoOperation::RegistryList));
        assert_eq!(
            action_to_operation(&DaoAction::RegistryGet {
                dao_id: "00".repeat(32),
            }),
            Some(DaoOperation::RegistryGet)
        );
        assert_eq!(
            action_to_operation(&DaoAction::FactoryCreate {
                token_id: "11".repeat(32),
                class: "np".to_string(),
                metadata_hash: "22".repeat(32),
            }),
            None
        );
    }

    #[test]
    fn test_operation_description() {
        assert_eq!(DaoOperation::Info.description(), "Get DAO information");
        assert_eq!(DaoOperation::Propose.description(), "Create proposal");
        assert_eq!(DaoOperation::Vote.description(), "Vote on proposal");
        assert_eq!(DaoOperation::Balance.description(), "Get DAO treasury balance");
        assert_eq!(DaoOperation::RegistryList.description(), "List DAO registry entries");
        assert_eq!(DaoOperation::RegistryGet.description(), "Get DAO registry entry");
    }

    #[test]
    fn test_operation_method() {
        assert_eq!(DaoOperation::Info.method(), "GET");
        assert_eq!(DaoOperation::Propose.method(), "POST");
        assert_eq!(DaoOperation::Vote.method(), "POST");
        assert_eq!(DaoOperation::Balance.method(), "GET");
        assert_eq!(DaoOperation::RegistryList.method(), "GET");
        assert_eq!(DaoOperation::RegistryGet.method(), "GET");
    }

    #[test]
    fn test_operation_endpoint_path() {
        assert_eq!(DaoOperation::Info.endpoint_path(), "/api/v1/dao/data");
        assert_eq!(DaoOperation::Propose.endpoint_path(), "/api/v1/dao/proposal/create");
        assert_eq!(DaoOperation::Vote.endpoint_path(), "/api/v1/dao/vote/cast");
        assert_eq!(DaoOperation::Balance.endpoint_path(), "/api/v1/dao/treasury/status");
        assert_eq!(DaoOperation::RegistryList.endpoint_path(), "/api/v1/dao/registry/list");
    }

    #[test]
    fn test_validate_proposal_id_valid() {
        assert!(validate_proposal_id("proposal-123").is_ok());
        assert!(validate_proposal_id("1").is_ok());
    }

    #[test]
    fn test_validate_proposal_id_invalid() {
        assert!(validate_proposal_id("").is_err());
        assert!(validate_proposal_id("proposal!").is_err());
    }

    #[test]
    fn test_validate_vote_choice_valid() {
        assert!(validate_vote_choice("yes").is_ok());
        assert!(validate_vote_choice("no").is_ok());
        assert!(validate_vote_choice("abstain").is_ok());
        assert!(validate_vote_choice("YES").is_ok());
    }

    #[test]
    fn test_validate_vote_choice_invalid() {
        assert!(validate_vote_choice("maybe").is_err());
        assert!(validate_vote_choice("").is_err());
    }

    #[test]
    fn test_validate_proposal_title_valid() {
        assert!(validate_proposal_title("My Proposal").is_ok());
    }

    #[test]
    fn test_validate_proposal_title_invalid() {
        assert!(validate_proposal_title("").is_err());
        let long_title = "a".repeat(256);
        assert!(validate_proposal_title(&long_title).is_err());
    }

    #[test]
    fn test_parse_hex_32() {
        let value = "aa".repeat(32);
        assert_eq!(parse_hex_32("dao_id", &value).unwrap(), [0xaa; 32]);
        assert!(parse_hex_32("dao_id", "ff").is_err());
    }

    #[test]
    fn test_parse_dao_class() {
        assert_eq!(parse_dao_class("np").unwrap(), DAOType::NP);
        assert_eq!(parse_dao_class("non_profit").unwrap(), DAOType::NP);
        assert_eq!(parse_dao_class("nonprofit").unwrap(), DAOType::NP);
        assert_eq!(parse_dao_class("for-profit").unwrap(), DAOType::FP);
        assert_eq!(parse_dao_class("for_profit").unwrap(), DAOType::FP);
        assert_eq!(parse_dao_class("forprofit").unwrap(), DAOType::FP);
        assert!(parse_dao_class("x").is_err());
    }

    #[test]
    fn test_build_registry_get_endpoint_trims_hex_prefix() {
        assert_eq!(
            build_registry_get_endpoint(&format!("0x{}", "ab".repeat(32))),
            format!("/api/v1/dao/registry/{}", "ab".repeat(32))
        );
    }

    #[test]
    fn test_build_signed_dao_registry_tx_register_flow() {
        let keypair = KeyPair::generate().unwrap();
        let token_id = [0x11u8; 32];
        let metadata_hash = [0x22u8; 32];
        let (tx, dao_id) = build_signed_dao_registry_tx(
            "dao_registry_register_v1",
            "did:sov:test",
            keypair.public_key.clone(),
            keypair.private_key.clone(),
            token_id,
            DAOType::NP,
            metadata_hash,
        )
        .unwrap();

        assert_eq!(tx.transaction_type, lib_blockchain::TransactionType::DaoExecution);
        assert_eq!(tx.dao_execution_data.as_ref().unwrap().execution_type, "dao_registry_register_v1");
        assert!(!tx.signature.signature.is_empty());
        assert_ne!(dao_id, [0u8; 32]);
    }

    #[test]
    fn test_build_signed_dao_registry_tx_factory_flow() {
        let keypair = KeyPair::generate().unwrap();
        let token_id = [0x33u8; 32];
        let metadata_hash = [0x44u8; 32];
        let (tx, _dao_id) = build_signed_dao_registry_tx(
            "dao_factory_create_v1",
            "did:sov:test",
            keypair.public_key.clone(),
            keypair.private_key.clone(),
            token_id,
            DAOType::FP,
            metadata_hash,
        )
        .unwrap();

        assert_eq!(tx.dao_execution_data.as_ref().unwrap().execution_type, "dao_factory_create_v1");
        assert!(!tx.signature.signature.is_empty());
    }

    #[test]
    fn test_build_request_body_propose() {
        let body = build_request_body(DaoOperation::Propose, Some("Title"), Some("Description"), None, None);
        assert_eq!(body.get("title").and_then(|v| v.as_str()), Some("Title"));
        assert_eq!(body.get("description").and_then(|v| v.as_str()), Some("Description"));
    }

    #[test]
    fn test_get_operation_message() {
        let msg = get_operation_message(DaoOperation::Propose, Some("My Proposal"), None, None);
        assert!(msg.contains("proposal"));
        assert!(msg.contains("My Proposal"));
    }
}
