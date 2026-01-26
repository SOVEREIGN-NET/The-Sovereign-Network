//! Command Handler for ZHTP CLI Operations
//! 
//! Handles execution of wallet, DAO, identity, and other operations

use anyhow::Result;
use serde_json::json;
use reqwest;

use super::argument_parsing::{
    ZhtpCommand, WalletCommand, DaoCommand, IdentityCommand, 
    ZkCommand, BlockchainCommand, NetworkCommand
};

const BASE_URL: &str = "http://localhost:9333/api/v1";

/// Helper: Make a POST request and print the result
async fn api_post(client: &reqwest::Client, endpoint: &str, body: serde_json::Value, success_msg: &str) -> Result<()> {
    let response = client
        .post(&format!("{}{}", BASE_URL, endpoint))
        .json(&body)
        .send()
        .await?;
    
    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("{}", success_msg);
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Request failed: {}", response.status());
    }
    Ok(())
}

/// Helper: Make a GET request and print the result
async fn api_get(client: &reqwest::Client, endpoint: &str, success_msg: &str) -> Result<()> {
    let response = client
        .get(&format!("{}{}", BASE_URL, endpoint))
        .send()
        .await?;
    
    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        println!("{}", success_msg);
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("Request failed: {}", response.status());
    }
    Ok(())
}

/// Execute a ZHTP command
pub async fn execute_command(command: ZhtpCommand) -> Result<()> {
    match command {
        ZhtpCommand::Node(_) => {
            // This should not be called for node commands
            Err(anyhow::anyhow!("Node command should be handled by main"))
        }
        ZhtpCommand::Wallet(wallet_cmd) => execute_wallet_command(wallet_cmd).await,
        ZhtpCommand::Dao(dao_cmd) => execute_dao_command(dao_cmd).await,
        ZhtpCommand::Identity(identity_cmd) => execute_identity_command(identity_cmd).await,
        ZhtpCommand::Zk(zk_cmd) => execute_zk_command(zk_cmd).await,
        ZhtpCommand::Blockchain(blockchain_cmd) => execute_blockchain_command(blockchain_cmd).await,
        ZhtpCommand::Network(network_cmd) => execute_network_command(network_cmd).await,
    }
}

/// Execute wallet command
async fn execute_wallet_command(command: WalletCommand) -> Result<()> {
    let client = reqwest::Client::new();
    
    match command {
        WalletCommand::Create { name, wallet_type } => {
            println!(" Creating new {} wallet: {}", wallet_type, name);
            let body = json!({"wallet_name": name, "wallet_type": wallet_type, "owner_identity": "auto"});
            api_post(&client, "/wallet/create", body, "Wallet created successfully!").await
        }
        WalletCommand::Balance { address } => {
            println!("Getting balance for wallet: {}", address);
            api_get(&client, &format!("/wallet/balance?wallet={}", address), "Balance information:").await
        }
        WalletCommand::Transfer { to, amount, fee } => {
            println!(" Transferring {} tokens to: {}", amount, to);
            let body = json!({"to": to, "amount": amount, "fee": fee.unwrap_or(1000), "wallet_type": "zhtp"});
            api_post(&client, "/wallet/transfer", body, "Transfer completed!").await
        }
        WalletCommand::History { address } => {
            println!("Getting transaction history for: {}", address);
            api_get(&client, &format!("/wallet/history?wallet={}", address), "Transaction history:").await
        }
        WalletCommand::Import { file, password } => {
            println!("Importing wallet from: {}", file);
            let body = json!({"file_path": file, "password": password});
            api_post(&client, "/wallet/import", body, "Wallet imported successfully!").await
        }
        WalletCommand::Sign { address, data } => {
            println!("Signing data with wallet: {}", address);
            let body = json!({"wallet": address, "data": data});
            api_post(&client, "/wallet/sign", body, "Data signed successfully!").await
        }
    }
}

/// Execute DAO command
async fn execute_dao_command(command: DaoCommand) -> Result<()> {
    let client = reqwest::Client::new();
    
    match command {
        DaoCommand::Info => {
            println!(" Getting DAO information...");
            api_get(&client, "/dao/info", "DAO Information:").await
        }
        DaoCommand::Propose { title, description } => {
            println!("Creating new proposal: {}", title);
            let body = json!({"title": title, "description": description, "proposal_type": "general"});
            api_post(&client, "/dao/proposal/create", body, "Proposal created successfully!").await
        }
        DaoCommand::Vote { proposal_id, choice } => {
            println!(" Voting {} on proposal ID: {}", if choice { "YES" } else { "NO" }, proposal_id);
            let body = json!({"proposal_id": proposal_id, "vote": if choice { "yes" } else { "no" }});
            api_post(&client, "/dao/proposal/vote", body, "Vote cast successfully!").await
        }
        DaoCommand::Treasury => {
            println!("Getting DAO treasury status...");
            api_get(&client, "/dao/treasury", "DAO Treasury:").await
        }
        DaoCommand::ClaimUbi => {
            println!("Claiming UBI payment...");
            api_post(&client, "/dao/ubi/claim", json!({}), "UBI claimed successfully!").await
        }
    }
}

/// Execute identity command
async fn execute_identity_command(command: IdentityCommand) -> Result<()> {
    let client = reqwest::Client::new();
    
    match command {
        IdentityCommand::Create { name } => {
            println!("Creating new identity: {}", name);
            let body = json!({"identity_name": name, "identity_type": "citizen"});
            api_post(&client, "/identity/create", body, "Identity created successfully!").await
        }
        IdentityCommand::List => {
            println!("Listing all identities...");
            api_get(&client, "/identity/list", "Identities:").await
        }
        IdentityCommand::Info { id } => {
            println!(" Getting identity information: {}", id);
            api_get(&client, &format!("/identity/profile?identity_id={}", id), "Identity Information:").await
        }
        IdentityCommand::Export { id } => {
            println!(" Exporting identity: {}", id);
            println!("Identity export functionality would be implemented here");
            Ok(())
        }
        IdentityCommand::Verify { proof } => {
            println!("Verifying identity proof...");
            let body = json!({"proof": proof, "verification_type": "zk_proof"});
            api_post(&client, "/identity/verify", body, "Identity verification result:").await
        }
        IdentityCommand::CreateZkDid { name } => {
            println!("Creating zero-knowledge DID: {}", name);
            let body = json!({"did_name": name, "privacy_level": "maximum"});
            api_post(&client, "/identity/create-zk-did", body, "ZK-DID created successfully!").await
        }
    }
}

/// Execute ZK command
async fn execute_zk_command(command: ZkCommand) -> Result<()> {
    let client = reqwest::Client::new();
    
    match command {
        ZkCommand::Generate { circuit_type, input } => {
            println!(" Generating ZK proof for circuit: {}", circuit_type);
            let body = json!({"circuit_type": circuit_type, "input_data": input, "proof_type": "plonky2"});
            api_post(&client, "/zk/proof/generate", body, "ZK proof generated successfully!").await
        }
        ZkCommand::Verify { proof } => {
            println!("Verifying ZK proof...");
            let body = json!({"proof": proof, "verification_type": "plonky2"});
            api_post(&client, "/zk/proof/verify", body, "ZK proof verification result:").await
        }
        ZkCommand::Commit { data } => {
            println!(" Creating ZK commitment...");
            let body = json!({"data": data, "commitment_type": "pedersen"});
            api_post(&client, "/zk/commitment", body, "ZK commitment created successfully!").await
        }
    }
}

/// Execute blockchain command
async fn execute_blockchain_command(command: BlockchainCommand) -> Result<()> {
    let client = reqwest::Client::new();
    
    match command {
        BlockchainCommand::Block { hash } => {
            println!("Getting block information...");
            let endpoint = hash.map_or("/blockchain/block".to_string(), |h| format!("/blockchain/block?hash={}", h));
            api_get(&client, &endpoint, "Block Information:").await
        }
        BlockchainCommand::Transaction { hash } => {
            println!(" Getting transaction: {}", hash);
            api_get(&client, &format!("/blockchain/transaction?hash={}", hash), "Transaction Information:").await
        }
        BlockchainCommand::Mempool => {
            println!(" Getting mempool status...");
            api_get(&client, "/blockchain/mempool", "Mempool Status:").await
        }
        BlockchainCommand::Stats => {
            println!("Getting blockchain statistics...");
            api_get(&client, "/blockchain/stats", "Blockchain Statistics:").await
        }
    }
}

/// Execute network command
async fn execute_network_command(command: NetworkCommand) -> Result<()> {
    let client = reqwest::Client::new();
    
    match command {
        NetworkCommand::Peers => {
            println!("Getting network peers...");
            api_get(&client, "/network/peers", "Network Peers:").await
        }
        NetworkCommand::Mesh => {
            println!("Getting mesh network status...");
            api_get(&client, "/network/mesh", "Mesh Network Status:").await
        }
        NetworkCommand::IspBypass => {
            println!(" Getting ISP bypass status...");
            api_get(&client, "/network/isp-bypass", "ISP Bypass Status:").await
        }
        NetworkCommand::Test => {
            println!(" Testing network connectivity...");
            api_post(&client, "/network/test", json!({}), "Network Test Results:").await
        }
    }
