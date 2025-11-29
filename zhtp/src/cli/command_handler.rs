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
    let base_url = "http://localhost:9333/api/v1";
    
    match command {
        WalletCommand::Create { name, wallet_type } => {
            println!(" Creating new {} wallet: {}", wallet_type, name);
            
            let request_body = json!({
                "wallet_name": name,
                "wallet_type": wallet_type,
                "owner_identity": "auto"
            });
            
            let response = client
                .post(&format!("{}/wallet/create", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Wallet created successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to create wallet: {}", response.status());
            }
        }
        WalletCommand::Balance { address } => {
            println!("Getting balance for wallet: {}", address);
            
            let response = client
                .get(&format!("{}/wallet/balance?wallet={}", base_url, address))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Balance information:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get balance: {}", response.status());
            }
        }
        WalletCommand::Transfer { to, amount, fee } => {
            println!(" Transferring {} tokens to: {}", amount, to);
            
            let request_body = json!({
                "to": to,
                "amount": amount,
                "fee": fee.unwrap_or(1000),
                "wallet_type": "zhtp"
            });
            
            let response = client
                .post(&format!("{}/wallet/transfer", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Transfer completed!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Transfer failed: {}", response.status());
            }
        }
        WalletCommand::History { address } => {
            println!("Getting transaction history for: {}", address);
            
            let response = client
                .get(&format!("{}/wallet/history?wallet={}", base_url, address))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Transaction history:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get history: {}", response.status());
            }
        }
        WalletCommand::Import { file, password } => {
            println!("Importing wallet from: {}", file);
            
            let request_body = json!({
                "file_path": file,
                "password": password
            });
            
            let response = client
                .post(&format!("{}/wallet/import", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Wallet imported successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to import wallet: {}", response.status());
            }
        }
        WalletCommand::Sign { address, data } => {
            println!("✍️ Signing data with wallet: {}", address);
            
            let request_body = json!({
                "wallet": address,
                "data": data
            });
            
            let response = client
                .post(&format!("{}/wallet/sign", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Data signed successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to sign data: {}", response.status());
            }
        }
    }
    
    Ok(())
}

/// Execute DAO command
async fn execute_dao_command(command: DaoCommand) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:9333/api/v1";
    
    match command {
        DaoCommand::Info => {
            println!(" Getting DAO information...");
            
            let response = client
                .get(&format!("{}/dao/info", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("DAO Information:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get DAO info: {}", response.status());
            }
        }
        DaoCommand::Propose { title, description } => {
            println!("Creating new proposal: {}", title);
            
            let request_body = json!({
                "title": title,
                "description": description,
                "proposal_type": "general"
            });
            
            let response = client
                .post(&format!("{}/dao/proposal/create", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Proposal created successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to create proposal: {}", response.status());
            }
        }
        DaoCommand::Vote { proposal_id, choice } => {
            println!(" Voting {} on proposal ID: {}", if choice { "YES" } else { "NO" }, proposal_id);
            
            let request_body = json!({
                "proposal_id": proposal_id,
                "vote": if choice { "yes" } else { "no" }
            });
            
            let response = client
                .post(&format!("{}/dao/proposal/vote", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Vote cast successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to cast vote: {}", response.status());
            }
        }
        DaoCommand::Treasury => {
            println!("🏦 Getting DAO treasury status...");
            
            let response = client
                .get(&format!("{}/dao/treasury", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("DAO Treasury:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get treasury info: {}", response.status());
            }
        }
        DaoCommand::ClaimUbi => {
            println!("Claiming UBI payment...");
            
            let request_body = json!({});
            
            let response = client
                .post(&format!("{}/dao/ubi/claim", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("UBI claimed successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to claim UBI: {}", response.status());
            }
        }
    }
    
    Ok(())
}

/// Execute identity command
async fn execute_identity_command(command: IdentityCommand) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:9333/api/v1";
    
    match command {
        IdentityCommand::Create { name } => {
            println!("Creating new identity: {}", name);
            
            let request_body = json!({
                "identity_name": name,
                "identity_type": "citizen"
            });
            
            let response = client
                .post(&format!("{}/identity/create", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Identity created successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to create identity: {}", response.status());
            }
        }
        IdentityCommand::List => {
            println!("Listing all identities...");
            
            let response = client
                .get(&format!("{}/identity/list", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Identities:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to list identities: {}", response.status());
            }
        }
        IdentityCommand::Info { id } => {
            println!(" Getting identity information: {}", id);
            
            let response = client
                .get(&format!("{}/identity/profile?identity_id={}", base_url, id))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Identity Information:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get identity info: {}", response.status());
            }
        }
        IdentityCommand::Export { id } => {
            println!(" Exporting identity: {}", id);
            println!("Identity export functionality would be implemented here");
        }
        IdentityCommand::Verify { proof } => {
            println!("Verifying identity proof...");
            
            let request_body = json!({
                "proof": proof,
                "verification_type": "zk_proof"
            });
            
            let response = client
                .post(&format!("{}/identity/verify", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Identity verification result:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to verify identity: {}", response.status());
            }
        }
        IdentityCommand::CreateZkDid { name } => {
            println!("Creating zero-knowledge DID: {}", name);
            
            let request_body = json!({
                "did_name": name,
                "privacy_level": "maximum"
            });
            
            let response = client
                .post(&format!("{}/identity/create-zk-did", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("ZK-DID created successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to create ZK-DID: {}", response.status());
            }
        }
    }
    
    Ok(())
}

/// Execute ZK command
async fn execute_zk_command(command: ZkCommand) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:9333/api/v1";
    
    match command {
        ZkCommand::Generate { circuit_type, input } => {
            println!(" Generating ZK proof for circuit: {}", circuit_type);
            
            let request_body = json!({
                "circuit_type": circuit_type,
                "input_data": input,
                "proof_type": "plonky2"
            });
            
            let response = client
                .post(&format!("{}/zk/proof/generate", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("ZK proof generated successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to generate proof: {}", response.status());
            }
        }
        ZkCommand::Verify { proof } => {
            println!("Verifying ZK proof...");
            
            let request_body = json!({
                "proof": proof,
                "verification_type": "plonky2"
            });
            
            let response = client
                .post(&format!("{}/zk/proof/verify", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("ZK proof verification result:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to verify proof: {}", response.status());
            }
        }
        ZkCommand::Commit { data } => {
            println!(" Creating ZK commitment...");
            
            let request_body = json!({
                "data": data,
                "commitment_type": "pedersen"
            });
            
            let response = client
                .post(&format!("{}/zk/commitment", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("ZK commitment created successfully!");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to create commitment: {}", response.status());
            }
        }
    }
    
    Ok(())
}

/// Execute blockchain command
async fn execute_blockchain_command(command: BlockchainCommand) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:9333/api/v1";
    
    match command {
        BlockchainCommand::Block { hash } => {
            let url = if let Some(h) = hash {
                format!("{}/blockchain/block?hash={}", base_url, h)
            } else {
                format!("{}/blockchain/block", base_url)
            };
            
            println!("Getting block information...");
            
            let response = client.get(&url).send().await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Block Information:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get block: {}", response.status());
            }
        }
        BlockchainCommand::Transaction { hash } => {
            println!(" Getting transaction: {}", hash);
            
            let response = client
                .get(&format!("{}/blockchain/transaction?hash={}", base_url, hash))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Transaction Information:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get transaction: {}", response.status());
            }
        }
        BlockchainCommand::Mempool => {
            println!(" Getting mempool status...");
            
            let response = client
                .get(&format!("{}/blockchain/mempool", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Mempool Status:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get mempool: {}", response.status());
            }
        }
        BlockchainCommand::Stats => {
            println!("Getting blockchain statistics...");
            
            let response = client
                .get(&format!("{}/blockchain/stats", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Blockchain Statistics:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get stats: {}", response.status());
            }
        }
    }
    
    Ok(())
}

/// Execute network command
async fn execute_network_command(command: NetworkCommand) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = "http://localhost:9333/api/v1";
    
    match command {
        NetworkCommand::Peers => {
            println!("Getting network peers...");
            
            let response = client
                .get(&format!("{}/network/peers", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Network Peers:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get peers: {}", response.status());
            }
        }
        NetworkCommand::Mesh => {
            println!("Getting mesh network status...");
            
            let response = client
                .get(&format!("{}/network/mesh", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Mesh Network Status:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get mesh status: {}", response.status());
            }
        }
        NetworkCommand::IspBypass => {
            println!(" Getting  status...");
            
            let response = client
                .get(&format!("{}/network/isp-bypass", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!(" Status:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to get  status: {}", response.status());
            }
        }
        NetworkCommand::Test => {
            println!(" Testing network connectivity...");
            
            let response = client
                .post(&format!("{}/network/test", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                println!("Network Test Results:");
                println!("{}", serde_json::to_string_pretty(&result)?);
            } else {
                println!("Failed to test network: {}", response.status());
            }
        }
    }
    
    Ok(())
}
