//! Blockchain commands for ZHTP orchestrator

use anyhow::Result;
use crate::cli::{BlockchainArgs, BlockchainAction, ZhtpCli, format_output};
use serde_json::json;

pub async fn handle_blockchain_command(args: BlockchainArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        BlockchainAction::Status => {
            println!("Orchestrating blockchain status check...");
            
            let response = client
                .get(&format!("{}/blockchain/status", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Blockchain status orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate blockchain status: {}", response.status());
            }
        }
        BlockchainAction::Transaction { tx_hash } => {
            println!(" Orchestrating transaction lookup: {}", tx_hash);
            
            let request_body = json!({
                "tx_hash": tx_hash,
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/blockchain/transaction", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Transaction lookup orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate transaction lookup: {}", response.status());
            }
        }
        BlockchainAction::Stats => {
            println!("Orchestrating blockchain statistics...");
            
            let response = client
                .get(&format!("{}/blockchain/stats", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Blockchain stats orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate blockchain stats: {}", response.status());
            }
        }
    }
    
    Ok(())
}
