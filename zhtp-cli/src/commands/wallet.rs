//! Wallet commands for ZHTP orchestrator

use anyhow::Result;
use crate::argument_parsing::{WalletArgs, WalletAction, ZhtpCli, format_output};
use serde_json::json;

pub async fn handle_wallet_command(args: WalletArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        WalletAction::Create { name, wallet_type } => {
            println!("💳 Orchestrating wallet creation: {}", name);
            
            let request_body = json!({
                "wallet_name": name,
                "wallet_type": wallet_type,
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/wallet/create", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Wallet creation orchestrated successfully!");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate wallet creation: {}", response.status());
            }
        }
        WalletAction::Balance { address } => {
            println!("Orchestrating balance check for: {}", address);
            
            let response = client
                .get(&format!("{}/wallet/balance", base_url))
                .header("x-wallet-address", address)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Balance orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate balance check: {}", response.status());
            }
        }
        WalletAction::Transfer { from, to, amount } => {
            println!(" Orchestrating transfer: {} from {} to {}", amount, from, to);
            
            let request_body = json!({
                "from": from,
                "to": to,
                "amount": amount,
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/wallet/transfer", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Transfer orchestrated successfully!");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate transfer: {}", response.status());
            }
        }
        WalletAction::History { address } => {
            println!("Orchestrating transaction history for: {}", address);
            
            let response = client
                .get(&format!("{}/wallet/history", base_url))
                .header("x-wallet-address", address)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Transaction history orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate history request: {}", response.status());
            }
        }
        WalletAction::List => {
            println!("Orchestrating wallet list...");
            
            let response = client
                .get(&format!("{}/wallet/list", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Wallet list orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate wallet list: {}", response.status());
            }
        }
    }
    
    Ok(())
}
