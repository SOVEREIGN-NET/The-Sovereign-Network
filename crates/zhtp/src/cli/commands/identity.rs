//! Identity commands for ZHTP orchestrator

use anyhow::Result;
use crate::cli::{IdentityArgs, IdentityAction, ZhtpCli, format_output};
use serde_json::json;
use chrono;
use uuid;

pub async fn handle_identity_command(args: IdentityArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::builder()
        .http1_only()  // Force HTTP/1.1 to avoid version parsing issues
        .build()?;
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        IdentityAction::Create { name } => {
            println!("Creating new ZHTP DID identity: {}", name);
            
            // Use the correct API format that matches the working PowerShell command
            let request_body = json!({
                "identity_type": "human",
                "display_name": name,
                "recovery_options": [
                    format!("recovery_phrase_{}", name.to_lowercase()),
                    format!("backup_phrase_{}", chrono::Utc::now().timestamp())
                ],
                "initial_wallet_type": "citizen_wallet"
            });
            
            let response = client
                .post(&format!("{}/identity/create", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                // Extract key information from the successful response
                if let Some(did) = result.get("did") {
                    println!("DID Created Successfully!");
                    println!("DID: {}", did.as_str().unwrap_or("N/A"));
                }
                if let Some(identity_id) = result.get("identity_id") {
                    println!("Identity ID: {}", identity_id.as_str().unwrap_or("N/A"));
                }
                if let Some(primary_wallet) = result.get("primary_wallet_id") {
                    println!("Primary Wallet: {}", primary_wallet.as_str().unwrap_or("N/A"));
                }
                if let Some(blockchain) = result.get("blockchain") {
                    if let Some(tx_hash) = blockchain.get("transaction_hash") {
                        println!("Blockchain TX: {}", tx_hash.as_str().unwrap_or("N/A"));
                    }
                    if let Some(status) = blockchain.get("registration_status") {
                        println!("Status: {}", status.as_str().unwrap_or("N/A"));
                    }
                }
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to create DID identity: {} - {}", status, error_text);
            }
        }
        IdentityAction::CreateDid { name, identity_type, recovery_options } => {
            println!("Creating zero-knowledge DID identity: {}", name);
            println!("🔖 Identity Type: {}", identity_type);
            
            // Use provided recovery options or generate defaults
            let final_recovery_options = if recovery_options.is_empty() {
                vec![
                    format!("recovery_phrase_{}", name.to_lowercase()),
                    format!("backup_phrase_{}", chrono::Utc::now().timestamp()),
                    format!("emergency_recovery_{}", uuid::Uuid::new_v4().to_string()[..8].to_string())
                ]
            } else {
                recovery_options
            };
            
            let request_body = json!({
                "identity_type": identity_type,
                "display_name": name,
                "recovery_options": final_recovery_options,
                "initial_wallet_type": "citizen_wallet"
            });
            
            println!("Recovery options configured: {} phrases", final_recovery_options.len());
            
            let response = client
                .post(&format!("{}/identity/create", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                println!("Zero-Knowledge DID Created Successfully!");
                
                // Extract and display comprehensive DID information
                if let Some(did) = result.get("did") {
                    println!("DID: {}", did.as_str().unwrap_or("N/A"));
                }
                if let Some(identity_id) = result.get("identity_id") {
                    println!("Identity ID: {}", identity_id.as_str().unwrap_or("N/A"));
                }
                
                // Wallet information
                if let Some(primary_wallet) = result.get("primary_wallet_id") {
                    println!("Primary Wallet: {}", primary_wallet.as_str().unwrap_or("N/A"));
                }
                if let Some(ubi_wallet) = result.get("ubi_wallet_id") {
                    println!("🎁 UBI Wallet: {}", ubi_wallet.as_str().unwrap_or("N/A"));
                }
                if let Some(savings_wallet) = result.get("savings_wallet_id") {
                    println!("🏦 Savings Wallet: {}", savings_wallet.as_str().unwrap_or("N/A"));
                }
                
                // DAO registration
                if let Some(dao_reg) = result.get("dao_registration") {
                    if let Some(voting_power) = dao_reg.get("voting_power") {
                        println!(" DAO Voting Power: {}", voting_power);
                    }
                }
                
                // UBI registration
                if let Some(ubi_reg) = result.get("ubi_registration") {
                    if let Some(daily_amount) = ubi_reg.get("daily_amount") {
                        println!("Daily UBI: {} ZHTP", daily_amount.as_u64().unwrap_or(0) as f64 / 1_000_000_000_000_000_000.0);
                    }
                }
                
                // Blockchain status
                if let Some(blockchain) = result.get("blockchain") {
                    if let Some(tx_hash) = blockchain.get("transaction_hash") {
                        println!("Blockchain TX: {}", tx_hash.as_str().unwrap_or("N/A"));
                    }
                    if let Some(status) = blockchain.get("registration_status") {
                        println!("Registration Status: {}", status.as_str().unwrap_or("N/A"));
                    }
                }
                
                println!(" Full Web4 citizen onboarding completed!");
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nComplete Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to create zero-knowledge DID: {} - {}", status, error_text);
            }
        }
        IdentityAction::Verify { identity_id } => {
            println!("Verifying ZHTP identity: {}", identity_id);
            
            let request_body = json!({
                "identity_data": {
                    "identity_id": identity_id,
                    "verification_requested": true
                },
                "verification_level": "Standard"
            });
            
            let response = client
                .post(&format!("{}/identity/verify", base_url))
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                // Extract verification results
                if let Some(verified) = result.get("verified") {
                    if verified.as_bool().unwrap_or(false) {
                        println!("Identity verification successful!");
                    } else {
                        println!("Identity verification failed!");
                    }
                }
                if let Some(score) = result.get("verification_score") {
                    println!("Verification Score: {}", score);
                }
                if let Some(level) = result.get("verification_level") {
                    println!(" Security Level: {}", level.as_str().unwrap_or("N/A"));
                }
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nFull Response:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to verify identity: {} - {}", status, error_text);
            }
        }
        IdentityAction::List => {
            println!("Listing ZHTP identities from blockchain...");
            
            // Since there's no direct list endpoint, we'll get blockchain status
            // and show identity information from there
            let response = client
                .get(&format!("{}/blockchain/block", base_url))
                .header("Accept", "application/json")
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                
                println!("Blockchain Identity Status:");
                if let Some(height) = result.get("latest_height") {
                    println!("Latest Block: {}", height);
                }
                
                // For now, show a message about checking server logs for created identities
                println!("To see created identities, check the server logs for DID creation events");
                println!("   or use 'zhtp blockchain stats' to see blockchain statistics");
                
                if cli.verbose {
                    let formatted = format_output(&result, &cli.format)?;
                    println!("\nBlockchain Status:");
                    println!("{}", formatted);
                }
            } else {
                let status = response.status();
                let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
                println!("Failed to get blockchain status: {} - {}", status, error_text);
            }
        }
    }
    
    Ok(())
}
