//! DAO commands for ZHTP orchestrator

use anyhow::Result;
use crate::cli::{DaoArgs, DaoAction, ZhtpCli, format_output};
use serde_json::json;

pub async fn handle_dao_command(args: DaoArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        DaoAction::Info => {
            println!(" Orchestrating DAO information request...");
            
            let response = client
                .get(&format!("{}/dao/info", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("DAO Information orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate DAO info: {}", response.status());
            }
        }
        DaoAction::Propose { title, description } => {
            println!("Orchestrating proposal creation: {}", title);
            
            let request_body = json!({
                "title": title,
                "description": description,
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/dao/proposal/create", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Proposal creation orchestrated successfully!");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate proposal creation: {}", response.status());
            }
        }
        DaoAction::Vote { proposal_id, choice } => {
            println!(" Orchestrating vote: {} on proposal {}", choice, proposal_id);
            
            let request_body = json!({
                "proposal_id": proposal_id,
                "choice": choice,
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/dao/proposal/vote", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Vote orchestrated successfully!");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate vote: {}", response.status());
            }
        }
        DaoAction::ClaimUbi => {
            println!("Orchestrating UBI claim...");
            
            let response = client
                .post(&format!("{}/dao/ubi/claim", base_url))
                .header("x-user-id", cli.user_id.as_deref().unwrap_or("anonymous"))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("UBI claim orchestrated successfully!");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate UBI claim: {}", response.status());
            }
        }
    }
    
    Ok(())
}
