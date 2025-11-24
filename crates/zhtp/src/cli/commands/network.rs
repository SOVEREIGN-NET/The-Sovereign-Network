//! Network commands for ZHTP orchestrator

use anyhow::Result;
use crate::cli::{NetworkArgs, NetworkAction, ZhtpCli, format_output};

pub async fn handle_network_command(args: NetworkArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        NetworkAction::Status => {
            println!("Orchestrating network status check...");
            
            let response = client
                .get(&format!("{}/network/status", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Network status orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate network status: {}", response.status());
            }
        }
        NetworkAction::Peers => {
            println!("Orchestrating peer list request...");
            
            let response = client
                .get(&format!("{}/network/peers", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Network peers orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate peer list: {}", response.status());
            }
        }
        NetworkAction::Test => {
            println!(" Orchestrating network connectivity test...");
            
            let response = client
                .post(&format!("{}/network/test", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Network test orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate network test: {}", response.status());
            }
        }
    }
    
    Ok(())
}
