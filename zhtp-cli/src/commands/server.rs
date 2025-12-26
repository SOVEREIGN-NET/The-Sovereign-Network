//! Server management commands for ZHTP orchestrator

use anyhow::Result;
use crate::argument_parsing::{ServerArgs, ServerAction, ZhtpCli, format_output};
use serde_json::json;

pub async fn handle_server_command(args: ServerArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        ServerAction::Start => {
            println!(" Starting ZHTP orchestrator server...");
            
            let request_body = json!({
                "action": "start",
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/server/start", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Server start orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to start orchestrator server: {}", response.status());
            }
        }
        ServerAction::Stop => {
            println!("⏹️ Stopping ZHTP orchestrator server...");
            
            let request_body = json!({
                "action": "stop",
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/server/stop", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Server stop orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to stop orchestrator server: {}", response.status());
            }
        }
        ServerAction::Restart => {
            println!(" Restarting ZHTP orchestrator server...");
            
            let request_body = json!({
                "action": "restart",
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/server/restart", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Server restart orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to restart orchestrator server: {}", response.status());
            }
        }
        ServerAction::Status => {
            println!("Checking ZHTP orchestrator server status...");
            
            let response = client
                .get(&format!("{}/server/status", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Server status orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to get server status: {}", response.status());
            }
        }
        ServerAction::Config => {
            println!(" Getting ZHTP orchestrator server configuration...");
            
            let response = client
                .get(&format!("{}/server/config", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Server configuration orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to get server configuration: {}", response.status());
            }
        }
    }
    
    Ok(())
}
