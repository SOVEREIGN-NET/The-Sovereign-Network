//! Component management commands for ZHTP orchestrator

use anyhow::Result;
use crate::cli::{ComponentArgs, ComponentAction, ZhtpCli, format_output};
use serde_json::json;

pub async fn handle_component_command(args: ComponentArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        ComponentAction::Start { name } => {
            println!(" Orchestrating component start: {}", name);
            
            let request_body = json!({
                "component": name,
                "action": "start",
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/component/start", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Component start orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate component start: {}", response.status());
            }
        }
        ComponentAction::Stop { name } => {
            println!("⏹️ Orchestrating component stop: {}", name);
            
            let request_body = json!({
                "component": name,
                "action": "stop",
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/component/stop", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Component stop orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate component stop: {}", response.status());
            }
        }
        ComponentAction::Status { name } => {
            println!("Orchestrating component status: {}", name);
            
            let request_body = json!({
                "component": name,
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/component/status", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Component status orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate component status: {}", response.status());
            }
        }
        ComponentAction::Restart { name } => {
            println!(" Orchestrating component restart: {}", name);
            
            let request_body = json!({
                "component": name,
                "action": "restart",
                "orchestrated": true
            });
            
            let response = client
                .post(&format!("{}/component/restart", base_url))
                .json(&request_body)
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Component restart orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate component restart: {}", response.status());
            }
        }
        ComponentAction::List => {
            println!("Orchestrating component list...");
            
            let response = client
                .get(&format!("{}/component/list", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Component list orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate component list: {}", response.status());
            }
        }
    }
    
    Ok(())
}
