//! System monitoring commands for ZHTP orchestrator

use anyhow::Result;
use crate::argument_parsing::{MonitorArgs, MonitorAction, ZhtpCli, format_output};

pub async fn handle_monitor_command(args: MonitorArgs, cli: &ZhtpCli) -> Result<()> {
    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    match args.action {
        MonitorAction::System => {
            println!("🖥️ Orchestrating system monitoring...");
            
            let response = client
                .get(&format!("{}/monitor/system", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("System monitoring orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate system monitoring: {}", response.status());
            }
        }
        MonitorAction::Health => {
            println!("Orchestrating health check for all components...");
            
            let response = client
                .get(&format!("{}/monitor/health", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Health check orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate health check: {}", response.status());
            }
        }
        MonitorAction::Performance => {
            println!(" Orchestrating performance metrics...");
            
            let response = client
                .get(&format!("{}/monitor/performance", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Performance metrics orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate performance metrics: {}", response.status());
            }
        }
        MonitorAction::Logs => {
            println!("Orchestrating log retrieval...");
            
            let response = client
                .get(&format!("{}/monitor/logs", base_url))
                .send()
                .await?;
                
            if response.status().is_success() {
                let result: serde_json::Value = response.json().await?;
                let formatted = format_output(&result, &cli.format)?;
                println!("Logs orchestrated:");
                println!("{}", formatted);
            } else {
                println!("Failed to orchestrate log retrieval: {}", response.status());
            }
        }
    }
    
    Ok(())
}
