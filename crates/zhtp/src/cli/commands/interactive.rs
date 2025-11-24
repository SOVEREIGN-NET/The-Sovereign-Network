//! Interactive shell for ZHTP orchestrator

use anyhow::Result;
use std::io::{self, Write};
use crate::cli::{InteractiveArgs, ZhtpCli, format_output};

pub async fn handle_interactive_command(_args: InteractiveArgs, cli: &ZhtpCli) -> Result<()> {
    println!(" ZHTP Orchestrator Interactive Shell");
    println!("======================================");
    println!("Type 'help' for available commands, 'exit' to quit");
    println!("Server: {}", cli.server);
    println!("Format: {:?}", cli.format);
    println!("");

    let client = reqwest::Client::new();
    let base_url = format!("http://{}/api/v1", cli.server);
    
    loop {
        print!("zhtp> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let input = input.trim();
                
                match input {
                    "exit" | "quit" => {
                        println!("Goodbye!");
                        break;
                    }
                    "help" => {
                        show_interactive_help();
                    }
                    "status" => {
                        if let Err(e) = check_orchestrator_status(&client, &base_url, cli).await {
                            println!("Error: {}", e);
                        }
                    }
                    "health" => {
                        if let Err(e) = check_component_health(&client, &base_url, cli).await {
                            println!("Error: {}", e);
                        }
                    }
                    "components" => {
                        if let Err(e) = list_components(&client, &base_url, cli).await {
                            println!("Error: {}", e);
                        }
                    }
                    "" => continue,
                    _ => {
                        if input.starts_with("start ") {
                            let component = input.strip_prefix("start ").unwrap();
                            if let Err(e) = start_component(&client, &base_url, component, cli).await {
                                println!("Error: {}", e);
                            }
                        } else if input.starts_with("stop ") {
                            let component = input.strip_prefix("stop ").unwrap();
                            if let Err(e) = stop_component(&client, &base_url, component, cli).await {
                                println!("Error: {}", e);
                            }
                        } else if input.starts_with("info ") {
                            let component = input.strip_prefix("info ").unwrap();
                            if let Err(e) = component_info(&client, &base_url, component, cli).await {
                                println!("Error: {}", e);
                            }
                        } else {
                            println!("Unknown command: {}", input);
                            println!("Type 'help' for available commands");
                        }
                    }
                }
            }
            Err(error) => {
                println!("Error reading input: {}", error);
                break;
            }
        }
    }
    
    Ok(())
}

fn show_interactive_help() {
    println!("Available commands:");
    println!("  status      - Show orchestrator status");
    println!("  health      - Check component health");
    println!("  components  - List all components");
    println!("  start <name> - Start a component");
    println!("  stop <name>  - Stop a component");
    println!("  info <name>  - Get component information");
    println!("  help        - Show this help message");
    println!("  exit/quit   - Exit the shell");
    println!("");
    println!("Components: protocols, blockchain, network, consensus, storage, economy, proofs, identity, crypto");
}

async fn check_orchestrator_status(client: &reqwest::Client, base_url: &str, cli: &ZhtpCli) -> Result<()> {
    println!(" Checking orchestrator status...");
    
    let response = client
        .get(&format!("{}/status", base_url))
        .send()
        .await?;
        
    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("{}", formatted);
    } else {
        println!("Orchestrator status unavailable: {}", response.status());
    }
    
    Ok(())
}

async fn check_component_health(client: &reqwest::Client, base_url: &str, cli: &ZhtpCli) -> Result<()> {
    println!("Checking component health...");
    
    let response = client
        .get(&format!("{}/monitor/health", base_url))
        .send()
        .await?;
        
    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("{}", formatted);
    } else {
        println!("Component health check failed: {}", response.status());
    }
    
    Ok(())
}

async fn list_components(client: &reqwest::Client, base_url: &str, cli: &ZhtpCli) -> Result<()> {
    println!("Listing components...");
    
    let response = client
        .get(&format!("{}/component/list", base_url))
        .send()
        .await?;
        
    if response.status().is_success() {
        let result: serde_json::Value = response.json().await?;
        let formatted = format_output(&result, &cli.format)?;
        println!("{}", formatted);
    } else {
        println!("Component list unavailable: {}", response.status());
    }
    
    Ok(())
}

async fn start_component(client: &reqwest::Client, base_url: &str, component: &str, cli: &ZhtpCli) -> Result<()> {
    println!(" Starting component: {}", component);
    
    let request_body = serde_json::json!({
        "component": component,
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
        println!("{}", formatted);
    } else {
        println!("Failed to start component: {}", response.status());
    }
    
    Ok(())
}

async fn stop_component(client: &reqwest::Client, base_url: &str, component: &str, cli: &ZhtpCli) -> Result<()> {
    println!("⏹️ Stopping component: {}", component);
    
    let request_body = serde_json::json!({
        "component": component,
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
        println!("{}", formatted);
    } else {
        println!("Failed to stop component: {}", response.status());
    }
    
    Ok(())
}

async fn component_info(client: &reqwest::Client, base_url: &str, component: &str, cli: &ZhtpCli) -> Result<()> {
    println!("Getting component info: {}", component);
    
    let request_body = serde_json::json!({
        "component": component,
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
        println!("{}", formatted);
    } else {
        println!("Failed to get component info: {}", response.status());
    }
    
    Ok(())
}
