//! Network Isolation CLI Commands
//! 
//! Commands for managing network isolation and ensuring ISP-free mesh operation

use anyhow::Result;
use zhtp::config::network_isolation::{NetworkIsolationConfig, initialize_network_isolation, verify_mesh_isolation};
use crate::argument_parsing::{IsolationArgs, IsolationAction, ZhtpCli};

/// Apply network isolation to block internet access
pub async fn apply_isolation() -> Result<String> {
    match initialize_network_isolation().await {
        Ok(()) => {
            // Verify it worked
            match verify_mesh_isolation().await {
                Ok(true) => Ok(" Network isolation applied successfully - mesh is now ISP-free!".to_string()),
                Ok(false) => Ok(" Network isolation applied but internet access still detected".to_string()),
                Err(e) => Ok(format!("Network isolation applied but verification failed: {}", e)),
            }
        },
        Err(e) => Ok(format!("Failed to apply network isolation: {}", e)),
    }
}

/// Check current network isolation status
pub async fn check_isolation_status() -> Result<String> {
    match verify_mesh_isolation().await {
        Ok(true) => Ok(" Network is isolated - no internet access (ISP-free mesh)".to_string()),
        Ok(false) => Ok(" Network has internet access - not isolated".to_string()),
        Err(e) => Ok(format!("Could not determine isolation status: {}", e)),
    }
}

/// Show network isolation configuration
pub async fn show_isolation_config() -> Result<String> {
    let config = NetworkIsolationConfig::default();
    
    let mut output = String::new();
    output.push_str(" Network Isolation Configuration:\n");
    output.push_str(&format!("Isolation enabled: {}\n", config.enable_isolation));
    output.push_str("Allowed subnets:\n");
    for subnet in &config.allowed_subnets {
        output.push_str(&format!("  - {}\n", subnet));
    }
    output.push_str("DHCP Configuration:\n");
    output.push_str(&format!("  IP range: {} - {}\n", 
        config.dhcp_config.ip_range_start, 
        config.dhcp_config.ip_range_end));
    output.push_str(&format!("  Default gateway: {:?}\n", config.dhcp_config.default_gateway));
    output.push_str(&format!("  DNS servers: {:?}\n", config.dhcp_config.dns_servers));
    
    Ok(output)
}

/// Remove network isolation (restore internet access)
pub async fn remove_isolation() -> Result<String> {
    let config = NetworkIsolationConfig::default();
    
    match config.remove_isolation().await {
        Ok(()) => Ok(" Network isolation removed - internet access restored".to_string()),
        Err(e) => Ok(format!("Failed to remove network isolation: {}", e)),
    }
}

/// Test network connectivity
pub async fn test_connectivity() -> Result<String> {
    let config = NetworkIsolationConfig::default();
    
    let mut output = String::new();
    output.push_str(" Testing network connectivity:\n");
    
    // Test local connectivity
    match config.test_connectivity("127.0.0.1").await {
        Ok(true) => output.push_str(" Local (127.0.0.1): Reachable\n"),
        Ok(false) => output.push_str(" Local (127.0.0.1): Not reachable\n"),
        Err(e) => output.push_str(&format!(" Local (127.0.0.1): Test failed - {}\n", e)),
    }
    
    // Test internet connectivity
    let internet_hosts = vec!["8.8.8.8", "1.1.1.1", "google.com"];
    for host in internet_hosts {
        match config.test_connectivity(host).await {
            Ok(true) => output.push_str(&format!(" Internet ({}): Reachable (isolation may be broken)\n", host)),
            Ok(false) => output.push_str(&format!(" Internet ({}): Not reachable (good isolation)\n", host)),
            Err(e) => output.push_str(&format!(" Internet ({}): Test failed (good isolation) - {}\n", host, e)),
        }
    }
    
    Ok(output)
}

/// Main handler for isolation CLI commands
pub async fn handle_isolation_command(args: IsolationArgs, _cli: &ZhtpCli) -> Result<()> {
    match args.action {
        IsolationAction::Apply => {
            let result = apply_isolation().await?;
            println!("{}", result);
        }
        IsolationAction::Check => {
            let result = check_isolation_status().await?;
            println!("{}", result);
        }
        IsolationAction::Remove => {
            let result = remove_isolation().await?;
            println!("{}", result);
        }
        IsolationAction::Test => {
            let result = test_connectivity().await?;
            println!("{}", result);
        }
    }
    Ok(())
}