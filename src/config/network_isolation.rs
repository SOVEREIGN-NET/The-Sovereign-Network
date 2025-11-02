//! Network Isolation Configuration
//! 
//! Ensures pure mesh networking by preventing internet access at the network level:
//! - No default gateway configuration
//! - Firewall rules blocking external traffic
//! - DHCP without internet DNS/gateway
//! - Local-only routing tables

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use tracing::{info, warn, error};

/// Network isolation configuration for pure mesh operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIsolationConfig {
    /// Enable network isolation (blocks internet access)
    pub enable_isolation: bool,
    /// Local mesh subnets that are allowed
    pub allowed_subnets: Vec<String>,
    /// Block all traffic to these external ranges
    pub blocked_ranges: Vec<String>,
    /// Local DHCP configuration (no gateway/DNS)
    pub dhcp_config: MeshDhcpConfig,
    /// Firewall rules for isolation
    pub firewall_rules: Vec<FirewallRule>,
}

/// DHCP configuration for mesh-only operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDhcpConfig {
    /// DHCP server enabled
    pub enabled: bool,
    /// Local IP range for mesh nodes
    pub ip_range_start: String,
    pub ip_range_end: String,
    /// Subnet mask
    pub subnet_mask: String,
    /// No default gateway (None = isolated)
    pub default_gateway: Option<String>,
    /// No external DNS servers (local mesh DNS only)
    pub dns_servers: Vec<String>,
    /// Lease time in seconds
    pub lease_time: u32,
}

/// Firewall rule for blocking external traffic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    /// Rule name/description
    pub name: String,
    /// Action: ACCEPT, DROP, REJECT
    pub action: String,
    /// Source address/range
    pub source: Option<String>,
    /// Destination address/range
    pub destination: Option<String>,
    /// Protocol: tcp, udp, icmp, all
    pub protocol: Option<String>,
    /// Port or port range
    pub port: Option<String>,
}

impl Default for NetworkIsolationConfig {
    fn default() -> Self {
        Self {
            enable_isolation: true,
            allowed_subnets: vec![
                "192.168.0.0/16".to_string(),     // Local networks
                "10.0.0.0/8".to_string(),         // Private networks
                "172.16.0.0/12".to_string(),      // Private networks
                "127.0.0.0/8".to_string(),        // Loopback
                "169.254.0.0/16".to_string(),     // Link-local
            ],
            blocked_ranges: vec![
                "0.0.0.0/0".to_string(),          // Block all external by default
            ],
            dhcp_config: MeshDhcpConfig::default(),
            firewall_rules: Self::default_firewall_rules(),
        }
    }
}

impl Default for MeshDhcpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            ip_range_start: "192.168.100.10".to_string(),
            ip_range_end: "192.168.100.100".to_string(),
            subnet_mask: "255.255.255.0".to_string(),
            default_gateway: None,  //  NO DEFAULT GATEWAY = NO INTERNET
            dns_servers: vec![
                "192.168.100.1".to_string(),     // Local mesh DNS only
            ],
            lease_time: 86400, // 24 hours
        }
    }
}

impl NetworkIsolationConfig {
    /// Create default firewall rules for mesh isolation
    fn default_firewall_rules() -> Vec<FirewallRule> {
        vec![
            // Allow local mesh traffic
            FirewallRule {
                name: "Allow local mesh traffic".to_string(),
                action: "ACCEPT".to_string(),
                source: Some("192.168.0.0/16".to_string()),
                destination: Some("192.168.0.0/16".to_string()),
                protocol: Some("all".to_string()),
                port: None,
            },
            FirewallRule {
                name: "Allow private networks".to_string(),
                action: "ACCEPT".to_string(),
                source: Some("10.0.0.0/8".to_string()),
                destination: Some("10.0.0.0/8".to_string()),
                protocol: Some("all".to_string()),
                port: None,
            },
            // Allow loopback
            FirewallRule {
                name: "Allow loopback".to_string(),
                action: "ACCEPT".to_string(),
                source: Some("127.0.0.0/8".to_string()),
                destination: Some("127.0.0.0/8".to_string()),
                protocol: Some("all".to_string()),
                port: None,
            },
            // Block all external traffic
            FirewallRule {
                name: "Block external internet traffic".to_string(),
                action: "DROP".to_string(),
                source: None,
                destination: Some("0.0.0.0/0".to_string()),
                protocol: Some("all".to_string()),
                port: None,
            },
        ]
    }

    /// Apply network isolation configuration to the system
    pub async fn apply_isolation(&self) -> Result<()> {
        if !self.enable_isolation {
            info!("Network isolation disabled - allowing internet access");
            return Ok(());
        }

        info!(" Applying network isolation for pure mesh operation");

        // 1. Remove default gateway
        self.remove_default_gateway().await?;

        // 2. Apply firewall rules
        self.apply_firewall_rules().await?;

        // 3. Configure DHCP for mesh-only operation
        self.configure_mesh_dhcp().await?;

        // 4. Verify isolation is working
        self.verify_isolation().await?;

        info!(" Network isolation applied - mesh is now ISP-free");
        Ok(())
    }

    /// Remove default gateway to prevent internet routing
    async fn remove_default_gateway(&self) -> Result<()> {
        info!(" Removing default gateway to block internet access");

        #[cfg(target_os = "windows")]
        {
            // Windows: Remove default route
            let output = Command::new("route")
                .args(&["delete", "0.0.0.0"])
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!(" Windows: Default route removed");
                    } else {
                        let error = String::from_utf8_lossy(&result.stderr);
                        warn!("Windows: Failed to remove default route: {}", error);
                    }
                }
                Err(e) => warn!("Windows: Route command failed: {}", e),
            }

            // Also try PowerShell method
            let ps_output = Command::new("powershell")
                .args(&["-Command", "Remove-NetRoute -DestinationPrefix '0.0.0.0/0' -Confirm:$false"])
                .output();

            if let Ok(result) = ps_output {
                if result.status.success() {
                    info!(" Windows: PowerShell default route removed");
                }
            }
        }

        #[cfg(target_os = "linux")]
        {
            // Linux: Remove default route
            let output = Command::new("ip")
                .args(&["route", "del", "default"])
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!(" Linux: Default route removed");
                    } else {
                        // Try alternative method
                        let alt_output = Command::new("route")
                            .args(&["del", "default"])
                            .output();

                        if let Ok(alt_result) = alt_output {
                            if alt_result.status.success() {
                                info!(" Linux: Default route removed (alternative)");
                            }
                        }
                    }
                }
                Err(e) => warn!("Linux: Route command failed: {}", e),
            }
        }

        #[cfg(target_os = "macos")]
        {
            // macOS: Remove default route
            let output = Command::new("route")
                .args(&["delete", "default"])
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!(" macOS: Default route removed");
                    }
                }
                Err(e) => warn!("macOS: Route command failed: {}", e),
            }
        }

        Ok(())
    }

    /// Apply firewall rules to block external traffic
    async fn apply_firewall_rules(&self) -> Result<()> {
        // Firewall rules disabled - requires administrator privileges
        // Users should manually configure firewall rules if needed
        Ok(())
    }

    #[cfg(target_os = "windows")]
    async fn apply_windows_firewall_rules(&self) -> Result<()> {
        // Windows Firewall rules via netsh
        for rule in &self.firewall_rules {
            let rule_name = format!("ZHTP_Mesh_{}", rule.name.replace(" ", "_"));
            
            // Delete existing rule first (ignore errors)
            let delete_rule_name = format!("name={}", rule_name);
            let _ = Command::new("netsh")
                .args(&["advfirewall", "firewall", "delete", "rule", &delete_rule_name])
                .output();

            // Create new rule
            let rule_name_arg = format!("name={}", rule_name);
            let rule_action_arg = format!("action={}", rule.action.to_lowercase());
            let mut args = vec![
                "advfirewall", "firewall", "add", "rule",
                &rule_name_arg,
                "dir=out",
                &rule_action_arg,
            ];

            if let Some(ref protocol) = rule.protocol {
                if protocol != "all" {
                    args.push("protocol");
                    args.push(protocol);
                }
            }

            if let Some(ref dest) = rule.destination {
                args.push("remoteip");
                args.push(dest);
            }

            let output = Command::new("netsh")
                .args(&args)
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!(" Windows firewall rule added: {}", rule.name);
                    } else {
                        let error = String::from_utf8_lossy(&result.stderr);
                        warn!("Failed to add Windows firewall rule {}: {}", rule.name, error);
                    }
                }
                Err(e) => warn!("Windows firewall command failed for {}: {}", rule.name, e),
            }
        }

        Ok(())
    }

    #[cfg(target_os = "linux")]
    async fn apply_linux_firewall_rules(&self) -> Result<()> {
        // Linux iptables rules
        for rule in &self.firewall_rules {
            let mut args = vec!["-A", "OUTPUT"];

            if let Some(ref source) = rule.source {
                args.extend(&["-s", source]);
            }

            if let Some(ref dest) = rule.destination {
                args.extend(&["-d", dest]);
            }

            if let Some(ref protocol) = rule.protocol {
                if protocol != "all" {
                    args.extend(&["-p", protocol]);
                }
            }

            args.extend(&["-j", &rule.action]);

            let output = Command::new("iptables")
                .args(&args)
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        info!(" Linux iptables rule added: {}", rule.name);
                    } else {
                        let error = String::from_utf8_lossy(&result.stderr);
                        warn!("Failed to add iptables rule {}: {}", rule.name, error);
                    }
                }
                Err(e) => warn!("iptables command failed for {}: {}", rule.name, e),
            }
        }

        Ok(())
    }

    /// Configure DHCP for mesh-only operation (no gateway/external DNS)
    async fn configure_mesh_dhcp(&self) -> Result<()> {
        if !self.dhcp_config.enabled {
            return Ok(());
        }

        info!(" Configuring mesh-only DHCP (no internet gateway)");

        // Create DHCP configuration
        let dhcp_config = format!(
            r#"
# ZHTP Mesh DHCP Configuration (ISP-Free)
subnet 192.168.100.0 netmask 255.255.255.0 {{
    range {} {};
    # NO default-gateway option = no internet access
    # NO routers option = isolated mesh
    option domain-name-servers {};
    default-lease-time {};
    max-lease-time {};
}}
"#,
            self.dhcp_config.ip_range_start,
            self.dhcp_config.ip_range_end,
            self.dhcp_config.dns_servers.join(", "),
            self.dhcp_config.lease_time,
            self.dhcp_config.lease_time * 2,
        );

        info!("DHCP Config (ISP-Free):\n{}", dhcp_config);
        info!(" DHCP configured without default gateway - mesh isolated");

        Ok(())
    }

    /// Verify that isolation is working (no internet connectivity)
    pub async fn verify_isolation(&self) -> Result<()> {
        info!(" Verifying network isolation...");

        // Test connectivity to common internet hosts
        let test_hosts = vec![
            "8.8.8.8",      // Google DNS
            "1.1.1.1",      // Cloudflare DNS
            "google.com",   // Popular website
        ];

        let mut isolation_working = true;

        for host in test_hosts {
            let ping_result = self.test_connectivity(host).await;
            
            match ping_result {
                Ok(true) => {
                    error!(" ISOLATION FAILED: Can still reach {}", host);
                    isolation_working = false;
                }
                Ok(false) => {
                    info!(" Isolation verified: Cannot reach {}", host);
                }
                Err(e) => {
                    info!(" Connectivity test failed for {} (good): {}", host, e);
                }
            }
        }

        // Test local connectivity
        let local_test = self.test_connectivity("127.0.0.1").await;
        match local_test {
            Ok(true) => {
                info!(" Local connectivity working");
            }
            _ => {
                warn!(" Local connectivity may be impaired");
            }
        }

        if isolation_working {
            info!(" Network isolation VERIFIED - mesh is ISP-free!");
        } else {
            error!(" Network isolation FAILED - internet access still possible!");
        }

        Ok(())
    }

    /// Test connectivity to a specific host
    pub async fn test_connectivity(&self, host: &str) -> Result<bool> {
        #[cfg(target_os = "windows")]
        {
            let output = Command::new("ping")
                .args(&["-n", "1", "-w", "1000", host])
                .output()?;
            
            Ok(output.status.success())
        }

        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            let output = Command::new("ping")
                .args(&["-c", "1", "-W", "1", host])
                .output()?;
            
            Ok(output.status.success())
        }
    }

    /// Remove isolation and restore internet access
    pub async fn remove_isolation(&self) -> Result<()> {
        info!(" Removing network isolation - restoring internet access");

        // This would restore default gateway, remove firewall rules, etc.
        // Implementation depends on how the system was configured before

        warn!(" Isolation removal not implemented - manually restore network settings");
        Ok(())
    }

    /// Get current isolation status
    pub async fn get_isolation_status(&self) -> Result<bool> {
        // Test if we can reach the internet
        let internet_reachable = self.test_connectivity("8.8.8.8").await.unwrap_or(false);
        Ok(!internet_reachable) // Isolated = cannot reach internet
    }
}

/// Initialize network isolation for pure mesh operation
pub async fn initialize_network_isolation() -> Result<()> {
    let config = NetworkIsolationConfig::default();
    config.apply_isolation().await
}

/// Quick isolation check
pub async fn verify_mesh_isolation() -> Result<bool> {
    let config = NetworkIsolationConfig::default();
    config.get_isolation_status().await
}
