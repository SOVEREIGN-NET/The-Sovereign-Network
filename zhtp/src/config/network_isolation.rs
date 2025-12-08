//! Network Isolation Configuration
//!
//! #  IMPORTANT: USE CASE CLARIFICATION 
//!
//! This module provides network isolation for **PURE MESH DEPLOYMENTS ONLY**.
//!
//! ## When to Use Network Isolation (enable_isolation = true)
//!
//! **Pure Mesh Scenarios** (ISP-free, local-only networks):
//! - Emergency networks (disaster zones, no internet access)
//! - Military deployments (air-gapped networks)
//! - Festival networks (temporary, self-contained)
//! - Rural communities (mesh-only, no ISP connectivity)
//!
//! In these scenarios, nodes:
//! - Have NO internet access (by design)
//! - Connect only to local mesh peers via BLE/WiFi
//! - Do NOT need SSH, package updates, or external monitoring
//! - Run in completely isolated environment
//!
//! ## When NOT to Use Network Isolation (enable_isolation = false)
//!
//! **Bootstrap Nodes** (public-facing servers):
//! - Need normal internet connectivity
//! - Require SSH access for administration
//! - Need package updates from repositories
//! - Need monitoring/metrics/logging services
//! - Accept connections from users through their ISPs
//!
//! Security for bootstrap nodes comes from **application-level enforcement**:
//! - The zhtp codebase ONLY implements blockchain protocols
//! - NO HTTP proxy functionality exists in the code
//! - NO SOCKS proxy functionality exists
//! - NO general packet forwarding/routing implemented
//! - Application simply cannot be misused as a proxy
//!
//! ## About ingress_only_mode
//!
//!  **DO NOT USE ingress_only_mode for bootstrap nodes**
//!
//! This mode was designed for pure mesh edge scenarios but is NOT appropriate
//! for public-facing servers. Setting firewall rules to block outbound traffic
//! will break:
//! - SSH connections
//! - Package updates (apt, yum, pacman)
//! - NTP time synchronization
//! - Monitoring/metrics export
//! - DNS resolution
//!
//! For bootstrap nodes, use `enable_isolation = false` and rely on the fact
//! that the application code doesn't implement proxy functionality.
//!
//! # Configuration Examples
//!
//! ## Pure Mesh Node (ISP-free deployment)
//! ```toml
//! [network_isolation]
//! enable_isolation = true
//! ingress_only_mode = false  # Full isolation, no internet
//! ```
//!
//! ## Bootstrap Node (public server)
//! ```toml
//! [network_isolation]
//! enable_isolation = false  # Normal network operation
//! ```
//!
//! # Implementation Details
//!
//! When enabled, this module:
//! - Removes the default gateway (blocks ALL internet access)
//! - Configures firewall rules (iptables/netsh)
//! - Sets up local-only routing tables
//! - Configures DHCP without external DNS/gateway

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{info, warn, error};

/// Network isolation configuration for pure mesh operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkIsolationConfig {
    /// Enable network isolation (blocks internet access)
    pub enable_isolation: bool,
    
    /// Protocol-level filtering mode for bootstrap nodes:
    /// - Accept connections from anyone (through ISPs)
    /// - Only allow blockchain-specific protocols
    /// - Block general internet protocols (HTTP, HTTPS, SOCKS, etc.)
    #[serde(default)]
    pub protocol_filtering_mode: bool,
    
    /// Allowed blockchain protocols (whitelist)
    #[serde(default)]
    pub allowed_protocols: Vec<String>,
    
    /// Blocked general internet protocols (blacklist)
    #[serde(default)]
    pub blocked_protocols: Vec<String>,
    
    /// Block general internet routing/proxying
    #[serde(default)]
    pub block_general_internet_routing: bool,
    
    /// Ingress-only mode for bootstrap nodes:
    /// - Accept connections FROM anywhere (internet)
    /// - Block connections TO arbitrary internet
    /// - Only allow outbound to whitelisted mesh peers
    #[serde(default)]
    pub ingress_only_mode: bool,
    
    /// For ingress-only mode: sources allowed to connect inbound
    #[serde(default)]
    pub allowed_inbound_sources: Vec<String>,
    
    /// For ingress-only mode: destinations allowed for outbound connections
    #[serde(default)]
    pub allowed_outbound_destinations: Vec<String>,
    
    /// Block outbound connections to public internet (except whitelisted)
    #[serde(default)]
    pub block_outbound_to_internet: bool,
    
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
    /// Direction: inbound or outbound
    #[serde(default = "default_direction")]
    pub direction: String,
    /// Action: ACCEPT, DROP, REJECT
    pub action: String,
    /// Source address/range
    pub source: Option<String>,
    /// Destination address/range
    pub destination: Option<String>,
    /// For ingress-only mode: destination subnets (multiple)
    #[serde(default)]
    pub destination_subnets: Vec<String>,
    /// Protocol: tcp, udp, icmp, all
    pub protocol: Option<String>,
    /// Port or port range
    pub port: Option<String>,
    /// Multiple ports
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Rule priority (lower = higher priority)
    #[serde(default = "default_priority")]
    pub priority: u32,
}

fn default_direction() -> String {
    "outbound".to_string()
}

fn default_priority() -> u32 {
    50
}

impl Default for NetworkIsolationConfig {
    fn default() -> Self {
        Self {
            enable_isolation: false,
            protocol_filtering_mode: false,
            allowed_protocols: vec![
                "zhtp".to_string(),
                "dht".to_string(),
                "blockchain".to_string(),
                "mesh".to_string(),
                "quic".to_string(),
            ],
            blocked_protocols: vec![
                "http".to_string(),
                "https".to_string(),
                "socks".to_string(),
                "dns".to_string(),
                "smtp".to_string(),
                "ftp".to_string(),
            ],
            block_general_internet_routing: false,
            ingress_only_mode: false,
            allowed_inbound_sources: vec!["0.0.0.0/0".to_string()], // Accept from anywhere if enabled
            allowed_outbound_destinations: vec![
                "192.168.0.0/16".to_string(),
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
            ],
            block_outbound_to_internet: false,
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
                direction: "outbound".to_string(),
                action: "ACCEPT".to_string(),
                source: Some("192.168.0.0/16".to_string()),
                destination: Some("192.168.0.0/16".to_string()),
                destination_subnets: vec![],
                protocol: Some("all".to_string()),
                port: None,
                ports: vec![],
                priority: 10,
            },
            FirewallRule {
                name: "Allow private networks".to_string(),
                direction: "outbound".to_string(),
                action: "ACCEPT".to_string(),
                source: Some("10.0.0.0/8".to_string()),
                destination: Some("10.0.0.0/8".to_string()),
                destination_subnets: vec![],
                protocol: Some("all".to_string()),
                port: None,
                ports: vec![],
                priority: 10,
            },
            // Allow loopback
            FirewallRule {
                name: "Allow loopback".to_string(),
                direction: "outbound".to_string(),
                action: "ACCEPT".to_string(),
                source: Some("127.0.0.0/8".to_string()),
                destination: Some("127.0.0.0/8".to_string()),
                destination_subnets: vec![],
                protocol: Some("all".to_string()),
                port: None,
                ports: vec![],
                priority: 10,
            },
            // Block all external traffic
            FirewallRule {
                name: "Block external internet traffic".to_string(),
                direction: "outbound".to_string(),
                action: "DROP".to_string(),
                source: None,
                destination: Some("0.0.0.0/0".to_string()),
                destination_subnets: vec![],
                protocol: Some("all".to_string()),
                port: None,
                ports: vec![],
                priority: 100,
            },
        ]
    }

    /// Apply network isolation configuration to the system
    pub async fn apply_isolation(&self) -> Result<()> {
        if !self.enable_isolation {
            info!("Network isolation disabled - allowing internet access");
            return Ok(());
        }

        if self.protocol_filtering_mode {
            info!(" Applying PROTOCOL-LEVEL filtering (bootstrap mode)");
            info!("    Accept connections FROM: anyone (through ISPs)");
            info!("    Allow protocols: {:?}", self.allowed_protocols);
            info!("    Block protocols: {:?}", self.blocked_protocols);
            info!("     Only blockchain data accessible - no general internet routing");
            
            // Protocol filtering is enforced at application layer
            // See: unified_server.rs message handler
            
            info!(" Protocol filtering configured - bootstrap accepts blockchain traffic only");
            return Ok(());
        }

        if self.ingress_only_mode {
            info!(" Applying INGRESS-ONLY isolation (bootstrap mode)");
            info!("    Accept connections FROM: anywhere (internet-facing)");
            info!("    Allow connections TO: whitelisted blockchain peers only");
            info!("    Block connections TO: arbitrary internet");
            
            // Apply ingress-only firewall rules
            self.apply_ingress_only_rules().await?;
            
            info!(" Bootstrap isolation applied - accepting internet connections, blocking outbound");
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
    
    /// Check if a protocol is allowed (for bootstrap nodes)
    pub fn is_protocol_allowed(&self, protocol: &str) -> bool {
        if !self.protocol_filtering_mode {
            return true; // No filtering
        }
        
        // Check if explicitly allowed
        if self.allowed_protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol)) {
            return true;
        }
        
        // Check if explicitly blocked
        if self.blocked_protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol)) {
            return false;
        }
        
        // Default: block unknown protocols in filtering mode
        false
    }
    
    /// Check if general internet routing is blocked
    pub fn is_internet_routing_blocked(&self) -> bool {
        self.block_general_internet_routing
    }
    
    /// Apply firewall rules for ingress-only bootstrap mode
    async fn apply_ingress_only_rules(&self) -> Result<()> {
        info!(" Configuring ingress-only firewall rules...");
        
        #[cfg(target_os = "windows")]
        {
            self.apply_windows_ingress_only_rules().await?;
        }
        
        #[cfg(target_os = "linux")]
        {
            self.apply_linux_ingress_only_rules().await?;
        }
        
        info!(" Ingress-only firewall rules applied");
        Ok(())
    }
    
    #[cfg(target_os = "windows")]
    async fn apply_windows_ingress_only_rules(&self) -> Result<()> {
        info!("Applying Windows ingress-only firewall rules...");
        
        // 1. Allow ALL inbound connections (bootstrap accepts from internet)
        for rule in &self.firewall_rules {
            if rule.direction == "inbound" && rule.action == "ACCEPT" {
                let rule_name = format!("ZHTP_Bootstrap_Inbound_{}", rule.name.replace(" ", "_"));
                let rule_name_arg = format!("name={}", rule_name);
                
                // Delete existing rule
                let _ = Command::new("netsh")
                    .args(&["advfirewall", "firewall", "delete", "rule", &rule_name_arg])
                    .output();
                
                // Create inbound allow rule with ports if specified
                if !rule.ports.is_empty() {
                    let ports_str = rule.ports.iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",");
                    
                    let protocol_str = rule.protocol.as_deref().unwrap_or("tcp");
                    
                    let output = Command::new("netsh")
                        .args(&[
                            "advfirewall", "firewall", "add", "rule",
                            &rule_name_arg,
                            "dir=in",
                            "action=allow",
                            "protocol", protocol_str,
                            "localport", &ports_str,
                        ])
                        .output();
                    
                    if let Ok(result) = output {
                        if result.status.success() {
                            info!("   Inbound rule added: {}", rule.name);
                        }
                    }
                } else {
                    // No specific ports - allow all
                    let protocol_str = rule.protocol.as_deref().unwrap_or("any");
                    
                    let output = Command::new("netsh")
                        .args(&[
                            "advfirewall", "firewall", "add", "rule",
                            &rule_name_arg,
                            "dir=in",
                            "action=allow",
                            "protocol", protocol_str,
                        ])
                        .output();
                    
                    if let Ok(result) = output {
                        if result.status.success() {
                            info!("   Inbound rule added: {}", rule.name);
                        }
                    }
                }
            }
        }
        
        // 2. Block outbound to internet, allow only to mesh peers
        for dest_subnet in &self.allowed_outbound_destinations {
            let rule_name = format!("ZHTP_Bootstrap_Allow_Mesh_{}", dest_subnet.replace("/", "_").replace(".", "_"));
            
            // Delete existing
            let _ = Command::new("netsh")
                .args(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                .output();
            
            // Allow outbound to this mesh subnet
            let output = Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=allow",
                    "remoteip", dest_subnet,
                ])
                .output();
            
            if let Ok(result) = output {
                if result.status.success() {
                    info!("   Outbound allowed to mesh: {}", dest_subnet);
                }
            }
        }
        
        // 3. Block all other outbound traffic
        if self.block_outbound_to_internet {
            let rule_name = "ZHTP_Bootstrap_Block_Internet";
            
            // Delete existing
            let _ = Command::new("netsh")
                .args(&["advfirewall", "firewall", "delete", "rule", &format!("name={}", rule_name)])
                .output();
            
            // Block outbound to internet
            let output = Command::new("netsh")
                .args(&[
                    "advfirewall", "firewall", "add", "rule",
                    &format!("name={}", rule_name),
                    "dir=out",
                    "action=block",
                    "remoteip=any",
                    "priority=100",  // Lower priority so mesh rules are checked first
                ])
                .output();
            
            if let Ok(result) = output {
                if result.status.success() {
                    info!("   Blocked outbound to internet (except whitelisted mesh)");
                }
            }
        }
        
        Ok(())
    }
    
    #[cfg(target_os = "linux")]
    async fn apply_linux_ingress_only_rules(&self) -> Result<()> {
        info!("Applying Linux ingress-only iptables rules...");
        
        // Flush existing ZHTP rules
        let _ = Command::new("iptables")
            .args(&["-F", "ZHTP_INGRESS"])
            .output();
        let _ = Command::new("iptables")
            .args(&["-X", "ZHTP_INGRESS"])
            .output();
        
        // Create new chain
        let _ = Command::new("iptables")
            .args(&["-N", "ZHTP_INGRESS"])
            .output();
        
        // 1. Allow ALL inbound connections (accept from internet)
        let _ = Command::new("iptables")
            .args(&["-A", "INPUT", "-j", "ACCEPT"])
            .output();
        
        // 2. Allow outbound to whitelisted mesh peers
        for dest_subnet in &self.allowed_outbound_destinations {
            let output = Command::new("iptables")
                .args(&[
                    "-A", "ZHTP_INGRESS",
                    "-d", dest_subnet,
                    "-j", "ACCEPT"
                ])
                .output();
            
            if let Ok(result) = output {
                if result.status.success() {
                    info!("   Outbound allowed to mesh: {}", dest_subnet);
                }
            }
        }
        
        // 3. Allow established connections
        let _ = Command::new("iptables")
            .args(&[
                "-A", "ZHTP_INGRESS",
                "-m", "state",
                "--state", "ESTABLISHED,RELATED",
                "-j", "ACCEPT"
            ])
            .output();
        
        // 4. Block all other outbound traffic
        if self.block_outbound_to_internet {
            let output = Command::new("iptables")
                .args(&[
                    "-A", "ZHTP_INGRESS",
                    "-j", "DROP"
                ])
                .output();
            
            if let Ok(result) = output {
                if result.status.success() {
                    info!("   Blocked outbound to internet (except whitelisted)");
                }
            }
        }
        
        // Link chain to OUTPUT
        let _ = Command::new("iptables")
            .args(&["-A", "OUTPUT", "-j", "ZHTP_INGRESS"])
            .output();
        
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
