//! Cross-Package Configuration Validation
//! 
//! Ensures configuration consistency across all ZHTP packages

use anyhow::Result;
use std::collections::HashMap;
use super::{NodeConfig, ConfigError};
use tracing::{info, warn, error};

/// Validate complete configuration across all packages
pub async fn validate_complete_configuration(config: &NodeConfig) -> Result<()> {
    info!("Validating configuration across {} packages...", config.package_count());
    
    // Validate port assignments
    validate_port_assignments(config)?;
    
    // Validate resource allocations
    validate_resource_allocations(config)?;
    
    // Validate security consistency
    validate_security_consistency(config)?;
    
    // Validate mesh mode configuration
    validate_mesh_mode_configuration(config)?;
    
    // Validate consensus parameters
    validate_consensus_parameters(config)?;
    
    // Validate economic parameters
    validate_economic_parameters(config)?;
    
    // Validate cross-package integration
    validate_integration_settings(config)?;
    
    info!("Configuration validation completed successfully");
    Ok(())
}

/// Validate that no packages are using conflicting ports
fn validate_port_assignments(config: &NodeConfig) -> Result<()> {
    let mut used_ports = HashMap::new();
    let mut conflicts = Vec::new();
    
    // Special handling for unified server: mesh and API can share port 9333
    let unified_server_port = 9333;
    let is_unified_mode = config.network_config.mesh_port == unified_server_port 
                       && config.protocols_config.api_port == unified_server_port;
    
    if is_unified_mode {
        // In unified mode, mesh and API intentionally share the same port
        used_ports.insert(unified_server_port, "unified-server".to_string());
        info!("Using unified server mode - mesh and API protocols share port {}", unified_server_port);
    } else {
        // Check mesh port
        if let Some(existing) = used_ports.insert(config.network_config.mesh_port, "mesh".to_string()) {
            conflicts.push((config.network_config.mesh_port, vec!["mesh".to_string(), existing]));
        }
        
        // Check API port
        if let Some(existing) = used_ports.insert(config.protocols_config.api_port, "protocols-api".to_string()) {
            conflicts.push((config.protocols_config.api_port, vec!["protocols-api".to_string(), existing]));
        }
    }
    
    // Check DHT port (always separate)
    if let Some(existing) = used_ports.insert(config.storage_config.dht_port, "storage-dht".to_string()) {
        conflicts.push((config.storage_config.dht_port, vec!["storage-dht".to_string(), existing]));
    }
    
    // Check for standard port conflicts
    let standard_ports = [22, 53, 80, 443, 8080, 3000, 5432, 27017];
    for &port in &standard_ports {
        if used_ports.contains_key(&port) {
            warn!(" Using standard system port {}: {}", port, used_ports[&port]);
        }
    }
    
    // Report conflicts
    if !conflicts.is_empty() {
        let first_conflict_port = conflicts[0].0;
        for (port, packages) in &conflicts {
            error!("Port conflict on {}: used by {:?}", port, packages);
        }
        return Err(ConfigError::PortConflict { port: first_conflict_port }.into());
    }
    
    info!("Port assignments validated - no conflicts detected");
    Ok(())
}

/// Validate resource allocation consistency
fn validate_resource_allocations(config: &NodeConfig) -> Result<()> {
    let allocations = &config.resource_allocations;
    
    // Check memory allocations
    let total_allocated_memory = allocations.bandwidth_allocation.len() * 100; // Rough estimate
    if total_allocated_memory > allocations.max_memory_mb {
        warn!("Memory allocation may exceed available memory");
    }
    
    // Check CPU thread allocations
    let crypto_threads = config.zk_config.verification_threads;
    let total_threads = crypto_threads + 4; // Base threads for other operations
    if total_threads > allocations.max_cpu_threads {
        warn!("Thread allocation exceeds available CPU threads");
    }
    
    // Check storage capacity
    if config.storage_config.storage_capacity_gb > allocations.max_disk_gb {
        return Err(ConfigError::ResourceConflict {
            details: format!(
                "Storage capacity ({} GB) exceeds max disk allocation ({} GB)",
                config.storage_config.storage_capacity_gb,
                allocations.max_disk_gb
            )
        }.into());
    }
    
    info!("Resource allocations validated");
    Ok(())
}

/// Validate security settings consistency across packages
fn validate_security_consistency(config: &NodeConfig) -> Result<()> {
    // Check post-quantum cryptography consistency
    if config.crypto_config.post_quantum_enabled != (config.security_level != super::SecurityLevel::Basic) {
        warn!("Post-quantum crypto setting doesn't match security level");
    }
    
    // Check ZK proof security level consistency
    let expected_zk_threads = match config.security_level {
        super::SecurityLevel::Basic => 1,
        super::SecurityLevel::Medium => 2,
        super::SecurityLevel::High => 4,
        super::SecurityLevel::Maximum => 8,
    };
    
    if config.zk_config.verification_threads < expected_zk_threads {
        warn!("ZK verification threads below recommended level for security setting");
    }
    
    // Check consensus security requirements
    if config.consensus_config.validator_enabled && config.consensus_config.min_stake < 1000 {
        warn!("Low minimum stake for validator participation");
    }
    
    info!("Security consistency validated");
    Ok(())
}

/// Validate mesh mode configuration
fn validate_mesh_mode_configuration(config: &NodeConfig) -> Result<()> {
    // Validate pure mesh mode requirements
    config.validate_pure_mesh_mode()?;
    
    // Check protocol availability for mesh mode
    let available_protocols: Vec<String> = config.network_config.protocols.clone();
    config.mesh_mode.validate_capabilities(&available_protocols)
        .map_err(|e| anyhow::anyhow!("Mesh mode validation failed: {}", e))?;
    
    // Check long-range relay requirements
    if config.mesh_mode == super::MeshMode::PureMesh && !config.network_config.long_range_relays {
        warn!("Pure mesh mode without long-range relays may have limited global reach");
    }
    
    // Check bootstrap peer configuration
    if config.mesh_mode == super::MeshMode::PureMesh && config.network_config.bootstrap_peers.is_empty() {
        warn!("Pure mesh mode without bootstrap peers may have connectivity issues");
    }
    
    info!("Mesh mode configuration validated");
    Ok(())
}

/// Validate consensus parameters
fn validate_consensus_parameters(config: &NodeConfig) -> Result<()> {
    let consensus = &config.consensus_config;
    
    // Check consensus type compatibility with other settings
    match consensus.consensus_type.as_str() {
        "PoS" => {
            if consensus.min_stake == 0 {
                return Err(ConfigError::ResourceConflict {
                    details: "Proof of Stake requires minimum stake > 0".to_string()
                }.into());
            }
        }
        "PoStorage" => {
            if config.storage_config.storage_capacity_gb == 0 {
                return Err(ConfigError::ResourceConflict {
                    details: "Proof of Storage requires storage capacity > 0".to_string()
                }.into());
            }
        }
        "PoUW" => {
            // Proof of Useful Work requires mesh participation
            if config.network_config.max_peers == 0 {
                return Err(ConfigError::ResourceConflict {
                    details: "Proof of Useful Work requires network participation".to_string()
                }.into());
            }
        }
        _ => {} // Other consensus types
    }
    
    // Check DAO configuration
    if consensus.dao_enabled && !config.economics_config.ubi_enabled {
        warn!("DAO enabled but UBI disabled - may affect governance participation");
    }
    
    info!("Consensus parameters validated");
    Ok(())
}

/// Validate economic parameters
fn validate_economic_parameters(config: &NodeConfig) -> Result<()> {
    let economics = &config.economics_config;
    
    // Check UBI parameters
    if economics.ubi_enabled && economics.daily_ubi_amount == 0 {
        warn!("UBI enabled but daily amount is 0");
    }
    
    // Check DAO fee percentage
    if economics.dao_fee_percentage < 0.0 || economics.dao_fee_percentage > 10.0 {
        warn!("DAO fee percentage outside recommended range (0-10%)");
    }
    
    // Check token economics
    let token_economics = &economics.token_economics;
    if token_economics.total_supply == 0 {
        return Err(ConfigError::ResourceConflict {
            details: "Total token supply cannot be 0".to_string()
        }.into());
    }
    
    if token_economics.inflation_rate > 20.0 {
        warn!("High inflation rate may affect token value stability");
    }
    
    // Check reward consistency
    if economics.mesh_rewards && !config.network_config.protocols.contains(&"mesh".to_string()) {
        warn!("Mesh rewards enabled but mesh protocols not configured");
    }
    
    info!("Economic parameters validated");
    Ok(())
}

/// Validate cross-package integration settings
fn validate_integration_settings(config: &NodeConfig) -> Result<()> {
    let integration = &config.integration_settings;
    
    // Check event bus configuration
    if !integration.event_bus_enabled {
        warn!("Event bus disabled - cross-package communication may be limited");
    }
    
    // Check health check intervals
    if integration.health_check_interval_ms < 1000 {
        warn!("Very short health check interval may impact performance");
    }
    
    if integration.health_check_interval_ms > 300000 { // 5 minutes
        warn!("Long health check interval may delay failure detection");
    }
    
    // Check timeout configurations
    for (package, timeout_ms) in &integration.cross_package_timeouts {
        if *timeout_ms < 1000 {
            warn!("Short timeout for package '{}' may cause premature failures", package);
        }
        if *timeout_ms > 60000 { // 1 minute
            warn!("Long timeout for package '{}' may delay error detection", package);
        }
    }
    
    info!("Integration settings validated");
    Ok(())
}

/// Comprehensive configuration health check
pub async fn perform_configuration_health_check(config: &NodeConfig) -> ConfigHealthReport {
    let mut report = ConfigHealthReport::new();
    
    // Check critical settings
    if !config.crypto_config.post_quantum_enabled && config.environment == super::Environment::Mainnet {
        report.add_critical("Post-quantum cryptography disabled in mainnet environment");
    }
    
    if !config.zk_config.plonky2_enabled {
        report.add_warning("Zero-knowledge proofs disabled - privacy features unavailable");
        report.add_recommendation("Enable plonky2_enabled = true in zk_config to activate privacy features");
    }
    
    if config.network_config.max_peers < 10 {
        report.add_warning("Low peer count may affect network resilience");
        report.add_recommendation("Consider increasing max_peers to at least 20 for better network redundancy");
    }
    
    // Check resource adequacy
    if config.resource_allocations.max_memory_mb < 1024 {
        report.add_warning("Low memory allocation may affect performance");
        report.add_recommendation("Increase max_memory_mb to at least 2048 MB for optimal performance");
    }
    
    // Check economic sustainability
    if config.economics_config.ubi_enabled && config.economics_config.daily_ubi_amount > 1000 {
        report.add_warning("High UBI amount may affect economic sustainability");
        report.add_recommendation("Consider reducing daily_ubi_amount below 1000 to maintain economic balance");
    }
    
    report
}

/// Configuration health check report
#[derive(Debug)]
pub struct ConfigHealthReport {
    pub critical_issues: Vec<String>,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

impl ConfigHealthReport {
    fn new() -> Self {
        Self {
            critical_issues: Vec::new(),
            warnings: Vec::new(),
            recommendations: Vec::new(),
        }
    }
    
    fn add_critical(&mut self, issue: &str) {
        self.critical_issues.push(issue.to_string());
    }
    
    fn add_warning(&mut self, warning: &str) {
        self.warnings.push(warning.to_string());
    }
    
    fn add_recommendation(&mut self, recommendation: &str) {
        self.recommendations.push(recommendation.to_string());
    }
    
    pub fn has_critical_issues(&self) -> bool {
        !self.critical_issues.is_empty()
    }
    
    pub fn print_report(&self) {
        if !self.critical_issues.is_empty() {
            error!(" Critical Configuration Issues:");
            for issue in &self.critical_issues {
                error!("   {}", issue);
            }
        }
        
        if !self.warnings.is_empty() {
            warn!("Configuration Warnings:");
            for warning in &self.warnings {
                warn!("   {}", warning);
            }
        }
        
        if !self.recommendations.is_empty() {
            info!("Configuration Recommendations:");
            for rec in &self.recommendations {
                info!("   {}", rec);
            }
        }
        
        if self.critical_issues.is_empty() && self.warnings.is_empty() {
            info!("Configuration health check passed");
        }
    }
}
