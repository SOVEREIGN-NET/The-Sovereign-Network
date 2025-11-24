//! Platform Isolation Implementation
//!
//! Provides secure isolation of WASM contracts from the host platform.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::contracts::runtime::{SandboxConfig};
use crate::contracts::runtime::sandbox::SecurityLevel;

/// Platform isolation manager for WASM contracts
#[derive(Debug)]
pub struct PlatformIsolationManager {
    /// Active isolation contexts
    isolation_contexts: HashMap<String, IsolationContext>,
    /// Global isolation configuration
    global_config: PlatformIsolationConfig,
}

/// Configuration for platform isolation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformIsolationConfig {
    /// Enable file system isolation
    pub enable_filesystem_isolation: bool,
    /// Enable network isolation
    pub enable_network_isolation: bool,
    /// Enable process isolation
    pub enable_process_isolation: bool,
    /// Maximum memory per contract
    pub max_memory_per_contract: u64,
    /// Maximum CPU time per contract
    pub max_cpu_time_ms: u64,
    /// Allowed system calls (whitelist)
    pub allowed_syscalls: Vec<String>,
}

/// Individual contract isolation context
#[derive(Debug)]
struct IsolationContext {
    /// Contract ID
    contract_id: String,
    /// Sandbox configuration
    sandbox_config: SandboxConfig,
    /// Resource usage tracking
    resource_usage: ResourceUsage,
    /// Isolation start time
    start_time: std::time::Instant,
}

/// Resource usage tracking
#[derive(Debug, Default)]
struct ResourceUsage {
    /// Memory allocated (bytes)
    memory_allocated: u64,
    /// CPU time used (milliseconds)
    cpu_time_ms: u64,
    /// Number of system calls made
    syscall_count: u32,
    /// Number of file operations
    file_operations: u32,
    /// Number of network operations
    network_operations: u32,
}

impl PlatformIsolationManager {
    /// Create new platform isolation manager
    pub fn new(config: PlatformIsolationConfig) -> Self {
        Self {
            isolation_contexts: HashMap::new(),
            global_config: config,
        }
    }

    /// Create isolated execution environment for a contract
    pub fn create_isolation_context(
        &mut self,
        contract_id: String,
        security_level: SecurityLevel,
    ) -> Result<()> {
        let sandbox_config = SandboxConfig::for_security_level(security_level);
        
        let context = IsolationContext {
            contract_id: contract_id.clone(),
            sandbox_config,
            resource_usage: ResourceUsage::default(),
            start_time: std::time::Instant::now(),
        };

        self.isolation_contexts.insert(contract_id.clone(), context);
        
        log::info!("Created isolation context for contract: {}", contract_id);
        Ok(())
    }

    /// Execute contract in isolated environment
    pub fn execute_isolated<F, T>(&mut self, contract_id: &str, execution_fn: F) -> Result<T>
    where
        F: FnOnce() -> Result<T>,
    {
        // Pre-execution checks
        {
            let context = self.isolation_contexts.get(contract_id)
                .ok_or_else(|| anyhow!("Isolation context not found: {}", contract_id))?;
            self.validate_resource_limits(context)?;
        }
        
        // Execute with monitoring
        let start = std::time::Instant::now();
        let result = execution_fn()?;
        let execution_time = start.elapsed();

        // Update resource usage and post-execution validation
        {
            let context = self.isolation_contexts.get_mut(contract_id)
                .ok_or_else(|| anyhow!("Isolation context not found: {}", contract_id))?;
            
            context.resource_usage.cpu_time_ms += execution_time.as_millis() as u64;
        }
        
        // Validate post-execution state (separate borrow)
        {
            let context = self.isolation_contexts.get(contract_id)
                .ok_or_else(|| anyhow!("Isolation context not found: {}", contract_id))?;
            self.validate_post_execution(context)?;
        }

        log::debug!("Isolated execution completed for contract: {} in {:?}", 
                   contract_id, execution_time);
        
        Ok(result)
    }

    /// Validate resource limits before execution
    fn validate_resource_limits(&self, context: &IsolationContext) -> Result<()> {
        // Check memory limits
        if context.resource_usage.memory_allocated > self.global_config.max_memory_per_contract {
            return Err(anyhow!("Memory limit exceeded: {} > {}", 
                context.resource_usage.memory_allocated, 
                self.global_config.max_memory_per_contract));
        }

        // Check CPU time limits
        if context.resource_usage.cpu_time_ms > self.global_config.max_cpu_time_ms {
            return Err(anyhow!("CPU time limit exceeded: {} > {}", 
                context.resource_usage.cpu_time_ms, 
                self.global_config.max_cpu_time_ms));
        }

        Ok(())
    }

    /// Validate state after execution
    fn validate_post_execution(&self, context: &IsolationContext) -> Result<()> {
        let execution_time = context.start_time.elapsed();
        
        // Check if execution time is reasonable
        if execution_time > context.sandbox_config.execution_limits.max_execution_time {
            return Err(anyhow!("Execution timeout: {:?} > {:?}", 
                execution_time, 
                context.sandbox_config.execution_limits.max_execution_time));
        }

        Ok(())
    }

    /// Track memory allocation
    pub fn track_memory_allocation(&mut self, contract_id: &str, bytes: u64) -> Result<()> {
        if let Some(context) = self.isolation_contexts.get_mut(contract_id) {
            context.resource_usage.memory_allocated += bytes;
            
            // Check limits
            if context.resource_usage.memory_allocated > self.global_config.max_memory_per_contract {
                return Err(anyhow!("Memory allocation would exceed limit"));
            }
        }
        Ok(())
    }

    /// Track system call
    pub fn track_syscall(&mut self, contract_id: &str, syscall_name: &str) -> Result<()> {
        // Check if syscall is allowed
        if !self.global_config.allowed_syscalls.contains(&syscall_name.to_string()) {
            return Err(anyhow!("System call not allowed: {}", syscall_name));
        }

        if let Some(context) = self.isolation_contexts.get_mut(contract_id) {
            context.resource_usage.syscall_count += 1;
        }
        
        Ok(())
    }

    /// Track file operation
    pub fn track_file_operation(&mut self, contract_id: &str) -> Result<()> {
        if !self.global_config.enable_filesystem_isolation {
            return Err(anyhow!("File system access not allowed"));
        }

        if let Some(context) = self.isolation_contexts.get_mut(contract_id) {
            context.resource_usage.file_operations += 1;
        }
        
        Ok(())
    }

    /// Track network operation
    pub fn track_network_operation(&mut self, contract_id: &str) -> Result<()> {
        if !self.global_config.enable_network_isolation {
            return Err(anyhow!("Network access not allowed"));
        }

        if let Some(context) = self.isolation_contexts.get_mut(contract_id) {
            context.resource_usage.network_operations += 1;
        }
        
        Ok(())
    }

    /// Remove isolation context
    pub fn remove_context(&mut self, contract_id: &str) -> Option<IsolationReport> {
        if let Some(context) = self.isolation_contexts.remove(contract_id) {
            let total_time = context.start_time.elapsed();
            
            Some(IsolationReport {
                contract_id: context.contract_id,
                total_execution_time: total_time,
                memory_used: context.resource_usage.memory_allocated,
                cpu_time_ms: context.resource_usage.cpu_time_ms,
                syscall_count: context.resource_usage.syscall_count,
                file_operations: context.resource_usage.file_operations,
                network_operations: context.resource_usage.network_operations,
            })
        } else {
            None
        }
    }

    /// Get resource usage for a contract
    pub fn get_resource_usage(&self, contract_id: &str) -> Option<&ResourceUsage> {
        self.isolation_contexts.get(contract_id).map(|ctx| &ctx.resource_usage)
    }
}

/// Report generated after isolation context is removed
#[derive(Debug, Serialize, Deserialize)]
pub struct IsolationReport {
    pub contract_id: String,
    pub total_execution_time: std::time::Duration,
    pub memory_used: u64,
    pub cpu_time_ms: u64,
    pub syscall_count: u32,
    pub file_operations: u32,
    pub network_operations: u32,
}

impl Default for PlatformIsolationConfig {
    fn default() -> Self {
        Self {
            enable_filesystem_isolation: true,
            enable_network_isolation: true,
            enable_process_isolation: true,
            max_memory_per_contract: 16 * 1024 * 1024, // 16MB
            max_cpu_time_ms: 5000, // 5 seconds
            allowed_syscalls: vec![
                "read".to_string(),
                "write".to_string(),
                "mmap".to_string(),
                "munmap".to_string(),
                "brk".to_string(),
            ],
        }
    }
}

/// Create platform isolation manager with security level
pub fn create_isolation_manager(security_level: SecurityLevel) -> PlatformIsolationManager {
    let config = match security_level {
        SecurityLevel::Minimal => PlatformIsolationConfig {
            max_memory_per_contract: 64 * 1024 * 1024, // 64MB
            max_cpu_time_ms: 30000, // 30 seconds
            ..Default::default()
        },
        SecurityLevel::Standard => PlatformIsolationConfig::default(),
        SecurityLevel::Maximum => PlatformIsolationConfig {
            max_memory_per_contract: 8 * 1024 * 1024, // 8MB
            max_cpu_time_ms: 1000, // 1 second
            allowed_syscalls: vec!["read".to_string(), "write".to_string()], // Minimal syscalls
            ..Default::default()
        },
    };

    PlatformIsolationManager::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_isolation_manager_creation() {
        let manager = create_isolation_manager(SecurityLevel::Standard);
        assert_eq!(manager.isolation_contexts.len(), 0);
    }

    #[test]
    fn test_create_isolation_context() {
        let mut manager = create_isolation_manager(SecurityLevel::Standard);
        let result = manager.create_isolation_context("test_contract".to_string(), SecurityLevel::Standard);
        assert!(result.is_ok());
        assert_eq!(manager.isolation_contexts.len(), 1);
    }

    #[test]
    fn test_resource_tracking() {
        let mut manager = create_isolation_manager(SecurityLevel::Standard);
        manager.create_isolation_context("test_contract".to_string(), SecurityLevel::Standard).unwrap();
        
        let result = manager.track_memory_allocation("test_contract", 1024);
        assert!(result.is_ok());
        
        let usage = manager.get_resource_usage("test_contract").unwrap();
        assert_eq!(usage.memory_allocated, 1024);
    }
}
