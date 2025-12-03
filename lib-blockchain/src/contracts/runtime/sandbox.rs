//! Sandbox Configuration and Management
//!
//! Provides configuration and management for secure contract execution sandboxes.

use super::RuntimeConfig;
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::Duration;

/// Sandbox security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Minimal restrictions (development only)
    Minimal,
    /// Standard production restrictions
    Standard,
    /// Maximum security (mainnet)
    Maximum,
}

/// Sandbox configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Security level
    pub security_level: SecurityLevel,
    /// Memory limits
    pub memory_limits: MemoryLimits,
    /// Execution limits
    pub execution_limits: ExecutionLimits,
    /// Allowed host functions
    pub allowed_host_functions: Vec<String>,
    /// Resource limits
    pub resource_limits: ResourceLimits,
}

/// Memory limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Maximum linear memory pages (64KB each)
    pub max_pages: u32,
    /// Maximum stack size in bytes
    pub max_stack_size: u32,
    /// Maximum heap size in bytes
    pub max_heap_size: u64,
    /// Enable memory growth
    pub allow_memory_growth: bool,
}

/// Execution limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionLimits {
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Maximum fuel (instruction count)
    pub max_fuel: u64,
    /// Maximum function call depth
    pub max_call_depth: u32,
    /// Maximum number of function calls
    pub max_function_calls: u64,
}

/// Resource limit configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum storage operations per execution
    pub max_storage_ops: u32,
    /// Maximum storage data size per operation
    pub max_storage_data_size: u64,
    /// Maximum events emitted per execution
    pub max_events: u32,
    /// Maximum log entries per execution
    pub max_logs: u32,
}

impl SandboxConfig {
    /// Create configuration for security level
    pub fn for_security_level(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Minimal => Self::minimal(),
            SecurityLevel::Standard => Self::standard(),
            SecurityLevel::Maximum => Self::maximum(),
        }
    }

    /// Minimal security configuration (development)
    pub fn minimal() -> Self {
        Self {
            security_level: SecurityLevel::Minimal,
            memory_limits: MemoryLimits {
                max_pages: 64,        // 4MB
                max_stack_size: 8192, // 8KB
                max_heap_size: 4 * 1024 * 1024, // 4MB
                allow_memory_growth: true,
            },
            execution_limits: ExecutionLimits {
                max_execution_time: Duration::from_secs(10),
                max_fuel: 10_000_000,
                max_call_depth: 100,
                max_function_calls: 10000,
            },
            allowed_host_functions: vec![
                "zhtp_log".to_string(),
                "zhtp_get_caller".to_string(),
                "zhtp_get_block_number".to_string(),
                "zhtp_get_timestamp".to_string(),
                "zhtp_storage_get".to_string(),
                "zhtp_storage_set".to_string(),
                "zhtp_emit_event".to_string(),
            ],
            resource_limits: ResourceLimits {
                max_storage_ops: 100,
                max_storage_data_size: 1024 * 1024, // 1MB
                max_events: 50,
                max_logs: 100,
            },
        }
    }

    /// Standard security configuration (testnet)
    pub fn standard() -> Self {
        Self {
            security_level: SecurityLevel::Standard,
            memory_limits: MemoryLimits {
                max_pages: 32,        // 2MB
                max_stack_size: 4096, // 4KB
                max_heap_size: 2 * 1024 * 1024, // 2MB
                allow_memory_growth: false,
            },
            execution_limits: ExecutionLimits {
                max_execution_time: Duration::from_secs(5),
                max_fuel: 5_000_000,
                max_call_depth: 50,
                max_function_calls: 5000,
            },
            allowed_host_functions: vec![
                "zhtp_log".to_string(),
                "zhtp_get_caller".to_string(),
                "zhtp_get_block_number".to_string(),
                "zhtp_storage_get".to_string(),
                "zhtp_storage_set".to_string(),
                "zhtp_emit_event".to_string(),
            ],
            resource_limits: ResourceLimits {
                max_storage_ops: 50,
                max_storage_data_size: 512 * 1024, // 512KB
                max_events: 25,
                max_logs: 50,
            },
        }
    }

    /// Maximum security configuration (mainnet)
    pub fn maximum() -> Self {
        Self {
            security_level: SecurityLevel::Maximum,
            memory_limits: MemoryLimits {
                max_pages: 16,        // 1MB
                max_stack_size: 2048, // 2KB
                max_heap_size: 1024 * 1024, // 1MB
                allow_memory_growth: false,
            },
            execution_limits: ExecutionLimits {
                max_execution_time: Duration::from_millis(1000), // 1 second
                max_fuel: 1_000_000,
                max_call_depth: 32,
                max_function_calls: 1000,
            },
            allowed_host_functions: vec![
                "zhtp_get_caller".to_string(),
                "zhtp_get_block_number".to_string(),
                "zhtp_storage_get".to_string(),
                "zhtp_storage_set".to_string(),
            ],
            resource_limits: ResourceLimits {
                max_storage_ops: 25,
                max_storage_data_size: 256 * 1024, // 256KB
                max_events: 10,
                max_logs: 25,
            },
        }
    }

    /// Convert to runtime config
    pub fn to_runtime_config(&self) -> RuntimeConfig {
        RuntimeConfig {
            max_memory_pages: self.memory_limits.max_pages,
            max_execution_time: self.execution_limits.max_execution_time,
            max_fuel: self.execution_limits.max_fuel,
            max_stack_size: self.memory_limits.max_stack_size,
            debug_mode: self.security_level == SecurityLevel::Minimal,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate memory limits
        if self.memory_limits.max_pages == 0 {
            return Err(anyhow!("Max pages must be greater than 0"));
        }
        if self.memory_limits.max_pages > 1024 { // 64MB max
            return Err(anyhow!("Max pages too large"));
        }

        // Validate execution limits
        if self.execution_limits.max_execution_time.is_zero() {
            return Err(anyhow!("Max execution time must be greater than 0"));
        }
        if self.execution_limits.max_fuel == 0 {
            return Err(anyhow!("Max fuel must be greater than 0"));
        }

        // Validate host functions
        for func in &self.allowed_host_functions {
            if !is_safe_host_function(func) {
                return Err(anyhow!("Unsafe host function: {}", func));
            }
        }

        Ok(())
    }

    /// Check if host function is allowed
    pub fn is_host_function_allowed(&self, function_name: &str) -> bool {
        self.allowed_host_functions.contains(&function_name.to_string())
    }
}

/// Contract sandbox for managing isolated execution
pub struct ContractSandbox {
    config: SandboxConfig,
    active_executions: HashMap<String, SandboxExecution>,
}

/// Active sandbox execution
#[derive(Debug)]
struct SandboxExecution {
    start_time: std::time::Instant,
    memory_used: u64,
    storage_ops: u32,
    events_emitted: u32,
    logs_written: u32,
    function_calls: u64,
    call_depth: u32,
}

impl ContractSandbox {
    /// Create new sandbox with configuration
    pub fn new(config: SandboxConfig) -> Result<Self> {
        config.validate()?;
        
        Ok(Self {
            config,
            active_executions: HashMap::new(),
        })
    }

    /// Start new execution in sandbox
    pub fn start_execution(&mut self, execution_id: String) -> Result<()> {
        if self.active_executions.contains_key(&execution_id) {
            return Err(anyhow!("Execution already active: {}", execution_id));
        }

        let execution = SandboxExecution {
            start_time: std::time::Instant::now(),
            memory_used: 0,
            storage_ops: 0,
            events_emitted: 0,
            logs_written: 0,
            function_calls: 0,
            call_depth: 0,
        };

        self.active_executions.insert(execution_id, execution);
        Ok(())
    }

    /// End execution and cleanup
    pub fn end_execution(&mut self, execution_id: &str) -> Result<SandboxExecutionReport> {
        let execution = self.active_executions.remove(execution_id)
            .ok_or_else(|| anyhow!("Execution not found: {}", execution_id))?;

        let execution_time = execution.start_time.elapsed();
        
        Ok(SandboxExecutionReport {
            execution_time,
            memory_used: execution.memory_used,
            storage_ops: execution.storage_ops,
            events_emitted: execution.events_emitted,
            logs_written: execution.logs_written,
            function_calls: execution.function_calls,
            max_call_depth: execution.call_depth,
        })
    }

    /// Track storage operation
    pub fn track_storage_op(&mut self, execution_id: &str, data_size: u64) -> Result<()> {
        let execution = self.active_executions.get_mut(execution_id)
            .ok_or_else(|| anyhow!("Execution not found: {}", execution_id))?;

        execution.storage_ops += 1;
        
        // Check limits
        if execution.storage_ops > self.config.resource_limits.max_storage_ops {
            return Err(anyhow!("Storage operation limit exceeded"));
        }
        
        if data_size > self.config.resource_limits.max_storage_data_size {
            return Err(anyhow!("Storage data size limit exceeded"));
        }

        Ok(())
    }

    /// Track event emission
    pub fn track_event(&mut self, execution_id: &str) -> Result<()> {
        let execution = self.active_executions.get_mut(execution_id)
            .ok_or_else(|| anyhow!("Execution not found: {}", execution_id))?;

        execution.events_emitted += 1;
        
        if execution.events_emitted > self.config.resource_limits.max_events {
            return Err(anyhow!("Event limit exceeded"));
        }

        Ok(())
    }

    /// Track function call
    pub fn track_function_call(&mut self, execution_id: &str, call_depth: u32) -> Result<()> {
        let execution = self.active_executions.get_mut(execution_id)
            .ok_or_else(|| anyhow!("Execution not found: {}", execution_id))?;

        execution.function_calls += 1;
        execution.call_depth = execution.call_depth.max(call_depth);
        
        // Check limits
        if execution.function_calls > self.config.execution_limits.max_function_calls {
            return Err(anyhow!("Function call limit exceeded"));
        }
        
        if call_depth > self.config.execution_limits.max_call_depth {
            return Err(anyhow!("Call depth limit exceeded"));
        }

        Ok(())
    }

    /// Get configuration
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }
}

/// Execution report from sandbox
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxExecutionReport {
    pub execution_time: Duration,
    pub memory_used: u64,
    pub storage_ops: u32,
    pub events_emitted: u32,
    pub logs_written: u32,
    pub function_calls: u64,
    pub max_call_depth: u32,
}

/// Check if host function is considered safe
fn is_safe_host_function(function_name: &str) -> bool {
    matches!(function_name,
        "zhtp_log" |
        "zhtp_get_caller" |
        "zhtp_get_block_number" |
        "zhtp_get_timestamp" |
        "zhtp_storage_get" |
        "zhtp_storage_set" |
        "zhtp_emit_event" |
        "zhtp_get_gas_remaining"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        let minimal = SandboxConfig::minimal();
        let standard = SandboxConfig::standard();
        let maximum = SandboxConfig::maximum();

        assert_eq!(minimal.security_level, SecurityLevel::Minimal);
        assert_eq!(standard.security_level, SecurityLevel::Standard);
        assert_eq!(maximum.security_level, SecurityLevel::Maximum);

        // Maximum should be most restrictive
        assert!(maximum.memory_limits.max_pages <= standard.memory_limits.max_pages);
        assert!(standard.memory_limits.max_pages <= minimal.memory_limits.max_pages);
    }

    #[test]
    fn test_config_validation() {
        let valid_config = SandboxConfig::standard();
        assert!(valid_config.validate().is_ok());

        let mut invalid_config = SandboxConfig::standard();
        invalid_config.memory_limits.max_pages = 0;
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_safe_host_functions() {
        assert!(is_safe_host_function("zhtp_log"));
        assert!(is_safe_host_function("zhtp_get_caller"));
        assert!(!is_safe_host_function("system_call"));
        assert!(!is_safe_host_function("file_open"));
    }

    #[test]
    fn test_sandbox_execution() {
        let config = SandboxConfig::standard();
        let mut sandbox = ContractSandbox::new(config).unwrap();

        let exec_id = "test_execution".to_string();
        
        // Start execution
        assert!(sandbox.start_execution(exec_id.clone()).is_ok());
        
        // Track operations
        assert!(sandbox.track_storage_op(&exec_id, 1024).is_ok());
        assert!(sandbox.track_event(&exec_id).is_ok());
        assert!(sandbox.track_function_call(&exec_id, 5).is_ok());
        
        // End execution
        let report = sandbox.end_execution(&exec_id).unwrap();
        assert_eq!(report.storage_ops, 1);
        assert_eq!(report.events_emitted, 1);
        assert_eq!(report.function_calls, 1);
        assert_eq!(report.max_call_depth, 5);
    }
}