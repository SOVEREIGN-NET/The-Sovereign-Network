//! # WASM Contract Runtime
//!
//! Sandboxed WebAssembly runtime for secure smart contract execution.
//! Provides process isolation, memory limits, and capability-based security.

use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use crate::integration::crypto_integration::PublicKey;

#[cfg(feature = "wasm-runtime")]
pub mod wasm_engine;
#[cfg(feature = "wasm-runtime")]
pub mod sandbox;
#[cfg(feature = "wasm-runtime")]
pub mod host_functions;

#[cfg(feature = "wasm-runtime")]
pub use wasm_engine::WasmEngine;
#[cfg(feature = "wasm-runtime")]
pub use sandbox::{SandboxConfig, ContractSandbox};
#[cfg(feature = "wasm-runtime")]
pub use host_functions::{HostFunctions, is_safe_host_function};

/// Contract runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeConfig {
    /// Maximum memory pages (64KB per page)
    pub max_memory_pages: u32,
    /// Maximum execution time
    pub max_execution_time: Duration,
    /// Maximum fuel (instruction count)
    pub max_fuel: u64,
    /// Stack size limit
    pub max_stack_size: u32,
    /// Enable debug mode
    pub debug_mode: bool,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            max_memory_pages: 16,           // 1MB memory limit
            max_execution_time: Duration::from_millis(1000), // 1 second timeout
            max_fuel: 1_000_000,           // 1M instructions
            max_stack_size: 1024,          // 1KB stack
            debug_mode: false,
        }
    }
}

/// Runtime execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeResult {
    /// Execution success
    pub success: bool,
    /// Return data
    pub return_data: Vec<u8>,
    /// Gas consumed
    pub gas_used: u64,
    /// Execution time
    pub execution_time: Duration,
    /// Memory used (bytes)
    pub memory_used: u64,
    /// Error message if any
    pub error: Option<String>,
}

impl RuntimeResult {
    /// Create successful result
    pub fn success(return_data: Vec<u8>, gas_used: u64, execution_time: Duration, memory_used: u64) -> Self {
        Self {
            success: true,
            return_data,
            gas_used,
            execution_time,
            memory_used,
            error: None,
        }
    }

    /// Create error result
    pub fn error(error: String, gas_used: u64, execution_time: Duration) -> Self {
        Self {
            success: false,
            return_data: Vec::new(),
            gas_used,
            execution_time,
            memory_used: 0,
            error: Some(error),
        }
    }
}

/// Contract runtime interface (abstraction for native vs WASM)
pub trait ContractRuntime {
    /// Execute contract method
    fn execute(
        &mut self,
        contract_code: &[u8],
        method: &str,
        params: &[u8],
        context: &RuntimeContext,
        config: &RuntimeConfig,
    ) -> Result<RuntimeResult>;

    /// Validate contract code
    fn validate_code(&self, code: &[u8]) -> Result<()>;

    /// Get runtime statistics
    fn get_stats(&self) -> RuntimeStats;
}

/// Runtime execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeContext {
    /// Caller's public key
    pub caller: PublicKey,
    /// Current block number
    pub block_number: u64,
    /// Block timestamp
    pub timestamp: u64,
    /// Gas limit
    pub gas_limit: u64,
    /// Transaction hash
    pub tx_hash: [u8; 32],
}

/// Runtime performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeStats {
    /// Total contracts executed
    pub contracts_executed: u64,
    /// Total gas consumed
    pub total_gas_used: u64,
    /// Total execution time
    pub total_execution_time: Duration,
    /// Average execution time
    pub avg_execution_time: Duration,
    /// Memory usage statistics
    pub memory_stats: MemoryStats,
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Peak memory usage
    pub peak_memory: u64,
    /// Current memory usage
    pub current_memory: u64,
    /// Average memory usage
    pub avg_memory: u64,
}

/// Native Rust runtime implementation (fallback)
pub struct NativeRuntime {
    stats: RuntimeStats,
}

impl NativeRuntime {
    pub fn new() -> Self {
        Self {
            stats: RuntimeStats {
                contracts_executed: 0,
                total_gas_used: 0,
                total_execution_time: Duration::new(0, 0),
                avg_execution_time: Duration::new(0, 0),
                memory_stats: MemoryStats {
                    peak_memory: 0,
                    current_memory: 0,
                    avg_memory: 0,
                },
            },
        }
    }
}

impl ContractRuntime for NativeRuntime {
    fn execute(
        &mut self,
        _contract_code: &[u8],
        method: &str,
        params: &[u8],
        _context: &RuntimeContext,
        config: &RuntimeConfig,
    ) -> Result<RuntimeResult> {
        let start_time = Instant::now();
        
        // For native runtime, we'll just validate method exists
        // implementation would execute native contract methods
        if method.is_empty() {
            return Ok(RuntimeResult::error(
                "Method name cannot be empty".to_string(),
                crate::GAS_BASE,
                start_time.elapsed(),
            ));
        }

        let execution_time = start_time.elapsed();
        
        // Check execution time limit
        if execution_time > config.max_execution_time {
            return Ok(RuntimeResult::error(
                "Execution timeout".to_string(),
                config.max_fuel,
                execution_time,
            ));
        }

        // Update stats
        self.stats.contracts_executed += 1;
        self.stats.total_execution_time += execution_time;
        self.stats.avg_execution_time = 
            self.stats.total_execution_time / self.stats.contracts_executed as u32;

        Ok(RuntimeResult::success(
            params.to_vec(), // Echo params as result for now
            crate::GAS_BASE,
            execution_time,
            1024, // Estimated memory usage
        ))
    }

    fn validate_code(&self, code: &[u8]) -> Result<()> {
        if code.is_empty() {
            return Err(anyhow!("Contract code cannot be empty"));
        }
        if code.len() > 1024 * 1024 {  // 1MB limit
            return Err(anyhow!("Contract code too large"));
        }
        Ok(())
    }

    fn get_stats(&self) -> RuntimeStats {
        self.stats.clone()
    }
}

impl Default for NativeRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Factory for creating contract runtimes
pub struct RuntimeFactory {
    config: RuntimeConfig,
    #[cfg(feature = "wasm-runtime")]
    wasm_enabled: bool,
}

impl RuntimeFactory {
    pub fn new(config: RuntimeConfig) -> Self {
        Self {
            config,
            #[cfg(feature = "wasm-runtime")]
            wasm_enabled: true,
        }
    }

    /// Create appropriate runtime based on contract type
    pub fn create_runtime(&self, _contract_type: &str) -> Result<Box<dyn ContractRuntime>> {
        #[cfg(feature = "wasm-runtime")]
        {
            if self.wasm_enabled {
                Ok(Box::new(wasm_engine::WasmEngine::new(self.config.clone())?))
            } else {
                Ok(Box::new(NativeRuntime::new()))
            }
        }

        #[cfg(not(feature = "wasm-runtime"))]
        {
            Ok(Box::new(NativeRuntime::new()))
        }
    }

    /// Check if WASM runtime is available
    pub fn is_wasm_available(&self) -> bool {
        #[cfg(feature = "wasm-runtime")]
        {
            self.wasm_enabled
        }
        #[cfg(not(feature = "wasm-runtime"))]
        {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    #[test]
    fn test_runtime_config() {
        let config = RuntimeConfig::default();
        assert_eq!(config.max_memory_pages, 16);
        assert_eq!(config.max_fuel, 1_000_000);
    }

    #[test]
    fn test_native_runtime() {
        let mut runtime = NativeRuntime::new();
        let keypair = KeyPair::generate().unwrap();
        
        let context = RuntimeContext {
            caller: keypair.public_key,
            block_number: 1,
            timestamp: 1234567890,
            gas_limit: 100000,
            tx_hash: [1u8; 32],
        };
        
        let config = RuntimeConfig::default();
        
        let result = runtime.execute(
            b"test_code",
            "test_method",
            b"test_params",
            &context,
            &config,
        ).unwrap();
        
        assert!(result.success);
        assert_eq!(result.return_data, b"test_params");
    }

    #[test]
    fn test_runtime_factory() {
        let config = RuntimeConfig::default();
        let factory = RuntimeFactory::new(config);
        
        let runtime = factory.create_runtime("test").unwrap();
        
        // Minimal valid WASM module (empty module with magic + version)
        // Magic: \0asm, Version: 1 (little-endian 4 bytes)
        let valid_wasm = [
            0x00, 0x61, 0x73, 0x6d, // WASM magic: \0asm
            0x01, 0x00, 0x00, 0x00, // Version 1
        ];
        
        assert!(runtime.validate_code(&valid_wasm).is_ok());
        assert!(runtime.validate_code(b"").is_err());
    }
}