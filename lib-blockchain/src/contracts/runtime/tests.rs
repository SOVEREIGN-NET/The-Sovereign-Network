//! Integration tests for WASM sandboxing
//!
//! Tests the complete WASM runtime integration

#[cfg(test)]
mod tests {
    use crate::contracts::{
        ContractExecutor, ExecutionContext, MemoryStorage, RuntimeConfig, RuntimeFactory,
        SandboxConfig, SecurityLevel
    };
    use lib_crypto::KeyPair;
    use std::time::Duration;

    #[test]
    fn test_runtime_factory_creation() {
        let config = RuntimeConfig::default();
        let factory = RuntimeFactory::new(config);
        
        // Should be able to create runtime
        let runtime = factory.create_runtime("native");
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_executor_with_wasm_config() {
        let storage = MemoryStorage::default();
        
        // Create runtime config with maximum security
        let runtime_config = SandboxConfig::maximum().to_runtime_config();
        
        let executor = ContractExecutor::with_runtime_config(storage, runtime_config);
        
        // Should have WASM availability check
        println!("WASM available: {}", executor.is_wasm_available());
        
        // Should have correct configuration
        let config = executor.runtime_config();
        assert_eq!(config.max_memory_pages, 16); // 1MB for maximum security
        assert_eq!(config.max_execution_time, Duration::from_millis(1000));
        assert_eq!(config.max_fuel, 1_000_000);
    }

    #[test]
    fn test_sandbox_security_levels() {
        let minimal = SandboxConfig::minimal();
        let standard = SandboxConfig::standard();
        let maximum = SandboxConfig::maximum();

        // Verify security progression
        assert!(maximum.memory_limits.max_pages <= standard.memory_limits.max_pages);
        assert!(standard.memory_limits.max_pages <= minimal.memory_limits.max_pages);
        
        // Verify execution time limits
        assert!(maximum.execution_limits.max_execution_time <= standard.execution_limits.max_execution_time);
        assert!(standard.execution_limits.max_execution_time <= minimal.execution_limits.max_execution_time);
        
        // Verify host function restrictions
        assert!(maximum.allowed_host_functions.len() <= standard.allowed_host_functions.len());
        assert!(standard.allowed_host_functions.len() <= minimal.allowed_host_functions.len());
    }

    #[test]
    fn test_execution_context_integration() {
        let storage = MemoryStorage::default();
        let runtime_config = RuntimeConfig::default();
        let mut executor = ContractExecutor::with_runtime_config(storage, runtime_config);
        
        let keypair = KeyPair::generate().unwrap();
        let mut context = ExecutionContext::new(
            keypair.public_key,
            12345,
            1234567890,
            100000,
            [1u8; 32],
        );

        // Test that context can be used with executor
        assert_eq!(context.remaining_gas(), 100000);
        
        // Test gas consumption
        assert!(context.consume_gas(1000).is_ok());
        assert_eq!(context.remaining_gas(), 99000);
        assert_eq!(context.gas_used, 1000);
    }

    #[cfg(feature = "wasm-runtime")]
    #[test]
    fn test_wasm_runtime_availability() {
        let config = RuntimeConfig::default();
        let factory = RuntimeFactory::new(config);
        
        // Should have WASM available when feature is enabled
        assert!(factory.is_wasm_available());
        
        // Should be able to create WASM runtime
        let wasm_runtime = factory.create_runtime("wasm");
        assert!(wasm_runtime.is_ok());
    }

    #[cfg(not(feature = "wasm-runtime"))]
    #[test]
    fn test_native_fallback() {
        let config = RuntimeConfig::default();
        let factory = RuntimeFactory::new(config);
        
        // Should fallback to native when WASM not available
        assert!(!factory.is_wasm_available());
        
        // Should still be able to create native runtime
        let native_runtime = factory.create_runtime("native");
        assert!(native_runtime.is_ok());
    }

    #[test]
    fn test_host_function_safety() {
        use crate::contracts::runtime::host_functions::is_safe_host_function;
        
        // Safe functions should be allowed
        assert!(is_safe_host_function("zhtp_log"));
        assert!(is_safe_host_function("zhtp_get_caller"));
        assert!(is_safe_host_function("zhtp_storage_get"));
        assert!(is_safe_host_function("zhtp_emit_event"));
        
        // Dangerous functions should be blocked
        assert!(!is_safe_host_function("system"));
        assert!(!is_safe_host_function("file_open"));
        assert!(!is_safe_host_function("network_connect"));
        assert!(!is_safe_host_function("malloc"));
        assert!(!is_safe_host_function("exit"));
    }

    #[test]
    fn test_security_configuration_validation() {
        // Valid configs should pass
        let valid_config = SandboxConfig::standard();
        assert!(valid_config.validate().is_ok());
        
        // Invalid configs should fail
        let mut invalid_config = SandboxConfig::standard();
        
        // Zero pages should fail
        invalid_config.memory_limits.max_pages = 0;
        assert!(invalid_config.validate().is_err());
        
        // Zero execution time should fail
        invalid_config = SandboxConfig::standard();
        invalid_config.execution_limits.max_execution_time = Duration::from_secs(0);
        assert!(invalid_config.validate().is_err());
        
        // Zero fuel should fail
        invalid_config = SandboxConfig::standard();
        invalid_config.execution_limits.max_fuel = 0;
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_runtime_statistics() {
        let storage = MemoryStorage::default();
        let mut executor = ContractExecutor::new(storage);
        
        // Statistics should be available (even if empty initially)
        let config = executor.runtime_config();
        assert!(config.max_memory_pages > 0);
        assert!(config.max_fuel > 0);
        assert!(config.max_execution_time > Duration::from_secs(0));
    }
}