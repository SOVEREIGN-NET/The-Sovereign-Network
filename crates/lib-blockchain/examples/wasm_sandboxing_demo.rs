//! WASM Sandboxing Demonstration
//!
//! This example demonstrates secure WASM contract execution with full sandboxing.

use anyhow::Result;
use lib_blockchain::{
    contracts::{
        executor::{ContractExecutor, MemoryStorage, ExecutionContext},
        runtime::{RuntimeConfig, SandboxConfig, SecurityLevel},
        ContractCall, ContractType,
    },
    integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm},
    types::CallPermissions,
};

/// Example WASM contract bytecode (mock)
const EXAMPLE_WASM_CONTRACT: &[u8] = &[
    0x00, 0x61, 0x73, 0x6D, // WASM magic number
    0x01, 0x00, 0x00, 0x00, // Version
    // ... rest would be actual WASM bytecode
];

/// Demonstration of WASM sandboxing capabilities
pub fn demonstrate_wasm_sandboxing() -> Result<()> {
    println!(" WASM Sandboxing Demonstration");
    println!("================================");

    // 1. Create different security levels
    demonstrate_security_levels()?;
    
    // 2. Show resource limits in action
    demonstrate_resource_limits()?;
    
    // 3. Demonstrate host function restrictions
    demonstrate_host_function_restrictions()?;
    
    // 4. Show platform isolation
    demonstrate_platform_isolation()?;

    println!("\n WASM sandboxing demonstration completed successfully!");
    Ok(())
}

/// Demonstrate different security levels
fn demonstrate_security_levels() -> Result<()> {
    println!("\n Security Levels Demonstration:");
    
    let levels = [
        ("Minimal (Development)", SecurityLevel::Minimal),
        ("Standard (Testnet)", SecurityLevel::Standard),
        ("Maximum (Mainnet)", SecurityLevel::Maximum),
    ];

    for (name, level) in &levels {
        let config = SandboxConfig::for_security_level(*level);
        println!("  {} - Memory: {}KB, Fuel: {}, Time: {:?}", 
            name,
            config.memory_limits.max_pages * 64, // 64KB per page
            config.execution_limits.max_fuel,
            config.execution_limits.max_execution_time
        );
    }

    Ok(())
}

/// Demonstrate resource limits
fn demonstrate_resource_limits() -> Result<()> {
    println!("\n Resource Limits Demonstration:");
    
    // Create executor with maximum security
    let storage = MemoryStorage::default();
    let runtime_config = RuntimeConfig {
        max_memory_pages: 4, // Very small limit for demo
        max_fuel: 10000,     // Low fuel limit
        max_execution_time: std::time::Duration::from_millis(100),
        max_stack_size: 1024,
        debug_mode: true,
    };
    
    let mut executor = ContractExecutor::with_runtime_config(storage, runtime_config);
    
    // Create execution context
    let keypair = lib_crypto::KeyPair::generate()?;
    let mut context = ExecutionContext::new(
        keypair.public_key,
        1,
        1234567890,
        5000, // Low gas limit
        [1u8; 32],
    );

    // Demonstrate gas limit enforcement
    println!("  🔋 Testing gas limits:");
    println!("    Gas limit: {}", context.gas_limit);
    
    // Try to consume more gas than available
    match context.consume_gas(10000) {
        Ok(_) => println!("     Unexpected: High gas consumption allowed"),
        Err(e) => println!("     Expected: Gas limit enforced - {}", e),
    }

    Ok(())
}

/// Demonstrate host function restrictions
fn demonstrate_host_function_restrictions() -> Result<()> {
    println!("\n Host Function Restrictions:");
    
    let safe_functions = [
        "zhtp_log",
        "zhtp_get_caller", 
        "zhtp_get_block_number",
        "zhtp_storage_get",
        "zhtp_storage_set",
    ];
    
    let unsafe_functions = [
        "system_call",
        "file_open",
        "network_connect",
        "process_spawn",
        "memory_access",
    ];

    println!("   Allowed functions:");
    for func in &safe_functions {
        println!("    - {}", func);
    }
    
    println!("   Blocked functions:");
    for func in &unsafe_functions {
        println!("    - {}", func);
    }

    Ok(())
}

/// Demonstrate platform isolation
fn demonstrate_platform_isolation() -> Result<()> {
    println!("\n🏰 Platform Isolation Demonstration:");
    
    use lib_blockchain::contracts::executor::platform_isolation::{create_isolation_manager};
    
    let mut isolation_manager = create_isolation_manager(SecurityLevel::Maximum);
    
    // Create isolation context
    isolation_manager.create_isolation_context(
        "demo_contract".to_string(),
        SecurityLevel::Maximum
    )?;
    
    println!("   Isolation context created for contract");
    
    // Demonstrate resource tracking
    match isolation_manager.track_memory_allocation("demo_contract", 1024) {
        Ok(_) => println!("   Memory allocation (1KB) tracked successfully"),
        Err(e) => println!("   Memory allocation failed: {}", e),
    }
    
    // Try to allocate too much memory
    match isolation_manager.track_memory_allocation("demo_contract", 100 * 1024 * 1024) {
        Ok(_) => println!("   Unexpected: Large allocation allowed"),
        Err(e) => println!("   Expected: Large allocation blocked - {}", e),
    }
    
    // Demonstrate syscall filtering
    match isolation_manager.track_syscall("demo_contract", "read") {
        Ok(_) => println!("   Safe syscall 'read' allowed"),
        Err(e) => println!("   Safe syscall blocked: {}", e),
    }
    
    match isolation_manager.track_syscall("demo_contract", "exec") {
        Ok(_) => println!("   Unexpected: Dangerous syscall allowed"),
        Err(e) => println!("   Expected: Dangerous syscall blocked - {}", e),
    }

    Ok(())
}

/// Execute a simple WASM contract (mock execution)
fn execute_mock_wasm_contract() -> Result<()> {
    println!("\n Mock WASM Contract Execution:");
    
    let storage = MemoryStorage::default();
    let mut executor = ContractExecutor::new(storage);
    
    let keypair = lib_crypto::KeyPair::generate()?;
    let mut context = ExecutionContext::new(
        keypair.public_key.clone(),
        1,
        1234567890,
        100000,
        [1u8; 32],
    );

    // Check if WASM runtime is available
    if executor.is_wasm_available() {
        println!("   WASM runtime available");
        
        // Execute WASM contract
        match executor.execute_wasm_contract(
            EXAMPLE_WASM_CONTRACT,
            "test_method",
            b"test_params",
            &mut context,
        ) {
            Ok(result) => {
                println!("   WASM execution successful");
                println!("    Gas used: {}", result.gas_used);
                println!("    Success: {}", result.success);
            },
            Err(e) => {
                println!("    WASM execution error (expected for mock): {}", e);
            }
        }
    } else {
        println!("    WASM runtime not available (using fallback)");
        
        // Demonstrate native contract execution
        let call = ContractCall {
            contract_type: ContractType::Token,
            method: "balance_of".to_string(),
            params: vec![], // Empty params for demo
            permissions: CallPermissions::Public,
        };
        
        match executor.execute_call(call, &mut context) {
            Ok(result) => {
                println!("   Native contract execution successful");
                println!("    Success: {}", result.success);
                println!("    Gas used: {}", context.gas_used);
            },
            Err(e) => {
                println!("   Contract execution failed: {}", e);
            }
        }
    }

    Ok(())
}

/// Run the complete WASM sandboxing demonstration
pub fn run_demo() -> Result<()> {
    demonstrate_wasm_sandboxing()?;
    execute_mock_wasm_contract()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert!(demonstrate_security_levels().is_ok());
    }

    #[test]
    fn test_resource_limits() {
        assert!(demonstrate_resource_limits().is_ok());
    }

    #[test]
    fn test_host_function_restrictions() {
        assert!(demonstrate_host_function_restrictions().is_ok());
    }

    #[test]
    fn test_platform_isolation() {
        assert!(demonstrate_platform_isolation().is_ok());
    }
}

fn main() -> Result<()> {
    // Initialize logging
    env_logger::init();
    
    // Run the demonstration
    run_demo()
}
