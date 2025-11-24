# Smart Contracts Guide - lib-blockchain

## Overview

The ZHTP blockchain provides a comprehensive smart contract platform supporting multiple contract types, WASM execution, and native integration with the blockchain's privacy and economic features.

## Contract Types

### 1. Token Contracts

Token contracts support both the native ZHTP token and custom token creation.

#### ZHTP Native Token

The blockchain includes a built-in ZHTP token with special properties:

```rust
use lib_blockchain::contracts::{TokenContract, ContractCall};

// Get ZHTP native token contract
let zhtp_contract = TokenContract::zhtp_native_token();

// Check ZHTP properties
assert_eq!(zhtp_contract.token_name, "Zero Hash Transfer Protocol");
assert_eq!(zhtp_contract.token_symbol, "ZHTP");
assert_eq!(zhtp_contract.decimals, 8);
assert!(zhtp_contract.is_deflationary);
```

#### Custom Token Deployment

Create custom tokens with configurable properties:

```rust
use lib_blockchain::contracts::TokenContract;

// Create custom token
let custom_token = TokenContract::new(
    "MyToken".to_string(),
    "MTK".to_string(),
    1_000_000 * 100_000_000, // 1M tokens with 8 decimals
    8,                        // decimals
    false,                    // not deflationary
)?;

// Deploy token contract
let deployment_call = ContractCall::deploy_token_contract(custom_token);
blockchain.execute_contract_call(deployment_call, &deployer_keypair)?;
```

#### Token Operations

```rust
// Transfer tokens
let transfer_call = ContractCall::transfer_tokens(
    contract_address,
    to_address,
    amount,
);
blockchain.execute_contract_call(transfer_call, &sender_keypair)?;

// Approve allowance
let approve_call = ContractCall::approve_tokens(
    contract_address,
    spender_address,
    allowance_amount,
);
blockchain.execute_contract_call(approve_call, &owner_keypair)?;

// Transfer from (using allowance)
let transfer_from_call = ContractCall::transfer_from_tokens(
    contract_address,
    from_address,
    to_address,
    amount,
);
blockchain.execute_contract_call(transfer_from_call, &spender_keypair)?;
```

### 2. Web4 Decentralized Website Contracts

Web4 contracts enable hosting decentralized websites on the blockchain with DHT storage.

#### Domain Registration

```rust
use lib_blockchain::contracts::{Web4Contract, WebsiteManifest};

// Deploy Web4 contract
let web4_contract = Web4Contract::new();
let deployment_call = ContractCall::deploy_web4_contract(web4_contract);
blockchain.execute_contract_call(deployment_call, &deployer_keypair)?;

// Register domain
let domain = "mysite.zhtp";
let register_call = ContractCall::register_web4_domain(
    contract_address,
    domain.to_string(),
);
blockchain.execute_contract_call(register_call, &owner_keypair)?;
```

#### Website Manifest Deployment

```rust
// Create website manifest
let manifest = WebsiteManifest {
    domain: "mysite.zhtp".to_string(),
    content_hash: content_hash_from_dht,
    routing_rules: vec![
        RoutingRule::new("/", "index.html"),
        RoutingRule::new("/about", "about.html"),
    ],
    access_control: AccessControlList::public(),
    metadata: WebsiteMetadata {
        title: "My Decentralized Website".to_string(),
        description: "A website hosted on ZHTP blockchain".to_string(),
        keywords: vec!["blockchain", "decentralized", "zhtp"],
    },
};

// Deploy manifest
let deploy_call = ContractCall::deploy_web4_manifest(
    contract_address,
    domain.to_string(),
    manifest,
);
blockchain.execute_contract_call(deploy_call, &owner_keypair)?;
```

#### Content Management

```rust
// Update website content
let update_call = ContractCall::update_web4_content(
    contract_address,
    domain.to_string(),
    new_content_hash,
    version_number,
);
blockchain.execute_contract_call(update_call, &owner_keypair)?;

// Add subdomain
let subdomain_call = ContractCall::add_web4_subdomain(
    contract_address,
    "blog.mysite.zhtp".to_string(),
    subdomain_manifest,
);
blockchain.execute_contract_call(subdomain_call, &owner_keypair)?;
```

### 3. Messaging Contracts

Encrypted messaging with token gates and access controls.

#### Whisper Messaging

```rust
use lib_blockchain::contracts::WhisperContract;

// Deploy messaging contract
let whisper_contract = WhisperContract::new(
    100, // message cost in ZHTP
    1000, // token gate requirement
    EncryptionLevel::High,
);
let deployment_call = ContractCall::deploy_whisper_contract(whisper_contract);
blockchain.execute_contract_call(deployment_call, &deployer_keypair)?;

// Send encrypted message
let message_call = ContractCall::send_whisper_message(
    contract_address,
    recipient_address,
    encrypted_message,
    message_type,
);
blockchain.execute_contract_call(message_call, &sender_keypair)?;
```

### 4. File Sharing Contracts

Decentralized file sharing with encryption and access controls.

```rust
use lib_blockchain::contracts::FileContract;

// Deploy file sharing contract
let file_contract = FileContract::new(
    50,   // file cost in ZHTP per MB
    true, // encryption required
);
let deployment_call = ContractCall::deploy_file_contract(file_contract);
blockchain.execute_contract_call(deployment_call, &deployer_keypair)?;

// Share file
let share_call = ContractCall::share_file(
    contract_address,
    file_hash,
    file_metadata,
    access_permissions,
);
blockchain.execute_contract_call(share_call, &owner_keypair)?;
```

### 5. Governance Contracts

DAO governance with proposal creation and voting.

```rust
use lib_blockchain::contracts::GovernanceContract;

// Deploy governance contract
let governance_contract = GovernanceContract::new(
    1000,    // minimum stake to create proposal
    7 * 24,  // voting period (7 days in hours)
    51,      // quorum percentage
);
let deployment_call = ContractCall::deploy_governance_contract(governance_contract);
blockchain.execute_contract_call(deployment_call, &deployer_keypair)?;

// Create proposal
let proposal_call = ContractCall::create_governance_proposal(
    contract_address,
    "Increase block size limit".to_string(),
    "Proposal to increase max block size from 1MB to 2MB".to_string(),
    ProposalType::ParameterChange,
);
blockchain.execute_contract_call(proposal_call, &proposer_keypair)?;

// Vote on proposal
let vote_call = ContractCall::cast_governance_vote(
    contract_address,
    proposal_id,
    VoteChoice::Yes,
);
blockchain.execute_contract_call(vote_call, &voter_keypair)?;
```

## Contract Development

### WASM Contract Development

Contracts are compiled to WebAssembly for execution:

```rust
// Example contract in Rust (compiled to WASM)
#[no_mangle]
pub extern "C" fn execute_contract() -> i32 {
    // Contract logic here
    let input = get_contract_input();
    let result = process_input(input);
    set_contract_output(result);
    0 // Success code
}

#[no_mangle]
pub extern "C" fn initialize_contract() -> i32 {
    // Contract initialization
    let config = get_initialization_config();
    setup_contract_state(config);
    0
}
```

### Gas System

All contract operations consume gas to prevent infinite loops:

```rust
use lib_blockchain::contracts::{GasConfig, GasPrice};

// Configure gas costs
let gas_config = GasConfig {
    base_cost: 21_000,           // Base transaction cost
    storage_cost: 20_000,        // Cost per storage operation
    computation_cost: 1,         // Cost per computational step
    memory_cost: 3,              // Cost per memory access
    network_cost: 68,            // Cost per network call
};

// Execute contract with gas limit
let execution_result = blockchain.execute_contract_with_gas(
    contract_call,
    1_000_000, // Gas limit
    &keypair,
)?;

// Check gas usage
println!("Gas used: {}", execution_result.gas_used);
println!("Gas remaining: {}", execution_result.gas_remaining);
```

### State Management

Contracts have persistent state storage:

```rust
// State operations in contracts
pub fn set_state(key: &[u8], value: &[u8]) -> Result<()> {
    // Set contract state
    contract_storage::set(key, value)
}

pub fn get_state(key: &[u8]) -> Result<Option<Vec<u8>>> {
    // Get contract state
    contract_storage::get(key)
}

pub fn delete_state(key: &[u8]) -> Result<()> {
    // Delete contract state
    contract_storage::delete(key)
}
```

### Event System

Contracts can emit events for external monitoring:

```rust
use lib_blockchain::contracts::{ContractEvent, EventType};

// Emit contract event
let event = ContractEvent {
    event_type: EventType::Transfer,
    data: serde_json::json!({
        "from": sender_address,
        "to": recipient_address,
        "amount": transfer_amount,
    }),
    timestamp: current_timestamp(),
};

emit_contract_event(event)?;
```

## Contract Security

### Sandbox Environment

Contracts execute in a secure sandbox:

- **Isolated Execution**: Contracts cannot access system resources
- **Memory Limits**: Bounded memory usage per contract
- **Time Limits**: Maximum execution time per call
- **API Restrictions**: Limited API surface for security

### Access Control

Implement proper access controls in contracts:

```rust
// Owner-only functions
pub fn admin_only_function(caller: Address) -> Result<()> {
    require(caller == get_contract_owner(), "Only owner can call");
    // Admin logic here
    Ok(())
}

// Token gate functions
pub fn token_gated_function(caller: Address, required_tokens: u64) -> Result<()> {
    let balance = get_token_balance(caller);
    require(balance >= required_tokens, "Insufficient tokens");
    // Gated logic here
    Ok(())
}
```

### Reentrancy Protection

Prevent reentrancy attacks:

```rust
static mut LOCKED: bool = false;

pub fn protected_function() -> Result<()> {
    unsafe {
        require(!LOCKED, "Reentrancy detected");
        LOCKED = true;
    }
    
    // Function logic here
    
    unsafe {
        LOCKED = false;
    }
    Ok(())
}
```

## Integration Examples

### Token + Web4 Integration

Combine tokens with Web4 for token-gated websites:

```rust
// Deploy token contract for access control
let access_token = TokenContract::new(
    "SiteAccess".to_string(),
    "ACCESS".to_string(),
    1000,  // Limited supply
    0,     // No decimals
    false, // Not deflationary
)?;

// Deploy Web4 contract with token gate
let web4_contract = Web4Contract::new_with_token_gate(
    access_token_address,
    1, // Require 1 ACCESS token
);

// Token holders can access the website
// Non-token holders see public landing page
```

### Messaging + File Integration

Combine messaging with file sharing:

```rust
// Share file through messaging
let file_share_message = WhisperMessage::new(
    MessageType::FileShare,
    serde_json::json!({
        "file_hash": shared_file_hash,
        "file_contract": file_contract_address,
        "access_key": encrypted_access_key,
    }),
    EncryptionLevel::High,
);

let message_call = ContractCall::send_whisper_message(
    messaging_contract_address,
    recipient_address,
    file_share_message,
);
```

## Performance Optimization

### Gas Optimization

Optimize contracts for lower gas usage:

```rust
// Use efficient data structures
use std::collections::BTreeMap; // More gas efficient than HashMap for small sets

// Batch operations
pub fn batch_transfer(transfers: Vec<Transfer>) -> Result<()> {
    for transfer in transfers {
        execute_transfer(transfer)?;
    }
    Ok(())
}

// Minimize storage operations
pub fn efficient_counter() -> Result<u64> {
    let current = get_state(b"counter")
        .unwrap_or_default()
        .map(|v| u64::from_le_bytes(v.try_into().unwrap()))
        .unwrap_or(0);
    
    let new_value = current + 1;
    set_state(b"counter", &new_value.to_le_bytes())?;
    
    Ok(new_value)
}
```

### Memory Optimization

```rust
// Use references to avoid cloning
pub fn process_large_data(data: &[u8]) -> Result<Hash> {
    // Process without copying
    let hash = compute_hash(data);
    Ok(hash)
}

// Stream processing for large datasets
pub fn process_stream<R: Read>(reader: R) -> Result<ProcessingResult> {
    let mut hasher = Hasher::new();
    let mut buffer = [0u8; 4096];
    
    for chunk in reader.bytes().chunks(4096) {
        let chunk: Vec<u8> = chunk.collect::<Result<Vec<_>, _>>()?;
        hasher.update(&chunk);
    }
    
    Ok(ProcessingResult::new(hasher.finalize()))
}
```

## Testing Contracts

### Unit Testing

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_token_transfer() {
        let mut blockchain = Blockchain::new_test();
        
        // Deploy token contract
        let token_contract = TokenContract::new_test();
        let contract_address = blockchain.deploy_contract(token_contract).unwrap();
        
        // Test transfer
        let transfer_call = ContractCall::transfer_tokens(
            contract_address,
            recipient_address(),
            1000,
        );
        
        let result = blockchain.execute_contract_call(transfer_call, &sender_keypair()).unwrap();
        assert!(result.success);
        
        // Verify balances
        let balance = blockchain.get_token_balance(contract_address, recipient_address()).unwrap();
        assert_eq!(balance, 1000);
    }
}
```

### Integration Testing

```rust
#[tokio::test]
async fn test_web4_deployment() -> Result<()> {
    let mut blockchain = Blockchain::new_test();
    
    // Deploy Web4 contract
    let web4_contract = Web4Contract::new();
    let contract_address = blockchain.deploy_contract(web4_contract).await?;
    
    // Register domain
    let domain = "test.zhtp";
    blockchain.register_domain(contract_address, domain, &owner_keypair()).await?;
    
    // Deploy manifest
    let manifest = create_test_manifest(domain);
    blockchain.deploy_manifest(contract_address, domain, manifest, &owner_keypair()).await?;
    
    // Test website access
    let website_data = blockchain.resolve_web4_content(domain).await?;
    assert!(!website_data.is_empty());
    
    Ok(())
}
```

## Best Practices

### Security Best Practices

1. **Input Validation**: Always validate external inputs
2. **Access Control**: Implement proper permission checks
3. **Reentrancy Protection**: Prevent reentrancy attacks
4. **Integer Overflow**: Check for arithmetic overflows
5. **Gas Limits**: Set reasonable gas limits for operations

### Development Best Practices

1. **Modular Design**: Split complex contracts into modules
2. **Documentation**: Document all public functions
3. **Testing**: Comprehensive unit and integration tests
4. **Upgradability**: Design for contract upgrades when needed
5. **Event Logging**: Emit events for important state changes

### Performance Best Practices

1. **Gas Optimization**: Minimize gas usage in operations
2. **Storage Efficiency**: Use efficient data structures
3. **Batch Operations**: Group related operations together
4. **Lazy Loading**: Load data only when needed
5. **Caching**: Cache frequently accessed data

## Troubleshooting

### Common Issues

1. **Gas Limit Exceeded**: Increase gas limit or optimize contract
2. **Access Denied**: Check contract permissions and ownership
3. **State Not Found**: Verify contract initialization
4. **Invalid Input**: Validate input parameters
5. **Contract Not Found**: Verify contract deployment

### Debugging Techniques

1. **Event Logs**: Use events to track contract execution
2. **Gas Analysis**: Monitor gas usage patterns
3. **State Inspection**: Check contract state at checkpoints
4. **Unit Testing**: Isolate and test individual functions
5. **Integration Testing**: Test full contract interactions

### Performance Issues

1. **High Gas Usage**: Optimize contract algorithms
2. **Slow Execution**: Reduce computational complexity
3. **Memory Issues**: Optimize data structures
4. **Storage Costs**: Minimize storage operations
5. **Network Latency**: Batch contract calls when possible