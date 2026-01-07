pub mod platform_isolation;

use crate::{
    types::*,
    contracts::tokens::*,
    contracts::messaging::*,
    contracts::contacts::*,
    contracts::groups::*,
};
use crate::contracts::utils::{generate_storage_key, generate_contract_id};
use crate::contracts::files::SharedFile;
use crate::contracts::runtime::{RuntimeFactory, RuntimeConfig, RuntimeContext, ContractRuntime};
use anyhow::{Result, anyhow};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::integration::crypto_integration::{PublicKey, Signature};

/// Discriminates the origin of a contract call for authorization purposes
///
/// Determines where token spending authority is derived from:
/// - User: Caller initiated the call directly, debit from ctx.caller
/// - Contract: Call originated from another contract, debit from ctx.contract
/// - System: Reserved for system-level calls
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallOrigin {
    /// User-initiated call: debit from ctx.caller
    User,
    /// Contract-to-contract call: debit from ctx.contract
    Contract,
    /// System-level call: reserved
    System,
}

/// Contract execution environment state
///
/// Immutable context passed to all contract calls, enabling capability-bound authorization
/// where token spending authority is determined by the execution context, not user-supplied parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Current caller's public key
    pub caller: PublicKey,
    /// Currently executing contract address (populated for contract-to-contract calls)
    pub contract: PublicKey,
    /// Origin of this call: User, Contract, or System
    pub call_origin: CallOrigin,
    /// Current block number
    pub block_number: u64,
    /// Current block timestamp
    pub timestamp: u64,
    /// Gas limit for this execution
    pub gas_limit: u64,
    /// Gas used so far
    pub gas_used: u64,
    /// Transaction hash that triggered this execution
    pub tx_hash: [u8; 32],
}

impl ExecutionContext {
    /// Create new execution context for user-initiated calls
    ///
    /// # Arguments
    /// - `caller`: The user or contract initiating the call
    /// - `block_number`: Current block height
    /// - `timestamp`: Current block timestamp
    /// - `gas_limit`: Maximum gas allowed for this execution
    /// - `tx_hash`: Hash of the transaction triggering this execution
    ///
    /// The created context will have `call_origin = CallOrigin::User` and `contract` as a zero address.
    pub fn new(
        caller: PublicKey,
        block_number: u64,
        timestamp: u64,
        gas_limit: u64,
        tx_hash: [u8; 32],
    ) -> Self {
        Self {
            caller,
            contract: PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            }, // Zero address for user calls
            call_origin: CallOrigin::User,
            block_number,
            timestamp,
            gas_limit,
            gas_used: 0,
            tx_hash,
        }
    }

    /// Create new execution context for contract-to-contract calls
    ///
    /// # Arguments
    /// - `caller`: The user or external origin
    /// - `contract`: The currently executing contract address
    /// - `block_number`: Current block height
    /// - `timestamp`: Current block timestamp
    /// - `gas_limit`: Maximum gas allowed for this execution
    /// - `tx_hash`: Hash of the transaction triggering this execution
    ///
    /// The created context will have `call_origin = CallOrigin::Contract`.
    pub fn with_contract(
        caller: PublicKey,
        contract: PublicKey,
        block_number: u64,
        timestamp: u64,
        gas_limit: u64,
        tx_hash: [u8; 32],
    ) -> Self {
        Self {
            caller,
            contract,
            call_origin: CallOrigin::Contract,
            block_number,
            timestamp,
            gas_limit,
            gas_used: 0,
            tx_hash,
        }
    }

    /// Check if there's enough gas remaining
    pub fn check_gas(&self, required: u64) -> Result<()> {
        if self.gas_used + required > self.gas_limit {
            return Err(anyhow!("Out of gas: required {}, available {}", 
                required, self.gas_limit - self.gas_used));
        }
        Ok(())
    }

    /// Consume gas
    pub fn consume_gas(&mut self, amount: u64) -> Result<()> {
        self.check_gas(amount)?;
        self.gas_used += amount;
        Ok(())
    }

    /// Get remaining gas
    pub fn remaining_gas(&self) -> u64 {
        self.gas_limit - self.gas_used
    }
}

/// Contract storage interface
pub trait ContractStorage {
    /// Get value from storage
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    
    /// Set value in storage
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    
    /// Delete value from storage
    fn delete(&mut self, key: &[u8]) -> Result<()>;
    
    /// Check if key exists in storage
    fn exists(&self, key: &[u8]) -> Result<bool>;
}

/// Simple in-memory storage implementation for testing
#[derive(Debug, Default)]
pub struct MemoryStorage {
    data: HashMap<Vec<u8>, Vec<u8>>,
}

impl ContractStorage for MemoryStorage {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.data.get(key).cloned())
    }
    
    fn set(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }
    
    fn delete(&mut self, key: &[u8]) -> Result<()> {
        self.data.remove(key);
        Ok(())
    }
    
    fn exists(&self, key: &[u8]) -> Result<bool> {
        Ok(self.data.contains_key(key))
    }
}

/// Main contract executor
pub struct ContractExecutor<S: ContractStorage> {
    storage: S,
    token_contracts: HashMap<[u8; 32], TokenContract>,
    web4_contracts: HashMap<[u8; 32], crate::contracts::web4::Web4Contract>,
    ubi_contracts: HashMap<[u8; 32], crate::contracts::UbiDistributor>,
    dev_grants_contracts: HashMap<[u8; 32], crate::contracts::DevGrants>,
    logs: Vec<ContractLog>,
    runtime_factory: RuntimeFactory,
    runtime_config: RuntimeConfig,
}

impl<S: ContractStorage> ContractExecutor<S> {
    /// Create new contract executor
    pub fn new(storage: S) -> Self {
        Self::with_runtime_config(storage, RuntimeConfig::default())
    }

    /// Create new contract executor with runtime configuration
    pub fn with_runtime_config(storage: S, runtime_config: RuntimeConfig) -> Self {
        let runtime_factory = RuntimeFactory::new(runtime_config.clone());

        let mut executor = Self {
            storage,
            token_contracts: HashMap::new(),
            web4_contracts: HashMap::new(),
            ubi_contracts: HashMap::new(),
            dev_grants_contracts: HashMap::new(),
            logs: Vec::new(),
            runtime_factory,
            runtime_config,
        };

        // Initialize ZHTP native token
        let lib_token = TokenContract::new_zhtp();
        executor.token_contracts.insert(lib_token.token_id, lib_token);

        executor
    }

    /// Execute a contract call
    pub fn execute_call(
        &mut self, 
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        // Check basic gas cost
        context.consume_gas(crate::GAS_BASE)?;
        
        // Store values needed for logging before moving call
        let contract_type = call.contract_type.clone();
        let method = call.method.clone();
        
        let result = match call.contract_type {
            ContractType::Token => self.execute_token_call(call, context),
            ContractType::WhisperMessaging => self.execute_messaging_call(call, context),
            ContractType::ContactRegistry => self.execute_contact_call(call, context),
            ContractType::GroupChat => self.execute_group_call(call, context),
            ContractType::FileSharing => self.execute_file_call(call, context),
            ContractType::Governance => self.execute_governance_call(call, context),
            ContractType::Web4Website => self.execute_web4_call(call, context),
            ContractType::UbiDistribution => self.execute_ubi_call(call, context),
            ContractType::DevGrants => self.execute_dev_grants_call(call, context),
        };

        // Log the execution
        // Generate a contract ID based on the call
        let contract_id = generate_contract_id(&[
            &bincode::serialize(&contract_type).unwrap_or_default(),
            method.as_bytes(),
            &context.tx_hash,
        ]);

        let log = ContractLog::new(
            contract_id,
            method,
            bincode::serialize(&context.caller).unwrap_or_default(),
            vec![], // Empty indexed fields for now
        );
        self.logs.push(log);

        result
    }

    /// Execute WASM contract (new sandboxed method)
    pub fn execute_wasm_contract(
        &mut self,
        contract_code: &[u8],
        method: &str,
        params: &[u8],
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        // Check basic gas cost for WASM execution
        context.consume_gas(crate::GAS_BASE)?;
        
        // Create runtime context
        let runtime_context = RuntimeContext {
            caller: context.caller.clone(),
            block_number: context.block_number,
            timestamp: context.timestamp,
            gas_limit: context.remaining_gas(),
            tx_hash: context.tx_hash,
        };

        // Get WASM runtime
        let mut runtime = self.runtime_factory.create_runtime("wasm")?;
        
        // Execute in sandboxed environment
        let runtime_result = runtime.execute(
            contract_code,
            method,
            params,
            &runtime_context,
            &self.runtime_config,
        )?;

        // Update gas usage
        context.consume_gas(runtime_result.gas_used)?;

        // Convert runtime result to contract result
        if runtime_result.success {
            Ok(ContractResult::with_return_data(&runtime_result.return_data, context.gas_used)?)
        } else {
            Err(anyhow!("WASM execution failed: {}", 
                runtime_result.error.unwrap_or_else(|| "Unknown error".to_string())))
        }
    }

    /// Execute token contract call
    fn execute_token_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_TOKEN)?;

        match call.method.as_str() {
            "create_custom_token" => {
                let params: (String, String, u64) = bincode::deserialize(&call.params)?;
                let (name, symbol, initial_supply) = params;
                
                let token = TokenContract::new_custom(
                    name.clone(),
                    symbol.clone(),
                    initial_supply,
                    context.caller.clone(),
                );
                
                let token_id = token.token_id;
                self.token_contracts.insert(token_id, token);
                
                // Store token data
                let storage_key = generate_storage_key("token", &token_id);
                let token_data = bincode::serialize(&self.token_contracts[&token_id])?;
                self.storage.set(&storage_key, &token_data)?;
                
                Ok(ContractResult::with_return_data(&token_id, context.gas_used)?)
            },
            "transfer" => {
                let params: ([u8; 32], PublicKey, u64) = bincode::deserialize(&call.params)?;
                let (token_id, to, amount) = params;

                if let Some(token) = self.token_contracts.get_mut(&token_id) {
                    // Use new capability-bound transfer API with ExecutionContext
                    let _burn_amount = token
                        .transfer(context, &to, amount)
                        .map_err(|e| anyhow!("{}", e))?;

                    // Update storage
                    let storage_key = generate_storage_key("token", &token_id);
                    let token_data = bincode::serialize(token)?;
                    self.storage.set(&storage_key, &token_data)?;

                    Ok(ContractResult::with_return_data(&"Transfer successful", context.gas_used)?)
                } else {
                    Err(anyhow!("Token not found"))
                }
            },
            "mint" => {
                let params: ([u8; 32], PublicKey, u64) = bincode::deserialize(&call.params)?;
                let (token_id, to, amount) = params;
                
                if let Some(token) = self.token_contracts.get_mut(&token_id) {
                    crate::contracts::tokens::functions::mint_tokens(
                        token,
                        &to,
                        amount,
                    ).map_err(|e| anyhow!("{}", e))?;
                    
                    // Update storage
                    let storage_key = generate_storage_key("token", &token_id);
                    let token_data = bincode::serialize(token)?;
                    self.storage.set(&storage_key, &token_data)?;
                    
                    Ok(ContractResult::with_return_data(&"Mint successful", context.gas_used)?)
                } else {
                    Err(anyhow!("Token not found"))
                }
            },
            "balance_of" => {
                let params: ([u8; 32], PublicKey) = bincode::deserialize(&call.params)?;
                let (token_id, owner) = params;
                
                if let Some(token) = self.token_contracts.get(&token_id) {
                    let balance = crate::contracts::tokens::functions::get_balance(token, &owner);
                    Ok(ContractResult::with_return_data(&balance, context.gas_used)?)
                } else {
                    Err(anyhow!("Token not found"))
                }
            },
            "total_supply" => {
                let token_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                if let Some(token) = self.token_contracts.get(&token_id) {
                    Ok(ContractResult::with_return_data(&token.total_supply, context.gas_used)?)
                } else {
                    Err(anyhow!("Token not found"))
                }
            },
            _ => Err(anyhow!("Unknown token method: {}", call.method)),
        }
    }

    /// Execute messaging contract call
    fn execute_messaging_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_MESSAGING)?;

        match call.method.as_str() {
            "send_message" => {
                let params: (Option<PublicKey>, Option<[u8; 32]>, String, Option<[u8; 32]>, bool, Option<u64>) = 
                    bincode::deserialize(&call.params)?;
                let (recipient, group_id, content, _file_attachment, _is_auto_burn, _burn_timestamp) = params;
                
                let message = if let Some(recipient) = recipient {
                    WhisperMessage::new_direct_message(
                        context.caller.clone(),
                        recipient,
                        content.into_bytes(),
                        100, // Default whisper tokens
                    )
                } else if let Some(group_id) = group_id {
                    WhisperMessage::new_group_message(
                        context.caller.clone(),
                        group_id,
                        content.into_bytes(),
                        100, // Default whisper tokens
                    )
                } else {
                    return Err(anyhow!("Must specify either recipient or group_id"));
                };
                
                // Store message
                let storage_key = generate_storage_key("message", &message.message_id);
                let message_data = bincode::serialize(&message)?;
                self.storage.set(&storage_key, &message_data)?;
                
                Ok(ContractResult::with_return_data(&message.message_id, context.gas_used)?)
            },
            "get_message" => {
                let message_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = generate_storage_key("message", &message_id);
                if let Some(message_data) = self.storage.get(&storage_key)? {
                    let message: WhisperMessage = bincode::deserialize(&message_data)?;
                    
                    // Check access permissions
                    if message.sender == context.caller || 
                       message.recipient == Some(context.caller.clone()) {
                        Ok(ContractResult::with_return_data(&message, context.gas_used)?)
                    } else {
                        Err(anyhow!("Access denied"))
                    }
                } else {
                    Err(anyhow!("Message not found"))
                }
            },
            _ => Err(anyhow!("Unknown messaging method: {}", call.method)),
        }
    }

    /// Execute contact contract call
    fn execute_contact_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_CONTACT)?;

        match call.method.as_str() {
            "add_contact" => {
                let params: (PublicKey, String) = bincode::deserialize(&call.params)?;
                let (contact_key, display_name) = params;
                
                let contact = ContactEntry::new(
                    context.caller.clone(),
                    display_name,
                    contact_key,
                );
                
                // Store contact
                let storage_key = contact.storage_key();
                let contact_data = bincode::serialize(&contact)?;
                self.storage.set(&storage_key, &contact_data)?;
                
                Ok(ContractResult::with_return_data(&contact.contact_id, context.gas_used)?)
            },
            "get_contact" => {
                let contact_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = generate_storage_key("contact", &contact_id);
                if let Some(contact_data) = self.storage.get(&storage_key)? {
                    let contact: ContactEntry = bincode::deserialize(&contact_data)?;
                    
                    // Check access permissions
                    if contact.owner == context.caller {
                        Ok(ContractResult::with_return_data(&contact, context.gas_used)?)
                    } else {
                        Err(anyhow!("Access denied"))
                    }
                } else {
                    Err(anyhow!("Contact not found"))
                }
            },
            "verify_contact" => {
                let contact_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = generate_storage_key("contact", &contact_id);
                if let Some(contact_data) = self.storage.get(&storage_key)? {
                    let mut contact: ContactEntry = bincode::deserialize(&contact_data)?;
                    
                    // Only owner can verify
                    if contact.owner == context.caller {
                        contact.verify();
                        
                        // Update storage
                        let updated_data = bincode::serialize(&contact)?;
                        self.storage.set(&storage_key, &updated_data)?;
                        
                        Ok(ContractResult::with_return_data(&"Contact verified", context.gas_used)?)
                    } else {
                        Err(anyhow!("Access denied"))
                    }
                } else {
                    Err(anyhow!("Contact not found"))
                }
            },
            _ => Err(anyhow!("Unknown contact method: {}", call.method)),
        }
    }

    /// Execute group contract call
    fn execute_group_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_GROUP)?;

        match call.method.as_str() {
            "create_group" => {
                let params: (String, String, u32, bool, u64) = bincode::deserialize(&call.params)?;
                let (name, description, max_members, is_private, whisper_token_cost) = params;
                
                let group = GroupChat::new(
                    name,
                    description,
                    context.caller.clone(),
                    max_members,
                    is_private,
                    whisper_token_cost,
                );
                
                // Store group
                let storage_key = group.storage_key();
                let group_data = bincode::serialize(&group)?;
                self.storage.set(&storage_key, &group_data)?;
                
                Ok(ContractResult::with_return_data(&group.group_id, context.gas_used)?)
            },
            "join_group" => {
                let group_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = generate_storage_key("group", &group_id);
                if let Some(group_data) = self.storage.get(&storage_key)? {
                    let mut group: GroupChat = bincode::deserialize(&group_data)?;
                    
                    group.add_member(context.caller.clone()).map_err(|e| anyhow!(e))?;
                    
                    // Update storage
                    let updated_data = bincode::serialize(&group)?;
                    self.storage.set(&storage_key, &updated_data)?;
                    
                    Ok(ContractResult::with_return_data(&"Joined group", context.gas_used)?)
                } else {
                    Err(anyhow!("Group not found"))
                }
            },
            "leave_group" => {
                let group_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = generate_storage_key("group", &group_id);
                if let Some(group_data) = self.storage.get(&storage_key)? {
                    let mut group: GroupChat = bincode::deserialize(&group_data)?;
                    
                    group.remove_member(&context.caller).map_err(|e| anyhow!(e))?;
                    
                    // Update storage
                    let updated_data = bincode::serialize(&group)?;
                    self.storage.set(&storage_key, &updated_data)?;
                    
                    Ok(ContractResult::with_return_data(&"Left group", context.gas_used)?)
                } else {
                    Err(anyhow!("Group not found"))
                }
            },
            _ => Err(anyhow!("Unknown group method: {}", call.method)),
        }
    }

    /// Execute file contract call
    fn execute_file_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_BASE)?; // Files use base gas cost

        match call.method.as_str() {
            "share_file" => {
                let params: (String, String, [u8; 32], u64, String, bool, u64, bool, Option<[u8; 32]>, Vec<String>, u64) =
                    bincode::deserialize(&call.params)?;
                let (filename, description, content_hash, file_size, mime_type, is_public, download_cost,
                     is_encrypted, encryption_key_hash, tags, max_downloads) = params;
                
                let file = SharedFile::new(
                    filename,
                    description,
                    context.caller.clone(),
                    content_hash,
                    file_size,
                    mime_type,
                    is_public,
                    download_cost,
                    is_encrypted,
                    encryption_key_hash,
                    tags,
                    max_downloads,
                );
                
                // Store file
                let storage_key = file.storage_key();
                let file_data = bincode::serialize(&file)?;
                self.storage.set(&storage_key, &file_data)?;
                
                Ok(ContractResult::with_return_data(&file.file_id, context.gas_used)?)
            },
            "download_file" => {
                let file_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = crate::contracts::utils::id_generation::generate_storage_key("file", &file_id);
                if let Some(file_data) = self.storage.get(&storage_key)? {
                    let mut file: SharedFile = bincode::deserialize(&file_data)?;
                    
                    // Check access and availability
                    if file.is_available_for_download(&context.caller) {
                        file.record_download().map_err(|e| anyhow!("{}", e))?;
                        
                        // Update storage
                        let updated_data = bincode::serialize(&file)?;
                        self.storage.set(&storage_key, &updated_data)?;
                        
                        Ok(ContractResult::with_return_data(&file.content_hash, context.gas_used)?)
                    } else {
                        Err(anyhow!("File not accessible or download limit reached"))
                    }
                } else {
                    Err(anyhow!("File not found"))
                }
            },
            "grant_file_access" => {
                let params: ([u8; 32], crate::integration::crypto_integration::PublicKey) = bincode::deserialize(&call.params)?;
                let (file_id, user) = params;
                
                let storage_key = crate::contracts::utils::id_generation::generate_storage_key("file", &file_id);
                if let Some(file_data) = self.storage.get(&storage_key)? {
                    let mut file: SharedFile = bincode::deserialize(&file_data)?;
                    
                    // Only owner can grant access
                    if file.owner == context.caller {
                        file.grant_access(user).map_err(|e| anyhow!("{}", e))?;
                        
                        // Update storage
                        let updated_data = bincode::serialize(&file)?;
                        self.storage.set(&storage_key, &updated_data)?;
                        
                        Ok(ContractResult::with_return_data(&"Access granted", context.gas_used)?)
                    } else {
                        Err(anyhow!("Access denied"))
                    }
                } else {
                    Err(anyhow!("File not found"))
                }
            },
            "revoke_file_access" => {
                let params: ([u8; 32], crate::integration::crypto_integration::PublicKey) = bincode::deserialize(&call.params)?;
                let (file_id, user) = params;
                
                let storage_key = crate::contracts::utils::id_generation::generate_storage_key("file", &file_id);
                if let Some(file_data) = self.storage.get(&storage_key)? {
                    let mut file: SharedFile = bincode::deserialize(&file_data)?;
                    
                    // Only owner can revoke access
                    if file.owner == context.caller {
                        file.revoke_access(&user).map_err(|e| anyhow!("{}", e))?;
                        
                        // Update storage
                        let updated_data = bincode::serialize(&file)?;
                        self.storage.set(&storage_key, &updated_data)?;
                        
                        Ok(ContractResult::with_return_data(&"Access revoked", context.gas_used)?)
                    } else {
                        Err(anyhow!("Access denied"))
                    }
                } else {
                    Err(anyhow!("File not found"))
                }
            },
            "get_file_info" => {
                let file_id: [u8; 32] = bincode::deserialize(&call.params)?;
                
                let storage_key = crate::contracts::utils::id_generation::generate_storage_key("file", &file_id);
                if let Some(file_data) = self.storage.get(&storage_key)? {
                    let file: SharedFile = bincode::deserialize(&file_data)?;
                    
                    // Only accessible users can get file info
                    if file.has_access(&context.caller) {
                        let file_info = (
                            file.filename,
                            file.description,
                            file.file_size,
                            file.mime_type,
                            file.upload_timestamp,
                            file.is_public,
                            file.download_count,
                            file.tags,
                        );
                        Ok(ContractResult::with_return_data(&file_info, context.gas_used)?)
                    } else {
                        Err(anyhow!("File not accessible"))
                    }
                } else {
                    Err(anyhow!("File not found"))
                }
            },
            _ => Err(anyhow!("Unknown file method: {}", call.method)),
        }
    }

    /// Execute governance contract call
    fn execute_governance_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_GROUP)?; // Use group gas for governance

        match call.method.as_str() {
            "create_proposal" => {
                // For now, return a simple success
                Ok(ContractResult::with_return_data(&"Governance not fully implemented", context.gas_used)?)
            },
            _ => Err(anyhow!("Unknown governance method: {}", call.method)),
        }
    }

    fn execute_web4_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        use crate::contracts::web4::Web4Contract;
        
        context.consume_gas(3000)?; // Base gas for Web4 operations

        // Get or create Web4 contract
        let contract_id = generate_contract_id(&[
            &bincode::serialize(&call.contract_type).unwrap_or_default(),
            call.method.as_bytes(),
            &context.tx_hash,
        ]);

        // For now, create a simple Web4 contract for demonstration
        // In production, you'd retrieve from storage or create with proper initialization
        let mut web4_contract = if let Some(existing) = self.web4_contracts.get_mut(&contract_id) {
            existing.clone()
        } else {
            // Create new Web4 contract with basic initialization
            use crate::contracts::web4::types::*;
            use std::collections::HashMap;
            
            let metadata = WebsiteMetadata {
                title: "New Web4 Site".to_string(),
                description: "Deployed via smart contract".to_string(),
                author: hex::encode(context.caller.as_bytes()),
                version: "1.0.0".to_string(),
                tags: vec![],
                language: "en".to_string(),
                created_at: chrono::Utc::now().timestamp() as u64,
                updated_at: chrono::Utc::now().timestamp() as u64,
                custom: HashMap::new(),
            };

            let domain_record = DomainRecord {
                domain: "new-site.zhtp".to_string(),
                owner: hex::encode(context.caller.as_bytes()),
                contract_address: hex::encode(&contract_id),
                registered_at: chrono::Utc::now().timestamp() as u64,
                expires_at: chrono::Utc::now().timestamp() as u64 + (365 * 24 * 60 * 60),
                status: DomainStatus::Active,
            };

            Web4Contract {
                contract_id: hex::encode(&contract_id),
                domain: "new-site.zhtp".to_string(),
                owner: hex::encode(context.caller.as_bytes()),
                metadata,
                routes: HashMap::new(),
                domain_record,
                created_at: chrono::Utc::now().timestamp() as u64,
                updated_at: chrono::Utc::now().timestamp() as u64,
                config: HashMap::new(),
            }
        };

        // Execute the contract method
        let result = web4_contract.execute(call);

        // Store the updated contract
        self.web4_contracts.insert(contract_id, web4_contract);

        Ok(result)
    }

    /// Execute UBI Distribution contract call
    fn execute_ubi_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_TOKEN)?;

        // Derive stable contract address for UBI Distribution
        let contract_id = generate_contract_id(&[
            &bincode::serialize(&ContractType::UbiDistribution).unwrap_or_default(),
            b"ubi_distribution",
        ]);

        // Create contract address PublicKey (stable for this contract type)
        let contract_address = PublicKey {
            dilithium_pk: contract_id.to_vec(),
            kyber_pk: contract_id.to_vec(),
            key_id: contract_id,
        };

        // Build capability-bound context for contract-origin execution
        // This ensures token.transfer() will debit ctx.contract, not ctx.caller
        let mut contract_context = ExecutionContext::with_contract(
            context.caller.clone(),
            contract_address,
            context.block_number,
            context.timestamp,
            context.gas_limit,
            context.tx_hash,
        );
        contract_context.gas_used = context.gas_used;

        // Get or create UBI contract instance
        if !self.ubi_contracts.contains_key(&contract_id) {
            // Create new UBI Distribution contract (default zero-governance for bootstrap)
            let zero_gov = PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            };
            let ubi = crate::contracts::UbiDistributor::new(zero_gov, 100)
                .map_err(|e| anyhow!("{:?}", e))?;
            self.ubi_contracts.insert(contract_id, ubi);
        }

        let ubi = self.ubi_contracts.get_mut(&contract_id).unwrap();

        let result = match call.method.as_str() {
            "claim_ubi" => {
                let params: (PublicKey, u64) = bincode::deserialize(&call.params)?;
                let (citizen, current_height) = params;

                // Get mutable reference to token for transfer
                if let Some(token) = self.token_contracts.get_mut(&TokenContract::new_zhtp().token_id) {
                    ubi.claim_ubi(&citizen, current_height, token, &contract_context)
                        .map_err(|e| anyhow!("{:?}", e))?;

                    // Update storage
                    let storage_key = generate_storage_key("ubi", &contract_id);
                    let ubi_data = bincode::serialize(&ubi)?;
                    self.storage.set(&storage_key, &ubi_data)?;

                    Ok(ContractResult::with_return_data(&"Claim UBI successful", contract_context.gas_used)?)
                } else {
                    Err(anyhow!("ZHTP token not found"))
                }
            },
            "register" => {
                let params: PublicKey = bincode::deserialize(&call.params)?;

                ubi.register(&params)
                    .map_err(|e| anyhow!("{:?}", e))?;

                // Update storage
                let storage_key = generate_storage_key("ubi", &contract_id);
                let ubi_data = bincode::serialize(&ubi)?;
                self.storage.set(&storage_key, &ubi_data)?;

                ContractResult::with_return_data(&"Citizen registered", contract_context.gas_used)
                    .map_err(|e| anyhow!("{:?}", e))
            },
            "receive_funds" => {
                let amount: u64 = bincode::deserialize(&call.params)?;

                ubi.receive_funds(amount)
                    .map_err(|e| anyhow!("{:?}", e))?;

                // Update storage
                let storage_key = generate_storage_key("ubi", &contract_id);
                let ubi_data = bincode::serialize(&ubi)?;
                self.storage.set(&storage_key, &ubi_data)?;

                ContractResult::with_return_data(&"Funds received", contract_context.gas_used)
                    .map_err(|e| anyhow!("{:?}", e))
            },
            _ => Err(anyhow!("Unknown UBI method: {}", call.method)),
        };

        // Update main context gas tracking
        context.gas_used = contract_context.gas_used;
        result
    }

    /// Execute Development Grants contract call
    fn execute_dev_grants_call(
        &mut self,
        call: ContractCall,
        context: &mut ExecutionContext,
    ) -> Result<ContractResult> {
        context.consume_gas(crate::GAS_TOKEN)?;

        // Derive stable contract address for DevGrants
        let contract_id = generate_contract_id(&[
            &bincode::serialize(&ContractType::DevGrants).unwrap_or_default(),
            b"dev_grants",
        ]);

        // Create contract address PublicKey (stable for this contract type)
        let contract_address = PublicKey {
            dilithium_pk: contract_id.to_vec(),
            kyber_pk: contract_id.to_vec(),
            key_id: contract_id,
        };

        // Build capability-bound context for contract-origin execution
        // This ensures token.transfer() will debit ctx.contract, not ctx.caller
        let mut contract_context = ExecutionContext::with_contract(
            context.caller.clone(),
            contract_address,
            context.block_number,
            context.timestamp,
            context.gas_limit,
            context.tx_hash,
        );
        contract_context.gas_used = context.gas_used;

        // Get or create DevGrants contract instance
        if !self.dev_grants_contracts.contains_key(&contract_id) {
            // Create new DevGrants contract (default zero-governance for bootstrap)
            let zero_gov = PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [0u8; 32],
            };
            let dev_grants = crate::contracts::DevGrants::new(zero_gov);
            self.dev_grants_contracts.insert(contract_id, dev_grants);
        }

        let dev_grants = self.dev_grants_contracts.get_mut(&contract_id).unwrap();

        let result = match call.method.as_str() {
            "receive_fees" => {
                let amount: u64 = bincode::deserialize(&call.params)?;

                dev_grants.receive_fees(amount)
                    .map_err(|e| anyhow!("{:?}", e))?;

                // Update storage
                let storage_key = generate_storage_key("dev_grants", &contract_id);
                let dg_data = bincode::serialize(&dev_grants)?;
                self.storage.set(&storage_key, &dg_data)?;

                Ok(ContractResult::with_return_data(&"Fees received", contract_context.gas_used)?)
            },
            "approve_grant" => {
                let params: (u64, PublicKey, u64) = bincode::deserialize(&call.params)?;
                let (proposal_id, recipient, amount) = params;

                dev_grants.approve_grant(&context.caller, proposal_id, &recipient, amount, context.block_number)
                    .map_err(|e| anyhow!("{:?}", e))?;

                // Update storage
                let storage_key = generate_storage_key("dev_grants", &contract_id);
                let dg_data = bincode::serialize(&dev_grants)?;
                self.storage.set(&storage_key, &dg_data)?;

                Ok(ContractResult::with_return_data(&"Grant approved", contract_context.gas_used)?)
            },
            "execute_grant" => {
                let params: (u64, PublicKey) = bincode::deserialize(&call.params)?;
                let (proposal_id, recipient) = params;

                // Get mutable reference to token for transfer
                if let Some(token) = self.token_contracts.get_mut(&TokenContract::new_zhtp().token_id) {
                    dev_grants.execute_grant(&context.caller, proposal_id, &recipient, context.block_number, token, &contract_context)
                        .map_err(|e| anyhow!("{:?}", e))?;

                    // Update storage
                    let storage_key = generate_storage_key("dev_grants", &contract_id);
                    let dg_data = bincode::serialize(&dev_grants)?;
                    self.storage.set(&storage_key, &dg_data)?;

                    Ok(ContractResult::with_return_data(&"Grant executed", contract_context.gas_used)?)
                } else {
                    Err(anyhow!("ZHTP token not found"))
                }
            },
            _ => Err(anyhow!("Unknown DevGrants method: {}", call.method)),
        };

        // Update main context gas tracking
        context.gas_used = contract_context.gas_used;
        result
    }

    /// Get contract logs
    pub fn get_logs(&self) -> &[ContractLog] {
        &self.logs
    }

    /// Clear logs
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Get token contract
    pub fn get_token_contract(&self, token_id: &[u8; 32]) -> Option<&TokenContract> {
        self.token_contracts.get(token_id)
    }

    /// Load token contract from storage
    pub fn load_token_contract(&mut self, token_id: &[u8; 32]) -> Result<()> {
        let storage_key = generate_storage_key("token", token_id);
        if let Some(token_data) = self.storage.get(&storage_key)? {
            let token: TokenContract = bincode::deserialize(&token_data)?;
            self.token_contracts.insert(*token_id, token);
            Ok(())
        } else {
            Err(anyhow!("Token not found in storage"))
        }
    }

    /// Save all token contracts to storage
    pub fn save_all_tokens(&mut self) -> Result<()> {
        for (token_id, token) in &self.token_contracts {
            let storage_key = generate_storage_key("token", token_id);
            let token_data = bincode::serialize(token)?;
            self.storage.set(&storage_key, &token_data)?;
        }
        Ok(())
    }

    /// Validate contract call signature
    pub fn validate_signature(
        &self,
        call: &ContractCall,
        signature: &Signature,
        public_key: &PublicKey,
    ) -> Result<bool> {
        let call_data = bincode::serialize(call)?;
        Ok(public_key.verify(&call_data, signature).unwrap_or(false))
    }
    /// Estimate gas cost for a contract call
    pub fn estimate_gas(&self, call: &ContractCall) -> u64 {
        let base_gas = crate::GAS_BASE;
        let specific_gas = match call.contract_type {
            ContractType::Token => crate::GAS_TOKEN,
            ContractType::WhisperMessaging => crate::GAS_MESSAGING,
            ContractType::ContactRegistry => crate::GAS_CONTACT,
            ContractType::GroupChat => crate::GAS_GROUP,
            ContractType::FileSharing => crate::GAS_BASE,
            ContractType::Governance => crate::GAS_GROUP,
            ContractType::Web4Website => 3000, // Web4 website contract gas
            ContractType::UbiDistribution => crate::GAS_TOKEN, // Token-like operations
            ContractType::DevGrants => crate::GAS_TOKEN, // Token-like operations
        };

        base_gas + specific_gas
    }

    /// Get runtime configuration
    pub fn runtime_config(&self) -> &RuntimeConfig {
        &self.runtime_config
    }

    /// Check if WASM runtime is available
    pub fn is_wasm_available(&self) -> bool {
        self.runtime_factory.is_wasm_available()
    }

    /// Update runtime configuration
    pub fn update_runtime_config(&mut self, config: RuntimeConfig) {
        self.runtime_config = config.clone();
        self.runtime_factory = RuntimeFactory::new(config);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::KeyPair;

    #[test]
    fn test_execution_context() {
        let keypair = KeyPair::generate().unwrap();
        let mut context = ExecutionContext::new(
            keypair.public_key,
            100,
            1234567890,
            10000,
            [1u8; 32],
        );

        assert_eq!(context.remaining_gas(), 10000);
        
        // Consume some gas
        assert!(context.consume_gas(1000).is_ok());
        assert_eq!(context.gas_used, 1000);
        assert_eq!(context.remaining_gas(), 9000);
        
        // Try to consume more gas than available
        assert!(context.consume_gas(10000).is_err());
    }

    #[test]
    fn test_memory_storage() {
        let mut storage = MemoryStorage::default();
        
        let key = b"test_key";
        let value = b"test_value";
        
        // Initially empty
        assert!(!storage.exists(key).unwrap());
        assert!(storage.get(key).unwrap().is_none());
        
        // Set value
        storage.set(key, value).unwrap();
        assert!(storage.exists(key).unwrap());
        assert_eq!(storage.get(key).unwrap().unwrap(), value);
        
        // Delete value
        storage.delete(key).unwrap();
        assert!(!storage.exists(key).unwrap());
        assert!(storage.get(key).unwrap().is_none());
    }

    #[test]
    fn test_contract_executor() {
        let storage = MemoryStorage::default();
        let executor = ContractExecutor::new(storage);
        
        // Should have ZHTP token initialized
        let lib_id = crate::contracts::utils::generate_lib_token_id();
        assert!(executor.get_token_contract(&lib_id).is_some());
    }

    #[test]
    fn test_token_execution() {
        let storage = MemoryStorage::default();
        let mut executor = ContractExecutor::new(storage);
        
        let creator_keypair = KeyPair::generate().unwrap();
        let mut context = ExecutionContext::new(
            creator_keypair.public_key.clone(),
            1,
            1234567890,
            100000,
            [1u8; 32],
        );

        // Create custom token
        let call = ContractCall {
            contract_type: ContractType::Token,
            method: "create_custom_token".to_string(),
            params: bincode::serialize(&("Test Token".to_string(), "TEST".to_string(), 1000000u64)).unwrap(),
            permissions: crate::types::CallPermissions::Public,
        };

        let result = executor.execute_call(call, &mut context).unwrap();
        assert!(result.success);
        
        let token_id: [u8; 32] = bincode::deserialize(&result.return_data).unwrap();
        assert!(executor.get_token_contract(&token_id).is_some());
    }

    #[test]
    fn test_gas_estimation() {
        let storage = MemoryStorage::default();
        let executor = ContractExecutor::new(storage);
        
        let token_call = ContractCall {
            contract_type: ContractType::Token,
            method: "transfer".to_string(),
            params: vec![],
            permissions: crate::types::CallPermissions::Public,
        };
        
        let estimated_gas = executor.estimate_gas(&token_call);
        assert_eq!(estimated_gas, crate::GAS_BASE + crate::GAS_TOKEN);
    }
}
