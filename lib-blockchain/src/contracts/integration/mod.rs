use crate::{
    contracts::executor::{ContractExecutor, ExecutionContext, ContractStorage},
    types::*,
    transaction::{Transaction, TransactionInput, TransactionOutput},
};
use anyhow::{Result, anyhow};
use crate::integration::crypto_integration::{PublicKey, Signature, KeyPair};
use serde::{Serialize, Deserialize};
use tracing::{debug, error};

/// Integration with ZHTP blockchain for contract execution
pub struct BlockchainIntegration<S: ContractStorage> {
    executor: ContractExecutor<S>,
}

impl<S: ContractStorage> BlockchainIntegration<S> {
    /// Create new blockchain integration
    pub fn new(executor: ContractExecutor<S>) -> Self {
        Self {
            executor,
        }
    }

    /// Process contract transaction from blockchain
    pub fn process_contract_transaction(
        &mut self,
        transaction: &Transaction,
        height: u64,
        timestamp: u64,
    ) -> Result<Vec<ContractResult>> {
        let mut results = Vec::new();
        
        // Extract contract calls from transaction data
        let contract_calls = self.extract_contract_calls(transaction)?;
        
        for (call, signature) in contract_calls {
            // Create execution context from height and timestamp
            let call_caller = call.get_caller().map_err(|e| anyhow!(e))?;
            let mut context = ExecutionContext::new(
                call_caller.clone(),
                height,
                timestamp,
                self.calculate_gas_limit(transaction)?,
                transaction.id().into(),
            );

            // Validate transaction signature
            let caller_key = self.extract_public_key(transaction)?;
            if call_caller != caller_key {
                return Err(anyhow!("Contract call caller does not match transaction signer"));
            }
            if !self.executor.validate_signature(&call, &signature, &caller_key)? {
                return Err(anyhow!("Invalid signature"));
            }

            // Execute the contract call
            match self.executor.execute_call(call, &mut context) {
                Ok(result) => results.push(result),
                Err(e) => {
                    error!("Contract execution failed: {}", e);
                    results.push(ContractResult::failure(context.gas_used));
                }
            }
        }

        Ok(results)
    }

    /// Extract contract calls from transaction
    fn extract_contract_calls(
        &self,
        transaction: &Transaction,
    ) -> Result<Vec<(ContractCall, Signature)>> {
        // Parse transaction memo to extract contract calls
        let mut calls = Vec::new();
        
        // Check if this is a contract transaction based on transaction type
        if transaction.transaction_type == TransactionType::ContractExecution {
            // For contract execution transactions, the memo contains serialized contract calls
            if transaction.memo.len() > 4 && &transaction.memo[0..4] == b"ZHTP" {
                // ZHTP contract transaction marker
                let contract_data = &transaction.memo[4..];
                let (call, signature): (ContractCall, Signature) = 
                    bincode::deserialize(contract_data)?;
                calls.push((call, signature));
            }
        }

        Ok(calls)
    }

    /// Extract public key from transaction
    fn extract_public_key(&self, transaction: &Transaction) -> Result<PublicKey> {
        // Extract the public key from the transaction signature
        // In the ZHTP system, we can derive the public key from the signature
        if let Some(input) = transaction.inputs.first() {
            // Use the public key from the input's scriptPubKey or signature
            // In ZHTP, the previous output's public key becomes the input's verification key
            debug!("Extracting public key from input: prev_hash={}", hex::encode(&input.previous_output.as_bytes()));
            
            // For contract calls, use the transaction signature's public key
            Ok(transaction.signature.public_key.clone())
        } else {
            Err(anyhow!("No inputs found in transaction"))
        }
    }

    /// Calculate gas limit for transaction
    fn calculate_gas_limit(&self, transaction: &Transaction) -> Result<u64> {
        // Calculate gas limit based on transaction size and type
        let base_gas = 21000u64; // Base transaction gas
        let data_gas = transaction.memo.len() as u64 * 16; // 16 gas per byte of memo data
        
        Ok(base_gas + data_gas)
    }

    /// Get executor reference
    pub fn executor(&self) -> &ContractExecutor<S> {
        &self.executor
    }

    /// Get mutable executor reference
    pub fn executor_mut(&mut self) -> &mut ContractExecutor<S> {
        &mut self.executor
    }
}

/// UTXO-based contract state management using TransactionOutput
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractUTXO {
    /// Transaction output representing the UTXO
    pub output: TransactionOutput,
    /// Transaction hash containing this output
    pub txid: [u8; 32],
    /// Output index in the transaction
    pub vout: u32,
    /// Contract state hash
    pub state_hash: [u8; 32],
    /// Contract type identifier
    pub contract_type: ContractType,
    /// Additional contract metadata
    pub metadata: Vec<u8>,
}

impl ContractUTXO {
    /// Create new contract UTXO
    pub fn new(
        output: TransactionOutput,
        txid: [u8; 32],
        vout: u32,
        state_hash: [u8; 32],
        contract_type: ContractType,
        metadata: Vec<u8>,
    ) -> Self {
        Self {
            output,
            txid,
            vout,
            state_hash,
            contract_type,
            metadata,
        }
    }

    /// Validate contract UTXO
    pub fn validate(&self) -> Result<()> {
        // Validate state hash
        if self.state_hash == [0u8; 32] {
            return Err(anyhow!("Invalid state hash"));
        }

        // Validate metadata size
        if self.metadata.len() > 1024 {
            return Err(anyhow!("Contract metadata too large"));
        }

        Ok(())
    }

    /// Get contract identifier
    pub fn contract_id(&self) -> [u8; 32] {
        crate::contracts::utils::generate_contract_id(&[
            &self.txid,
            &self.vout.to_le_bytes(),
            &self.state_hash,
        ])
    }
}

/// Contract transaction builder
pub struct ContractTransactionBuilder {
    calls: Vec<(ContractCall, Signature)>,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
}

impl ContractTransactionBuilder {
    /// Create new transaction builder
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
        }
    }

    /// Add contract call
    pub fn add_call(&mut self, call: ContractCall, signature: Signature) -> &mut Self {
        self.calls.push((call, signature));
        self
    }

    /// Add input
    pub fn add_input(&mut self, input: TransactionInput) -> &mut Self {
        self.inputs.push(input);
        self
    }

    /// Add output
    pub fn add_output(&mut self, output: TransactionOutput) -> &mut Self {
        self.outputs.push(output);
        self
    }

    /// Set transaction fee
    pub fn set_fee(&mut self, fee: u64) -> &mut Self {
        self.fee = fee;
        self
    }

    /// Build transaction
    pub fn build(&self, keypair: &KeyPair) -> Result<Transaction> {
        if self.calls.is_empty() {
            return Err(anyhow!("No contract calls specified"));
        }

        // Serialize contract calls
        let mut memo = Vec::new();
        memo.extend_from_slice(b"ZHTP"); // Contract transaction marker
        
        for (call, signature) in &self.calls {
            let call_data = bincode::serialize(&(call, signature))?;
            memo.extend_from_slice(&call_data);
        }

        // Sign transaction (simplified - would need proper signing logic)
        let temp_tx = Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ContractExecution,
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            fee: self.fee,
            signature: crate::integration::crypto_integration::Signature {
                signature: Vec::new(),
                public_key: crate::integration::crypto_integration::PublicKey::new(Vec::new()),
                algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
                timestamp: 0,
            }, // Temporary placeholder
            memo: memo.clone(),
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        };

        let tx_hash = temp_tx.signing_hash();
        let signature = keypair.sign(&tx_hash.as_array())?;

        let tx = Transaction {
            version: 1,
            chain_id: 0x03, // Default to development network
            transaction_type: TransactionType::ContractExecution,
            inputs: self.inputs.clone(),
            outputs: self.outputs.clone(),
            fee: self.fee,
            signature,
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        };

        Ok(tx)
    }
}

impl Default for ContractTransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Contract event system for cross-module communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContractEvent {
    /// Token transfer event
    TokenTransfer {
        token_id: [u8; 32],
        from: PublicKey,
        to: PublicKey,
        amount: u64,
    },
    /// Message sent event
    MessageSent {
        message_id: [u8; 32],
        sender: PublicKey,
        recipient: Option<PublicKey>,
        group_id: Option<[u8; 32]>,
    },
    /// Contact added event
    ContactAdded {
        contact_id: [u8; 32],
        owner: PublicKey,
        contact: PublicKey,
    },
    /// Group created event
    GroupCreated {
        group_id: [u8; 32],
        creator: PublicKey,
        name: String,
    },
    /// File shared event
    FileShared {
        file_id: [u8; 32],
        owner: PublicKey,
        filename: String,
    },
    /// Swap executed event (SOV↔DAO token swap)
    SwapExecuted {
        pool_id: [u8; 32],
        trader: PublicKey,
        sov_amount: u64,
        token_amount: u64,
        /// True if SOV→Token, false if Token→SOV
        sov_to_token: bool,
        fee_amount: u64,
    },
    /// Pool created event
    PoolCreated {
        pool_id: [u8; 32],
        token_id: [u8; 32],
        /// "NP" or "FP"
        dao_type: String,
        initial_sov: u64,
        initial_token: u64,
    },
    /// Fee collected and sent to treasury
    FeeCollected {
        pool_id: [u8; 32],
        sov_fees: u64,
        token_fees: u64,
        treasury_addr: PublicKey,
    },
}

impl ContractEvent {
    /// Get event type as string
    pub fn event_type(&self) -> &'static str {
        match self {
            ContractEvent::TokenTransfer { .. } => "TokenTransfer",
            ContractEvent::MessageSent { .. } => "MessageSent",
            ContractEvent::ContactAdded { .. } => "ContactAdded",
            ContractEvent::GroupCreated { .. } => "GroupCreated",
            ContractEvent::FileShared { .. } => "FileShared",
            ContractEvent::SwapExecuted { .. } => "SwapExecuted",
            ContractEvent::PoolCreated { .. } => "PoolCreated",
            ContractEvent::FeeCollected { .. } => "FeeCollected",
        }
    }

    /// Serialize event to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        bincode::serialize(self).map_err(|e| anyhow!("Serialization error: {}", e))
    }

    /// Deserialize event from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| anyhow!("Deserialization error: {}", e))
    }
}

/// Event listener trait for contract events
pub trait ContractEventListener {
    /// Handle contract event
    fn on_event(&mut self, event: ContractEvent) -> Result<()>;
}

/// Event publisher for contract events
pub struct ContractEventPublisher {
    listeners: Vec<Box<dyn ContractEventListener>>,
}

impl ContractEventPublisher {
    /// Create new event publisher
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }

    /// Add event listener
    pub fn add_listener(&mut self, listener: Box<dyn ContractEventListener>) {
        self.listeners.push(listener);
    }

    /// Publish event to all listeners
    pub fn publish(&mut self, event: ContractEvent) -> Result<()> {
        for listener in &mut self.listeners {
            listener.on_event(event.clone())?;
        }
        Ok(())
    }
}

impl Default for ContractEventPublisher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::executor::MemoryStorage;
    use lib_crypto::KeyPair;

    #[test]
    fn test_contract_utxo() {
        let output = TransactionOutput::new(
            [1u8; 32].into(),
            [2u8; 32].into(),
            PublicKey::new(vec![0u8; 32]),
        );

        let contract_utxo = ContractUTXO::new(
            output,
            [1u8; 32],
            0,
            [2u8; 32],
            ContractType::Token,
            b"metadata".to_vec(),
        );

        assert!(contract_utxo.validate().is_ok());
        assert_ne!(contract_utxo.contract_id(), [0u8; 32]);
    }

    #[test]
    fn test_transaction_builder() {
        let keypair = KeyPair::generate().unwrap();
        let mut builder = ContractTransactionBuilder::new();

        let call = ContractCall {
            contract_type: ContractType::Token,
            method: "transfer".to_string(),
            params: vec![1, 2, 3],
            permissions: crate::types::CallPermissions::Public,
        };

        let signature = keypair.sign(&bincode::serialize(&call).unwrap()).unwrap();

        builder.add_call(call, signature);

        let input = TransactionInput::new(
            [1u8; 32].into(),
            0,
            [2u8; 32].into(),
            crate::integration::zk_integration::ZkTransactionProof::default(),
        );

        let output = TransactionOutput::new(
            [3u8; 32].into(),
            [4u8; 32].into(),
            PublicKey::new(vec![0u8; 32]),
        );

        builder.add_input(input);
        builder.add_output(output);
        builder.set_fee(100);

        let transaction = builder.build(&keypair).unwrap();
        assert!(!transaction.inputs.is_empty());
        assert!(!transaction.outputs.is_empty());
        assert!(!transaction.memo.is_empty());
    }

    #[test]
    fn test_contract_events() {
        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let event = ContractEvent::TokenTransfer {
            token_id: [1u8; 32],
            from: keypair1.public_key,
            to: keypair2.public_key,
            amount: 1000,
        };

        assert_eq!(event.event_type(), "TokenTransfer");

        let serialized = event.to_bytes().unwrap();
        let deserialized = ContractEvent::from_bytes(&serialized).unwrap();

        match deserialized {
            ContractEvent::TokenTransfer { amount, .. } => assert_eq!(amount, 1000),
            _ => panic!("Wrong event type"),
        }
    }

    #[test]
    fn test_blockchain_integration() {
        let storage = MemoryStorage::default();
        let executor = ContractExecutor::new(storage);
        let integration = BlockchainIntegration::new(executor);

        // Test that integration is created successfully
        // Integration no longer holds blockchain reference directly
        let _executor_ref = integration.executor();
    }

    struct TestEventListener {
        events: Vec<ContractEvent>,
    }

    impl ContractEventListener for TestEventListener {
        fn on_event(&mut self, event: ContractEvent) -> Result<()> {
            self.events.push(event);
            Ok(())
        }
    }

    #[test]
    fn test_event_publisher() {
        let mut publisher = ContractEventPublisher::new();
        let listener = TestEventListener { events: Vec::new() };
        
        publisher.add_listener(Box::new(listener));

        let keypair1 = KeyPair::generate().unwrap();
        let keypair2 = KeyPair::generate().unwrap();

        let event = ContractEvent::TokenTransfer {
            token_id: [1u8; 32],
            from: keypair1.public_key,
            to: keypair2.public_key,
            amount: 1000,
        };

        assert!(publisher.publish(event).is_ok());
    }
}
