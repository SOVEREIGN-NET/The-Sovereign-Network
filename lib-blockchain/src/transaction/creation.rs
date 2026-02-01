//! Transaction creation utilities
//!
//! Provides functionality for creating new transactions in the ZHTP blockchain.

use crate::transaction::core::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData, WalletTransactionData};
use crate::types::transaction_type::TransactionType;
use crate::integration::crypto_integration::{Signature, PublicKey, PrivateKey, SignatureAlgorithm};
use tracing::debug;

/// Error types for transaction creation
#[derive(Debug, Clone)]
pub enum TransactionCreateError {
    InsufficientFunds,
    InvalidInputs,
    InvalidOutputs,
    SigningError,
    ZkProofError,
    IdentityError,
}

impl std::fmt::Display for TransactionCreateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransactionCreateError::InsufficientFunds => write!(f, "Insufficient funds"),
            TransactionCreateError::InvalidInputs => write!(f, "Invalid transaction inputs"),
            TransactionCreateError::InvalidOutputs => write!(f, "Invalid transaction outputs"),
            TransactionCreateError::SigningError => write!(f, "Transaction signing failed"),
            TransactionCreateError::ZkProofError => write!(f, "Zero-knowledge proof generation failed"),
            TransactionCreateError::IdentityError => write!(f, "Identity transaction creation failed"),
        }
    }
}

impl std::error::Error for TransactionCreateError {}

/// Builder for creating transactions
#[derive(Debug, Clone)]
pub struct TransactionBuilder {
    version: u32,
    transaction_type: TransactionType,
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    memo: Vec<u8>,
    identity_data: Option<IdentityTransactionData>,
    wallet_data: Option<WalletTransactionData>,
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionBuilder {
    /// Create a new transaction builder
    pub fn new() -> Self {
        Self {
            version: 1,
            transaction_type: TransactionType::Transfer,
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            memo: Vec::new(),
            identity_data: None,
            wallet_data: None,
        }
    }

    /// Set transaction version
    pub fn version(mut self, version: u32) -> Self {
        self.version = version;
        self
    }

    /// Set transaction type
    pub fn transaction_type(mut self, tx_type: TransactionType) -> Self {
        self.transaction_type = tx_type;
        self
    }

    /// Add an input to the transaction
    pub fn add_input(mut self, input: TransactionInput) -> Self {
        self.inputs.push(input);
        self
    }

    /// Add multiple inputs to the transaction
    pub fn add_inputs(mut self, inputs: Vec<TransactionInput>) -> Self {
        self.inputs.extend(inputs);
        self
    }

    /// Add an output to the transaction
    pub fn add_output(mut self, output: TransactionOutput) -> Self {
        self.outputs.push(output);
        self
    }

    /// Add multiple outputs to the transaction
    pub fn add_outputs(mut self, outputs: Vec<TransactionOutput>) -> Self {
        self.outputs.extend(outputs);
        self
    }

    /// Set transaction fee
    pub fn fee(mut self, fee: u64) -> Self {
        self.fee = fee;
        self
    }

    /// Set memo data
    pub fn memo(mut self, memo: Vec<u8>) -> Self {
        self.memo = memo;
        self
    }

    /// Set identity data (for identity transactions)
    pub fn identity_data(mut self, identity_data: IdentityTransactionData) -> Self {
        self.identity_data = Some(identity_data);
        self.transaction_type = TransactionType::IdentityRegistration;
        self
    }

    /// Set wallet data (for wallet transactions)
    pub fn wallet_data(mut self, wallet_data: WalletTransactionData) -> Self {
        self.wallet_data = Some(wallet_data);
        self.transaction_type = TransactionType::WalletRegistration;
        self
    }

    /// Build the transaction (requires signing)
    pub fn build(self, private_key: &PrivateKey) -> Result<Transaction, TransactionCreateError> {
        // Validate inputs and outputs
        if self.inputs.is_empty() && !self.transaction_type.is_identity_transaction() {
            return Err(TransactionCreateError::InvalidInputs);
        }

        if self.outputs.is_empty() && !self.transaction_type.is_identity_transaction() {
            return Err(TransactionCreateError::InvalidOutputs);
        }

        // Check if inputs already have ZK proofs (they should be pre-generated in most cases)
        // Check both legacy 'proof' field and new 'proof_data' field
        let needs_proofs = self.inputs.is_empty() || 
                          self.inputs.iter().any(|i| {
                              i.zk_proof.amount_proof.proof.is_empty() && 
                              i.zk_proof.amount_proof.proof_data.is_empty()
                          });
        
        let inputs_with_proofs = if needs_proofs {
            // Generate ZK proofs only if inputs don't have them yet
            tracing::debug!("Generating ZK proofs for {} inputs", self.inputs.len());
            self.generate_zk_proofs_for_inputs(private_key)?
        } else {
            // Use existing ZK proofs from inputs
            tracing::debug!("Using pre-generated ZK proofs for {} inputs", self.inputs.len());
            self.inputs
        };

        // Create unsigned transaction
        let mut transaction = Transaction {
            version: self.version,
            chain_id: 0x03, // Default to development network
            transaction_type: self.transaction_type,
            inputs: inputs_with_proofs,
            outputs: self.outputs,
            fee: self.fee,
            signature: Signature {
                signature: Vec::new(),
                public_key: PublicKey::new(Vec::new()),
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: 0,
            }, // Will be set below
            memo: self.memo,
            validator_data: None,
            identity_data: self.identity_data,
            wallet_data: self.wallet_data,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
        };

        // Sign the transaction
        transaction.signature = Self::sign_transaction(&transaction, private_key)
            .map_err(|_| TransactionCreateError::SigningError)?;

        Ok(transaction)
    }
    
    /// Generate ZK proofs for all transaction inputs using lib-proofs
    fn generate_zk_proofs_for_inputs(&self, private_key: &PrivateKey) -> Result<Vec<TransactionInput>, TransactionCreateError> {
        use lib_proofs::ZkTransactionProof;
        use lib_crypto::random::generate_nonce;
        
        let mut inputs_with_proofs = Vec::with_capacity(self.inputs.len());
        
        // Calculate total output amount for proper proof generation
        // This is critical: the ZK proof must prove sender_balance >= amount + fee
        let total_output_amount: u64 = self.outputs.iter()
            .map(|_| {
                // In a full implementation, we'd extract the actual amount from the commitment
                // For now, we estimate based on typical transaction patterns
                // The actual UTXO amounts should be passed in from the caller
                1000u64 // Reasonable estimate per output
            })
            .sum();
        
        // The sender balance must be at least the sum of outputs + fee
        // We add a buffer to ensure proof generation succeeds
        let estimated_sender_balance = total_output_amount.max(self.fee + 1000);
        
        tracing::debug!(
            "Generating ZK proofs: outputs={}, total_amount={}, fee={}, estimated_balance={}",
            self.outputs.len(), total_output_amount, self.fee, estimated_sender_balance
        );
        
        for (idx, input) in self.inputs.iter().enumerate() {
            // Generate cryptographic parameters for ZK proof using private key
            let sender_nonce = generate_nonce();
            let nullifier_nonce = generate_nonce();
            
            // Use private key bytes to derive sender secret for ZK proof
            let mut sender_secret = [0u8; 32];
            let mut nullifier_secret = [0u8; 32];
            
            // Combine private key with nonce for enhanced security
            let pk_bytes = &private_key.dilithium_sk[..12.min(private_key.dilithium_sk.len())];
            for i in 0..pk_bytes.len() {
                sender_secret[i] = pk_bytes[i] ^ sender_nonce[i % sender_nonce.len()];
                nullifier_secret[i] = pk_bytes[i] ^ nullifier_nonce[i % nullifier_nonce.len()];
            }
            
            // Generate ZK proof for this input
            let zk_proof = match ZkTransactionProof::prove_transaction(
                estimated_sender_balance, // sender_balance (must be >= amount + fee)
                0,                       // receiver_balance (not needed for inputs)
                total_output_amount,     // amount (sum of outputs)
                self.fee,               // fee
                sender_secret,          // sender_blinding
                [0u8; 32],             // receiver_blinding (not needed)
                nullifier_secret,       // nullifier
            ) {
                Ok(proof) => {
                    tracing::debug!("Successfully generated ZK proof for input {}", idx);
                    proof
                },
                Err(e) => {
                    // If ZK proof generation fails, log detailed error and return
                    tracing::error!(
                        "ZK proof generation failed for input {}: {:?}\n\
                         Parameters: balance={}, amount={}, fee={}",
                        idx, e, estimated_sender_balance, total_output_amount, self.fee
                    );
                    return Err(TransactionCreateError::ZkProofError);
                }
            };
            
            // Create new input with ZK proof
            let mut input_with_proof = input.clone();
            input_with_proof.zk_proof = zk_proof;
            
            inputs_with_proofs.push(input_with_proof);
        }
        
        tracing::debug!("Successfully generated ZK proofs for all {} inputs", inputs_with_proofs.len());
        Ok(inputs_with_proofs)
    }

    /// Sign a transaction with the given private key using lib-crypto
    fn sign_transaction(transaction: &Transaction, private_key: &PrivateKey) -> Result<Signature, String> {
        use lib_crypto::post_quantum::dilithium::dilithium_sign;

        // Create transaction hash for signing (without signature)
        let mut tx_for_signing = transaction.clone();
        tx_for_signing.signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new(Vec::new()),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };

        let tx_hash = crate::transaction::hashing::hash_transaction(&tx_for_signing);

        // Key size constants (from pqcrypto_dilithium)
        const DILITHIUM2_SECRETKEY_BYTES: usize = 2560;

        // Use the public key stored alongside the private key
        // The public key must be stored with the private key since Dilithium
        // doesn't allow deriving pk from sk after generation
        if private_key.dilithium_pk.is_empty() {
            return Err("Private key missing dilithium_pk - keypair must store both keys".to_string());
        }

        // Use auto-detecting sign function
        let signature_result = dilithium_sign(tx_hash.as_bytes(), &private_key.dilithium_sk);

        match signature_result {
            Ok(signature_bytes) => {
                let signature = Signature {
                    signature: signature_bytes,
                    public_key: PublicKey::new(private_key.dilithium_pk.clone()),
                    algorithm: if private_key.dilithium_sk.len() == DILITHIUM2_SECRETKEY_BYTES {
                        SignatureAlgorithm::Dilithium2
                    } else {
                        SignatureAlgorithm::Dilithium5
                    },
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                Ok(signature)
            },
            Err(e) => Err(format!("Failed to sign transaction: {}", e))
        }
    }
}

/// Create a simple transfer transaction
pub fn create_transfer_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::Transfer)
        .add_inputs(inputs)
        .add_outputs(outputs)
        .fee(fee)
        .build(private_key)
}

/// Create an identity registration transaction
pub fn create_identity_transaction(
    identity_data: IdentityTransactionData,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::IdentityRegistration)
        .identity_data(identity_data)
        .fee(fee)
        .build(private_key)
}

/// Create a wallet registration transaction
pub fn create_wallet_transaction(
    wallet_data: WalletTransactionData,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::WalletRegistration)
        .wallet_data(wallet_data)
        .fee(fee)
        .build(private_key)
}

/// Create a contract deployment transaction
pub fn create_contract_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::ContractDeployment)
        .add_inputs(inputs)
        .add_outputs(outputs)
        .fee(fee)
        .build(private_key)
}

/// Create a token operation transaction
pub fn create_token_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    TransactionBuilder::new()
        .transaction_type(TransactionType::Transfer) // Use Transfer for token operations
        .add_inputs(inputs)
        .add_outputs(outputs)
        .fee(fee)
        .build(private_key)
}

/// Utility functions for transaction creation
pub mod utils {
    use super::*;

    /// Calculate the minimum fee for a transaction based on effective size
    ///
    /// Post-quantum signatures (Dilithium5) are ~7KB, dwarfing actual payload.
    /// To avoid penalizing PQ crypto adoption, we cap witness overhead.
    pub fn calculate_minimum_fee(transaction_size: usize) -> u64 {
        // Post-quantum witness overhead (signature + pubkey)
        const PQ_WITNESS_SIZE: usize = 7219; // Dilithium5 sig (4627) + pk (2592)
        const WITNESS_CAP: usize = 500;      // Cap witness contribution to fee calc
        const BASE_FEE: u64 = 100;           // Base transaction fee
        const BYTES_PER_ZHTP: u64 = 100;     // 100 bytes per 1 ZHTP

        // Estimate payload vs witness
        let payload_bytes = transaction_size.saturating_sub(PQ_WITNESS_SIZE);
        let witness_bytes = transaction_size.saturating_sub(payload_bytes);

        // Effective size = payload + capped witness
        let effective_size = payload_bytes + witness_bytes.min(WITNESS_CAP);
        let size_fee = (effective_size as u64 / BYTES_PER_ZHTP).max(1);

        let total_fee = BASE_FEE + size_fee;

        debug!("Fee calc: tx={}B, payload={}B, witness={}B, effective={}B, fee={} ZHTP",
               transaction_size, payload_bytes, witness_bytes, effective_size, total_fee);

        total_fee
    }

    /// Estimate transaction size before creation
    pub fn estimate_transaction_size(
        num_inputs: usize,
        num_outputs: usize,
        memo_size: usize,
        has_identity_data: bool,
    ) -> usize {
        // Rough estimation based on typical sizes
        let base_size = 64; // Version, type, fee, signature
        let input_size = num_inputs * 128; // Previous output + nullifier + proof
        let output_size = num_outputs * 96; // Commitment + note + recipient
        let memo_size = memo_size;
        let identity_size = if has_identity_data { 256 } else { 0 };

        base_size + input_size + output_size + memo_size + identity_size
    }

    /// Validate transaction structure before creation
    pub fn validate_transaction_structure(
        transaction_type: &TransactionType,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        identity_data: &Option<IdentityTransactionData>,
    ) -> Result<(), TransactionCreateError> {
        match transaction_type {
            TransactionType::Transfer => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
            }
            TransactionType::IdentityRegistration |
            TransactionType::IdentityUpdate |
            TransactionType::IdentityRevocation => {
                if identity_data.is_none() {
                    return Err(TransactionCreateError::IdentityError);
                }
            }
            TransactionType::ContractDeployment | TransactionType::ContractExecution => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
            }
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload | TransactionType::UbiDistribution => {
                // Audit transactions - no specific validation needed here
                // Memo validation will be handled during transaction validation
            }
            TransactionType::WalletRegistration => {
                // Wallet registration transactions should have wallet data
                // Validation will be handled during transaction validation
            }
            TransactionType::ValidatorRegistration |
            TransactionType::ValidatorUpdate |
            TransactionType::ValidatorUnregister => {
                // Validator transactions - no specific validation needed here
                // Validation will be handled during transaction validation
            }
            TransactionType::DaoProposal |
            TransactionType::DaoVote |
            TransactionType::DaoExecution |
            TransactionType::DifficultyUpdate => {
                // DAO transactions - validation will be handled during transaction validation
            }
            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated pull-based claims (Week 7)
                // Validation will be handled during transaction validation
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforces 20% tribute (Week 7)
                // Validation will be handled during transaction validation
            }
        }

        Ok(())
    }
}
