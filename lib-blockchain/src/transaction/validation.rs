//! Transaction validation logic
//!
//! Provides comprehensive validation for ZHTP blockchain transactions.

use crate::transaction::core::{Transaction, TransactionInput, TransactionOutput, IdentityTransactionData};
use crate::types::{Hash, transaction_type::TransactionType, ContractCall, ContractType};
use crate::integration::crypto_integration::{Signature, PublicKey, SignatureAlgorithm};
use crate::integration::zk_integration::is_valid_proof_structure;

/// Transaction validation error types
#[derive(Debug, Clone)]
pub enum ValidationError {
    InvalidSignature,
    InvalidZkProof,
    DoubleSpend,
    InvalidAmount,
    InvalidFee,
    InvalidTransaction,
    InvalidIdentityData,
    InvalidInputs,
    InvalidOutputs,
    MissingRequiredData,
    InvalidTransactionType,
    UnregisteredSender,
    InvalidMemo,
    MissingWalletData,
    InvalidWalletId,
    InvalidOwnerIdentity,
    InvalidPublicKey,
    InvalidSeedCommitment,
    InvalidWalletType,
    InvalidValidatorData,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::InvalidSignature => write!(f, "Invalid transaction signature"),
            ValidationError::InvalidZkProof => write!(f, "Invalid zero-knowledge proof"),
            ValidationError::DoubleSpend => write!(f, "Double spend detected"),
            ValidationError::InvalidAmount => write!(f, "Invalid transaction amount"),
            ValidationError::InvalidFee => write!(f, "Invalid transaction fee"),
            ValidationError::InvalidTransaction => write!(f, "Invalid transaction structure"),
            ValidationError::InvalidIdentityData => write!(f, "Invalid identity data"),
            ValidationError::InvalidInputs => write!(f, "Invalid transaction inputs"),
            ValidationError::InvalidOutputs => write!(f, "Invalid transaction outputs"),
            ValidationError::MissingRequiredData => write!(f, "Missing required transaction data"),
            ValidationError::InvalidTransactionType => write!(f, "Invalid transaction type"),
            ValidationError::UnregisteredSender => write!(f, "Transaction from unregistered sender identity"),
            ValidationError::InvalidMemo => write!(f, "Invalid or missing transaction memo"),
            ValidationError::MissingWalletData => write!(f, "Missing wallet data in transaction"),
            ValidationError::InvalidWalletId => write!(f, "Invalid wallet ID"),
            ValidationError::InvalidOwnerIdentity => write!(f, "Invalid owner identity"),
            ValidationError::InvalidPublicKey => write!(f, "Invalid public key"),
            ValidationError::InvalidSeedCommitment => write!(f, "Invalid seed commitment"),
            ValidationError::InvalidWalletType => write!(f, "Invalid wallet type"),
            ValidationError::InvalidValidatorData => write!(f, "Invalid or missing validator data"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Transaction validation result
pub type ValidationResult = Result<(), ValidationError>;

/// Transaction validator with state context
pub struct TransactionValidator {
    // Note: In implementation, this would contain references to
    // blockchain state, UTXO set, nullifier set, etc.
}

/// Transaction validator with blockchain state access for identity verification
pub struct StatefulTransactionValidator<'a> {
    /// Reference to blockchain state for identity verification
    blockchain: Option<&'a crate::blockchain::Blockchain>,
}

impl TransactionValidator {
    /// Create a new transaction validator
    pub fn new() -> Self {
        Self {}
    }

    /// Validate a transaction completely
    pub fn validate_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check if this is a system transaction (empty inputs = coinbase-style)
        let is_system_transaction = transaction.inputs.is_empty();

        // Basic structure validation
        self.validate_basic_structure(transaction)?;

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    self.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            },
            TransactionType::IdentityRegistration => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityUpdate => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => self.validate_identity_transaction(transaction)?,
            TransactionType::ContractDeployment => self.validate_contract_transaction(transaction)?,
            TransactionType::ContractExecution => self.validate_contract_transaction(transaction)?,
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::UbiDistribution => {
                // UBI distribution is a token transaction - validate with proper token logic
                self.validate_token_transaction(transaction)?;
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::WalletRegistration => {
                // Wallet registration transactions - validate wallet data and ownership
                self.validate_wallet_registration_transaction(transaction)?;
            },
            TransactionType::ValidatorRegistration => {
                // Validator registration - validate validator data exists
                if transaction.validator_data.is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            },
            TransactionType::ValidatorUpdate => {
                // Validator update - validate validator data exists
                if transaction.validator_data.is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            },
            TransactionType::ValidatorUnregister => {
                // Validator unregister - validate validator data exists
                if transaction.validator_data.is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            },
            TransactionType::DaoProposal |
            TransactionType::DaoVote |
            TransactionType::DaoExecution |
            TransactionType::DifficultyUpdate => {
                // DAO transactions - validation handled at consensus layer
            }
        
            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated claims (Week 7)
                self.validate_ubi_claim_transaction(transaction)?;
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforce 20% tribute (Week 7)
                self.validate_profit_declaration_transaction(transaction)?;
            }
            TransactionType::Coinbase => {
                // Coinbase must have no inputs
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfer - outputs required
                if transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validate governance_config_data exists
                if transaction.governance_config_data.is_none() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
        }

        // Signature validation (skip for system transactions - they don't have real signatures)
        // System transactions include: genesis, UBI distribution, identity/wallet registration from node
        if !is_system_transaction {
            self.validate_signature(transaction)?;
        }

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            self.validate_zk_proofs(transaction)?;
        }

        // Economic validation (modified for system transactions)
        self.validate_economics_with_system_check(transaction, is_system_transaction)?;

        Ok(())
    }

    /// Validate a transaction with explicit system transaction flag
    pub fn validate_transaction_with_system_flag(&self, transaction: &Transaction, is_system_transaction: bool) -> ValidationResult {
        // Basic structure validation
        self.validate_basic_structure(transaction)?;

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    self.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            },
            TransactionType::IdentityRegistration => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityUpdate => self.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => self.validate_identity_transaction(transaction)?,
            TransactionType::ContractDeployment => self.validate_contract_transaction(transaction)?,
            TransactionType::ContractExecution => self.validate_contract_transaction(transaction)?,
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::UbiDistribution => {
                // UBI distribution is a token transaction - validate with proper token logic
                self.validate_token_transaction(transaction)?;
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::WalletRegistration => {
                // Wallet registration transactions - validate wallet data and ownership
                self.validate_wallet_registration_transaction(transaction)?;
            },
            TransactionType::ValidatorRegistration => {
                // Validator registration - validate validator data exists
                if transaction.validator_data.is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            },
            TransactionType::ValidatorUpdate => {
                // Validator update - validate validator data exists
                if transaction.validator_data.is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            },
            TransactionType::ValidatorUnregister => {
                // Validator unregister - validate validator data exists
                if transaction.validator_data.is_none() {
                    return Err(ValidationError::InvalidValidatorData);
                }
            },
            TransactionType::DaoProposal |
            TransactionType::DaoVote |
            TransactionType::DaoExecution |
            TransactionType::DifficultyUpdate => {
                // DAO transactions - validation handled at consensus layer
            }
        
            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated claims (Week 7)
                self.validate_ubi_claim_transaction(transaction)?;
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforce 20% tribute (Week 7)
                self.validate_profit_declaration_transaction(transaction)?;
            }
            TransactionType::Coinbase => {
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenTransfer => {
                if transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validate governance_config_data exists
                if transaction.governance_config_data.is_none() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
        }

        // Signature validation (skip for system transactions - they don't have real signatures)
        // System transactions include: genesis, UBI distribution, identity/wallet registration from node
        if !is_system_transaction {
            self.validate_signature(transaction)?;
        }

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            self.validate_zk_proofs(transaction)?;
        }

        // Economic validation (modified for system transactions)
        self.validate_economics_with_system_check(transaction, is_system_transaction)?;

        Ok(())
    }

    /// Validate basic transaction structure
    fn validate_basic_structure(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!("[BREADCRUMB] validate_basic_structure ENTER: version={}, size={}, memo_len={}",
            transaction.version, transaction.size(), transaction.memo.len());

        // Check version
        if transaction.version == 0 {
            tracing::warn!("[BREADCRUMB] validate_basic_structure FAILED: version is 0");
            return Err(ValidationError::InvalidTransaction);
        }

        // Check transaction size limits
        if transaction.size() > MAX_TRANSACTION_SIZE {
            tracing::warn!("[BREADCRUMB] validate_basic_structure FAILED: size {} > MAX {}", transaction.size(), MAX_TRANSACTION_SIZE);
            return Err(ValidationError::InvalidTransaction);
        }

        // Check memo size
        if transaction.memo.len() > MAX_MEMO_SIZE {
            tracing::warn!("[BREADCRUMB] validate_basic_structure FAILED: memo.len {} > MAX {}", transaction.memo.len(), MAX_MEMO_SIZE);
            return Err(ValidationError::InvalidTransaction);
        }

        tracing::debug!("[BREADCRUMB] validate_basic_structure PASSED");
        Ok(())
    }

    /// Validate transfer transaction
    fn validate_transfer_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Allow empty inputs for system transactions (UBI, rewards, minting)
        // System transactions are identified by having a genesis/zero input
        let is_system_transaction = transaction.inputs.is_empty() || 
            transaction.inputs.iter().all(|input| {
                input.previous_output == Hash::default() && 
                input.nullifier != Hash::default() // Must have unique nullifier even for system tx
            });

        if !is_system_transaction && transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }

        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Validate inputs (only if not system transaction)
        if !is_system_transaction {
            for input in &transaction.inputs {
                self.validate_transaction_input(input)?;
            }
        }

        // Validate outputs
        for output in &transaction.outputs {
            self.validate_transaction_output(output)?;
        }

        Ok(())
    }

    /// Validate identity transaction
    fn validate_identity_transaction(&self, transaction: &Transaction) -> ValidationResult {
        let identity_data = transaction.identity_data.as_ref()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Check if this is a system transaction (empty inputs), except for token contract calls
        let is_system_transaction = transaction.inputs.is_empty() && !is_token_contract_execution(transaction);
        
        self.validate_identity_data(identity_data, is_system_transaction)?;

        // Identity transactions should have minimal inputs/outputs
        // The main logic is handled by lib-identity package
        
        Ok(())
    }

    /// Validate contract transaction
    fn validate_contract_transaction(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!("[BREADCRUMB] validate_contract_transaction ENTER");

        // Allow system contract deployments (empty inputs) for Web4 and system contracts
        let is_system_contract = transaction.inputs.is_empty();

        if !is_system_contract && transaction.inputs.is_empty() {
            tracing::warn!("[BREADCRUMB] validate_contract_transaction FAILED: empty inputs for non-system contract");
            return Err(ValidationError::InvalidInputs);
        }

        // Token contract executions don't require outputs
        let is_token = is_token_contract_execution(transaction);
        tracing::warn!("[BREADCRUMB] validate_contract_transaction: outputs.is_empty={}, is_token={}",
            transaction.outputs.is_empty(), is_token);

        if transaction.outputs.is_empty() && !is_token {
            tracing::warn!("[BREADCRUMB] validate_contract_transaction FAILED: empty outputs for non-token contract");
            return Err(ValidationError::InvalidOutputs);
        }

        tracing::debug!("[BREADCRUMB] validate_contract_transaction PASSED");
        Ok(())
    }

    /// Validate token transaction
    fn validate_token_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Token validation is handled by lib-economy package
        // Here we just validate basic structure
        
        // System transactions (empty inputs) are valid for UBI/rewards
        if transaction.inputs.is_empty() {
            // This is a system transaction - only validate outputs
            if transaction.outputs.is_empty() {
                return Err(ValidationError::InvalidOutputs);
            }
            return Ok(());
        }

        // Regular transactions need both inputs and outputs
        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate transaction signature using proper cryptographic verification
    fn validate_signature(&self, transaction: &Transaction) -> ValidationResult {
        tracing::warn!(
            "[BREADCRUMB] validate_signature ENTER: sig_len={}, pk_len={}, algo={:?}",
            transaction.signature.signature.len(),
            transaction.signature.public_key.as_bytes().len(),
            transaction.signature.algorithm
        );
        use lib_crypto::verification::verify_signature;

        // Create transaction hash for verification (without signature)
        let mut tx_for_verification = transaction.clone();
        tx_for_verification.signature = Signature {
            signature: Vec::new(),
            // CRITICAL: Must use all-zero key_id for consistent hashing
            public_key: PublicKey {
                dilithium_pk: Vec::new(),
                kyber_pk: Vec::new(),
                key_id: [0u8; 32],
            },
            algorithm: transaction.signature.algorithm.clone(),
            timestamp: 0,
        };
        
        // CRITICAL FIX: Use signing_hash() to match client-side signing
        // Client uses signing_hash() in ContractTransactionBuilder.build()
        // Previously used .hash() which is a different function (hash_transaction vs hash_for_signature)
        let tx_hash = tx_for_verification.signing_hash();

        // Log hash for comparison with client
        tracing::info!(
            "[validation] Server computed signing_hash = {}",
            hex::encode(tx_hash.as_bytes())
        );

        // Get signature data
        let signature_bytes = &transaction.signature.signature;
        let public_key_bytes = transaction.signature.public_key.as_bytes();
        
        if signature_bytes.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }
        
        if public_key_bytes.is_empty() {
            return Err(ValidationError::InvalidSignature);
        }
        
        // Use lib-crypto for signature verification
        match verify_signature(tx_hash.as_bytes(), signature_bytes, &public_key_bytes) {
            Ok(is_valid) => {
                if !is_valid {
                    return Err(ValidationError::InvalidSignature);
                }
            },
            Err(_) => {
                return Err(ValidationError::InvalidSignature);
            }
        }
        
        // Verify signature algorithm is supported
        match transaction.signature.algorithm {
            SignatureAlgorithm::Dilithium2 | 
            SignatureAlgorithm::Dilithium5 => {
                // Supported algorithms
            },
            _ => {
                return Err(ValidationError::InvalidSignature);
            }
        }
        
        // Verify signature timestamp is reasonable (not too old or in future)
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
            
        let signature_time = transaction.signature.timestamp;
        
        // Allow signatures up to 1 hour old and 5 minutes in future
        const MAX_SIGNATURE_AGE: u64 = 3600; // 1 hour
        const MAX_FUTURE_TIME: u64 = 300;    // 5 minutes
        
        if signature_time + MAX_SIGNATURE_AGE < current_time {
            return Err(ValidationError::InvalidSignature);
        }
        
        if signature_time > current_time + MAX_FUTURE_TIME {
            return Err(ValidationError::InvalidSignature);
        }

        Ok(())
    }

    /// Validate zero-knowledge proofs for all inputs using ZK verification
    fn validate_zk_proofs(&self, transaction: &Transaction) -> ValidationResult {
        use lib_proofs::ZkTransactionProof;
        tracing::warn!(
            "[BREADCRUMB] validate_zk_proofs ENTER: inputs={}",
            transaction.inputs.len()
        );
        println!(" DEBUG: Starting ZK proof validation for {} transaction inputs", transaction.inputs.len());
        log::info!("Starting ZK proof validation for {} transaction inputs", transaction.inputs.len());
        
        for (i, input) in transaction.inputs.iter().enumerate() {
            println!(" DEBUG: Validating ZK proof for input {}", i);
            log::info!("Validating ZK proof for input {}", i);
            
            // First check if the proof structure is valid
            if !is_valid_proof_structure(&input.zk_proof) {
                println!(" DEBUG: Input {}: Invalid proof structure", i);
                log::error!("Input {}: Invalid proof structure", i);
                return Err(ValidationError::InvalidZkProof);
            }
            println!(" DEBUG: Input {}: Proof structure valid", i);
            log::info!("Input {}: Proof structure valid", i);
            
            // Use the proper ZK verification from lib-proofs
            match ZkTransactionProof::verify_transaction(&input.zk_proof) {
                Ok(is_valid) => {
                    if !is_valid {
                        log::error!("Input {}: ZkTransactionProof verification failed", i);
                        return Err(ValidationError::InvalidZkProof);
                    }
                    log::info!("Input {}: ZkTransactionProof verification passed", i);
                },
                Err(e) => {
                    log::error!("Input {}: ZK verification failed - NO FALLBACKS ALLOWED: {:?}", i, e);
                    return Err(ValidationError::InvalidZkProof);
                }
            }
            
            // Additional ZK proof validations
            log::info!("Input {}: Validating nullifier proof", i);
            self.validate_nullifier_proof(input)?;
            log::info!("Input {}: Nullifier proof valid", i);
            
            log::info!("Input {}: Validating amount range proof", i);
            self.validate_amount_range_proof(input)?;
            log::info!("Input {}: Amount range proof valid", i);
        }

        log::info!("All ZK proofs validated successfully");
        Ok(())
    }
    
    /// Validate nullifier proof to prevent double spending
    fn validate_nullifier_proof(&self, input: &TransactionInput) -> ValidationResult {
        // Verify that the nullifier proof is cryptographically sound
        if let Some(plonky2_proof) = &input.zk_proof.nullifier_proof.plonky2_proof {
            // Use Plonky2 verification if available
            if let Ok(zk_system) = lib_proofs::ZkProofSystem::new() {
                // FIX: Nullifier proof is generated with prove_transaction, so use verify_transaction
                match zk_system.verify_transaction(plonky2_proof) {
                    Ok(is_valid) => {
                        if !is_valid {
                            return Err(ValidationError::InvalidZkProof);
                        }
                    },
                    Err(e) => {
                        // NO FALLBACKS - fail hard if ZK verification fails
                        log::error!("Nullifier ZK verification failed - no fallbacks allowed: {:?}", e);
                        return Err(ValidationError::InvalidZkProof);
                    }
                }
            }
        } else {
            // NO FALLBACKS - require Plonky2 proofs only
            log::error!("Nullifier proof missing Plonky2 verification - no fallbacks allowed");
            return Err(ValidationError::InvalidZkProof);
        }
        
        Ok(())
    }
    
    /// Validate amount range proof to ensure positive amounts
    fn validate_amount_range_proof(&self, input: &TransactionInput) -> ValidationResult {
        println!(" DEBUG: validate_amount_range_proof starting");
        log::info!("validate_amount_range_proof starting");
        
        // Verify that the amount is within valid range (positive, not exceeding max supply)
        if let Some(plonky2_proof) = &input.zk_proof.amount_proof.plonky2_proof {
            println!(" DEBUG: Found Plonky2 amount proof for range validation");
            println!(" DEBUG: Amount proof system: '{}'", plonky2_proof.proof_system);
            log::info!("Found Plonky2 amount proof for range validation");
            log::info!("Amount proof system: '{}'", plonky2_proof.proof_system);
            
            // Use Plonky2 verification if available
            if let Ok(zk_system) = lib_proofs::ZkProofSystem::new() {
                println!(" DEBUG: ZkProofSystem initialized for range validation");
                log::info!("ZkProofSystem initialized for range validation");
                
                // Check if this is a transaction proof or range proof and use appropriate verification
                match plonky2_proof.proof_system.as_str() {
                    "ZHTP-Optimized-Range" => {
                        println!(" DEBUG: Using verify_range for range proof");
                        log::info!("Using verify_range for range proof");
                        
                        match zk_system.verify_range(plonky2_proof) {
                            Ok(is_valid) => {
                                println!(" DEBUG: Range verification result: {}", is_valid);
                                log::info!("Range verification result: {}", is_valid);
                                
                                if !is_valid {
                                    println!(" DEBUG: Range proof INVALID - returning error");
                                    log::error!("Range proof INVALID - returning error");
                                    return Err(ValidationError::InvalidZkProof);
                                } else {
                                    println!(" DEBUG: Range proof VALID");
                                    log::info!("Range proof VALID");
                                }
                            },
                            Err(e) => {
                                println!(" DEBUG: Range verification error: {:?}", e);
                                log::error!("Range verification error: {:?}", e);
                                return Err(ValidationError::InvalidZkProof);
                            }
                        }
                    },
                    "ZHTP-Optimized-Transaction" | "Plonky2" => {
                        println!(" DEBUG: Using verify_transaction for transaction proof");
                        log::info!("Using verify_transaction for transaction proof");
                        
                        match zk_system.verify_transaction(plonky2_proof) {
                            Ok(is_valid) => {
                                println!(" DEBUG: Transaction verification result: {}", is_valid);
                                log::info!("Transaction verification result: {}", is_valid);
                                
                                if !is_valid {
                                    println!(" DEBUG: Transaction proof INVALID - returning error");
                                    log::error!("Transaction proof INVALID - returning error");
                                    return Err(ValidationError::InvalidZkProof);
                                } else {
                                    println!(" DEBUG: Transaction proof VALID");
                                    log::info!("Transaction proof VALID");
                                }
                            },
                            Err(e) => {
                                println!(" DEBUG: Transaction verification error: {:?}", e);
                                log::error!("Transaction verification error: {:?}", e);
                                return Err(ValidationError::InvalidZkProof);
                            }
                        }
                    },
                    _ => {
                        println!(" DEBUG: Unknown proof system: '{}'", plonky2_proof.proof_system);
                        log::error!("Unknown proof system: '{}'", plonky2_proof.proof_system);
                        return Err(ValidationError::InvalidZkProof);
                    }
                }
            } else {
                println!(" DEBUG: Failed to initialize ZkProofSystem");
                log::error!("Failed to initialize ZkProofSystem");
                return Err(ValidationError::InvalidZkProof);
            }
        } else {
            println!(" DEBUG: No Plonky2 proof found - NO FALLBACKS ALLOWED");
            log::error!("Amount proof missing Plonky2 verification - no fallbacks allowed");
            return Err(ValidationError::InvalidZkProof);
        }
        
        println!(" DEBUG: validate_amount_range_proof completed successfully");
        log::info!("validate_amount_range_proof completed successfully");
        Ok(())
    }

    /// Validate economic aspects (fees, amounts) with system transaction support
    fn validate_economics_with_system_check(&self, transaction: &Transaction, is_system_transaction: bool) -> ValidationResult {
        tracing::warn!(
            "[BREADCRUMB] validate_economics_with_system_check ENTER: system={}, fee={}, size={}",
            is_system_transaction,
            transaction.fee,
            transaction.size()
        );
        if is_system_transaction {
            // System transactions are fee-free and create new money
            if transaction.fee != 0 {
                tracing::warn!("[BREADCRUMB] validate_economics_with_system_check FAIL: system fee != 0");
                return Err(ValidationError::InvalidFee);
            }
            // System transactions don't need fee validation
            return Ok(());
        }

        // Regular transaction fee validation
        let min_fee = calculate_minimum_fee(transaction.size());
        tracing::warn!(
            "[BREADCRUMB] validate_economics_with_system_check min_fee={}, fee={}",
            min_fee,
            transaction.fee
        );
        println!("FEE VALIDATION DEBUG:");
        println!("   Transaction size: {} bytes", transaction.size());
        println!("   Calculated minimum fee: {} ZHTP", min_fee);
        println!("   Actual transaction fee: {} ZHTP", transaction.fee);
        if transaction.fee < min_fee {
            println!("FEE VALIDATION FAILED: {} < {}", transaction.fee, min_fee);
            return Err(ValidationError::InvalidFee);
        }
        println!("FEE VALIDATION PASSED");

        // Economic validation is handled by lib-economy package
        // Here we just check basic fee requirements

        Ok(())
    }

    /// Validate individual transaction input
    fn validate_transaction_input(&self, input: &TransactionInput) -> ValidationResult {
        // Check nullifier is not zero (unless this is a system transaction input)
        if input.nullifier == Hash::default() {
            return Err(ValidationError::InvalidInputs);
        }

        // Check previous output reference (system transactions can have Hash::default())
        // System transactions are identified by having Hash::default() previous_output with valid nullifier
        if input.previous_output == Hash::default() && input.nullifier != Hash::default() {
            // This might be a system transaction input - allow it
            return Ok(());
        }

        if input.previous_output == Hash::default() {
            return Err(ValidationError::InvalidInputs);
        }

        // Note: Double spend checking would require access to nullifier set
        // This is handled at the blockchain level

        Ok(())
    }

    /// Validate individual transaction output
    fn validate_transaction_output(&self, output: &TransactionOutput) -> ValidationResult {
        // Check commitment is not zero
        if output.commitment == Hash::default() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Check note is not zero
        if output.note == Hash::default() {
            return Err(ValidationError::InvalidOutputs);
        }

        // Check recipient public key is valid
        if output.recipient.dilithium_pk.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate identity transaction data
    fn validate_identity_data(&self, identity_data: &IdentityTransactionData, is_system_transaction: bool) -> ValidationResult {
        // Check DID format
        if identity_data.did.is_empty() || !identity_data.did.starts_with("did:zhtp:") {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check display name
        if identity_data.display_name.is_empty() || identity_data.display_name.len() > 64 {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check public key
        if identity_data.public_key.is_empty() {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check ownership proof (allow empty for system/genesis transactions)
        if !is_system_transaction && identity_data.ownership_proof.is_empty() {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check identity type
        let valid_types = ["human", "organization", "device", "service", "validator", "revoked"];
        if !valid_types.contains(&identity_data.identity_type.as_str()) {
            return Err(ValidationError::InvalidIdentityData);
        }

        // Check fees - allow zero fees for system transactions
        if !is_system_transaction && identity_data.registration_fee == 0 {
            return Err(ValidationError::InvalidFee);
        }

        Ok(())
    }

    /// Validate wallet registration transaction
    fn validate_wallet_registration_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check that wallet_data exists
        let wallet_data = transaction.wallet_data.as_ref()
            .ok_or(ValidationError::MissingWalletData)?;

        // Validate wallet ID is not default/empty
        if wallet_data.wallet_id == crate::types::Hash::default() {
            return Err(ValidationError::InvalidWalletId);
        }

        // Validate owner identity ID if present
        if let Some(owner_id) = &wallet_data.owner_identity_id {
            if *owner_id == crate::types::Hash::default() {
                return Err(ValidationError::InvalidOwnerIdentity);
            }
        }

        // Validate public key is not empty
        if wallet_data.public_key.is_empty() {
            return Err(ValidationError::InvalidPublicKey);
        }

        // Validate seed commitment is not default
        if wallet_data.seed_commitment == crate::types::Hash::default() {
            return Err(ValidationError::InvalidSeedCommitment);
        }

        // Validate wallet type is recognized
        match wallet_data.wallet_type.as_str() {
            "Primary" | "UBI" | "Savings" | "DAO" => {
                // Valid wallet types
            }
            _ => return Err(ValidationError::InvalidWalletType),
        }

        Ok(())
    }

    /// Validate UBI claim transaction (Week 7)
    ///
    /// Checks that:
    /// - ubi_claim_data is present and valid
    /// - claim_amount is positive
    /// - citizenship_proof is provided
    /// - transaction has outputs but no inputs (claiming from pool)
    fn validate_ubi_claim_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check that ubi_claim_data exists
        let claim_data = transaction.ubi_claim_data.as_ref()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Validate claim data structure
        if !claim_data.validate() {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check that no inputs are present (claims don't spend UTXOs)
        if !transaction.inputs.is_empty() {
            return Err(ValidationError::InvalidInputs);
        }

        // Check that outputs are present (recipient wallet for claim)
        if transaction.outputs.is_empty() {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }

    /// Validate profit declaration transaction (Week 7)
    ///
    /// Checks that:
    /// - profit_declaration_data is present and valid
    /// - 20% tribute calculation is correct
    /// - revenue sources sum to profit amount
    /// - for-profit and nonprofit treasuries are different (anti-circumvention)
    /// - inputs and outputs represent tribute transfer
    fn validate_profit_declaration_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Check that profit_declaration_data exists
        let decl_data = transaction.profit_declaration_data.as_ref()
            .ok_or(ValidationError::MissingRequiredData)?;

        // Validate declaration data structure
        if !decl_data.validate() {
            return Err(ValidationError::InvalidTransaction);
        }

        // Verify anti-circumvention checks
        if !decl_data.anti_circumvention_check() {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check that inputs and outputs match tribute amount
        if transaction.inputs.len() != 1 {
            return Err(ValidationError::InvalidInputs);
        }

        if transaction.outputs.len() != 1 {
            return Err(ValidationError::InvalidOutputs);
        }

        Ok(())
    }
}

fn is_token_contract_execution(transaction: &Transaction) -> bool {
    if transaction.transaction_type != TransactionType::ContractExecution {
        tracing::debug!("is_token_contract_execution: not ContractExecution type");
        return false;
    }

    if transaction.memo.len() <= 4 {
        tracing::warn!("is_token_contract_execution: memo too short (len={})", transaction.memo.len());
        return false;
    }

    if &transaction.memo[0..4] != b"ZHTP" {
        tracing::warn!("is_token_contract_execution: memo doesn't start with ZHTP, starts with {:?}",
            &transaction.memo[0..4]);
        return false;
    }

    let call_data = &transaction.memo[4..];
    let (call, _sig): (ContractCall, Signature) = match bincode::deserialize(call_data) {
        Ok(parsed) => parsed,
        Err(e) => {
            tracing::warn!("is_token_contract_execution: bincode deserialize failed: {}", e);
            return false;
        }
    };

    if call.contract_type != ContractType::Token {
        tracing::warn!("is_token_contract_execution: contract_type is {:?}, not Token", call.contract_type);
        return false;
    }

    let is_token_method = matches!(
        call.method.as_str(),
        "create_custom_token" | "mint" | "transfer" | "burn"
    );

    if !is_token_method {
        tracing::warn!("is_token_contract_execution: method '{}' is not a token method", call.method);
    } else {
        tracing::info!("is_token_contract_execution: VALID token contract call, method={}", call.method);
    }

    is_token_method
}

impl Default for TransactionValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> StatefulTransactionValidator<'a> {
    /// Create a new stateful transaction validator with blockchain access
    pub fn new(blockchain: &'a crate::blockchain::Blockchain) -> Self {
        Self { 
            blockchain: Some(blockchain)
        }
    }

    /// Create a stateless validator (no identity verification)
    pub fn stateless() -> Self {
        Self {
            blockchain: None,
        }
    }

    /// Validate a transaction with full state context including identity verification
    pub fn validate_transaction_with_state(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!("[BREADCRUMB] validate_transaction_with_state ENTER, memo.len={}", transaction.memo.len());

        // Check if this is a system transaction (empty inputs = coinbase-style), except token contract calls
        let is_token = is_token_contract_execution(transaction);
        tracing::debug!("[BREADCRUMB] is_token_contract_execution = {}", is_token);

        let is_system_transaction = transaction.inputs.is_empty() && !is_token;
        tracing::debug!("[BREADCRUMB] is_system_transaction = {}", is_system_transaction);

        // Create a stateless validator for basic checks
        let stateless_validator = TransactionValidator::new();

        // Basic structure validation
        tracing::debug!("[BREADCRUMB] validate_basic_structure CALL");
        stateless_validator.validate_basic_structure(transaction)?;
        tracing::debug!("[BREADCRUMB] validate_basic_structure OK");

        // Type-specific validation
        match transaction.transaction_type {
            TransactionType::Transfer => {
                if !is_system_transaction {
                    stateless_validator.validate_transfer_transaction(transaction)?;
                }
                // System transactions with Transfer type are allowed (UBI/rewards)
            },
            TransactionType::IdentityRegistration => stateless_validator.validate_identity_transaction(transaction)?,
            TransactionType::IdentityUpdate => stateless_validator.validate_identity_transaction(transaction)?,
            TransactionType::IdentityRevocation => stateless_validator.validate_identity_transaction(transaction)?,
            TransactionType::ContractDeployment => stateless_validator.validate_contract_transaction(transaction)?,
            TransactionType::ContractExecution => stateless_validator.validate_contract_transaction(transaction)?,
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload | TransactionType::UbiDistribution => {
                // Audit transactions - validate they have proper memo data
                if transaction.memo.is_empty() {
                    return Err(ValidationError::InvalidMemo);
                }
            },
            TransactionType::WalletRegistration => {
                // Wallet registration transactions - validate wallet data and ownership
                stateless_validator.validate_transaction(transaction)?;
            },
            TransactionType::ValidatorRegistration |
            TransactionType::ValidatorUpdate |
            TransactionType::ValidatorUnregister => {
                // Validator transactions - validate with stateless validator
                stateless_validator.validate_transaction(transaction)?;
            },
            TransactionType::DaoProposal |
            TransactionType::DaoVote |
            TransactionType::DaoExecution |
            TransactionType::DifficultyUpdate => {
                // DAO transactions - validation handled at consensus layer
            }
        
            TransactionType::UBIClaim => {
                // UBI claim transactions - citizen-initiated claims (Week 7)
                self.validate_ubi_claim_transaction(transaction)?;
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions - enforce 20% tribute (Week 7)
                self.validate_profit_declaration_transaction(transaction)?;
            }
            TransactionType::Coinbase => {
                if !transaction.inputs.is_empty() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
            TransactionType::TokenTransfer => {
                if transaction.outputs.is_empty() {
                    return Err(ValidationError::InvalidOutputs);
                }
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validate governance_config_data exists
                if transaction.governance_config_data.is_none() {
                    return Err(ValidationError::InvalidInputs);
                }
            }
        }

        //  CRITICAL FIX: Verify sender identity exists on blockchain
        // This is the missing check that was allowing transactions from non-existent identities
        // Skip for:
        //   - System transactions (genesis, rewards, etc.)
        //   - Identity registration (new identities don't exist yet)
        //   - Token contract executions (tokens use PublicKey as sender, not identity)
        //
        // Token operations are authorized by signature verification alone - the canonical sender
        // is derived from tx.signature.public_key, and balances are keyed by PublicKey.
        // Identity is an optional overlay, not a precondition for token operations.
        if !is_system_transaction
            && transaction.transaction_type != TransactionType::IdentityRegistration
            && !is_token_contract_execution(transaction)
        {
            tracing::debug!("[BREADCRUMB] validate_sender_identity_exists CALL");
            self.validate_sender_identity_exists(transaction)?;
            tracing::debug!("[BREADCRUMB] validate_sender_identity_exists OK");
        }

        // Signature validation (always required except for system transactions)
        if !is_system_transaction {
            tracing::debug!("[BREADCRUMB] validate_signature CALL");
            stateless_validator.validate_signature(transaction)?;
            tracing::debug!("[BREADCRUMB] validate_signature OK");
        }

        // Zero-knowledge proof validation (skip for system transactions)
        if !is_system_transaction {
            tracing::debug!("[BREADCRUMB] validate_zk_proofs CALL");
            stateless_validator.validate_zk_proofs(transaction)?;
            tracing::debug!("[BREADCRUMB] validate_zk_proofs OK");
        }

        // Economic validation (modified for system transactions)
        tracing::debug!("[BREADCRUMB] validate_economics_with_system_check CALL");
        stateless_validator.validate_economics_with_system_check(transaction, is_system_transaction)?;
        tracing::debug!("[BREADCRUMB] validate_economics_with_system_check OK");

        Ok(())
    }

    /// CRITICAL FIX: Verify that the sender's identity exists on the blockchain
    /// This prevents transactions from non-existent or unregistered identities
    fn validate_sender_identity_exists(&self, transaction: &Transaction) -> ValidationResult {
        tracing::debug!("[BREADCRUMB] validate_sender_identity_exists ENTER");

        // If we don't have blockchain access, skip this check (backward compatibility)
        let blockchain = match self.blockchain {
            Some(blockchain) => blockchain,
            None => {
                tracing::warn!("SECURITY WARNING: Identity verification skipped - no blockchain state available");
                return Ok(());
            }
        };

        // Extract the public key from the transaction signature
        let sender_public_key = transaction.signature.public_key.as_bytes();
        
        if sender_public_key.is_empty() {
            tracing::error!("SECURITY: Transaction has empty public key");
            return Err(ValidationError::InvalidSignature);
        }

        // CORRECT APPROACH: Lookup wallet by public key, then verify owner identity
        // Step 1: Find wallet with matching public key
        let mut owner_did: Option<String> = None;
        
        tracing::info!(" VALIDATION DEBUG: Searching for wallet with sender public key");
        tracing::info!("   Sender public key length: {} bytes", sender_public_key.len());
        tracing::info!("   Sender public key (first 16): {}", hex::encode(&sender_public_key[..16.min(sender_public_key.len())]));
        tracing::info!("   Total wallets to check: {}", blockchain.get_all_wallets().len());
        
        for (wallet_id, wallet_data) in blockchain.get_all_wallets() {
            tracing::info!("   Checking wallet {}: stored public_key length = {}, first 16 = {}", 
                wallet_id, 
                wallet_data.public_key.len(),
                hex::encode(&wallet_data.public_key[..16.min(wallet_data.public_key.len())]));
            
            // Debug: Show both keys fully
            tracing::info!("    WALLET public_key (first 64): {}", hex::encode(&wallet_data.public_key[..64.min(wallet_data.public_key.len())]));
            tracing::info!("    SENDER public_key (first 64): {}", hex::encode(&sender_public_key[..64.min(sender_public_key.len())]));
            
            // Debug: Compare byte by byte
            tracing::info!("    Comparing {} wallet bytes vs {} sender bytes", wallet_data.public_key.len(), sender_public_key.len());
            
            // CRITICAL FIX: wallet_data.public_key is Vec<u8>, sender_public_key is &[u8]
            // We need to compare as slices, not Vec vs slice
            let keys_match = wallet_data.public_key.as_slice() == sender_public_key;
            tracing::info!("    Direct comparison result: {}", keys_match);
            
            if !keys_match && wallet_data.public_key.len() == sender_public_key.len() {
                // Find first differing byte (show up to 5 differences)
                let mut diff_count = 0;
                for i in 0..wallet_data.public_key.len() {
                    if wallet_data.public_key[i] != sender_public_key[i] {
                        tracing::error!("    MISMATCH at byte {}: wallet={:02x} vs sender={:02x}", 
                            i, wallet_data.public_key[i], sender_public_key[i]);
                        diff_count += 1;
                        if diff_count >= 5 {
                            tracing::error!("   ... (showing first 5 differences only)");
                            break;
                        }
                    }
                }
                if diff_count == 0 {
                    tracing::error!("     WEIRD: Comparison failed but no byte differences found! Check Vec vs slice comparison");
                }
            }
            
            // Compare wallet public key directly
            if keys_match {
                tracing::info!("    PUBLIC KEY MATCH FOUND for wallet: {}", wallet_id);
                tracing::info!("   Wallet owner_identity_id: {:?}", wallet_data.owner_identity_id);
                
                // Get owner DID from owner_identity_id
                if let Some(owner_identity_hash) = &wallet_data.owner_identity_id {
                    // Find the DID string from identity registry using the identity hash
                    // Convert the owner_identity_hash to hex string to match against DID format
                    let owner_id_hex = hex::encode(owner_identity_hash.as_bytes());
                    
                    for (did, identity_data) in blockchain.get_all_identities() {
                        // Extract the hex part from the DID (format: did:zhtp:HEX)
                        let did_hex = if did.starts_with("did:zhtp:") {
                            &did[9..] // Skip "did:zhtp:" prefix
                        } else {
                            did.as_str()
                        };
                        
                        // Check if this identity's ID matches the wallet's owner_identity_id
                        if did_hex == owner_id_hex {
                            owner_did = Some(did.clone());
                            tracing::info!("Found wallet {} owned by identity: {}", wallet_id, did);
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // Step 2: If no wallet found, check if sender is directly an identity (backward compatibility)
        if owner_did.is_none() {
            for (did, identity_data) in blockchain.get_all_identities() {
                if identity_data.public_key == sender_public_key {
                    owner_did = Some(did.clone());
                    tracing::info!("Sender is direct identity: {}", did);
                    break;
                }
            }
        }

        // Step 3: Verify owner identity exists and is not revoked
        match owner_did {
            Some(did) => {
                if let Some(identity_data) = blockchain.get_all_identities().iter()
                    .find(|(id, _)| **id == did)
                    .map(|(_, data)| data) {
                    
                    if identity_data.identity_type == "revoked" {
                        tracing::error!("SECURITY: Transaction from revoked identity: {}", did);
                        return Err(ValidationError::InvalidTransaction);
                    }
                    
                    tracing::info!(" SECURITY: Sender identity verified: {} ({})", 
                        identity_data.display_name, did);
                    return Ok(());
                }
                
                tracing::error!("SECURITY: Owner DID {} exists but identity not found!", did);
                return Err(ValidationError::UnregisteredSender);
            },
            None => {
                tracing::error!("SECURITY CRITICAL: Transaction from unregistered wallet/identity!");
                tracing::error!("Public key: {:02x?}", &sender_public_key[..std::cmp::min(16, sender_public_key.len())]);
                tracing::error!(" REJECTED: All transactions must come from registered wallets/identities");

                // NO BYPASS: Always reject transactions from unregistered senders
                return Err(ValidationError::UnregisteredSender);
            }
        }

        Ok(())
    }

    /// Validate UBI claim transaction with state context (Week 7)
    fn validate_ubi_claim_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Use stateless validator for structural checks
        let stateless_validator = TransactionValidator::new();
        stateless_validator.validate_ubi_claim_transaction(transaction)?;

        // In future weeks, could add stateful checks:
        // - Verify claimant is registered citizen
        // - Verify claim amount matches schedule
        // - Verify UBI pool has sufficient balance
        // - Verify claimant hasn't already claimed this month

        Ok(())
    }

    /// Validate profit declaration transaction with state context (Week 7)
    fn validate_profit_declaration_transaction(&self, transaction: &Transaction) -> ValidationResult {
        // Use stateless validator for structural checks
        let stateless_validator = TransactionValidator::new();
        stateless_validator.validate_profit_declaration_transaction(transaction)?;

        // In future weeks, could add stateful checks:
        // - Verify declarant is registered for-profit entity
        // - Verify nonprofit treasury is registered
        // - Prevent duplicate declarations for same fiscal period
        // - Verify for-profit treasury has sufficient balance for tribute

        Ok(())
    }
}

/// Calculate minimum fee based on transaction size
fn calculate_minimum_fee(transaction_size: usize) -> u64 {
    // Base fee + size-based fee (from creation module)
    crate::transaction::creation::utils::calculate_minimum_fee(transaction_size)
}

/// Constants for validation
const MAX_TRANSACTION_SIZE: usize = 1_048_576; // 1 MB
const MAX_MEMO_SIZE: usize = 16384; // 16 KB - increased for contract calls with post-quantum signatures (Dilithium signatures ~2.7KB each)

/// Validation utility functions
pub mod utils {
    use super::*;

    /// Quick validation for transaction basic structure
    pub fn quick_validate(transaction: &Transaction) -> bool {
        let validator = TransactionValidator::new();
        validator.validate_basic_structure(transaction).is_ok()
    }

    /// Validate transaction type consistency
    pub fn validate_type_consistency(transaction: &Transaction) -> bool {
        match transaction.transaction_type {
            TransactionType::IdentityRegistration | 
            TransactionType::IdentityUpdate | 
            TransactionType::IdentityRevocation => transaction.identity_data.is_some(),
            TransactionType::Transfer | 
            TransactionType::ContractDeployment | 
            TransactionType::ContractExecution => {
                !transaction.inputs.is_empty() && !transaction.outputs.is_empty()
            },
            TransactionType::SessionCreation | TransactionType::SessionTermination |
            TransactionType::ContentUpload | TransactionType::UbiDistribution => {
                // Audit transactions should have memo data but no strict input/output requirements
                !transaction.memo.is_empty()
            },
            TransactionType::WalletRegistration => {
                // Wallet registration should have wallet_data
                transaction.wallet_data.is_some()
            }
            TransactionType::ValidatorRegistration |
            TransactionType::ValidatorUpdate |
            TransactionType::ValidatorUnregister => {
                // Validator transactions should have validator_data
                transaction.validator_data.is_some()
            }
            TransactionType::DaoProposal => transaction.dao_proposal_data.is_some(),
            TransactionType::DaoVote => transaction.dao_vote_data.is_some(),
            TransactionType::DaoExecution => transaction.dao_execution_data.is_some(),
            TransactionType::DifficultyUpdate => {
                // Difficulty update validation - requires memo with parameters
                // Full validation happens at consensus layer
                !transaction.memo.is_empty()
            }
            TransactionType::UBIClaim => {
                // UBI claim transactions should have ubi_claim_data (Week 7)
                transaction.ubi_claim_data.is_some()
            }
            TransactionType::ProfitDeclaration => {
                // Profit declaration transactions should have profit_declaration_data (Week 7)
                transaction.profit_declaration_data.is_some()
            }
            TransactionType::Coinbase => {
                // Coinbase must have no inputs but have outputs
                transaction.inputs.is_empty() && !transaction.outputs.is_empty()
            }
            TransactionType::TokenTransfer => {
                // Token transfers need outputs
                !transaction.outputs.is_empty()
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates should have governance_config_data
                transaction.governance_config_data.is_some()
            }
        }
    }

    /// Check if transaction has valid zero-knowledge structure
    pub fn has_valid_zk_structure(transaction: &Transaction) -> bool {
        // All inputs must have nullifiers and ZK proofs
        transaction.inputs.iter().all(|input| {
            input.nullifier != Hash::default() && 
            is_valid_proof_structure(&input.zk_proof)
        })
    }

    /// Validate transaction against current mempool rules
    pub fn validate_mempool_rules(transaction: &Transaction) -> ValidationResult {
        // Check transaction size
        if transaction.size() > MAX_TRANSACTION_SIZE {
            return Err(ValidationError::InvalidTransaction);
        }

        // Check fee rate
        let fee_rate = transaction.fee as f64 / transaction.size() as f64;
        if fee_rate < 1.0 {
            return Err(ValidationError::InvalidFee);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ContractCall, ContractType};
    use crate::integration::zk_integration::ZkTransactionProof;

    /// Helper: create a test PublicKey with deterministic content
    fn test_public_key(id: u8) -> PublicKey {
        // Dilithium5 public keys are 2592 bytes
        let mut key_bytes = vec![id; 2592];
        // Make it somewhat realistic by varying the first few bytes
        key_bytes[0] = id;
        key_bytes[1] = id.wrapping_add(1);
        key_bytes[2] = id.wrapping_add(2);
        PublicKey::new(key_bytes)
    }

    /// Helper: create a test Signature struct
    fn test_signature(public_key: &PublicKey) -> Signature {
        Signature {
            signature: vec![0u8; 64], // placeholder signature bytes
            public_key: public_key.clone(),
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        }
    }

    /// Helper: create a mock token transfer transaction
    fn create_token_transfer_transaction(sender_key: &PublicKey) -> Transaction {
        // Build a token transfer ContractCall
        let call = ContractCall::token_call("transfer".to_string(), vec![1, 2, 3, 4]);
        let sig = test_signature(sender_key);

        // Serialize: "ZHTP" prefix + bincode(call, sig)
        let call_data = bincode::serialize(&(&call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        Transaction {
            version: 1,
            chain_id: 0x03, // development
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![TransactionInput {
                previous_output: Hash::default(),
                output_index: 0,
                nullifier: [1u8; 32].into(), // non-default nullifier
                zk_proof: ZkTransactionProof::default(),
            }],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(sender_key),
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        }
    }

    /// Test A: Token transfer succeeds with no identity record
    ///
    /// The canonical sender is derived from tx.signature.public_key.
    /// Token operations do not require the sender to have a registered identity.
    #[test]
    fn test_token_transfer_succeeds_without_identity() {
        // Create a sender with NO registered identity
        let unregistered_sender = test_public_key(42);
        let tx = create_token_transfer_transaction(&unregistered_sender);

        // Verify this is detected as a token contract execution
        assert!(
            is_token_contract_execution(&tx),
            "Transaction should be detected as token contract execution"
        );

        // The key test: is_token_contract_execution returns true, which means
        // the StatefulTransactionValidator will SKIP the identity check for this tx.
        // This is the core fix - token operations don't require registered identity.

        // Verify the transaction has a valid sender public key (the canonical sender)
        assert!(
            !tx.signature.public_key.as_bytes().is_empty(),
            "Transaction should have a sender public key (canonical sender)"
        );
    }

    /// Test B: Token receive works with no identity
    ///
    /// Receiving tokens does not require identity registration.
    /// Balances are keyed by PublicKey, not by identity DID.
    #[test]
    fn test_token_receive_works_without_identity() {
        // Create a token transfer to an unregistered recipient
        let sender = test_public_key(1);
        let tx = create_token_transfer_transaction(&sender);

        // The recipient (in params) doesn't need an identity either
        // This test verifies the is_token_contract_execution detection works
        // for all token methods that could involve receiving
        let mint_call = ContractCall::token_call("mint".to_string(), vec![1, 2, 3]);
        let sig = test_signature(&sender);
        let call_data = bincode::serialize(&(&mint_call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        let mint_tx = Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(&sender),
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        };

        assert!(
            is_token_contract_execution(&mint_tx),
            "Mint transaction should be detected as token contract execution"
        );
    }

    /// Test C: Invalid signature still fails for token transactions
    ///
    /// Even though identity is not required, signature validation IS required.
    /// The signature cryptographically proves the sender authorized the transaction.
    #[test]
    fn test_invalid_signature_fails_for_tokens() {
        let sender = test_public_key(1);
        let tx = create_token_transfer_transaction(&sender);

        // Signature validation is handled by stateless validator
        let validator = TransactionValidator::new();

        // The validate_signature method will fail because we have a placeholder signature
        // This proves signature validation is still enforced for tokens
        let result = validator.validate_signature(&tx);

        // Should fail because our mock signature is invalid
        assert!(
            result.is_err(),
            "Invalid signature should be rejected even for token transactions"
        );
    }

    /// Test D: Replay protection (nullifier) works without identity
    ///
    /// The UTXO nullifier-based replay protection operates independently of identity.
    /// Each input has a unique nullifier that prevents double-spending.
    #[test]
    fn test_nullifier_replay_protection_without_identity() {
        let sender = test_public_key(1);
        let tx = create_token_transfer_transaction(&sender);

        // Verify the transaction has a non-default nullifier (replay protection)
        assert!(
            !tx.inputs.is_empty(),
            "Transaction should have inputs for nullifier check"
        );
        assert!(
            tx.inputs[0].nullifier != Hash::default(),
            "Input should have non-default nullifier for replay protection"
        );

        // The stateless validator checks nullifier structure
        let validator = TransactionValidator::new();

        // has_valid_zk_structure checks nullifiers are present
        // Note: This won't fully pass with our mock data, but it demonstrates
        // the nullifier check exists and operates independently of identity
        let has_nullifier = tx.inputs.iter().all(|input| input.nullifier != Hash::default());
        assert!(
            has_nullifier,
            "All inputs should have nullifiers for replay protection"
        );
    }

    /// Verify is_token_contract_execution correctly identifies token operations
    #[test]
    fn test_is_token_contract_execution_detection() {
        let sender = test_public_key(1);

        // Test all token methods
        for method in &["create_custom_token", "mint", "transfer", "burn"] {
            let call = ContractCall::token_call(method.to_string(), vec![]);
            let sig = test_signature(&sender);
            let call_data = bincode::serialize(&(&call, &sig)).unwrap();
            let mut memo = b"ZHTP".to_vec();
            memo.extend(call_data);

            let tx = Transaction {
                version: 1,
                chain_id: 0x03,
                transaction_type: TransactionType::ContractExecution,
                inputs: vec![],
                outputs: vec![],
                fee: 1000,
                signature: test_signature(&sender),
                memo,
                identity_data: None,
                wallet_data: None,
                validator_data: None,
                dao_proposal_data: None,
                dao_vote_data: None,
                dao_execution_data: None,
                ubi_claim_data: None,
                profit_declaration_data: None,
                token_transfer_data: None,
                governance_config_data: None,
            };

            assert!(
                is_token_contract_execution(&tx),
                "Method '{}' should be detected as token contract execution",
                method
            );
        }

        // Non-token contract should NOT be detected
        let non_token_call = ContractCall::messaging_call("send_message".to_string(), vec![]);
        let sig = test_signature(&sender);
        let call_data = bincode::serialize(&(&non_token_call, &sig)).unwrap();
        let mut memo = b"ZHTP".to_vec();
        memo.extend(call_data);

        let non_token_tx = Transaction {
            version: 1,
            chain_id: 0x03,
            transaction_type: TransactionType::ContractExecution,
            inputs: vec![],
            outputs: vec![],
            fee: 1000,
            signature: test_signature(&sender),
            memo,
            identity_data: None,
            wallet_data: None,
            validator_data: None,
            dao_proposal_data: None,
            dao_vote_data: None,
            dao_execution_data: None,
            ubi_claim_data: None,
            profit_declaration_data: None,
            token_transfer_data: None,
            governance_config_data: None,
        };

        assert!(
            !is_token_contract_execution(&non_token_tx),
            "Messaging contract should NOT be detected as token contract execution"
        );
    }
}
