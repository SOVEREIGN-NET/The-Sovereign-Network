//! Transaction creation utilities
//!
//! Provides functionality for creating new transactions in the ZHTP blockchain.

use crate::integration::crypto_integration::{
    PrivateKey, PublicKey, Signature, SignatureAlgorithm,
};
use crate::transaction::contract_deployment::ContractDeploymentPayloadV1;
use crate::transaction::core::{
    IdentityTransactionData, Transaction, TransactionInput, TransactionOutput, TransactionPayload,
    WalletTransactionData, TX_VERSION_V8,
};
use crate::types::transaction_type::TransactionType;
use tracing::debug;

/// Error types for transaction creation
#[derive(Debug, Clone)]
pub enum TransactionCreateError {
    InsufficientFunds,
    InvalidInputs,
    InvalidOutputs,
    InvalidContractDeploymentPayload(String),
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
            TransactionCreateError::InvalidContractDeploymentPayload(msg) => {
                write!(f, "Invalid contract deployment payload: {}", msg)
            }
            TransactionCreateError::SigningError => write!(f, "Transaction signing failed"),
            TransactionCreateError::ZkProofError => {
                write!(f, "Zero-knowledge proof generation failed")
            }
            TransactionCreateError::IdentityError => {
                write!(f, "Identity transaction creation failed")
            }
        }
    }
}

impl std::error::Error for TransactionCreateError {}

/// Pre-fetched Merkle witness for a UTXO input, used to generate a real ZK spend proof.
#[derive(Debug, Clone)]
pub struct InputMerkleWitness {
    /// Actual balance of the UTXO being spent.
    pub sender_balance: u64,
    /// The nullifier_seed used when the UTXO was committed.
    pub nullifier_seed: u64,
    /// The sender_secret used when the UTXO was committed.
    pub sender_secret: u64,
    /// Leaf index in the Merkle tree.
    pub leaf_index: u32,
    /// Sibling hashes from leaf to root (32 levels, each [u8; 32]).
    pub siblings: Vec<[u8; 32]>,
    /// Current Merkle root.
    pub root: [u8; 32],
}

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
    /// Pre-fetched Merkle witnesses for each input (indexed by input position).
    /// When present, real ZK proofs are generated. When absent, falls back to
    /// dummy self-consistent proofs (backward compatible).
    merkle_witnesses: Vec<Option<InputMerkleWitness>>,
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
            merkle_witnesses: Vec::new(),
        }
    }

    /// Set pre-fetched Merkle witnesses for inputs.
    ///
    /// Each entry corresponds to an input by position. When a witness is `Some`,
    /// the builder generates a real ZK proof bound to the on-chain Merkle tree.
    /// When `None`, the input gets a self-consistent dummy proof (backward compat).
    pub fn merkle_witnesses(mut self, witnesses: Vec<Option<InputMerkleWitness>>) -> Self {
        self.merkle_witnesses = witnesses;
        self
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
    pub fn build(mut self, private_key: &PrivateKey) -> Result<Transaction, TransactionCreateError> {
        // Validate inputs and outputs
        if self.inputs.is_empty() && !self.transaction_type.is_identity_transaction() {
            return Err(TransactionCreateError::InvalidInputs);
        }

        if self.outputs.is_empty() && !self.transaction_type.is_identity_transaction() {
            return Err(TransactionCreateError::InvalidOutputs);
        }

        // ── Compute Poseidon leaf commitments for Transfer outputs ───────
        // Each output gets a Merkle leaf = Poseidon(nullifier_seed, sender_secret, amount).
        // The secrets are derived from the sender's private key so only the sender (and
        // recipient via the note) can later prove ownership in a ZK proof.
        if self.transaction_type == TransactionType::Transfer {
            self.compute_output_leaf_commitments(private_key);
        }

        // Check if inputs already have ZK proofs (they should be pre-generated in most cases)
        // Check both legacy 'proof' field and new 'proof_data' field
        let needs_proofs = self.inputs.is_empty()
            || self.inputs.iter().any(|i| {
                i.zk_proof.amount_proof.proof.is_empty()
                    && i.zk_proof.amount_proof.proof_data.is_empty()
            });

        let inputs_with_proofs = if needs_proofs {
            // Generate ZK proofs only if inputs don't have them yet
            tracing::debug!("Generating ZK proofs for {} inputs", self.inputs.len());
            self.generate_zk_proofs_for_inputs(private_key)?
        } else {
            // Use existing ZK proofs from inputs
            tracing::debug!(
                "Using pre-generated ZK proofs for {} inputs",
                self.inputs.len()
            );
            self.inputs
        };

        // Build payload from legacy builder fields
        let payload = if let Some(id) = self.identity_data {
            TransactionPayload::Identity(id)
        } else if let Some(wd) = self.wallet_data {
            TransactionPayload::Wallet(wd)
        } else {
            TransactionPayload::None
        };

        // Create unsigned transaction
        let mut transaction = Transaction {
            version: TX_VERSION_V8,
            chain_id: 0x03, // Default to development network
            transaction_type: self.transaction_type,
            inputs: inputs_with_proofs,
            outputs: self.outputs,
            fee: self.fee,
            signature: Signature {
                signature: Vec::new(),
                public_key: PublicKey::new([0u8; 2592]),
                algorithm: SignatureAlgorithm::DEFAULT,
                timestamp: 0,
            }, // Will be set below
            memo: self.memo,
            payload,
        };

        // Sign the transaction
        transaction.signature = Self::sign_transaction(&transaction, private_key)
            .map_err(|_| TransactionCreateError::SigningError)?;

        Ok(transaction)
    }

    /// Compute Poseidon Merkle leaf commitments for each output in a Transfer transaction.
    ///
    /// For each output, derives `(nullifier_seed, sender_secret)` deterministically from
    /// the sender's private key + recipient key_id + output index, then computes:
    ///   `leaf = Poseidon(nullifier_seed, sender_secret, amount)`
    ///
    /// The leaf commitment is stored in `TransactionOutput.merkle_leaf` so the executor
    /// inserts it into the persistent UTXO Merkle tree. The recipient can later recover
    /// the secrets to generate a ZK spend proof.
    fn compute_output_leaf_commitments(&mut self, private_key: &PrivateKey) {
        use lib_proofs::transaction::circuit::{self, hash_to_bytes};

        for (index, output) in self.outputs.iter_mut().enumerate() {
            let (nullifier_seed, sender_secret) = circuit::derive_utxo_secrets(
                &private_key.dilithium_sk,
                &output.recipient.key_id,
                index as u64,
            );

            // Amount is not directly stored on TransactionOutput (it uses commitments).
            // For now, we use the fee as a proxy for the output amount since Transfer
            // distributes inputs equally. The caller should set the amount explicitly
            // in a future enhancement. Use 0 as placeholder — the amount will be set
            // correctly when the full UTXO model is wired up.
            //
            // TODO: Pass explicit output amounts into the builder so leaf commitments
            // are computed with the real amount.
            let amount = 0u64; // Placeholder — see TODO above

            let leaf_hash = circuit::real::compute_leaf_commitment(
                nullifier_seed,
                sender_secret,
                amount,
            );

            output.merkle_leaf = crate::types::Hash::new(hash_to_bytes(leaf_hash));

            debug!(
                "Output {} leaf commitment: nullifier_seed={}, amount={}, merkle_leaf={}",
                index,
                nullifier_seed,
                amount,
                hex::encode(&hash_to_bytes(leaf_hash)[..8]),
            );
        }
    }

    /// Generate ZK proofs for all transaction inputs using lib-proofs.
    ///
    /// When a pre-fetched `InputMerkleWitness` is available for an input, generates a
    /// real Plonky2 proof bound to the on-chain Merkle tree root. Otherwise falls back
    /// to a self-consistent dummy proof (backward compatible with existing tests).
    fn generate_zk_proofs_for_inputs(
        &self,
        _private_key: &PrivateKey,
    ) -> Result<Vec<TransactionInput>, TransactionCreateError> {
        use lib_proofs::transaction::circuit::bytes_to_hash;
        use lib_proofs::ZkTransactionProof;

        let mut inputs_with_proofs = Vec::with_capacity(self.inputs.len());

        for (idx, input) in self.inputs.iter().enumerate() {
            let witness = self.merkle_witnesses.get(idx).and_then(|w| w.as_ref());

            let zk_proof = if let Some(w) = witness {
                // ── Real proof: bound to on-chain Merkle root ────────────
                let merkle_root = bytes_to_hash(w.root);
                let siblings: Vec<[u64; 4]> = w.siblings.iter().map(|s| bytes_to_hash(*s)).collect();

                if siblings.len() != lib_proofs::transaction::circuit::MERKLE_DEPTH {
                    tracing::error!(
                        "Input {}: expected {} siblings, got {}",
                        idx,
                        lib_proofs::transaction::circuit::MERKLE_DEPTH,
                        siblings.len(),
                    );
                    return Err(TransactionCreateError::ZkProofError);
                }

                // Total output amount (the "amount" in the circuit constraint:
                // amount + fee <= sender_balance).
                let total_output_amount: u64 = w.sender_balance.saturating_sub(self.fee);

                ZkTransactionProof::prove_transaction_with_merkle(
                    w.sender_balance,
                    total_output_amount,
                    self.fee,
                    w.sender_secret,
                    w.nullifier_seed,
                    merkle_root,
                    w.leaf_index,
                    &siblings,
                )
                .map_err(|e| {
                    tracing::error!(
                        "Real ZK proof generation failed for input {}: {:?} (balance={}, fee={})",
                        idx, e, w.sender_balance, self.fee,
                    );
                    TransactionCreateError::ZkProofError
                })?
            } else {
                // ── Fallback: self-consistent dummy proof ─────────────────
                // Used when no Merkle witness is available (backward compat).
                let (nullifier_seed, sender_secret) =
                    lib_proofs::transaction::circuit::derive_utxo_secrets(
                        &[0u8; 64], // No real private key in fallback path
                        &input.nullifier.as_bytes()[..32].try_into().unwrap_or([0u8; 32]),
                        idx as u64,
                    );
                let sender_balance = self.fee + 1000;

                ZkTransactionProof::prove_transaction(
                    sender_balance,
                    0,
                    1000,
                    self.fee,
                    {
                        let mut b = [0u8; 32];
                        b[..8].copy_from_slice(&sender_secret.to_le_bytes());
                        b
                    },
                    [0u8; 32],
                    {
                        let mut b = [0u8; 32];
                        b[..8].copy_from_slice(&nullifier_seed.to_le_bytes());
                        b
                    },
                )
                .map_err(|e| {
                    tracing::error!("Fallback ZK proof generation failed for input {}: {:?}", idx, e);
                    TransactionCreateError::ZkProofError
                })?
            };

            let mut input_with_proof = input.clone();
            input_with_proof.zk_proof = zk_proof;
            inputs_with_proofs.push(input_with_proof);

            tracing::debug!(
                "Generated ZK proof for input {} (real={})",
                idx,
                witness.is_some(),
            );
        }

        Ok(inputs_with_proofs)
    }

    /// Sign a transaction with the given private key using lib-crypto
    fn sign_transaction(
        transaction: &Transaction,
        private_key: &PrivateKey,
    ) -> Result<Signature, String> {
        use lib_crypto::post_quantum::dilithium::dilithium_sign;

        // Create transaction hash for signing (without signature)
        let mut tx_for_signing = transaction.clone();
        tx_for_signing.signature = Signature {
            signature: Vec::new(),
            public_key: PublicKey::new([0u8; 2592]),
            algorithm: SignatureAlgorithm::DEFAULT,
            timestamp: 0,
        };

        let tx_hash = crate::transaction::hashing::hash_transaction(&tx_for_signing);

        // Use the public key stored alongside the private key
        // The public key must be stored with the private key since Dilithium
        // doesn't allow deriving pk from sk after generation
        if private_key.dilithium_pk.is_empty() {
            return Err(
                "Private key missing dilithium_pk - keypair must store both keys".to_string(),
            );
        }

        // Use auto-detecting sign function
        let signature_result = dilithium_sign(tx_hash.as_bytes(), &private_key.dilithium_sk);

        match signature_result {
            Ok(signature_bytes) => {
                let signature = Signature {
                    signature: signature_bytes,
                    public_key: PublicKey::new(private_key.dilithium_pk),
                    algorithm: SignatureAlgorithm::DEFAULT,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                };
                Ok(signature)
            }
            Err(e) => Err(format!("Failed to sign transaction: {}", e)),
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
#[deprecated(
    note = "use create_contract_deployment_transaction() so ContractDeployment memo schema is enforced"
)]
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

/// Create a canonical contract deployment transaction with schema-validated payload.
pub fn create_contract_deployment_transaction(
    inputs: Vec<TransactionInput>,
    outputs: Vec<TransactionOutput>,
    payload: ContractDeploymentPayloadV1,
    fee: u64,
    private_key: &PrivateKey,
) -> Result<Transaction, TransactionCreateError> {
    let memo = payload
        .encode_memo()
        .map_err(TransactionCreateError::InvalidContractDeploymentPayload)?;

    TransactionBuilder::new()
        .transaction_type(TransactionType::ContractDeployment)
        .add_inputs(inputs)
        .add_outputs(outputs)
        .memo(memo)
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
    /// # Overview
    /// Post-quantum signatures (Dilithium5) are ~7KB, dwarfing actual payload.
    /// To avoid penalizing PQ crypto adoption, we cap witness overhead while still
    /// charging something for large witnesses to discourage spam.
    ///
    /// # Fee Structure
    /// - **BASE_FEE**: 100 SOV (reduced from 1000 to make transactions affordable)
    /// - **Size Fee**: 1 SOV per 100 bytes of "effective size"
    /// - **Effective Size**: payload_bytes + min(witness_bytes, WITNESS_CAP)
    ///
    /// # Economic Rationale
    /// The BASE_FEE reduction from 1000 to 100 SOV makes small transactions 10x cheaper,
    /// improving accessibility while still providing economic spam prevention. Combined
    /// with the witness cap, this ensures post-quantum transactions remain affordable
    /// without creating a spam vector through zero-cost large witnesses.
    pub fn calculate_minimum_fee(transaction_size: usize) -> u64 {
        calculate_minimum_fee_with_config(
            transaction_size,
            &crate::transaction::TxFeeConfig::default(),
        )
    }

    /// Calculate the minimum fee for a transaction using governance-configurable parameters.
    pub fn calculate_minimum_fee_with_config(
        transaction_size: usize,
        config: &crate::transaction::TxFeeConfig,
    ) -> u64 {
        // Post-quantum witness overhead (signature + pubkey)
        // Dilithium5: 4627 byte sig + 2592 byte pk = 7219 bytes total
        // Dilithium5: 2420 byte sig + 1312 byte pk = 3732 bytes total
        // This constant assumes Dilithium5 as it's the highest-security variant.
        const PQ_WITNESS_SIZE: usize = 7219;

        // Cap witness contribution to fee calculation at 500 bytes.
        //
        // Rationale for 500 bytes:
        // - Classical signatures (Ed25519): ~64 bytes signature + 32 bytes pubkey = ~96 bytes
        //   plus metadata (algorithm, timestamp) and message overhead = ~150-200 bytes.
        // - A 500-byte cap comfortably covers classical crypto plus extensions without
        //   overcharging, while being well below both Dilithium5 (~3.7KB) and Dilithium5
        //   (~7.2KB) witness sizes.
        // - For PQ transactions: Capping at 500 bytes means users pay only a bounded
        //   premium (~5x classical) rather than 36-72x, encouraging PQ adoption.
        // - Economic defense: Not treating witness size as completely free discourages
        //   spam attacks with artificially inflated witnesses.
        // - Empirically chosen as a conservative trade-off between fee fairness
        //   (not linearly penalizing PQ size) and economic integrity (charging something
        //   for large witnesses to prevent abuse).
        let witness_cap = config.witness_cap as usize;

        // Base transaction fee - reduced from 1000 to 100 SOV.
        //
        // Economic justification:
        // - Makes small transactions affordable for everyday use (e.g., token transfers).
        // - A 10x reduction still provides spam protection via computational + bandwidth costs.
        // - Combined with size-based fees, prevents both tiny spam and large payload abuse.
        // - Aligns with network goal of accessible, usable cryptocurrency vs. high-fee networks.
        let base_fee: u64 = config.base_fee;
        let bytes_per_sov: u64 = config.bytes_per_sov;

        // Estimate payload vs witness
        //
        // This calculation assumes Dilithium5 post-quantum signatures (largest witness).
        // For transaction_size >= PQ_WITNESS_SIZE (7219 bytes):
        //   - payload_bytes = transaction_size - 7219
        //   - witness_bytes = 7219
        //
        // For transaction_size < PQ_WITNESS_SIZE (small or non-PQ5 transactions):
        //   - payload_bytes = 0 (saturating_sub floors at 0)
        //   - witness_bytes = transaction_size (all bytes treated as witness)
        //
        // This means:
        // - Small transactions (< 7219 bytes) have all bytes counted as witness
        // - Dilithium5 transactions (~3732 byte witness) are treated as all-witness
        // - Classical crypto transactions (~200 bytes) are treated as all-witness
        // - BUT: witness is capped at WITNESS_CAP (500 bytes) for fee purposes
        //
        // Result: All transactions < 7219 bytes pay roughly the same base fee
        // (BASE_FEE + ~5 SOV for capped witness), which simplifies economics and
        // avoids penalizing Dilithium5 or classical signatures.
        let payload_bytes = transaction_size.saturating_sub(PQ_WITNESS_SIZE);
        let witness_bytes = transaction_size.saturating_sub(payload_bytes);

        // Effective size = payload + capped witness
        // Examples:
        // - 500 byte classical tx: 0 payload + 500 witness (capped) = 500 bytes → 105 SOV
        // - 3732 byte D2 tx: 0 payload + 500 witness (capped) = 500 bytes → 105 SOV
        // - 10000 byte D5 tx: 2781 payload + 500 witness (capped) = 3281 bytes → 132 SOV
        let effective_size = payload_bytes + witness_bytes.min(witness_cap);
        let size_fee = (effective_size as u64 / bytes_per_sov).max(1);

        let total_fee = base_fee + size_fee;

        debug!(
            "Fee calc: tx={}B, payload={}B, witness={}B, effective={}B, fee={} SOV",
            transaction_size, payload_bytes, witness_bytes, effective_size, total_fee
        );

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
        has_identity_data: bool,
    ) -> Result<(), TransactionCreateError> {
        match transaction_type {
            TransactionType::Transfer => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
            }
            TransactionType::IdentityRegistration
            | TransactionType::IdentityUpdate
            | TransactionType::IdentityRevocation => {
                if !has_identity_data {
                    return Err(TransactionCreateError::IdentityError);
                }
            }
            TransactionType::ContractDeployment | TransactionType::ContractExecution => {
                if inputs.is_empty() || outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
            }
            TransactionType::SessionCreation
            | TransactionType::SessionTermination
            | TransactionType::ContentUpload
            | TransactionType::UbiDistribution => {
                // Audit transactions - no specific validation needed here
                // Memo validation will be handled during transaction validation
            }
            TransactionType::WalletRegistration => {
                // Wallet registration transactions should have wallet data
                // Validation will be handled during transaction validation
            }
            TransactionType::WalletUpdate => {
                // Wallet update transactions should have wallet data
                // Validation will be handled during transaction validation
            }
            TransactionType::ValidatorRegistration
            | TransactionType::ValidatorUpdate
            | TransactionType::ValidatorUnregister => {
                // Validator transactions - no specific validation needed here
                // Validation will be handled during transaction validation
            }
            TransactionType::GatewayRegistration
            | TransactionType::GatewayUpdate
            | TransactionType::GatewayUnregister => {
                // Gateway transactions - validation handled during transaction validation
            }
            TransactionType::DaoProposal
            | TransactionType::DaoVote
            | TransactionType::DaoExecution
            | TransactionType::DifficultyUpdate => {
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
            TransactionType::Coinbase => {
                // Coinbase transactions must have outputs but no inputs
                if !inputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
                if outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidOutputs);
                }
            }
            TransactionType::TokenTransfer => {
                // Token transfers need outputs
                if outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidOutputs);
                }
            }
            TransactionType::GovernanceConfigUpdate => {
                // Governance config updates - validation will be handled during transaction validation
                // Requires governance_config_data and caller must have Governance role
            }
            TransactionType::TokenMint => {
                // System-controlled token mint - validation handled at consensus layer
            }
            TransactionType::TokenCreation
            | TransactionType::TokenSwap
            | TransactionType::CreatePool
            | TransactionType::AddLiquidity
            | TransactionType::RemoveLiquidity => {
                // AMM/Token operations - validation handled at consensus layer
            }
            TransactionType::BondingCurveDeploy => {
                // Bonding curve token deployment - validation handled at consensus layer
            }
            TransactionType::BondingCurveBuy => {
                // Bonding curve token purchase - validation handled at consensus layer
            }
            TransactionType::BondingCurveSell => {
                // Bonding curve token sale - validation handled at consensus layer
            }
            TransactionType::BondingCurveGraduate => {
                // Bonding curve graduation - validation handled at consensus layer
            }
            TransactionType::UpdateOracleCommittee => {
                // Oracle committee update - validation handled at consensus layer
            }
            TransactionType::UpdateOracleConfig => {
                // Oracle config update - validation handled at consensus layer
            }
            TransactionType::OracleAttestation => {
                // Oracle price attestation - validation handled at block execution layer
            }
            TransactionType::CancelOracleUpdate => {
                // Cancel oracle update - validation handled at consensus layer
            }
            TransactionType::InitEntityRegistry => {
                // Entity registry init - must have no inputs/outputs
                if !inputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
                if !outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidOutputs);
                }
            }
            TransactionType::RecordOnRampTrade
            | TransactionType::TreasuryAllocation
            | TransactionType::InitCbeToken
            | TransactionType::CreateEmploymentContract
            | TransactionType::ProcessPayroll
            | TransactionType::DaoStake
            | TransactionType::DaoUnstake
            | TransactionType::DomainRegistration
            | TransactionType::DomainUpdate => {
                // Threshold-approval, staking, domain, and legacy CBE transactions - no inputs/outputs
                if !inputs.is_empty() {
                    return Err(TransactionCreateError::InvalidInputs);
                }
                if !outputs.is_empty() {
                    return Err(TransactionCreateError::InvalidOutputs);
                }
            }
        }

        Ok(())
    }
}
