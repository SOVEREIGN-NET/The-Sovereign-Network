//! Canonical contract deployment transaction schema.
//!
//! Contract deployment payloads are encoded in transaction memo bytes as:
//! `CONTRACT_DEPLOYMENT_MEMO_PREFIX || bincode(ContractDeploymentPayloadV1)`.

use serde::{Deserialize, Serialize};
use bincode::Options;

/// Versioned memo prefix for contract deployment payloads.
pub const CONTRACT_DEPLOYMENT_MEMO_PREFIX: &[u8] = b"ZHTP_DEPLOY_V1:";

/// Maximum contract code bytes accepted in deployment payload.
pub const MAX_DEPLOYMENT_CODE_BYTES: usize = 8 * 1024;
/// Maximum ABI bytes accepted in deployment payload.
pub const MAX_DEPLOYMENT_ABI_BYTES: usize = 4 * 1024;
/// Maximum init args bytes accepted in deployment payload.
pub const MAX_DEPLOYMENT_INIT_ARGS_BYTES: usize = 2 * 1024;
/// Maximum memory limit accepted in deployment payload.
pub const MAX_DEPLOYMENT_MEMORY_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum contract type string length.
pub const MAX_DEPLOYMENT_CONTRACT_TYPE_BYTES: usize = 64;
/// Maximum memo bytes accepted by transaction validator.
pub const MAX_DEPLOYMENT_MEMO_BYTES: usize = 16 * 1024;

/// Canonical deployment payload for `TransactionType::ContractDeployment`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContractDeploymentPayloadV1 {
    /// Contract family/type (for example: "wasm", "token", "web4").
    pub contract_type: String,
    /// Compiled contract code bytes.
    pub code: Vec<u8>,
    /// ABI bytes (typically JSON-encoded ABI document).
    pub abi: Vec<u8>,
    /// Deterministic init arguments encoding.
    pub init_args: Vec<u8>,
    /// Maximum gas allowed for deployment execution.
    pub gas_limit: u64,
    /// Maximum memory allowed for deployment execution.
    pub memory_limit_bytes: u32,
}

impl ContractDeploymentPayloadV1 {
    /// Validate payload fields and bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.contract_type.trim().is_empty() {
            return Err("contract_type is required".to_string());
        }
        if self.contract_type.len() > MAX_DEPLOYMENT_CONTRACT_TYPE_BYTES {
            return Err(format!(
                "contract_type length {} exceeds max {}",
                self.contract_type.len(),
                MAX_DEPLOYMENT_CONTRACT_TYPE_BYTES
            ));
        }
        if self.code.is_empty() {
            return Err("code is required".to_string());
        }
        if self.code.len() > MAX_DEPLOYMENT_CODE_BYTES {
            return Err(format!(
                "code length {} exceeds max {}",
                self.code.len(),
                MAX_DEPLOYMENT_CODE_BYTES
            ));
        }
        if self.abi.is_empty() {
            return Err("abi is required".to_string());
        }
        if self.abi.len() > MAX_DEPLOYMENT_ABI_BYTES {
            return Err(format!(
                "abi length {} exceeds max {}",
                self.abi.len(),
                MAX_DEPLOYMENT_ABI_BYTES
            ));
        }
        if self.init_args.len() > MAX_DEPLOYMENT_INIT_ARGS_BYTES {
            return Err(format!(
                "init_args length {} exceeds max {}",
                self.init_args.len(),
                MAX_DEPLOYMENT_INIT_ARGS_BYTES
            ));
        }
        if self.gas_limit == 0 || self.gas_limit > crate::execution_limits::MAX_TX_GAS {
            return Err(format!(
                "gas_limit {} out of bounds (1..={})",
                self.gas_limit,
                crate::execution_limits::MAX_TX_GAS
            ));
        }
        if self.memory_limit_bytes == 0 || self.memory_limit_bytes > MAX_DEPLOYMENT_MEMORY_BYTES {
            return Err(format!(
                "memory_limit_bytes {} out of bounds (1..={})",
                self.memory_limit_bytes, MAX_DEPLOYMENT_MEMORY_BYTES
            ));
        }
        Ok(())
    }

    /// Encode this payload into canonical memo bytes.
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_DEPLOYMENT_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("failed to serialize deployment payload: {e}"))?;
        let mut memo = CONTRACT_DEPLOYMENT_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        if memo.len() > MAX_DEPLOYMENT_MEMO_BYTES {
            return Err(format!(
                "deployment memo length {} exceeds max {}",
                memo.len(),
                MAX_DEPLOYMENT_MEMO_BYTES
            ));
        }
        Ok(memo)
    }

    /// Decode canonical memo bytes into deployment payload.
    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(CONTRACT_DEPLOYMENT_MEMO_PREFIX) {
            return Err("missing deployment memo prefix".to_string());
        }
        if memo.len() > MAX_DEPLOYMENT_MEMO_BYTES {
            return Err(format!(
                "deployment memo length {} exceeds max {}",
                memo.len(),
                MAX_DEPLOYMENT_MEMO_BYTES
            ));
        }
        let payload_bytes = &memo[CONTRACT_DEPLOYMENT_MEMO_PREFIX.len()..];
        let payload: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_DEPLOYMENT_MEMO_BYTES as u64)
            .deserialize(payload_bytes)
            .map_err(|e| format!("invalid deployment payload encoding: {e}"))?;
        payload.validate()?;
        Ok(payload)
    }
}
