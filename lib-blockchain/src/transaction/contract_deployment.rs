//! Canonical contract deployment transaction schema.
//!
//! Contract deployment payloads are encoded in transaction memo bytes as:
//! `CONTRACT_DEPLOYMENT_MEMO_PREFIX || bincode(DefaultOptions with_limit(MAX_DEPLOYMENT_MEMO_BYTES), ContractDeploymentPayloadV1)`.
//!
//! Both `encode_memo` and `decode_memo` use `bincode::DefaultOptions::new().with_limit(...)` to
//! guarantee deterministic round-trip compatibility required for consensus serialization.

use serde::{Deserialize, Serialize};
use bincode::Options;

/// Shared bincode options used by both `encode_memo` and `decode_memo` to guarantee
/// deterministic round-trip compatibility required for consensus serialization.
fn memo_bincode_options() -> impl Options {
    bincode::DefaultOptions::new().with_limit(MAX_DEPLOYMENT_MEMO_BYTES as u64)
}

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
        let encoded = memo_bincode_options()
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
        let payload: Self = memo_bincode_options()
            .deserialize(payload_bytes)
            .map_err(|e| format!("invalid deployment payload encoding: {e}"))?;
        payload.validate()?;
        Ok(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_payload() -> ContractDeploymentPayloadV1 {
        ContractDeploymentPayloadV1 {
            contract_type: "wasm".to_string(),
            code: vec![0x00, 0x61, 0x73, 0x6d], // minimal wasm magic bytes
            abi: br#"{"contract":"demo","version":"1.0.0"}"#.to_vec(),
            init_args: vec![],
            gas_limit: 100_000,
            memory_limit_bytes: 65_536,
        }
    }

    /// Round-trip: encode_memo → decode_memo must produce the original payload.
    #[test]
    fn test_encode_decode_round_trip() {
        let payload = valid_payload();
        let memo = payload.encode_memo().expect("encode should succeed");
        let decoded = ContractDeploymentPayloadV1::decode_memo(&memo).expect("decode should succeed");
        assert_eq!(payload, decoded);
    }

    /// Memo without the canonical prefix must be rejected.
    #[test]
    fn test_decode_rejects_missing_prefix() {
        let result = ContractDeploymentPayloadV1::decode_memo(b"not_a_valid_memo");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing deployment memo prefix"));
    }

    /// A payload that fails validation must not be encodable.
    #[test]
    fn test_encode_rejects_invalid_payload() {
        let mut payload = valid_payload();
        payload.gas_limit = 0; // invalid
        let result = payload.encode_memo();
        assert!(result.is_err());
    }

    /// Payloads with fields at or near their individual byte-length bounds must
    /// round-trip without error, confirming the memo size limit is not hit for
    /// valid near-maximum inputs.
    #[test]
    fn test_encode_decode_near_max_bounds() {
        let payload = ContractDeploymentPayloadV1 {
            contract_type: "a".repeat(MAX_DEPLOYMENT_CONTRACT_TYPE_BYTES),
            code: vec![0x00; MAX_DEPLOYMENT_CODE_BYTES],
            abi: vec![0x01; MAX_DEPLOYMENT_ABI_BYTES],
            init_args: vec![0x02; MAX_DEPLOYMENT_INIT_ARGS_BYTES],
            gas_limit: crate::execution_limits::MAX_TX_GAS,
            memory_limit_bytes: MAX_DEPLOYMENT_MEMORY_BYTES,
        };
        let memo = payload.encode_memo().expect("near-bounds encode should succeed");
        let decoded = ContractDeploymentPayloadV1::decode_memo(&memo)
            .expect("near-bounds decode should succeed");
        assert_eq!(payload, decoded);
    }

    /// A code field exceeding MAX_DEPLOYMENT_CODE_BYTES must be rejected.
    #[test]
    fn test_encode_rejects_code_too_large() {
        let mut payload = valid_payload();
        payload.code = vec![0x00; MAX_DEPLOYMENT_CODE_BYTES + 1];
        let result = payload.encode_memo();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("code length"));
    }
}
