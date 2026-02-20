//! Canonical contract execution transaction memo schemas.
//!
//! Supported memo formats:
//! - V1 (legacy): `b"ZHTP"  || bincode((ContractCall, Signature))`
//! - V2 (canonical deployed dispatch): `b"ZHTP2" || bincode(([u8;32], ContractCall, Signature))`
//!
//! V2 carries an explicit deployed `contract_id` so execution can be dispatched to
//! the exact storage namespace and deployed code.

use bincode::Options;

use crate::integration::crypto_integration::Signature;
use crate::types::ContractCall;

/// Legacy memo prefix (kept for read compatibility).
pub const CONTRACT_EXECUTION_MEMO_PREFIX_V1: &[u8] = b"ZHTP";
/// Canonical memo prefix with explicit target contract id.
pub const CONTRACT_EXECUTION_MEMO_PREFIX_V2: &[u8] = b"ZHTP2";

/// Maximum bytes accepted for a contract execution memo.
pub const MAX_CONTRACT_EXECUTION_MEMO_BYTES: usize = 1024 * 1024;

fn memo_bincode_options() -> impl Options {
    bincode::DefaultOptions::new().with_limit(MAX_CONTRACT_EXECUTION_MEMO_BYTES as u64)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractExecutionMemoVersion {
    V1Legacy,
    V2ContractId,
}

#[derive(Debug, Clone)]
pub struct DecodedContractExecutionMemo {
    pub version: ContractExecutionMemoVersion,
    pub contract_id: Option<[u8; 32]>,
    pub call: ContractCall,
    pub signature: Signature,
}

impl DecodedContractExecutionMemo {
    /// Decode any supported contract execution memo format.
    pub fn decode_compat(memo: &[u8]) -> Result<Self, String> {
        if memo.len() > MAX_CONTRACT_EXECUTION_MEMO_BYTES {
            return Err(format!(
                "contract execution memo length {} exceeds max {}",
                memo.len(),
                MAX_CONTRACT_EXECUTION_MEMO_BYTES
            ));
        }

        if memo.starts_with(CONTRACT_EXECUTION_MEMO_PREFIX_V2) {
            let payload = &memo[CONTRACT_EXECUTION_MEMO_PREFIX_V2.len()..];
            let (contract_id, call, signature): ([u8; 32], ContractCall, Signature) =
                memo_bincode_options()
                    .deserialize(payload)
                    .map_err(|e| format!("invalid V2 contract execution memo payload: {e}"))?;
            call.validate()
                .map_err(|e| format!("invalid ContractCall payload: {e}"))?;
            return Ok(Self {
                version: ContractExecutionMemoVersion::V2ContractId,
                contract_id: Some(contract_id),
                call,
                signature,
            });
        }

        if memo.starts_with(CONTRACT_EXECUTION_MEMO_PREFIX_V1) {
            let payload = &memo[CONTRACT_EXECUTION_MEMO_PREFIX_V1.len()..];
            let (call, signature): (ContractCall, Signature) = memo_bincode_options()
                .deserialize(payload)
                .map_err(|e| format!("invalid V1 contract execution memo payload: {e}"))?;
            call.validate()
                .map_err(|e| format!("invalid ContractCall payload: {e}"))?;
            return Ok(Self {
                version: ContractExecutionMemoVersion::V1Legacy,
                contract_id: None,
                call,
                signature,
            });
        }

        Err("contract execution memo must start with ZHTP2 or ZHTP prefix".to_string())
    }
}

/// Encode canonical V2 memo with explicit target `contract_id`.
pub fn encode_contract_execution_memo_v2(
    contract_id: [u8; 32],
    call: &ContractCall,
    signature: &Signature,
) -> Result<Vec<u8>, String> {
    call.validate()
        .map_err(|e| format!("invalid ContractCall payload: {e}"))?;

    let encoded = memo_bincode_options()
        .serialize(&(contract_id, call.clone(), signature.clone()))
        .map_err(|e| format!("failed to serialize V2 contract execution memo payload: {e}"))?;
    let mut memo = CONTRACT_EXECUTION_MEMO_PREFIX_V2.to_vec();
    memo.extend_from_slice(&encoded);

    if memo.len() > MAX_CONTRACT_EXECUTION_MEMO_BYTES {
        return Err(format!(
            "contract execution memo length {} exceeds max {}",
            memo.len(),
            MAX_CONTRACT_EXECUTION_MEMO_BYTES
        ));
    }

    Ok(memo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CallPermissions, ContractType};

    fn sample_call() -> ContractCall {
        ContractCall {
            contract_type: ContractType::Web4Website,
            method: "set_homepage".to_string(),
            params: vec![1, 2, 3],
            permissions: CallPermissions::Public,
        }
    }

    fn sample_sig(seed: u8) -> Signature {
        Signature {
            signature: vec![seed; 64],
            public_key: crate::integration::crypto_integration::PublicKey {
                dilithium_pk: vec![seed; 32],
                kyber_pk: vec![seed.wrapping_add(1); 32],
                key_id: [seed; 32],
            },
            algorithm: crate::integration::crypto_integration::SignatureAlgorithm::Dilithium2,
            timestamp: 1,
        }
    }

    #[test]
    fn decode_v2_round_trip() {
        let contract_id = [7u8; 32];
        let call = sample_call();
        let sig = sample_sig(9);
        let memo = encode_contract_execution_memo_v2(contract_id, &call, &sig)
            .expect("encode must succeed");
        let decoded =
            DecodedContractExecutionMemo::decode_compat(&memo).expect("decode must succeed");
        assert_eq!(decoded.version, ContractExecutionMemoVersion::V2ContractId);
        assert_eq!(decoded.contract_id, Some(contract_id));
        assert_eq!(decoded.call, call);
        assert_eq!(decoded.signature.public_key.key_id, sig.public_key.key_id);
        assert_eq!(decoded.signature.signature, sig.signature);
    }

    #[test]
    fn decode_v1_legacy_compat() {
        let call = sample_call();
        let sig = sample_sig(11);
        let mut memo = CONTRACT_EXECUTION_MEMO_PREFIX_V1.to_vec();
        memo.extend(
            memo_bincode_options()
                .serialize(&(call.clone(), sig.clone()))
                .expect("serialize"),
        );
        let decoded =
            DecodedContractExecutionMemo::decode_compat(&memo).expect("decode V1 must succeed");
        assert_eq!(decoded.version, ContractExecutionMemoVersion::V1Legacy);
        assert_eq!(decoded.contract_id, None);
        assert_eq!(decoded.call, call);
        assert_eq!(decoded.signature.public_key.key_id, sig.public_key.key_id);
        assert_eq!(decoded.signature.signature, sig.signature);
    }
}
