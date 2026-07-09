//! Domain registration and update transaction payloads.
//!
//! Domain records are authoritative on-chain. The sled/DHT DomainRegistry is a
//! read-through cache populated from chain state at startup.
//!
//! ## Memo encoding
//!
//! Payloads are encoded into `Transaction::memo` as:
//!   `DOMAIN_REGISTRATION_PREFIX    || bincode(DomainRegistrationPayloadV1)`   // legacy, no on-chain fee
//!   `DOMAIN_REGISTRATION_PREFIX_V2 || bincode(DomainRegistrationPayloadV2)`   // canonical, fee in consensus
//!   `DOMAIN_UPDATE_PREFIX          || bincode(DomainUpdatePayload)`
//!
//! V1 is decode-only (replays historical chain). All new registrations
//! emit V2 carrying the SOV fee inline so `process_domain_transactions`
//! can debit/credit at block-apply time. Per the project's bincode rule
//! (`feedback_*` in MEMORY.md) we do not insert fields mid-struct — V2
//! is a separate struct behind a separate prefix.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

pub const DOMAIN_REGISTRATION_PREFIX: &[u8] = b"DOMREG1:";
pub const DOMAIN_REGISTRATION_PREFIX_V2: &[u8] = b"DOMREG2:";
pub const DOMAIN_UPDATE_PREFIX: &[u8] = b"DOMUPD1:";

/// Canonical on-chain domain record — stored in `Blockchain::domain_registry`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnChainDomainRecord {
    /// Domain name (e.g. "mysite.sov")
    pub domain: String,
    /// Owner DID (did:zhtp:hex)
    pub owner_did: String,
    /// Current Web4Manifest CID
    pub manifest_cid: String,
    /// BLAKE3 hash of the build output
    pub build_hash: String,
    /// Human-readable title
    pub title: String,
    /// Human-readable description
    pub description: String,
    /// Category tag
    pub category: String,
    /// Discovery tags
    pub tags: Vec<String>,
    /// Block timestamp at registration
    pub registered_at: u64,
    /// Expiration (registered_at + duration_days * 86400)
    pub expires_at: u64,
    /// Monotonically increasing deployment version (starts at 1)
    pub version: u64,
    /// Block timestamp of last update
    pub updated_at: u64,
    /// Hash of the SOV fee payment transaction
    pub fee_tx_hash: String,
}

/// Public payload type used by handlers, validators, and the block executor.
/// Always carries the fee fields; for V1-decoded historical txes those
/// fields are populated with zeros to indicate "legacy, no on-chain fee".
#[derive(Debug, Clone)]
pub struct DomainRegistrationPayload {
    pub domain: String,
    pub owner_did: String,
    pub manifest_cid: String,
    pub build_hash: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub duration_days: u64,
    pub fee_tx_hash: String,
    /// Canonical fee amount in atomic SOV units. Zero for V1 payloads
    /// (legacy historical txes). Non-zero for V2 — debited at block-apply.
    pub fee_amount_atoms: u128,
    /// Wallet that pays the fee. Zeroed `[0; 32]` for V1. For V2, must be
    /// the signer's Primary wallet — validation enforces this.
    pub fee_payer_wallet_id: [u8; 32],
}

/// Legacy (V1) wire layout — kept verbatim so historical chain replay
/// continues to deserialise. New txes never emit V1.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainRegistrationPayloadV1 {
    pub domain: String,
    pub owner_did: String,
    pub manifest_cid: String,
    pub build_hash: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub duration_days: u64,
    pub fee_tx_hash: String,
}

/// V2 wire layout — extends V1 with the canonical fee fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DomainRegistrationPayloadV2 {
    pub domain: String,
    pub owner_did: String,
    pub manifest_cid: String,
    pub build_hash: String,
    pub title: String,
    pub description: String,
    pub category: String,
    pub tags: Vec<String>,
    pub duration_days: u64,
    pub fee_tx_hash: String,
    pub fee_amount_atoms: u128,
    pub fee_payer_wallet_id: [u8; 32],
}

/// Payload embedded in a `DomainUpdate` transaction memo.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainUpdatePayload {
    pub domain: String,
    pub owner_did: String,
    pub new_manifest_cid: String,
    pub expected_previous_manifest_cid: String,
    pub build_hash: String,
    pub message: Option<String>,
    pub fee_tx_hash: String,
}

impl DomainRegistrationPayload {
    /// Always emits V2 — the canonical fee-bearing wire format.
    pub fn encode_memo(&self) -> Result<Vec<u8>> {
        let v2 = DomainRegistrationPayloadV2 {
            domain: self.domain.clone(),
            owner_did: self.owner_did.clone(),
            manifest_cid: self.manifest_cid.clone(),
            build_hash: self.build_hash.clone(),
            title: self.title.clone(),
            description: self.description.clone(),
            category: self.category.clone(),
            tags: self.tags.clone(),
            duration_days: self.duration_days,
            fee_tx_hash: self.fee_tx_hash.clone(),
            fee_amount_atoms: self.fee_amount_atoms,
            fee_payer_wallet_id: self.fee_payer_wallet_id,
        };
        let payload = bincode::serialize(&v2)
            .map_err(|e| anyhow!("Failed to encode DomainRegistrationPayloadV2: {}", e))?;
        let mut memo =
            Vec::with_capacity(DOMAIN_REGISTRATION_PREFIX_V2.len() + payload.len());
        memo.extend_from_slice(DOMAIN_REGISTRATION_PREFIX_V2);
        memo.extend_from_slice(&payload);
        Ok(memo)
    }

    /// Tries V2 first, then falls back to V1 for historical replay.
    /// V1-decoded payloads have `fee_amount_atoms = 0` and
    /// `fee_payer_wallet_id = [0; 32]` — `process_domain_transactions`
    /// treats that as "legacy, no on-chain fee".
    pub fn decode_memo(memo: &[u8]) -> Result<Self> {
        if let Some(v2_bytes) = memo.strip_prefix(DOMAIN_REGISTRATION_PREFIX_V2) {
            let v2: DomainRegistrationPayloadV2 = bincode::deserialize(v2_bytes)
                .map_err(|e| anyhow!("Failed to decode DomainRegistrationPayloadV2: {}", e))?;
            return Ok(Self {
                domain: v2.domain,
                owner_did: v2.owner_did,
                manifest_cid: v2.manifest_cid,
                build_hash: v2.build_hash,
                title: v2.title,
                description: v2.description,
                category: v2.category,
                tags: v2.tags,
                duration_days: v2.duration_days,
                fee_tx_hash: v2.fee_tx_hash,
                fee_amount_atoms: v2.fee_amount_atoms,
                fee_payer_wallet_id: v2.fee_payer_wallet_id,
            });
        }
        if let Some(v1_bytes) = memo.strip_prefix(DOMAIN_REGISTRATION_PREFIX) {
            let v1: DomainRegistrationPayloadV1 = bincode::deserialize(v1_bytes)
                .map_err(|e| anyhow!("Failed to decode DomainRegistrationPayloadV1: {}", e))?;
            return Ok(Self {
                domain: v1.domain,
                owner_did: v1.owner_did,
                manifest_cid: v1.manifest_cid,
                build_hash: v1.build_hash,
                title: v1.title,
                description: v1.description,
                category: v1.category,
                tags: v1.tags,
                duration_days: v1.duration_days,
                fee_tx_hash: v1.fee_tx_hash,
                fee_amount_atoms: 0,
                fee_payer_wallet_id: [0u8; 32],
            });
        }
        Err(anyhow!("Missing DOMREG1: or DOMREG2: prefix in memo"))
    }
}

impl DomainUpdatePayload {
    pub fn encode_memo(&self) -> Result<Vec<u8>> {
        let payload = bincode::serialize(self)
            .map_err(|e| anyhow!("Failed to encode DomainUpdatePayload: {}", e))?;
        let mut memo = Vec::with_capacity(DOMAIN_UPDATE_PREFIX.len() + payload.len());
        memo.extend_from_slice(DOMAIN_UPDATE_PREFIX);
        memo.extend_from_slice(&payload);
        Ok(memo)
    }

    pub fn decode_memo(memo: &[u8]) -> Result<Self> {
        let memo = memo
            .strip_prefix(DOMAIN_UPDATE_PREFIX)
            .ok_or_else(|| anyhow!("Missing DOMAIN_UPDATE_PREFIX"))?;
        bincode::deserialize(memo)
            .map_err(|e| anyhow!("Failed to decode DomainUpdatePayload: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1_payload_bytes() -> Vec<u8> {
        let v1 = DomainRegistrationPayloadV1 {
            domain: "test.sov".to_string(),
            owner_did: "did:zhtp:abcd".to_string(),
            manifest_cid: "cid123".to_string(),
            build_hash: "hash123".to_string(),
            title: "Test".to_string(),
            description: "A test domain".to_string(),
            category: "general".to_string(),
            tags: vec!["test".to_string()],
            duration_days: 365,
            fee_tx_hash: "audit-hash".to_string(),
        };
        let mut memo = DOMAIN_REGISTRATION_PREFIX.to_vec();
        memo.extend_from_slice(&bincode::serialize(&v1).unwrap());
        memo
    }

    #[test]
    fn v1_memo_decodes_with_zero_fee_fields() {
        // Historical chain replay must still succeed and surface zeroed
        // fee fields so `process_domain_transactions` treats it as legacy.
        let memo = v1_payload_bytes();
        let p = DomainRegistrationPayload::decode_memo(&memo).expect("V1 decode");
        assert_eq!(p.domain, "test.sov");
        assert_eq!(p.fee_amount_atoms, 0);
        assert_eq!(p.fee_payer_wallet_id, [0u8; 32]);
    }

    #[test]
    fn v2_encode_decode_roundtrips() {
        let original = DomainRegistrationPayload {
            domain: "site.sov".to_string(),
            owner_did: "did:zhtp:cafe".to_string(),
            manifest_cid: "cid456".to_string(),
            build_hash: "hash456".to_string(),
            title: "Site".to_string(),
            description: "Production site".to_string(),
            category: "website".to_string(),
            tags: vec!["web4".to_string()],
            duration_days: 365,
            fee_tx_hash: String::new(),
            fee_amount_atoms: 10 * lib_types::TOKEN_SCALE_18,
            fee_payer_wallet_id: [0xab; 32],
        };
        let memo = original.encode_memo().expect("V2 encode");
        assert!(memo.starts_with(DOMAIN_REGISTRATION_PREFIX_V2));
        let decoded = DomainRegistrationPayload::decode_memo(&memo).expect("V2 decode");
        assert_eq!(decoded.domain, original.domain);
        assert_eq!(decoded.fee_amount_atoms, original.fee_amount_atoms);
        assert_eq!(decoded.fee_payer_wallet_id, original.fee_payer_wallet_id);
    }

    #[test]
    fn v2_emit_never_collides_with_v1_prefix() {
        let p = DomainRegistrationPayload {
            domain: "x.sov".to_string(),
            owner_did: "did:zhtp:1".to_string(),
            manifest_cid: String::new(),
            build_hash: String::new(),
            title: String::new(),
            description: String::new(),
            category: "g".to_string(),
            tags: vec![],
            duration_days: 1,
            fee_tx_hash: String::new(),
            fee_amount_atoms: 1,
            fee_payer_wallet_id: [1u8; 32],
        };
        let memo = p.encode_memo().unwrap();
        assert!(memo.starts_with(DOMAIN_REGISTRATION_PREFIX_V2));
        assert!(!memo.starts_with(DOMAIN_REGISTRATION_PREFIX));
    }

    #[test]
    fn unknown_prefix_is_rejected() {
        let bogus = b"DOMREG9:garbage".to_vec();
        assert!(DomainRegistrationPayload::decode_memo(&bogus).is_err());
    }

    #[test]
    fn cons516_rejects_fee_tx_hash_not_in_mempool() {
        use crate::blockchain::Blockchain;
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::Transaction;
        use crate::types::transaction_type::TransactionType;

        let bc = Blockchain::default();
        let signer = [0x11u8; 32];
        let payload = DomainRegistrationPayload {
            domain: "evil.sov".to_string(),
            owner_did: format!("did:zhtp:{}", hex::encode(signer)),
            manifest_cid: String::new(),
            build_hash: String::new(),
            title: String::new(),
            description: String::new(),
            category: "test".to_string(),
            tags: vec![],
            duration_days: 365,
            fee_tx_hash: "ab".repeat(32),
            fee_amount_atoms: 0,
            fee_payer_wallet_id: [0u8; 32],
        };
        let domain_tx = Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::DomainRegistration,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: Signature {
                signature: vec![0u8; 64],
                public_key: PublicKey {
                    dilithium_pk: [0u8; 2592],
                    kyber_pk: [0u8; 1568],
                    key_id: signer,
                },
                algorithm: SignatureAlgorithm::Dilithium5,
                timestamp: 0,
            },
            memo: payload.encode_memo().unwrap(),
            payload: crate::transaction::TransactionPayload::None,
        };

        let err = validate_cons516_companion_fee(&bc, &domain_tx, &payload).unwrap_err();
        assert!(
            err.contains("not found in mempool"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn cons516_accepts_valid_companion_token_transfer() {
        use crate::blockchain::Blockchain;
        use crate::contracts::utils::generate_lib_token_id;
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::fee::DEFAULT_DOMAIN_REGISTRATION_FEE_ATOMS;
        use crate::transaction::{TokenTransferData, Transaction};
        use crate::types::transaction_type::TransactionType;

        let mut bc = Blockchain::default();
        let signer = [0x22u8; 32];
        let sig = Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: signer,
            },
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };
        let treasury = crate::Blockchain::deterministic_treasury_wallet_id().as_array();
        let fee_tx = Transaction::new_token_transfer(
            TokenTransferData {
                token_id: generate_lib_token_id(),
                from: signer,
                to: treasury,
                amount: DEFAULT_DOMAIN_REGISTRATION_FEE_ATOMS,
                nonce: 0,
            },
            sig.clone(),
            vec![],
        );
        let fee_hash = hex::encode(fee_tx.hash().as_bytes());
        bc.pending_transactions.push(fee_tx);

        let payload = DomainRegistrationPayload {
            domain: "paid.sov".to_string(),
            owner_did: format!("did:zhtp:{}", hex::encode(signer)),
            manifest_cid: String::new(),
            build_hash: String::new(),
            title: String::new(),
            description: String::new(),
            category: "test".to_string(),
            tags: vec![],
            duration_days: 365,
            fee_tx_hash: fee_hash,
            fee_amount_atoms: 0,
            fee_payer_wallet_id: [0u8; 32],
        };
        let domain_tx = Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::DomainRegistration,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: sig,
            memo: payload.encode_memo().unwrap(),
            payload: crate::transaction::TransactionPayload::None,
        };

        validate_cons516_companion_fee(&bc, &domain_tx, &payload)
            .expect("valid companion fee tx in mempool");
    }

    #[test]
    fn cons516_rejects_underpaid_companion() {
        use crate::blockchain::Blockchain;
        use crate::contracts::utils::generate_lib_token_id;
        use crate::integration::crypto_integration::{PublicKey, Signature, SignatureAlgorithm};
        use crate::transaction::fee::DEFAULT_DOMAIN_REGISTRATION_FEE_ATOMS;
        use crate::transaction::{TokenTransferData, Transaction};
        use crate::types::transaction_type::TransactionType;

        let mut bc = Blockchain::default();
        let signer = [0x33u8; 32];
        let sig = Signature {
            signature: vec![0u8; 64],
            public_key: PublicKey {
                dilithium_pk: [0u8; 2592],
                kyber_pk: [0u8; 1568],
                key_id: signer,
            },
            algorithm: SignatureAlgorithm::Dilithium5,
            timestamp: 0,
        };
        let treasury = crate::Blockchain::deterministic_treasury_wallet_id().as_array();
        let fee_tx = Transaction::new_token_transfer(
            TokenTransferData {
                token_id: generate_lib_token_id(),
                from: signer,
                to: treasury,
                amount: DEFAULT_DOMAIN_REGISTRATION_FEE_ATOMS - 1,
                nonce: 0,
            },
            sig.clone(),
            vec![],
        );
        let fee_hash = hex::encode(fee_tx.hash().as_bytes());
        bc.pending_transactions.push(fee_tx);

        let payload = DomainRegistrationPayload {
            domain: "cheap.sov".to_string(),
            owner_did: format!("did:zhtp:{}", hex::encode(signer)),
            manifest_cid: String::new(),
            build_hash: String::new(),
            title: String::new(),
            description: String::new(),
            category: "test".to_string(),
            tags: vec![],
            duration_days: 365,
            fee_tx_hash: fee_hash,
            fee_amount_atoms: 0,
            fee_payer_wallet_id: [0u8; 32],
        };
        let domain_tx = Transaction {
            version: 2,
            chain_id: 0x03,
            transaction_type: TransactionType::DomainRegistration,
            inputs: vec![],
            outputs: vec![],
            fee: 0,
            signature: sig,
            memo: payload.encode_memo().unwrap(),
            payload: crate::transaction::TransactionPayload::None,
        };

        let err = validate_cons516_companion_fee(&bc, &domain_tx, &payload).unwrap_err();
        assert!(err.contains("below required"), "unexpected error: {err}");
    }
}

/// Validate CONS-516 companion-fee binding for DOMREG2 registrations.
///
/// When inline fee fields are zero, `fee_tx_hash` must reference a **pending**
/// mempool `TokenTransfer` that pays ≥ `domain_registration_fee_atoms` SOV from
/// the domain signer's key to the DAO treasury wallet.
pub fn validate_cons516_companion_fee(
    bc: &crate::blockchain::Blockchain,
    domain_tx: &crate::transaction::Transaction,
    payload: &DomainRegistrationPayload,
) -> Result<(), String> {
    use crate::types::transaction_type::TransactionType;

    let fee_hash_hex = payload.fee_tx_hash.trim();
    if fee_hash_hex.len() != 64
        || !fee_hash_hex.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("fee_tx_hash must be 64 hex chars".into());
    }
    let fee_hash_bytes =
        hex::decode(fee_hash_hex).map_err(|_| "fee_tx_hash is not valid hex".to_string())?;
    if fee_hash_bytes.len() != 32 {
        return Err("fee_tx_hash must decode to 32 bytes".into());
    }
    let mut fee_hash = [0u8; 32];
    fee_hash.copy_from_slice(&fee_hash_bytes);

    let fee_tx = bc
        .get_pending_transactions()
        .into_iter()
        .find(|t| t.hash().as_array() == fee_hash)
        .ok_or_else(|| {
            format!(
                "fee_tx_hash {} not found in mempool (companion TokenTransfer required)",
                fee_hash_hex
            )
        })?;

    if fee_tx.transaction_type != TransactionType::TokenTransfer {
        return Err(format!(
            "fee_tx_hash must reference TokenTransfer, got {:?}",
            fee_tx.transaction_type
        ));
    }
    let transfer = fee_tx
        .token_transfer_data()
        .ok_or_else(|| "companion tx missing TokenTransfer payload".to_string())?;

    let required = bc.tx_fee_config.domain_registration_fee_atoms;
    let sov_id = crate::contracts::utils::generate_lib_token_id();
    if transfer.token_id != sov_id {
        return Err("companion fee must use SOV token".into());
    }
    if transfer.amount < required {
        return Err(format!(
            "companion fee {} atoms below required {} atoms",
            transfer.amount, required
        ));
    }
    let signer_key = domain_tx.signature.public_key.key_id;
    if transfer.from != signer_key {
        return Err("companion fee must be sent from domain signer key".into());
    }
    let treasury = crate::Blockchain::deterministic_treasury_wallet_id();
    if transfer.to != treasury.as_array() {
        return Err("companion fee recipient must be DAO treasury wallet".into());
    }
    Ok(())
}
