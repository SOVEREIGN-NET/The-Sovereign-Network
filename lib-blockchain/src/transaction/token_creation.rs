//! Canonical token creation transaction schema.
//!
//! Token creation payloads are encoded in transaction memo bytes as:
//! `TOKEN_CREATION_MEMO_PREFIX || bincode(TokenCreationPayloadV1)`.

use bincode::Options;
use serde::{Deserialize, Serialize};

/// Versioned memo prefix for token creation payload.
pub const TOKEN_CREATION_MEMO_PREFIX: &[u8] = b"ZHTP_TOKEN_CREATE_V1:";
/// Maximum token name length.
pub const MAX_TOKEN_NAME_BYTES: usize = 64;
/// Maximum token symbol length.
pub const MAX_TOKEN_SYMBOL_BYTES: usize = 10;
/// Maximum memo bytes accepted for token creation payload.
pub const MAX_TOKEN_CREATION_MEMO_BYTES: usize = 4096;

/// Canonical token creation payload for `TransactionType::TokenCreation`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenCreationPayloadV1 {
    /// Human-readable token name.
    pub name: String,
    /// Token ticker symbol.
    pub symbol: String,
    /// Initial mint amount assigned to creator.
    pub initial_supply: u64,
    /// Display decimals for client formatting.
    pub decimals: u8,
}

impl TokenCreationPayloadV1 {
    /// Validate payload fields and bounds.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name is required".to_string());
        }
        if self.name.len() > MAX_TOKEN_NAME_BYTES {
            return Err(format!(
                "name length {} exceeds max {}",
                self.name.len(),
                MAX_TOKEN_NAME_BYTES
            ));
        }
        if self.symbol.trim().is_empty() {
            return Err("symbol is required".to_string());
        }
        if self.symbol.len() > MAX_TOKEN_SYMBOL_BYTES {
            return Err(format!(
                "symbol length {} exceeds max {}",
                self.symbol.len(),
                MAX_TOKEN_SYMBOL_BYTES
            ));
        }
        if self.initial_supply == 0 {
            return Err("initial_supply must be greater than 0".to_string());
        }
        Ok(())
    }

    /// Encode this payload into canonical memo bytes.
    pub fn encode_memo(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let encoded = bincode::DefaultOptions::new()
            .with_limit(MAX_TOKEN_CREATION_MEMO_BYTES as u64)
            .serialize(self)
            .map_err(|e| format!("failed to serialize token creation payload: {e}"))?;
        let mut memo = TOKEN_CREATION_MEMO_PREFIX.to_vec();
        memo.extend_from_slice(&encoded);
        if memo.len() > MAX_TOKEN_CREATION_MEMO_BYTES {
            return Err(format!(
                "token creation memo length {} exceeds max {}",
                memo.len(),
                MAX_TOKEN_CREATION_MEMO_BYTES
            ));
        }
        Ok(memo)
    }

    /// Decode canonical memo bytes into token creation payload.
    pub fn decode_memo(memo: &[u8]) -> Result<Self, String> {
        if !memo.starts_with(TOKEN_CREATION_MEMO_PREFIX) {
            return Err("missing token creation memo prefix".to_string());
        }
        if memo.len() > MAX_TOKEN_CREATION_MEMO_BYTES {
            return Err(format!(
                "token creation memo length {} exceeds max {}",
                memo.len(),
                MAX_TOKEN_CREATION_MEMO_BYTES
            ));
        }
        let payload_bytes = &memo[TOKEN_CREATION_MEMO_PREFIX.len()..];
        let payload: Self = bincode::DefaultOptions::new()
            .with_limit(MAX_TOKEN_CREATION_MEMO_BYTES as u64)
            .deserialize(payload_bytes)
            .map_err(|e| format!("invalid token creation payload encoding: {e}"))?;
        payload.validate()?;
        Ok(payload)
    }
}
