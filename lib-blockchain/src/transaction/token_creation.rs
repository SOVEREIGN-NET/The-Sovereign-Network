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
/// Canonical treasury allocation for non-SOV token deployments (20%).
pub const TOKEN_CREATION_TREASURY_ALLOCATION_BPS: u16 = 2_000;

/// Canonical token creation payload for `TransactionType::TokenCreation`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenCreationPayloadV1 {
    /// Human-readable token name.
    pub name: String,
    /// Token ticker symbol.
    pub symbol: String,
    /// Total initial supply minted at deployment (split across creator/treasury per policy).
    pub initial_supply: u64,
    /// Display decimals for client formatting.
    pub decimals: u8,
    /// Treasury allocation in basis points. Canonical value is fixed at 2_000 (20%).
    #[serde(default = "default_token_creation_treasury_allocation_bps")]
    pub treasury_allocation_bps: u16,
    /// Treasury recipient key id for the deployment allocation.
    #[serde(default)]
    pub treasury_recipient: [u8; 32],
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
        if self.treasury_allocation_bps != TOKEN_CREATION_TREASURY_ALLOCATION_BPS {
            return Err(format!(
                "treasury_allocation_bps must be {}",
                TOKEN_CREATION_TREASURY_ALLOCATION_BPS
            ));
        }
        if self.treasury_recipient == [0u8; 32] {
            return Err("treasury_recipient must be non-zero".to_string());
        }
        Ok(())
    }

    /// Deterministically split initial supply into (creator, treasury) allocation.
    pub fn split_initial_supply(&self) -> (u64, u64) {
        let treasury_u128 =
            (self.initial_supply as u128 * self.treasury_allocation_bps as u128) / 10_000u128;
        let treasury = u64::try_from(treasury_u128)
            .expect("treasury split must fit in u64 because initial_supply is u64");
        let creator = self.initial_supply.saturating_sub(treasury);
        (creator, treasury)
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

fn default_token_creation_treasury_allocation_bps() -> u16 {
    TOKEN_CREATION_TREASURY_ALLOCATION_BPS
}

#[cfg(test)]
mod tests {
    use super::{TokenCreationPayloadV1, TOKEN_CREATION_TREASURY_ALLOCATION_BPS};

    #[test]
    fn split_initial_supply_uses_canonical_twenty_percent() {
        let payload = TokenCreationPayloadV1 {
            name: "CarbonBlue".to_string(),
            symbol: "CBE".to_string(),
            initial_supply: 100,
            decimals: 8,
            treasury_allocation_bps: TOKEN_CREATION_TREASURY_ALLOCATION_BPS,
            treasury_recipient: [1u8; 32],
        };

        let (creator, treasury) = payload.split_initial_supply();
        assert_eq!(creator, 80);
        assert_eq!(treasury, 20);
    }

    #[test]
    fn reject_zero_treasury_recipient() {
        let payload = TokenCreationPayloadV1 {
            name: "Token".to_string(),
            symbol: "TOK".to_string(),
            initial_supply: 1,
            decimals: 8,
            treasury_allocation_bps: TOKEN_CREATION_TREASURY_ALLOCATION_BPS,
            treasury_recipient: [0u8; 32],
        };

        assert!(payload.validate().is_err());
    }

    #[test]
    fn reject_non_canonical_treasury_bps() {
        let payload = TokenCreationPayloadV1 {
            name: "Token".to_string(),
            symbol: "TOK".to_string(),
            initial_supply: 1,
            decimals: 8,
            treasury_allocation_bps: 1_000,
            treasury_recipient: [1u8; 32],
        };

        assert!(payload.validate().is_err());
    }
}
