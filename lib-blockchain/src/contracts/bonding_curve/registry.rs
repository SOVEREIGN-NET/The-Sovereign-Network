//! Bonding Curve Registry
//!
//! Index of all bonding curve tokens with query capabilities.
//! Tracks phase transitions and graduation status.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use super::{
    token::BondingCurveToken,
    types::{Phase, CurveError},
};

/// Bonding Curve Registry
///
/// Maintains index of all bonding curve tokens for efficient querying.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BondingCurveRegistry {
    /// All registered tokens by ID
    tokens: HashMap<[u8; 32], BondingCurveToken>,

    /// Index by phase
    curve_tokens: Vec<[u8; 32]>,
    graduated_tokens: Vec<[u8; 32]>,
    amm_tokens: Vec<[u8; 32]>,

    /// Total count statistics
    total_deployed: u64,
    total_graduated: u64,
    total_migrated_to_amm: u64,
}

impl BondingCurveRegistry {
    /// Create new empty registry
    pub fn new() -> Self {
        Self {
            tokens: HashMap::new(),
            curve_tokens: Vec::new(),
            graduated_tokens: Vec::new(),
            amm_tokens: Vec::new(),
            total_deployed: 0,
            total_graduated: 0,
            total_migrated_to_amm: 0,
        }
    }

    /// Register a new bonding curve token
    pub fn register(&mut self, token: BondingCurveToken) -> Result<(), CurveError> {
        if self.tokens.contains_key(&token.token_id) {
            return Err(CurveError::InvalidParameters(
                "Token already registered".to_string()
            ));
        }

        // Add to phase index
        match token.phase {
            Phase::Curve => self.curve_tokens.push(token.token_id),
            Phase::Graduated => self.graduated_tokens.push(token.token_id),
            Phase::AMM => self.amm_tokens.push(token.token_id),
        }

        self.tokens.insert(token.token_id, token);
        self.total_deployed += 1;

        Ok(())
    }

    /// Get token by ID
    pub fn get(&self, token_id: &[u8; 32]) -> Option<&BondingCurveToken> {
        self.tokens.get(token_id)
    }

    /// Get mutable token by ID
    pub fn get_mut(&mut self, token_id: &[u8; 32]) -> Option<&mut BondingCurveToken> {
        self.tokens.get_mut(token_id)
    }

    /// Update token phase (called on graduation/migration)
    pub fn update_phase(
        &mut self,
        token_id: &[u8; 32],
        new_phase: Phase,
    ) -> Result<(), CurveError> {
        let token = self.tokens.get(token_id)
            .ok_or(CurveError::InvalidParameters("Token not found".to_string()))?;

        let old_phase = token.phase;

        // Update indices
        match old_phase {
            Phase::Curve => {
                self.curve_tokens.retain(|id| id != token_id);
                self.total_graduated += 1;
            }
            Phase::Graduated => {
                self.graduated_tokens.retain(|id| id != token_id);
                self.total_migrated_to_amm += 1;
            }
            Phase::AMM => {}
        }

        match new_phase {
            Phase::Graduated => self.graduated_tokens.push(*token_id),
            Phase::AMM => self.amm_tokens.push(*token_id),
            Phase::Curve => {}
        }

        // Update token phase
        if let Some(token) = self.tokens.get_mut(token_id) {
            token.phase = new_phase;
        }

        Ok(())
    }

    /// Get all tokens in a specific phase
    pub fn get_by_phase(&self, phase: Phase) -> Vec<&BondingCurveToken> {
        let ids = match phase {
            Phase::Curve => &self.curve_tokens,
            Phase::Graduated => &self.graduated_tokens,
            Phase::AMM => &self.amm_tokens,
        };

        ids.iter()
            .filter_map(|id| self.tokens.get(id))
            .collect()
    }

    /// Get tokens that can graduate (curve phase + threshold met)
    pub fn get_ready_to_graduate(
        &self,
        current_timestamp: u64,
    ) -> Vec<&BondingCurveToken> {
        self.curve_tokens
            .iter()
            .filter_map(|id| self.tokens.get(id))
            .filter(|token| token.can_graduate(current_timestamp))
            .collect()
    }

    /// Get total token count
    pub fn total_count(&self) -> usize {
        self.tokens.len()
    }

    /// Get count by phase
    pub fn count_by_phase(&self, phase: Phase) -> usize {
        match phase {
            Phase::Curve => self.curve_tokens.len(),
            Phase::Graduated => self.graduated_tokens.len(),
            Phase::AMM => self.amm_tokens.len(),
        }
    }

    /// Get all tokens
    pub fn get_all(&self) -> Vec<&BondingCurveToken> {
        self.tokens.values().collect()
    }

    /// Check if token exists
    pub fn contains(&self, token_id: &[u8; 32]) -> bool {
        self.tokens.contains_key(token_id)
    }

    /// Get registry statistics
    pub fn stats(&self) -> RegistryStats {
        RegistryStats {
            total_deployed: self.total_deployed,
            in_curve_phase: self.curve_tokens.len() as u64,
            graduated_pending_amm: self.graduated_tokens.len() as u64,
            active_in_amm: self.amm_tokens.len() as u64,
            total_graduated: self.total_graduated,
            total_migrated_to_amm: self.total_migrated_to_amm,
        }
    }
}

impl Default for BondingCurveRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Registry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryStats {
    pub total_deployed: u64,
    pub in_curve_phase: u64,
    pub graduated_pending_amm: u64,
    pub active_in_amm: u64,
    pub total_graduated: u64,
    pub total_migrated_to_amm: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contracts::bonding_curve::types::{CurveType, Threshold};
    use crate::integration::crypto_integration::PublicKey;

    fn test_token(id: u8, phase: Phase) -> BondingCurveToken {
        let mut token = BondingCurveToken::deploy(
            [id; 32],
            format!("Token {}", id),
            format!("TK{}", id),
            CurveType::Linear { base_price: 100, slope: 1 },
            Threshold::ReserveAmount(1000),
            true,
            PublicKey {
                dilithium_pk: vec![],
                kyber_pk: vec![],
                key_id: [id; 32],
            },
            100,
            1_600_000_000,
        )
        .unwrap();
        token.phase = phase;
        token
    }

    #[test]
    fn test_register_token() {
        let mut registry = BondingCurveRegistry::new();
        let token = test_token(1, Phase::Curve);

        assert!(registry.register(token).is_ok());
        assert_eq!(registry.total_count(), 1);
        assert_eq!(registry.count_by_phase(Phase::Curve), 1);
    }

    #[test]
    fn test_duplicate_registration_fails() {
        let mut registry = BondingCurveRegistry::new();
        let token = test_token(1, Phase::Curve);

        assert!(registry.register(token.clone()).is_ok());
        assert!(registry.register(token).is_err());
    }

    #[test]
    fn test_get_by_phase() {
        let mut registry = BondingCurveRegistry::new();

        registry.register(test_token(1, Phase::Curve)).unwrap();
        registry.register(test_token(2, Phase::Curve)).unwrap();
        registry.register(test_token(3, Phase::Graduated)).unwrap();
        registry.register(test_token(4, Phase::AMM)).unwrap();

        assert_eq!(registry.get_by_phase(Phase::Curve).len(), 2);
        assert_eq!(registry.get_by_phase(Phase::Graduated).len(), 1);
        assert_eq!(registry.get_by_phase(Phase::AMM).len(), 1);
    }

    #[test]
    fn test_update_phase() {
        let mut registry = BondingCurveRegistry::new();
        let token = test_token(1, Phase::Curve);
        let id = token.token_id;

        registry.register(token).unwrap();
        assert_eq!(registry.count_by_phase(Phase::Curve), 1);

        registry.update_phase(&id, Phase::Graduated).unwrap();
        assert_eq!(registry.count_by_phase(Phase::Curve), 0);
        assert_eq!(registry.count_by_phase(Phase::Graduated), 1);

        let token = registry.get(&id).unwrap();
        assert_eq!(token.phase, Phase::Graduated);
    }

    #[test]
    fn test_stats() {
        let mut registry = BondingCurveRegistry::new();

        registry.register(test_token(1, Phase::Curve)).unwrap();
        registry.register(test_token(2, Phase::Graduated)).unwrap();
        registry.register(test_token(3, Phase::AMM)).unwrap();

        let stats = registry.stats();
        assert_eq!(stats.total_deployed, 3);
        assert_eq!(stats.in_curve_phase, 1);
        assert_eq!(stats.graduated_pending_amm, 1);
        assert_eq!(stats.active_in_amm, 1);
    }
}
