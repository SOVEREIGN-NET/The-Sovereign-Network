//! Multi-signature implementation for ZHTP
//! 
//! implementation from crypto.rs, lines 841-910

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::{PrivateKey, PublicKey, Signature};
use crate::keypair::KeyPair;

/// Multi-signature scheme supporting threshold signatures
/// implementation from crypto.rs, lines 841-849
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiSig {
    /// Required number of signatures
    pub threshold: usize,
    /// Total number of participants
    pub participants: Vec<PublicKey>,
    /// Partial signatures
    pub signatures: HashMap<usize, Signature>,
}

impl MultiSig {
    /// Create a new multi-signature setup
    /// implementation from crypto.rs, lines 851-861
    pub fn new(threshold: usize, participants: Vec<PublicKey>) -> Result<Self> {
        if threshold == 0 || threshold > participants.len() {
            return Err(anyhow::anyhow!("Invalid threshold"));
        }
        
        Ok(MultiSig {
            threshold,
            participants,
            signatures: HashMap::new(),
        })
    }
    
    /// Add a partial signature
    /// implementation from crypto.rs, lines 863-874
    pub fn add_signature(&mut self, participant_index: usize, signature: Signature) -> Result<()> {
        if participant_index >= self.participants.len() {
            return Err(anyhow::anyhow!("Invalid participant index"));
        }
        
        // Verify signature is from the correct participant
        if signature.public_key.key_id != self.participants[participant_index].key_id {
            return Err(anyhow::anyhow!("Signature from wrong participant"));
        }
        
        self.signatures.insert(participant_index, signature);
        Ok(())
    }
    
    /// Check if we have enough signatures to execute
    /// implementation from crypto.rs, lines 876-879
    pub fn is_complete(&self) -> bool {
        self.signatures.len() >= self.threshold
    }
    
    /// Verify all collected signatures
    /// implementation from crypto.rs, lines 881-910
    pub fn verify(&self, message: &[u8]) -> Result<bool> {
        if !self.is_complete() {
            return Ok(false);
        }
        
        // Verify each signature
        for (index, signature) in &self.signatures {
            let participant_key = &self.participants[*index];
            
            // Create a temporary keypair for verification
            let temp_keypair = KeyPair {
                public_key: participant_key.clone(),
                private_key: PrivateKey {
                    dilithium_sk: vec![],
                    dilithium_pk: participant_key.dilithium_pk.clone(),
                    kyber_sk: vec![],
                    // ed25519_sk removed - pure PQC only
                    master_seed: vec![0u8; 64],
                },
            };
            
            if !temp_keypair.verify(signature, message)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keypair::KeyPair;

    #[test]
    fn test_multisig_2_of_3() -> Result<()> {
        // From original crypto.rs, lines 1370-1395
        let message = b"ZHTP KeyPair Validation Test";
        
        // Generate participants exactly like original 
        let kp1 = KeyPair::generate()?;
        let kp2 = KeyPair::generate()?;
        let kp3 = KeyPair::generate()?;
        
        let participants = vec![
            kp1.public_key.clone(),
            kp2.public_key.clone(),
            kp3.public_key.clone(),
        ];
        
        let mut multisig = MultiSig::new(2, participants)?; // 2-of-3
        
        // Sign with two participants exactly like original
        let sig1 = kp1.sign(message)?;
        let sig2 = kp2.sign(message)?;
        
        multisig.add_signature(0, sig1)?;
        assert!(!multisig.is_complete());
        
        multisig.add_signature(1, sig2)?;
        assert!(multisig.is_complete());
        
        // Verify exactly like original
        assert!(multisig.verify(message)?);

        Ok(())
    }

    #[test]
    fn test_multisig_insufficient_signatures() -> Result<()> {
        let message = b"ZHTP KeyPair Validation Test";
        
        let kp1 = KeyPair::generate()?;
        let kp2 = KeyPair::generate()?;
        
        let participants = vec![
            kp1.public_key.clone(),
            kp2.public_key.clone(),
        ];
        
        let mut multisig = MultiSig::new(2, participants)?; // Need both signatures
        
        // Only add one signature
        let sig1 = kp1.sign(message)?;
        multisig.add_signature(0, sig1)?;
        
        assert!(!multisig.is_complete());
        
        // Verification should fail due to insufficient signatures
        assert!(!multisig.verify(message)?);

        Ok(())
    }

    #[test]
    fn test_invalid_threshold() {
        let participants = vec![KeyPair::generate().unwrap().public_key];

        // Threshold 0 should fail
        let result = MultiSig::new(0, participants.clone());
        assert!(result.is_err());

        // Threshold > participants should fail  
        let result = MultiSig::new(2, participants);
        assert!(result.is_err());
    }
}
