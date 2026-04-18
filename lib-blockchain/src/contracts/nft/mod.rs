//! Non-Fungible Token (NFT) contract.
//!
//! Each NftContract represents a collection. Individual tokens within a collection
//! have unique u64 IDs, per-token metadata, and tracked ownership.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Metadata for an individual NFT.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftMetadata {
    /// Display name of this token.
    pub name: String,
    /// Human-readable description.
    pub description: String,
    /// Web4 content CID for the primary image/media.
    pub image_cid: String,
    /// Key-value attributes (trait_type → value).
    pub attributes: Vec<(String, String)>,
    /// DID of the creator.
    pub creator_did: String,
    /// Unix timestamp of minting.
    pub created_at: u64,
}

/// A single NFT collection on-chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftContract {
    /// Unique collection identifier (blake3 derived).
    pub collection_id: [u8; 32],
    /// Collection name.
    pub name: String,
    /// Short symbol (e.g. "ART").
    pub symbol: String,
    /// DID of the collection creator.
    pub creator_did: String,
    /// Wallet key_id of the creator (authorised to mint).
    pub creator_key_id: [u8; 32],
    /// Optional cap on total tokens in this collection.
    pub max_supply: Option<u64>,
    /// How many tokens have been minted (lifetime, including burned).
    pub total_minted: u64,
    /// Next token ID to assign.
    next_token_id: u64,
    /// Token ownership: token_id → owner wallet key_id.
    owners: HashMap<u64, [u8; 32]>,
    /// Per-token metadata.
    metadata: HashMap<u64, NftMetadata>,
    /// Unix timestamp of collection creation.
    pub created_at: u64,
}

impl NftContract {
    /// Create a new empty collection.
    pub fn new(
        collection_id: [u8; 32],
        name: String,
        symbol: String,
        creator_did: String,
        creator_key_id: [u8; 32],
        max_supply: Option<u64>,
        created_at: u64,
    ) -> Self {
        Self {
            collection_id,
            name,
            symbol,
            creator_did,
            creator_key_id,
            max_supply,
            total_minted: 0,
            next_token_id: 1, // token IDs start at 1
            owners: HashMap::new(),
            metadata: HashMap::new(),
            created_at,
        }
    }

    /// Mint a new token in this collection.
    ///
    /// Only the collection creator may mint. Returns the assigned token_id.
    pub fn mint(
        &mut self,
        minter_key_id: &[u8; 32],
        recipient: [u8; 32],
        metadata: NftMetadata,
    ) -> Result<u64> {
        // Authorization: only collection creator can mint
        if minter_key_id != &self.creator_key_id {
            return Err(anyhow!("Only the collection creator can mint"));
        }

        // Supply cap
        if let Some(cap) = self.max_supply {
            if self.total_minted >= cap {
                return Err(anyhow!(
                    "Max supply reached: {}/{}",
                    self.total_minted,
                    cap
                ));
            }
        }

        let token_id = self.next_token_id;
        self.next_token_id += 1;
        self.total_minted += 1;
        self.owners.insert(token_id, recipient);
        self.metadata.insert(token_id, metadata);

        Ok(token_id)
    }

    /// Transfer a token to a new owner.
    pub fn transfer(
        &mut self,
        token_id: u64,
        from: &[u8; 32],
        to: [u8; 32],
    ) -> Result<()> {
        let owner = self
            .owners
            .get(&token_id)
            .ok_or_else(|| anyhow!("Token {} does not exist", token_id))?;

        if owner != from {
            return Err(anyhow!(
                "Sender does not own token {}: owner={}, from={}",
                token_id,
                hex::encode(&owner[..8]),
                hex::encode(&from[..8]),
            ));
        }

        self.owners.insert(token_id, to);
        Ok(())
    }

    /// Burn (destroy) a token. Only the owner can burn.
    pub fn burn(&mut self, token_id: u64, owner: &[u8; 32]) -> Result<()> {
        let current_owner = self
            .owners
            .get(&token_id)
            .ok_or_else(|| anyhow!("Token {} does not exist", token_id))?;

        if current_owner != owner {
            return Err(anyhow!("Only the owner can burn token {}", token_id));
        }

        self.owners.remove(&token_id);
        self.metadata.remove(&token_id);
        Ok(())
    }

    /// Get the owner of a token.
    pub fn owner_of(&self, token_id: u64) -> Option<&[u8; 32]> {
        self.owners.get(&token_id)
    }

    /// List all token IDs owned by a wallet.
    pub fn tokens_of(&self, wallet_id: &[u8; 32]) -> Vec<u64> {
        self.owners
            .iter()
            .filter(|(_, owner)| *owner == wallet_id)
            .map(|(id, _)| *id)
            .collect()
    }

    /// Get metadata for a token.
    pub fn metadata_of(&self, token_id: u64) -> Option<&NftMetadata> {
        self.metadata.get(&token_id)
    }

    /// Total tokens currently in existence (minted minus burned).
    pub fn total_supply(&self) -> u64 {
        self.owners.len() as u64
    }

    /// Iterator over all tokens with their owners.
    pub fn all_tokens(&self) -> impl Iterator<Item = (u64, &[u8; 32], Option<&NftMetadata>)> {
        self.owners
            .iter()
            .map(move |(id, owner)| (*id, owner, self.metadata.get(id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_collection() -> NftContract {
        NftContract::new(
            [1u8; 32],
            "Test Art".to_string(),
            "ART".to_string(),
            "did:zhtp:creator".to_string(),
            [2u8; 32],
            Some(10),
            1000,
        )
    }

    #[test]
    fn test_mint() {
        let mut col = test_collection();
        let meta = NftMetadata {
            name: "Piece #1".to_string(),
            description: "First piece".to_string(),
            image_cid: "Qm123".to_string(),
            attributes: vec![("color".to_string(), "blue".to_string())],
            creator_did: "did:zhtp:creator".to_string(),
            created_at: 1000,
        };
        let id = col.mint(&[2u8; 32], [3u8; 32], meta).unwrap();
        assert_eq!(id, 1);
        assert_eq!(col.total_minted, 1);
        assert_eq!(col.owner_of(1), Some(&[3u8; 32]));
    }

    #[test]
    fn test_mint_unauthorized() {
        let mut col = test_collection();
        let meta = NftMetadata {
            name: "x".to_string(),
            description: "x".to_string(),
            image_cid: "x".to_string(),
            attributes: vec![],
            creator_did: "x".to_string(),
            created_at: 0,
        };
        assert!(col.mint(&[99u8; 32], [3u8; 32], meta).is_err());
    }

    #[test]
    fn test_max_supply() {
        let mut col = NftContract::new(
            [1u8; 32], "T".into(), "T".into(),
            "d".into(), [2u8; 32], Some(1), 0,
        );
        let meta = || NftMetadata {
            name: "x".into(), description: "x".into(), image_cid: "x".into(),
            attributes: vec![], creator_did: "x".into(), created_at: 0,
        };
        col.mint(&[2u8; 32], [3u8; 32], meta()).unwrap();
        assert!(col.mint(&[2u8; 32], [3u8; 32], meta()).is_err());
    }

    #[test]
    fn test_transfer() {
        let mut col = test_collection();
        let meta = NftMetadata {
            name: "x".into(), description: "x".into(), image_cid: "x".into(),
            attributes: vec![], creator_did: "x".into(), created_at: 0,
        };
        col.mint(&[2u8; 32], [3u8; 32], meta).unwrap();
        col.transfer(1, &[3u8; 32], [4u8; 32]).unwrap();
        assert_eq!(col.owner_of(1), Some(&[4u8; 32]));
    }

    #[test]
    fn test_transfer_not_owner() {
        let mut col = test_collection();
        let meta = NftMetadata {
            name: "x".into(), description: "x".into(), image_cid: "x".into(),
            attributes: vec![], creator_did: "x".into(), created_at: 0,
        };
        col.mint(&[2u8; 32], [3u8; 32], meta).unwrap();
        assert!(col.transfer(1, &[99u8; 32], [4u8; 32]).is_err());
    }

    #[test]
    fn test_burn() {
        let mut col = test_collection();
        let meta = NftMetadata {
            name: "x".into(), description: "x".into(), image_cid: "x".into(),
            attributes: vec![], creator_did: "x".into(), created_at: 0,
        };
        col.mint(&[2u8; 32], [3u8; 32], meta).unwrap();
        col.burn(1, &[3u8; 32]).unwrap();
        assert_eq!(col.owner_of(1), None);
        assert_eq!(col.total_supply(), 0);
        assert_eq!(col.total_minted, 1); // lifetime counter doesn't decrease
    }

    #[test]
    fn test_tokens_of() {
        let mut col = test_collection();
        let meta = || NftMetadata {
            name: "x".into(), description: "x".into(), image_cid: "x".into(),
            attributes: vec![], creator_did: "x".into(), created_at: 0,
        };
        col.mint(&[2u8; 32], [3u8; 32], meta()).unwrap();
        col.mint(&[2u8; 32], [4u8; 32], meta()).unwrap();
        col.mint(&[2u8; 32], [3u8; 32], meta()).unwrap();
        let owned = col.tokens_of(&[3u8; 32]);
        assert_eq!(owned.len(), 2);
        assert!(owned.contains(&1));
        assert!(owned.contains(&3));
    }
}
