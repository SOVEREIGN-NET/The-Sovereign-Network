//! Key Encoding Helpers
//!
//! Key encoding is PROTOCOL. These functions define the canonical byte layout
//! for all storage keys. Never inline key construction in business logic.
//!
//! # Key Design Principles
//!
//! 1. **Deterministic** - Same input always produces same key
//! 2. **Sortable** - Keys sort in useful order (e.g., blocks by height)
//! 3. **Prefix-free** - No key is a prefix of another (enables range scans)
//! 4. **Compact** - Minimize storage overhead
//!
//! # Format Conventions
//!
//! - Heights are big-endian u64 (sorts numerically)
//! - Hashes are raw bytes (32 bytes)
//! - Composite keys use fixed-width fields (no delimiters needed)

use super::{Address, BlockHash, OutPoint, TokenId, TxHash};

// =============================================================================
// BLOCK KEYS
// =============================================================================

/// Key for blocks_by_height tree: height (8 bytes BE) → block_hash
///
/// Big-endian ensures numeric sort order.
#[inline]
pub fn block_height_key(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

/// Key for blocks_by_hash tree: block_hash (32 bytes) → block_bytes
#[inline]
pub fn block_hash_key(hash: &BlockHash) -> &[u8; 32] {
    hash.as_bytes()
}

// =============================================================================
// UTXO KEYS
// =============================================================================

/// Key for utxos tree: tx_hash (32 bytes) + output_index (4 bytes BE) → utxo_bytes
///
/// Layout: [tx_hash: 32][index: 4] = 36 bytes total
///
/// This allows range scans over all outputs of a transaction.
#[inline]
pub fn utxo_key(outpoint: &OutPoint) -> [u8; 36] {
    let mut key = [0u8; 36];
    key[..32].copy_from_slice(outpoint.tx.as_bytes());
    key[32..].copy_from_slice(&outpoint.index.to_be_bytes());
    key
}

/// Parse an outpoint from a UTXO key
#[inline]
pub fn parse_utxo_key(key: &[u8]) -> Option<OutPoint> {
    if key.len() != 36 {
        return None;
    }
    let mut tx_bytes = [0u8; 32];
    tx_bytes.copy_from_slice(&key[..32]);
    let index = u32::from_be_bytes([key[32], key[33], key[34], key[35]]);
    Some(OutPoint {
        tx: TxHash(tx_bytes),
        index,
    })
}

// =============================================================================
// ACCOUNT KEYS
// =============================================================================

/// Key for accounts tree: address (32 bytes) → account_bytes
#[inline]
pub fn account_key(addr: &Address) -> &[u8; 32] {
    addr.as_bytes()
}

// =============================================================================
// TOKEN BALANCE KEYS
// =============================================================================

/// Key for token_balances tree: token_id (32 bytes) + address (32 bytes) → balance
///
/// Layout: [token_id: 32][address: 32] = 64 bytes total
///
/// This allows:
/// - Range scan over all holders of a token (prefix = token_id)
/// - Point lookup for specific (token, address) pair
#[inline]
pub fn token_balance_key(token: &TokenId, addr: &Address) -> [u8; 64] {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(token.as_bytes());
    key[32..].copy_from_slice(addr.as_bytes());
    key
}

/// Parse token ID and address from a balance key
#[inline]
pub fn parse_token_balance_key(key: &[u8]) -> Option<(TokenId, Address)> {
    if key.len() != 64 {
        return None;
    }
    let mut token_bytes = [0u8; 32];
    let mut addr_bytes = [0u8; 32];
    token_bytes.copy_from_slice(&key[..32]);
    addr_bytes.copy_from_slice(&key[32..]);
    Some((TokenId(token_bytes), Address(addr_bytes)))
}

/// Get prefix for scanning all balances of a token
#[inline]
pub fn token_balances_prefix(token: &TokenId) -> [u8; 32] {
    *token.as_bytes()
}

// =============================================================================
// TOKEN CONTRACT KEYS
// =============================================================================

/// Key for token_contracts tree: token_id (32 bytes) → contract_bytes
#[inline]
pub fn token_contract_key(token: &TokenId) -> &[u8; 32] {
    token.as_bytes()
}

// =============================================================================
// IDENTITY KEYS
// =============================================================================
// CONSENSUS CORE SPEC: All keys are fixed-size [u8; 32] or [u8; 40].
// Callers MUST hash DID strings using `did_to_hash()` before calling these.
// =============================================================================

/// Key for identities tree: did_hash (32 bytes) → IdentityConsensus
///
/// The did_hash is blake3(did_string). Caller must hash first.
/// This function just returns the key for use in sled operations.
#[inline]
pub fn identity_key(did_hash: &[u8; 32]) -> &[u8; 32] {
    did_hash
}

/// Key for identity_by_owner index: owner address → did_hash
#[inline]
pub fn identity_by_owner_key(addr: &Address) -> &[u8; 32] {
    addr.as_bytes()
}

/// Key for identity lookup by registration height
///
/// Layout: [height: 8 bytes BE][did_hash: 32 bytes] = 40 bytes total
///
/// This allows range scans over identities registered at a specific height.
#[inline]
pub fn identity_by_height_key(height: u64, did_hash: &[u8; 32]) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&height.to_be_bytes());
    key[8..].copy_from_slice(did_hash);
    key
}

/// Get prefix for scanning all identities at a height
#[inline]
pub fn identity_height_prefix(height: u64) -> [u8; 8] {
    height.to_be_bytes()
}

/// Parse did_hash from an identity_by_height key
#[inline]
pub fn parse_identity_by_height_key(key: &[u8]) -> Option<(u64, [u8; 32])> {
    if key.len() != 40 {
        return None;
    }
    let height = u64::from_be_bytes([key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7]]);
    let mut did_hash = [0u8; 32];
    did_hash.copy_from_slice(&key[8..40]);
    Some((height, did_hash))
}

// =============================================================================
// META KEYS
// =============================================================================

/// Well-known meta keys
pub mod meta {
    /// Key for latest block height
    pub const LATEST_HEIGHT: &[u8] = b"latest_height";

    /// Key for genesis block hash
    pub const GENESIS_HASH: &[u8] = b"genesis_hash";

    /// Key for chain ID
    pub const CHAIN_ID: &[u8] = b"chain_id";
}

// =============================================================================
// TESTS
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_height_key_ordering() {
        // Keys should sort in ascending height order
        let k0 = block_height_key(0);
        let k1 = block_height_key(1);
        let k100 = block_height_key(100);
        let kmax = block_height_key(u64::MAX);

        assert!(k0 < k1);
        assert!(k1 < k100);
        assert!(k100 < kmax);
    }

    #[test]
    fn test_utxo_key_roundtrip() {
        let outpoint = OutPoint {
            tx: TxHash([0xab; 32]),
            index: 42,
        };
        let key = utxo_key(&outpoint);
        let parsed = parse_utxo_key(&key).unwrap();

        assert_eq!(parsed.tx, outpoint.tx);
        assert_eq!(parsed.index, outpoint.index);
    }

    #[test]
    fn test_utxo_key_length() {
        let outpoint = OutPoint {
            tx: TxHash([0; 32]),
            index: 0,
        };
        assert_eq!(utxo_key(&outpoint).len(), 36);
    }

    #[test]
    fn test_token_balance_key_roundtrip() {
        let token = TokenId([0xcd; 32]);
        let addr = Address([0xef; 32]);
        let key = token_balance_key(&token, &addr);
        let (parsed_token, parsed_addr) = parse_token_balance_key(&key).unwrap();

        assert_eq!(parsed_token, token);
        assert_eq!(parsed_addr, addr);
    }

    #[test]
    fn test_token_balance_key_length() {
        let key = token_balance_key(&TokenId::NATIVE, &Address::ZERO);
        assert_eq!(key.len(), 64);
    }

    #[test]
    fn test_token_balances_prefix() {
        let token = TokenId([0x11; 32]);
        let addr1 = Address([0x22; 32]);
        let addr2 = Address([0x33; 32]);

        let key1 = token_balance_key(&token, &addr1);
        let key2 = token_balance_key(&token, &addr2);
        let prefix = token_balances_prefix(&token);

        // Both keys should start with the token prefix
        assert!(key1.starts_with(&prefix));
        assert!(key2.starts_with(&prefix));
    }

    #[test]
    fn test_token_contract_key() {
        let token = TokenId([0xab; 32]);
        let key = token_contract_key(&token);
        assert_eq!(key.len(), 32);
        assert_eq!(key, token.as_bytes());
    }

    #[test]
    fn test_parse_invalid_keys() {
        assert!(parse_utxo_key(&[0; 35]).is_none()); // too short
        assert!(parse_utxo_key(&[0; 37]).is_none()); // too long
        assert!(parse_token_balance_key(&[0; 63]).is_none()); // too short
        assert!(parse_token_balance_key(&[0; 65]).is_none()); // too long
    }

    /// Helper to hash a DID string (simulates did_to_hash from mod.rs)
    fn hash_did(did: &str) -> [u8; 32] {
        blake3::hash(did.as_bytes()).into()
    }

    #[test]
    fn test_identity_key_deterministic() {
        let did = "did:zhtp:abc123def456";
        let did_hash = hash_did(did);
        let key1 = identity_key(&did_hash);
        let key2 = identity_key(&did_hash);
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_identity_key_unique() {
        let hash1 = hash_did("did:zhtp:abc123");
        let hash2 = hash_did("did:zhtp:def456");
        let key1 = identity_key(&hash1);
        let key2 = identity_key(&hash2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_identity_by_height_key() {
        let did_hash = hash_did("did:zhtp:test");
        let key = identity_by_height_key(100, &did_hash);
        assert_eq!(key.len(), 40);

        // First 8 bytes should be height in BE
        assert_eq!(&key[..8], &100u64.to_be_bytes());

        // Last 32 bytes should be DID hash
        assert_eq!(&key[8..], &did_hash);
    }

    #[test]
    fn test_identity_by_height_key_roundtrip() {
        let did_hash = hash_did("did:zhtp:roundtrip");
        let height = 12345u64;
        let key = identity_by_height_key(height, &did_hash);

        let (parsed_height, parsed_hash) = parse_identity_by_height_key(&key).unwrap();
        assert_eq!(parsed_height, height);
        assert_eq!(parsed_hash, did_hash);
    }

    #[test]
    fn test_identity_height_prefix() {
        let prefix = identity_height_prefix(100);
        let hash_a = hash_did("did:zhtp:a");
        let hash_b = hash_did("did:zhtp:b");
        let key1 = identity_by_height_key(100, &hash_a);
        let key2 = identity_by_height_key(100, &hash_b);
        let key3 = identity_by_height_key(101, &hash_a);

        assert!(key1.starts_with(&prefix));
        assert!(key2.starts_with(&prefix));
        assert!(!key3.starts_with(&prefix));
    }
}
