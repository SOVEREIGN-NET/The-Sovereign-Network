//! Canonical balance-key resolution for custom (non-SOV) tokens.
//!
//! BUBL and other custom tokens store balances under the holder's identity
//! `key_id` — `blake3(dilithium_pk || kyber_pk)`, the same 32 bytes in
//! `did:zhtp:{hex}`. Rewards mint to that key. SOV remains wallet_id-keyed elsewhere.

use lib_blockchain::{Blockchain, Hash};
use lib_crypto::types::keys::PublicKey;

fn is_zhtp_did(address: &str) -> bool {
    address.len() >= 9 && address[..9].eq_ignore_ascii_case("did:zhtp:")
}

fn strip_address_prefix(address: &str) -> &str {
    if is_zhtp_did(address) {
        &address[9..]
    } else if let Some(rest) = address.strip_prefix("0x") {
        rest
    } else {
        address
    }
}

fn dilithium_key_id(public_key_bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    let pk: [u8; 2592] = public_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("public_key must be 2592 bytes"))?;
    Ok(PublicKey::new(pk).key_id)
}

/// Resolve the sled `token_balances` key for a custom token holder.
///
/// Accepts `did:zhtp:{key_id}`, wallet_id hex, identity_id hex, or 2592-byte
/// dilithium public key hex. Wallet and identity identifiers map to the owner's
/// dilithium-derived `key_id`, not the raw wallet_id bytes.
pub fn resolve_custom_token_balance_key(
    blockchain: &Blockchain,
    address: &str,
) -> anyhow::Result<[u8; 32]> {
    let hex_part = strip_address_prefix(address);
    let bytes = hex::decode(hex_part).map_err(|_| anyhow::anyhow!("Invalid address hex"))?;

    if bytes.len() == 32 {
        // `did:zhtp:{key_id}` is already the sled balance key for custom tokens.
        // Do not remap through wallet projection — that derives blake3(dilithium)
        // only and diverges from TokenCreation/transfer keys when kyber is present.
        if is_zhtp_did(address) {
            let mut key_id = [0u8; 32];
            key_id.copy_from_slice(&bytes);
            return Ok(key_id);
        }

        let wallet_id_hex = hex::encode(&bytes);
        if let Some(wallet) = blockchain.wallet_transaction_data(&wallet_id_hex) {
            return dilithium_key_id(&wallet.public_key);
        }

        let identity_hash = Hash::from_slice(&bytes);
        if let Some((_, wallet)) = blockchain
            .wallet_registry_snapshot()
            .into_iter()
            .find(|(_, w)| w.owner_identity_id.as_ref() == Some(&identity_hash))
        {
            return dilithium_key_id(&wallet.public_key);
        }

        let mut key_id = [0u8; 32];
        key_id.copy_from_slice(&bytes);
        return Ok(key_id);
    }

    if bytes.len() == 2592 {
        return dilithium_key_id(&bytes);
    }

    anyhow::bail!(
        "Address must be did:zhtp, 32-byte wallet/key_id hex, or 2592-byte dilithium public key"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_blockchain::transaction::WalletTransactionData;

    fn test_wallet_data(wallet_id: [u8; 32], owner: [u8; 32]) -> WalletTransactionData {
        let mut dilithium_pk = [0u8; 2592];
        dilithium_pk[0] = 0xAB;
        WalletTransactionData {
            wallet_id: Hash::from_slice(&wallet_id),
            wallet_type: "Primary".to_string(),
            wallet_name: "Primary".to_string(),
            alias: None,
            public_key: dilithium_pk.to_vec(),
            owner_identity_id: Some(Hash::from_slice(&owner)),
            seed_commitment: Hash::default(),
            created_at: 0,
            registration_fee: 0,
            capabilities: 0,
            initial_balance: 0,
        }
    }

    #[test]
    fn did_zhtp_prefix_is_case_insensitive() {
        let key_id = [0x33u8; 32];
        let lower = format!("did:zhtp:{}", hex::encode(key_id));
        let mixed = format!("did:ZHTP:{}", hex::encode(key_id));
        let bc = lib_blockchain::Blockchain::new().expect("blockchain");
        let via_lower = resolve_custom_token_balance_key(&bc, &lower).expect("lower");
        let via_mixed = resolve_custom_token_balance_key(&bc, &mixed).expect("mixed");
        assert_eq!(via_lower, key_id);
        assert_eq!(via_mixed, key_id);
    }

    #[test]
    fn wallet_id_resolves_to_dilithium_key_id_not_raw_wallet_bytes() {
        let mut bc = lib_blockchain::Blockchain::new().expect("blockchain");
        let wallet_id = [0x11u8; 32];
        let owner_id = [0x22u8; 32];
        let wallet_hex = hex::encode(wallet_id);
        bc.register_wallet(test_wallet_data(wallet_id, owner_id))
            .expect("register wallet");

        let via_wallet = resolve_custom_token_balance_key(&bc, &wallet_hex).expect("wallet");
        let via_did = resolve_custom_token_balance_key(
            &bc,
            &format!("did:zhtp:{}", hex::encode(via_wallet)),
        )
        .expect("did");

        assert_ne!(via_wallet, wallet_id, "must not use raw wallet_id bytes");
        assert_eq!(via_wallet, via_did, "wallet_id and DID must agree");
    }
}