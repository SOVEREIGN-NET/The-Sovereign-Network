//! Key ratchet for forward secrecy.
//!
//! Each message derives a unique key from a chain key. After derivation,
//! the old chain key is replaced — past message keys are unrecoverable.
//! Periodic Kyber re-encapsulation provides post-compromise security.

use serde::{Deserialize, Serialize};

/// Ratchet state for a messaging session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRatchet {
    /// Current chain key — derives message keys. Replaced after each message.
    chain_key: [u8; 32],
    /// Message counter within current epoch
    counter: u64,
    /// Ratchet epoch — increments on Kyber re-key
    epoch: u32,
}

/// A derived message key + nonce for encrypting/decrypting one message.
pub struct MessageKey {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub epoch: u32,
    pub counter: u64,
}

impl KeyRatchet {
    /// Create a new ratchet from a shared secret (from Kyber KEM).
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        // Derive initial chain key from shared secret
        let chain_key = lib_crypto::hash_blake3(
            &[shared_secret.as_slice(), b"zhtp-msg-chain-v1"].concat(),
        );
        Self {
            chain_key,
            counter: 0,
            epoch: 0,
        }
    }

    /// Derive the next message key. Advances the ratchet — old chain key is gone.
    pub fn next_message_key(&mut self) -> MessageKey {
        let counter = self.counter;
        let epoch = self.epoch;

        // Derive message key: BLAKE3(chain_key || "msg" || counter)
        let msg_key = lib_crypto::hash_blake3(
            &[
                &self.chain_key[..],
                b"msg",
                &counter.to_le_bytes(),
            ]
            .concat(),
        );

        // Derive nonce: first 12 bytes of BLAKE3(chain_key || "nonce" || counter)
        let nonce_full = lib_crypto::hash_blake3(
            &[
                &self.chain_key[..],
                b"nonce",
                &counter.to_le_bytes(),
            ]
            .concat(),
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        // Advance chain key — old key is gone (forward secrecy)
        self.chain_key = lib_crypto::hash_blake3(
            &[&self.chain_key[..], b"next", &counter.to_le_bytes()].concat(),
        );
        self.counter += 1;

        MessageKey {
            key: msg_key,
            nonce,
            epoch,
            counter,
        }
    }

    /// Derive a message key for a specific counter (for decryption of received messages).
    /// This is stateless — doesn't advance the ratchet.
    pub fn derive_key_at(chain_key: &[u8; 32], counter: u64) -> MessageKey {
        let msg_key = lib_crypto::hash_blake3(
            &[chain_key.as_slice(), b"msg", &counter.to_le_bytes()].concat(),
        );
        let nonce_full = lib_crypto::hash_blake3(
            &[chain_key.as_slice(), b"nonce", &counter.to_le_bytes()].concat(),
        );
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&nonce_full[..12]);

        MessageKey {
            key: msg_key,
            nonce,
            epoch: 0,
            counter,
        }
    }

    /// Mix in new keying material (from Kyber re-encapsulation).
    pub fn rekey(&mut self, new_secret: &[u8; 32]) {
        self.chain_key = lib_crypto::hash_blake3(
            &[&self.chain_key[..], &new_secret[..], b"rekey"].concat(),
        );
        self.epoch += 1;
        self.counter = 0;
    }

    pub fn epoch(&self) -> u32 {
        self.epoch
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }
}
