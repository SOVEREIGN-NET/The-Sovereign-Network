//! Cross-target identity derivation primitives.
//!
//! This crate is intentionally small and WASM/mobile-friendly.
//! It defines the canonical derivations for:
//! - Root Secret (RS) from a recovery entropy source (optional helper)
//! - Root Signing Key (Dilithium5) from RS via domain-separated HKDF
//! - DID anchored to the Root Signing public key
//! - Operational key binding payload + signature helpers
//!
//! Invariant:
//! - DID MUST be derived from the root signing public key.
//! - DID MUST NOT be a direct hash of raw seed/entropy material.

use anyhow::{anyhow, Result};
use crystals_dilithium::dilithium5::{Keypair as Dilithium5Keypair, PublicKey as Dilithium5PublicKey, SecretKey as Dilithium5SecretKey, SIGNBYTES};
use hkdf::Hkdf;
use sha3::{Sha3_256, Sha3_512};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DID_PREFIX: &str = "did:zhtp:";

// Domain separation labels. Changing any of these is a breaking identity change.
const INFO_ROOT_SECRET_V1: &[u8] = b"zhtp:root-secret:v1";
const INFO_ROOT_SIGNING_SEED_V1: &[u8] = b"zhtp:root-signing-seed:v1";
const INFO_OPKEY_BINDING_V1: &[u8] = b"zhtp:opkey-binding:v1";

/// 32-byte recovery entropy (typically encoded as a 24-word mnemonic elsewhere).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryEntropy32(pub [u8; 32]);

/// Root Secret (RS). High-entropy derivation root.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootSecret64(pub [u8; 64]);

/// Root signing keypair bytes (Dilithium5, crystals-dilithium encoding).
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RootSigningKeypair {
    pub public_key: Vec<u8>,  // 2592 bytes
    pub secret_key: Vec<u8>,  // 4864 bytes (crystals-dilithium)
}

impl RootSigningKeypair {
    pub fn from_root_secret(rs: &RootSecret64) -> Result<Self> {
        let seed = derive_root_signing_seed32(rs)?;
        let kp = Dilithium5Keypair::generate(Some(&seed));
        let pk = kp.public.to_bytes().to_vec();
        let sk = kp.secret.to_bytes().to_vec();
        Ok(Self { public_key: pk, secret_key: sk })
    }
}

/// Derive a 64-byte Root Secret (RS) from 32 bytes of recovery entropy using HKDF.
///
/// This allows keeping a 24-word mnemonic UX while having an RS that meets the ">=64 bytes" requirement.
pub fn derive_root_secret64_from_recovery_entropy(entropy: &RecoveryEntropy32) -> Result<RootSecret64> {
    let hk = Hkdf::<Sha3_512>::new(None, &entropy.0);
    let mut out = [0u8; 64];
    hk.expand(INFO_ROOT_SECRET_V1, &mut out)
        .map_err(|e| anyhow!("HKDF expand failed: {:?}", e))?;
    Ok(RootSecret64(out))
}

/// Derive the 32-byte seed used for deterministic Dilithium5 KeyGen from Root Secret.
pub fn derive_root_signing_seed32(rs: &RootSecret64) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha3_256>::new(None, &rs.0);
    let mut out = [0u8; 32];
    hk.expand(INFO_ROOT_SIGNING_SEED_V1, &mut out)
        .map_err(|e| anyhow!("HKDF expand failed: {:?}", e))?;
    Ok(out)
}

/// Derive the canonical DID from the root signing public key.
pub fn did_from_root_signing_public_key(dilithium_pk: &[u8]) -> String {
    let h = blake3::hash(dilithium_pk);
    format!("{}{}", DID_PREFIX, hex_lower(h.as_bytes()))
}

/// Build the operational key binding message to be signed by the active root signing key.
pub fn op_key_binding_message(
    did: &str,
    purpose: &str,
    algorithm: &str,
    op_public_key: &[u8],
    created_at_unix: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(
        INFO_OPKEY_BINDING_V1.len()
            + did.len()
            + purpose.len()
            + algorithm.len()
            + op_public_key.len()
            + 8
            + 5,
    );
    msg.extend_from_slice(INFO_OPKEY_BINDING_V1);
    msg.push(0);
    msg.extend_from_slice(did.as_bytes());
    msg.push(0);
    msg.extend_from_slice(purpose.as_bytes());
    msg.push(0);
    msg.extend_from_slice(algorithm.as_bytes());
    msg.push(0);
    msg.extend_from_slice(op_public_key);
    msg.push(0);
    msg.extend_from_slice(&created_at_unix.to_le_bytes());
    msg
}

pub fn sign_op_key_binding(message: &[u8], root_dilithium_sk: &[u8]) -> Result<Vec<u8>> {
    let sk = Dilithium5SecretKey::from_bytes(root_dilithium_sk);
    let sig = sk.sign(message);
    Ok(sig.to_vec())
}

pub fn verify_op_key_binding(message: &[u8], signature: &[u8], root_dilithium_pk: &[u8]) -> Result<bool> {
    if signature.len() != SIGNBYTES {
        return Ok(false);
    }
    let pk = Dilithium5PublicKey::from_bytes(root_dilithium_pk);
    let mut sig_arr = [0u8; SIGNBYTES];
    sig_arr.copy_from_slice(signature);
    Ok(pk.verify(message, &sig_arr))
}

/// Legacy-only helper: derive the legacy DID that was produced by directly using a 32-byte entropy
/// as Dilithium5 seed (no RS HKDF step).
///
/// This exists only to support "break" migrations where old identities must be located.
pub fn legacy_did_from_recovery_entropy(entropy: &RecoveryEntropy32) -> String {
    let kp = Dilithium5Keypair::generate(Some(&entropy.0));
    did_from_root_signing_public_key(&kp.public.to_bytes())
}

fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(LUT[(b >> 4) as usize] as char);
        s.push(LUT[(b & 0x0f) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_is_derived_from_root_pk_not_raw_entropy() {
        let entropy = RecoveryEntropy32([7u8; 32]);
        let rs = derive_root_secret64_from_recovery_entropy(&entropy).unwrap();
        let rsk = RootSigningKeypair::from_root_secret(&rs).unwrap();

        let did = did_from_root_signing_public_key(&rsk.public_key);
        let legacy_did = legacy_did_from_recovery_entropy(&entropy);

        assert_ne!(did, legacy_did, "Break mode: new DID must differ from legacy DID");
        assert!(did.starts_with(DID_PREFIX));
    }

    #[test]
    fn deterministic_root_keypair_from_rs() {
        let mut rs_bytes = [0u8; 64];
        rs_bytes[0] = 42;
        let rs = RootSecret64(rs_bytes);

        let k1 = RootSigningKeypair::from_root_secret(&rs).unwrap();
        let k2 = RootSigningKeypair::from_root_secret(&rs).unwrap();

        assert_eq!(k1.public_key, k2.public_key);
        assert_eq!(k1.secret_key, k2.secret_key);
    }

    #[test]
    fn op_key_binding_sign_verify_roundtrip() {
        let entropy = RecoveryEntropy32([9u8; 32]);
        let rs = derive_root_secret64_from_recovery_entropy(&entropy).unwrap();
        let rsk = RootSigningKeypair::from_root_secret(&rs).unwrap();
        let did = did_from_root_signing_public_key(&rsk.public_key);

        let op_pk = vec![1u8; 1568];
        let msg = op_key_binding_message(&did, "transport/kem", "kyber1024", &op_pk, 123);
        let sig = sign_op_key_binding(&msg, &rsk.secret_key).unwrap();
        assert!(verify_op_key_binding(&msg, &sig, &rsk.public_key).unwrap());
    }
}

