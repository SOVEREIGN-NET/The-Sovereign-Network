//! HKDF key derivation - preserving ZHTP key derivation
//! 
//! implementation from crypto.rs, lines 710-717

use anyhow::Result;
use sha3::Sha3_256;
use hkdf::Hkdf;

/// Derive multiple keys from a master key using HKDF
pub fn derive_keys(master_key: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    let hk = Hkdf::<Sha3_256>::new(None, master_key);
    let mut output = vec![0u8; output_len];
    hk.expand(info, &mut output)
        .map_err(|_| anyhow::anyhow!("HKDF expansion failed"))?;
    Ok(output)
}

/// HKDF with SHA-3 (alias for derive_keys)
pub fn hkdf_sha3(master_key: &[u8], info: &[u8], output_len: usize) -> Result<Vec<u8>> {
    derive_keys(master_key, info, output_len)
}
