//! Development mode signature handling - for browser integration only
//!
//! DEVELOPMENT MODE IS NOT AVAILABLE IN PRODUCTION BUILD
//! These functions are only enabled when the "development" feature flag is active.
//! In production builds, all signatures MUST use Dilithium2 (CONSENSUS_SIGNATURE_SCHEME).

#[cfg(feature = "development")]
pub mod development {
    /// Check if signature is in development mode format
    pub fn is_development_signature(signature: &[u8]) -> bool {
        if signature.len() < 64 {
            let sig_str = String::from_utf8_lossy(signature);
            return sig_str.starts_with("1234")
                || sig_str.contains("test")
                || sig_str.contains("dev")
                || sig_str.contains("mock")
                || signature.len() < 16;
        }

        // Check for browser-generated development signatures (hex format)
        if signature.len() > 100 && signature.len() < 5000 {
            let sig_str = String::from_utf8_lossy(signature);
            if sig_str.chars().all(|c| c.is_ascii_hexdigit()) && signature.len() >= 1000 {
                return true;
            }
        }

        false
    }

    /// Check if public key is in development mode format
    pub fn is_development_public_key(public_key: &[u8]) -> bool {
        let pk_str = String::from_utf8_lossy(public_key);
        pk_str.starts_with("abcdef")
            || pk_str.starts_with("dilithium")
            || pk_str.contains("_pub_")
            || pk_str.contains("_priv_")
    }

    /// Accept development mode signatures for browser compatibility
    /// ONLY AVAILABLE IN DEVELOPMENT BUILDS
    pub fn accept_development_signature() -> bool {
        true
    }
}

#[cfg(not(feature = "development"))]
pub mod development {
    /// Check if signature is in development mode format
    /// Always returns false in production builds
    pub fn is_development_signature(_signature: &[u8]) -> bool {
        false
    }

    /// Check if public key is in development mode format
    /// Always returns false in production builds
    pub fn is_development_public_key(_public_key: &[u8]) -> bool {
        false
    }

    /// Accept development mode signatures for browser compatibility
    /// Always returns false in production builds - development signatures are rejected
    pub fn accept_development_signature() -> bool {
        false
    }
}
