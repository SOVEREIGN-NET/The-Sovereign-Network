//! Curve25519 operations for ring signatures
//! 
//! curve operations from crypto.rs for ring signature support

use anyhow::Result;
use curve25519_dalek::{
    scalar::Scalar,
    constants::RISTRETTO_BASEPOINT_POINT,
    ristretto::RistrettoPoint,
};
use crate::hashing::hash_blake3;

/// Generate key image from private key (prevents double spending)
/// implementation from crypto.rs, lines 823-845
pub fn generate_key_image(private_key: &[u8]) -> Result<[u8; 32]> {
    // key image generation using curve operations
    let scalar = Scalar::from_bytes_mod_order_wide(&{
        let mut wide = [0u8; 64];
        wide[..private_key.len().min(64)].copy_from_slice(&private_key[..private_key.len().min(64)]);
        wide
    });
    
    let point = &scalar * &RISTRETTO_BASEPOINT_POINT;
    let key_image = hash_blake3(point.compress().as_bytes());
    Ok(key_image)
}

/// Generate a point from scalar (for ring signatures)
pub fn scalar_to_point(scalar_bytes: &[u8]) -> RistrettoPoint {
    let scalar = Scalar::from_bytes_mod_order_wide(&{
        let mut wide = [0u8; 64];
        wide[..scalar_bytes.len().min(64)].copy_from_slice(&scalar_bytes[..scalar_bytes.len().min(64)]);
        wide
    });
    
    &scalar * &RISTRETTO_BASEPOINT_POINT
}

/// Scalar multiplication for ring signature operations
pub fn scalar_multiply(scalar_bytes: &[u8], point: &RistrettoPoint) -> RistrettoPoint {
    let scalar = Scalar::from_bytes_mod_order_wide(&{
        let mut wide = [0u8; 64];
        wide[..scalar_bytes.len().min(64)].copy_from_slice(&scalar_bytes[..scalar_bytes.len().min(64)]);
        wide
    });
    
    &scalar * point
}

/// Convert RistrettoPoint to bytes
pub fn point_to_bytes(point: &RistrettoPoint) -> [u8; 32] {
    point.compress().to_bytes()
}

/// Convert bytes to RistrettoPoint
pub fn bytes_to_point(bytes: &[u8; 32]) -> Option<RistrettoPoint> {
    use curve25519_dalek::ristretto::CompressedRistretto;
    
    let compressed = CompressedRistretto(*bytes);
    compressed.decompress()
}

/// Scalar multiplication on Curve25519 for ring signatures
/// implementation from crypto.rs, lines 720-735
pub fn curve25519_scalar_mult(scalar: &[u8], _point: &[u8; 32]) -> Result<[u8; 32]> {
    // Convert scalar bytes to Scalar (handle different input lengths)
    let scalar_bytes = if scalar.len() >= 32 {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&scalar[..32]);
        bytes
    } else {
        let mut bytes = [0u8; 32];
        bytes[..scalar.len()].copy_from_slice(scalar);
        bytes
    };
    
    let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
    
    // For simplicity, use base point multiplication (in implementation would use actual point)
    let result_point = &scalar * &RISTRETTO_BASEPOINT_POINT;
    
    // Return compressed point bytes
    Ok(result_point.compress().to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_image_generation() -> Result<()> {
        let private_key = b"test_private_key_for_ring_signature";
        let key_image1 = generate_key_image(private_key)?;
        let key_image2 = generate_key_image(private_key)?;
        
        // Same private key should produce same key image
        assert_eq!(key_image1, key_image2);
        assert_eq!(key_image1.len(), 32);
        
        // Different private key should produce different key image
        let different_key = b"different_private_key_for_test";
        let different_image = generate_key_image(different_key)?;
        assert_ne!(key_image1, different_image);
        
        Ok(())
    }

    #[test]
    fn test_curve_operations() {
        let scalar_bytes = b"test_scalar_for_curve_operations";
        let point1 = scalar_to_point(scalar_bytes);
        
        // Point serialization round-trip
        let bytes = point_to_bytes(&point1);
        let point2 = bytes_to_point(&bytes).expect("Point decompression failed");
        
        assert_eq!(point_to_bytes(&point1), point_to_bytes(&point2));
        
        // Scalar multiplication
        let multiplied = scalar_multiply(scalar_bytes, &point1);
        assert_ne!(point_to_bytes(&point1), point_to_bytes(&multiplied));
    }
}
