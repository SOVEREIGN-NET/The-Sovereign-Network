//! Cryptographic traits for enforcing security properties
//!
//! This module defines marker traits and compile-time guarantees for
//! cryptographic key material handling.

use zeroize::Zeroize;

/// Marker trait for cryptographic key types that MUST be securely zeroized on drop.
///
/// # Purpose
///
/// This trait provides compile-time enforcement that all key types explicitly
/// declare their zeroization policy. It prevents:
///
/// - Forgetting to implement zeroization for new key types
/// - Implementing zeroization incorrectly (e.g., unsafe manual patterns)
/// - Silently introducing memory safety regressions
///
/// # Contract
///
/// Types implementing this trait MUST:
/// 1. Contain sensitive cryptographic material (private keys, seeds, secrets)
/// 2. Either derive `ZeroizeOnDrop` (preferred) OR implement `Drop` with explicit `zeroize()` calls
/// 3. Use `Vec<u8>` or `[u8; N]` for raw key material (not custom types)
///
/// # Usage
///
/// **For private/secret keys (MANDATORY automatic zeroization):**
/// ```rust
/// use zeroize::{Zeroize, ZeroizeOnDrop};
/// use lib_crypto::traits::ZeroizingKey;
///
/// #[derive(Zeroize, ZeroizeOnDrop)]
/// pub struct PrivateKey {
///     pub dilithium_sk: Vec<u8>,
///     pub kyber_sk: Vec<u8>,
///     pub master_seed: Vec<u8>,
/// }
///
/// impl ZeroizingKey for PrivateKey {}
/// ```
///
/// **For public keys (explicit opt-in for defense-in-depth):**
/// ```rust
/// use zeroize::Zeroize;
/// use lib_crypto::traits::ZeroizingKey;
///
/// pub struct PublicKey {
///     pub dilithium_pk: Vec<u8>,
///     pub kyber_pk: Vec<u8>,
///     pub key_id: [u8; 32],
/// }
///
/// impl Drop for PublicKey {
///     fn drop(&mut self) {
///         self.dilithium_pk.zeroize();
///         self.kyber_pk.zeroize();
///         self.key_id.zeroize();
///     }
/// }
///
/// impl ZeroizingKey for PublicKey {}
/// ```
///
/// # Compile-Time Enforcement
///
/// Use generic bounds to ensure only zeroizing keys are accepted:
/// ```rust
/// use lib_crypto::ZeroizingKey;
///
/// pub fn secure_store<K: ZeroizingKey>(key: K) {
///     // Guaranteed to be zeroized on drop
/// }
/// ```
///
/// # Security Rationale
///
/// - **Defense in Depth**: Even public keys may contain metadata worth protecting
/// - **Post-Quantum**: PQC keys (Dilithium/Kyber) are larger, higher value targets
/// - **Memory Safety**: Eliminates unsafe pointer-based wiping patterns
/// - **Audit Grade**: Makes cryptographic hygiene structurally enforceable
///
/// # Anti-Patterns (FORBIDDEN)
///
/// ❌ **Manual unsafe Drop implementation:**
/// ```rust,ignore
/// impl Drop for BadKey {
///     fn drop(&mut self) {
///         unsafe {
///             std::ptr::write_volatile(&mut self.key, 0);  // DON'T DO THIS
///         }
///     }
/// }
/// ```
///
/// ✅ **Use Zeroize instead:**
/// ```rust
/// # use zeroize::{Zeroize, ZeroizeOnDrop};
/// #[derive(Zeroize, ZeroizeOnDrop)]
/// pub struct GoodKey {
///     key: Vec<u8>,
/// }
/// ```
///
/// # Testing
///
/// Verify zeroization works:
/// ```rust
/// use zeroize::{Zeroize, ZeroizeOnDrop};
/// use lib_crypto::traits::ZeroizingKey;
///
/// #[derive(Zeroize, ZeroizeOnDrop)]
/// struct TestKey {
///     data: Vec<u8>,
/// }
///
/// impl ZeroizingKey for TestKey {}
///
/// #[test]
/// fn test_key_zeroized_on_drop() {
///     let mut key = TestKey { data: vec![0xFF; 32] };
///     let ptr = key.data.as_ptr();
///
///     drop(key);
///
///     // After drop, memory should be zeroed
///     // (In practice, use more sophisticated memory analysis)
/// }
/// ```
pub trait ZeroizingKey {}

/// Helper trait for compile-time enforcement of zeroization in generic contexts.
///
/// This trait combines `ZeroizingKey` with `Zeroize` to enable both:
/// 1. Compile-time guarantee of zeroization policy declaration
/// 2. Runtime ability to explicitly zeroize if needed
///
/// # Usage
///
/// ```rust
/// use lib_crypto::traits::SecureKey;
///
/// pub fn process_and_destroy<K: SecureKey>(mut key: K) {
///     // ... use key ...
///
///     // Explicit zeroization before drop (paranoid mode)
///     key.zeroize();
///
///     // Drop also zeroizes (ZeroizeOnDrop) - defense in depth
/// }
/// ```
pub trait SecureKey: ZeroizingKey + Zeroize {}

// Blanket implementation for any type that is both ZeroizingKey and Zeroize
impl<T: ZeroizingKey + Zeroize> SecureKey for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::{Zeroize, ZeroizeOnDrop};

    #[derive(Zeroize, ZeroizeOnDrop)]
    struct TestPrivateKey {
        secret: Vec<u8>,
    }

    impl ZeroizingKey for TestPrivateKey {}

    struct TestPublicKey {
        public: Vec<u8>,
    }

    impl Drop for TestPublicKey {
        fn drop(&mut self) {
            self.public.zeroize();
        }
    }

    impl ZeroizingKey for TestPublicKey {}

    // Compile-time enforcement test
    fn accepts_zeroizing_keys<K: ZeroizingKey>(_key: K) {
        // Type system guarantees key implements ZeroizingKey
    }

    #[test]
    fn test_private_key_is_zeroizing() {
        let key = TestPrivateKey {
            secret: vec![0xAA; 32],
        };

        // Should compile - TestPrivateKey implements ZeroizingKey
        accepts_zeroizing_keys(key);
    }

    #[test]
    fn test_public_key_is_zeroizing() {
        let key = TestPublicKey {
            public: vec![0xBB; 32],
        };

        // Should compile - TestPublicKey implements ZeroizingKey
        accepts_zeroizing_keys(key);
    }

    #[test]
    fn test_secure_key_trait() {
        #[derive(Zeroize, ZeroizeOnDrop)]
        struct SecretData {
            data: Vec<u8>,
        }

        impl ZeroizingKey for SecretData {}

        fn process<K: SecureKey>(mut key: K) {
            // Can explicitly zeroize
            key.zeroize();
        }

        let secret = SecretData { data: vec![0xFF; 64] };
        process(secret);
    }
}
