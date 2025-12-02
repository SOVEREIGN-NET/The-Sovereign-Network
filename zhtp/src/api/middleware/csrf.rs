//! CSRF Protection Middleware (P0-7)
//!
//! Implements Cross-Site Request Forgery protection using double-submit pattern
//! with cryptographic binding to session ID.

use std::sync::Arc;
use lib_crypto::hash_blake3;
use lib_protocols::types::{ZhtpRequest, ZhtpResponse, ZhtpStatus, ZhtpMethod};

/// CSRF protection using double-submit cookie pattern with session binding
#[derive(Clone)]
pub struct CsrfProtection {
    secret: Arc<[u8; 32]>,
}

impl CsrfProtection {
    /// Create a new CSRF protection instance with random secret
    pub fn new() -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);

        Self {
            secret: Arc::new(secret),
        }
    }

    /// Generate CSRF token for a session
    pub fn generate_token(&self, session_id: &str) -> String {
        let token_data = [session_id.as_bytes(), &*self.secret].concat();
        hex::encode(hash_blake3(&token_data))
    }

    /// Validate CSRF token against session ID
    pub fn validate_token(&self, session_id: &str, token: &str) -> bool {
        let expected = self.generate_token(session_id);
        // Constant-time comparison to prevent timing attacks
        constant_time_compare(&expected, token)
    }

    /// Check CSRF token for state-changing requests
    pub fn check_csrf(&self, request: &ZhtpRequest, session_id: &str) -> Result<(), ZhtpResponse> {
        // Only check POST/PUT/DELETE/PATCH (state-changing methods)
        match request.method {
            ZhtpMethod::Post | ZhtpMethod::Put | ZhtpMethod::Delete => {
                // Check X-CSRF-Token header
                if let Some(token) = request.headers.get("X-CSRF-Token") {
                    if self.validate_token(session_id, &token) {
                        Ok(())
                    } else {
                        Err(ZhtpResponse::error(
                            ZhtpStatus::Forbidden,
                            "Invalid CSRF token".to_string(),
                        ))
                    }
                } else {
                    Err(ZhtpResponse::error(
                        ZhtpStatus::Forbidden,
                        "Missing CSRF token".to_string(),
                    ))
                }
            }
            // GET and other safe methods don't require CSRF protection
            _ => Ok(()),
        }
    }
}

impl Default for CsrfProtection {
    fn default() -> Self {
        Self::new()
    }
}

/// Constant-time string comparison to prevent timing attacks
fn constant_time_compare(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result = 0u8;
    for (byte_a, byte_b) in a.bytes().zip(b.bytes()) {
        result |= byte_a ^ byte_b;
    }

    result == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_csrf_token_generation() {
        let csrf = CsrfProtection::new();
        let session_id = "test_session_123";

        let token1 = csrf.generate_token(session_id);
        let token2 = csrf.generate_token(session_id);

        // Same session should generate same token
        assert_eq!(token1, token2);
        assert_eq!(token1.len(), 64); // 32 bytes as hex
    }

    #[test]
    fn test_csrf_token_validation() {
        let csrf = CsrfProtection::new();
        let session_id = "test_session_123";

        let token = csrf.generate_token(session_id);

        // Valid token should validate
        assert!(csrf.validate_token(session_id, &token));

        // Invalid token should fail
        assert!(!csrf.validate_token(session_id, "invalid_token"));

        // Wrong session ID should fail
        assert!(!csrf.validate_token("different_session", &token));
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare("hello", "hello"));
        assert!(!constant_time_compare("hello", "world"));
        assert!(!constant_time_compare("hello", "hello!"));
        assert!(!constant_time_compare("hello!", "hello"));
    }
}
