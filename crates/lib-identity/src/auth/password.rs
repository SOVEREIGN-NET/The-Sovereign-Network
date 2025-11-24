//! Password management using lib-crypto hashing and key derivation
//! 
//! Only allows password authentication for identities that have been imported
//! using 20-word seed phrases. Passwords are derived from identity seeds.

use anyhow::Result;
use lib_crypto::{hash_blake3, derive_keys};
use crate::types::IdentityId;
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub enum PasswordError {
    IdentityNotImported,
    InvalidPassword,
    PasswordNotSet,
    WeakPassword,
    TooShort,
    TooLong,
    NoUppercase,
    NoLowercase,
    NoDigit,
    NoSpecialChar,
    ContainsSpaces,
    CommonPassword,
    SameAsOldPassword,
}

impl std::fmt::Display for PasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PasswordError::IdentityNotImported => write!(f, "Identity must be imported via 20-word phrase before setting password"),
            PasswordError::InvalidPassword => write!(f, "Invalid password"),
            PasswordError::PasswordNotSet => write!(f, "No password set for this identity"),
            PasswordError::WeakPassword => write!(f, "Password does not meet security requirements"),
            PasswordError::TooShort => write!(f, "Password too short - minimum 8 characters required"),
            PasswordError::TooLong => write!(f, "Password too long - maximum 128 characters allowed"),
            PasswordError::NoUppercase => write!(f, "Password must contain at least one uppercase letter (A-Z)"),
            PasswordError::NoLowercase => write!(f, "Password must contain at least one lowercase letter (a-z)"),
            PasswordError::NoDigit => write!(f, "Password must contain at least one digit (0-9)"),
            PasswordError::NoSpecialChar => write!(f, "Password must contain at least one special character (!@#$%^&*()_+-=[]{{}};:,.<>?)"),
            PasswordError::ContainsSpaces => write!(f, "Password cannot contain spaces"),
            PasswordError::CommonPassword => write!(f, "Password is too common - please choose a more unique password"),
            PasswordError::SameAsOldPassword => write!(f, "New password must be different from old password"),
        }
    }
}

impl std::error::Error for PasswordError {}

/// Password validation result
#[derive(Debug, Clone)]
pub struct PasswordValidation {
    pub valid: bool,
    pub identity_id: IdentityId,
    pub validated_at: u64,
}

/// Password strength score (0-100)
#[derive(Debug, Clone)]
pub struct PasswordStrength {
    pub score: u8,  // 0-100
    pub has_uppercase: bool,
    pub has_lowercase: bool,
    pub has_digit: bool,
    pub has_special: bool,
    pub length: usize,
    pub entropy: f64,
    pub is_common: bool,
}

impl PasswordStrength {
    /// Check if password meets minimum requirements
    pub fn meets_requirements(&self) -> bool {
        self.score >= 60 && 
        self.has_uppercase && 
        self.has_lowercase && 
        self.has_digit && 
        self.has_special && 
        self.length >= 8 &&
        !self.is_common
    }

    /// Get strength level description
    pub fn level(&self) -> &'static str {
        match self.score {
            0..=20 => "Very Weak",
            21..=40 => "Weak",
            41..=60 => "Fair",
            61..=80 => "Strong",
            81..=100 => "Very Strong",
            _ => "Unknown",
        }
    }
}

/// Secure password hash with salt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct PasswordHash {
    pub hash: [u8; 32],
    pub salt: [u8; 32],
    pub created_at: u64,
}

/// Password authentication for identities
#[derive(Debug)]
pub struct IdentityPasswordAuth {
    /// Password hashes for imported identities only
    password_hashes: HashMap<IdentityId, PasswordHash>,
    /// Track which identities have been imported (from seed phrases)
    imported_identities: HashMap<IdentityId, u64>, // identity_id -> import_timestamp
}

impl IdentityPasswordAuth {
    pub fn new() -> Self {
        Self {
            password_hashes: HashMap::new(),
            imported_identities: HashMap::new(),
        }
    }

    /// Validate password strength and requirements
    pub fn validate_password_strength(password: &str) -> Result<PasswordStrength, PasswordError> {
        let length = password.len();
        
        // Check length constraints
        if length < 8 {
            return Err(PasswordError::TooShort);
        }
        if length > 128 {
            return Err(PasswordError::TooLong);
        }
        
        // Check for spaces
        if password.contains(' ') {
            return Err(PasswordError::ContainsSpaces);
        }
        
        // Check character requirements
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        let has_special = password.chars().any(|c| {
            "!@#$%^&*()_+-=[]{}|;:,.<>?/~`".contains(c)
        });
        
        if !has_uppercase {
            return Err(PasswordError::NoUppercase);
        }
        if !has_lowercase {
            return Err(PasswordError::NoLowercase);
        }
        if !has_digit {
            return Err(PasswordError::NoDigit);
        }
        if !has_special {
            return Err(PasswordError::NoSpecialChar);
        }
        
        // Check against common passwords
        let is_common = Self::is_common_password(password);
        if is_common {
            return Err(PasswordError::CommonPassword);
        }
        
        // Calculate entropy (bits)
        let charset_size = 
            (if has_uppercase { 26 } else { 0 }) +
            (if has_lowercase { 26 } else { 0 }) +
            (if has_digit { 10 } else { 0 }) +
            (if has_special { 32 } else { 0 });
        
        let entropy = (length as f64) * (charset_size as f64).log2();
        
        // Calculate score (0-100)
        let mut score = 0u8;
        
        // Length score (0-30 points)
        score += match length {
            8..=11 => 10,
            12..=15 => 20,
            16.. => 30,
            _ => 0,
        };
        
        // Character diversity score (40 points total)
        if has_uppercase { score += 10; }
        if has_lowercase { score += 10; }
        if has_digit { score += 10; }
        if has_special { score += 10; }
        
        // Entropy bonus (0-20 points)
        score += match entropy as u32 {
            0..=40 => 0,
            41..=60 => 10,
            61.. => 20,
        };
        
        // Pattern detection penalty
        if Self::has_common_patterns(password) {
            score = score.saturating_sub(20);
        }
        
        // Sequential characters penalty
        if Self::has_sequential_chars(password) {
            score = score.saturating_sub(10);
        }
        
        Ok(PasswordStrength {
            score,
            has_uppercase,
            has_lowercase,
            has_digit,
            has_special,
            length,
            entropy,
            is_common,
        })
    }

    /// Check if password is in common password list
    fn is_common_password(password: &str) -> bool {
        // List of most common passwords to reject
        const COMMON_PASSWORDS: &[&str] = &[
            "password", "Password1", "Password123", "12345678", "password1",
            "123456789", "12345678910", "qwerty", "Qwerty123", "abc123",
            "password!", "Password!", "letmein", "welcome", "Welcome1",
            "admin", "Admin123", "root", "toor", "pass", "Pass123",
            "test", "Test123", "user", "User123", "guest", "Guest123",
            "changeme", "Changeme1", "default", "Default1",
        ];
        
        let lower = password.to_lowercase();
        COMMON_PASSWORDS.iter().any(|&common| {
            password == common || lower == common.to_lowercase()
        })
    }

    /// Check for common patterns
    fn has_common_patterns(password: &str) -> bool {
        // Check for keyboard patterns
        let keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "123456", "abcdef"];
        let lower = password.to_lowercase();
        
        keyboard_patterns.iter().any(|&pattern| lower.contains(pattern))
    }

    /// Check for sequential characters
    fn has_sequential_chars(password: &str) -> bool {
        let chars: Vec<char> = password.chars().collect();
        if chars.len() < 3 {
            return false;
        }
        
        for window in chars.windows(3) {
            // Check for sequential ascending
            if let (Some(a), Some(b), Some(c)) = (
                window[0].to_digit(36),
                window[1].to_digit(36),
                window[2].to_digit(36),
            ) {
                if b == a + 1 && c == b + 1 {
                    return true;
                }
                if b == a.wrapping_sub(1) && c == b.wrapping_sub(1) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Mark an identity as imported (can set password after this)
    pub fn mark_identity_imported(&mut self, identity_id: &IdentityId) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        self.imported_identities.insert(identity_id.clone(), timestamp);
        
        tracing::info!(
            " Identity {} marked as imported - can now set password",
            hex::encode(&identity_id.0[..8])
        );
    }

    /// Check if identity has been imported
    pub fn is_identity_imported(&self, identity_id: &IdentityId) -> bool {
        self.imported_identities.contains_key(identity_id)
    }

    /// Set password for an imported identity
    pub fn set_password(&mut self, identity_id: &IdentityId, password: &str, identity_seed: &[u8]) -> Result<(), PasswordError> {
        // Check if identity is imported
        if !self.is_identity_imported(identity_id) {
            return Err(PasswordError::IdentityNotImported);
        }

        // Validate password strength
        let strength = Self::validate_password_strength(password)?;
        
        if !strength.meets_requirements() {
            return Err(PasswordError::WeakPassword);
        }

        // Generate salt using identity seed for consistency
        let salt_material = [
            identity_seed,
            identity_id.0.as_slice(),
            b"password_salt"
        ].concat();
        let salt = hash_blake3(&salt_material);

        // Derive password hash using HKDF with salt and identity context
        let password_key_material = [
            password.as_bytes(),
            &salt,
            identity_seed,
            identity_id.0.as_slice()
        ].concat();
        
        // Use HKDF to derive secure password hash
        let derived_key = derive_keys(
            &password_key_material,
            b"ZHTP_password_derivation_v1",
            32
        ).map_err(|_| PasswordError::WeakPassword)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&derived_key[..32]);

        let password_hash = PasswordHash {
            hash,
            salt,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.password_hashes.insert(identity_id.clone(), password_hash);

        tracing::info!(
            " Password set for identity {} (strength: {} - {})",
            hex::encode(&identity_id.0[..8]),
            strength.score,
            strength.level()
        );

        Ok(())
    }

    /// Validate password for an identity
    pub fn validate_password(&self, identity_id: &IdentityId, password: &str, identity_seed: &[u8]) -> Result<PasswordValidation, PasswordError> {
        // Check if identity is imported
        if !self.is_identity_imported(identity_id) {
            return Err(PasswordError::IdentityNotImported);
        }

        // Get stored password hash
        let stored_hash = self.password_hashes.get(identity_id)
            .ok_or(PasswordError::PasswordNotSet)?;

        // Recreate password hash using same process
        let password_key_material = [
            password.as_bytes(),
            &stored_hash.salt,
            identity_seed,
            identity_id.0.as_slice()
        ].concat();

        // Derive hash using same method
        let derived_key = derive_keys(
            &password_key_material,
            b"ZHTP_password_derivation_v1",
            32
        ).map_err(|_| PasswordError::InvalidPassword)?;

        let mut test_hash = [0u8; 32];
        test_hash.copy_from_slice(&derived_key[..32]);

        // Constant-time comparison
        let valid = constant_time_eq(&test_hash, &stored_hash.hash);

        if valid {
            tracing::info!(
                " Password validation successful for identity {}",
                hex::encode(&identity_id.0[..8])
            );
        } else {
            tracing::warn!(
                " Password validation failed for identity {}",
                hex::encode(&identity_id.0[..8])
            );
        }

        Ok(PasswordValidation {
            valid,
            identity_id: identity_id.clone(),
            validated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Check if password is set for an identity
    pub fn has_password(&self, identity_id: &IdentityId) -> bool {
        self.password_hashes.contains_key(identity_id)
    }

    /// Change password for an identity (requires old password verification)
    pub fn change_password(
        &mut self,
        identity_id: &IdentityId,
        old_password: &str,
        new_password: &str,
        identity_seed: &[u8]
    ) -> Result<(), PasswordError> {
        // Verify old password first
        let validation = self.validate_password(identity_id, old_password, identity_seed)?;
        if !validation.valid {
            return Err(PasswordError::InvalidPassword);
        }

        // Check that new password is different from old
        if old_password == new_password {
            return Err(PasswordError::SameAsOldPassword);
        }

        // Set new password (this validates strength)
        self.set_password(identity_id, new_password, identity_seed)?;

        tracing::info!(
            " Password changed for identity {}",
            hex::encode(&identity_id.0[..8])
        );

        Ok(())
    }

    /// Remove password for an identity
    pub fn remove_password(&mut self, identity_id: &IdentityId) -> bool {
        if let Some(mut hash) = self.password_hashes.remove(identity_id) {
            hash.zeroize();
            tracing::info!(
                "🗑️ Password removed for identity {}",
                hex::encode(&identity_id.0[..8])
            );
            true
        } else {
            false
        }
    }

    /// Get list of identities with passwords set
    pub fn list_identities_with_passwords(&self) -> Vec<&IdentityId> {
        self.password_hashes.keys().collect()
    }

    /// Get list of imported identities
    pub fn list_imported_identities(&self) -> Vec<&IdentityId> {
        self.imported_identities.keys().collect()
    }
}

/// Constant-time equality comparison to prevent timing attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

impl Default for IdentityPasswordAuth {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[test]
    fn test_password_manager_import_required() {
        let mut pm = IdentityPasswordAuth::new();
        let identity_id = Hash::from_bytes(&[1u8; 32]);
        let seed = [42u8; 32];
        
        // Should fail before import
        assert!(pm.set_password(&identity_id, "Test@Pass123", &seed).is_err());
        
        // Mark as imported
        pm.mark_identity_imported(&identity_id);
        
        // Should work after import
        assert!(pm.set_password(&identity_id, "Test@Pass123", &seed).is_ok());
    }

    #[test]
    fn test_password_validation() {
        let mut pm = IdentityPasswordAuth::new();
        let identity_id = Hash::from_bytes(&[2u8; 32]);
        let seed = [84u8; 32];
        let password = "Test@Password123";
        
        pm.mark_identity_imported(&identity_id);
        pm.set_password(&identity_id, password, &seed).unwrap();
        
        // Correct password
        let validation = pm.validate_password(&identity_id, password, &seed).unwrap();
        assert!(validation.valid);
        
        // Wrong password
        let validation = pm.validate_password(&identity_id, "Wrong@Pass123", &seed).unwrap();
        assert!(!validation.valid);
    }
}
