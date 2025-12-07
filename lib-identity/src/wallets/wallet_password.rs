//! Optional password protection for individual wallets
//! 
//! This provides an additional security layer where specific wallets
//! can require a password even if the user has signed into their DID.
//! This is useful for high-value wallets (savings, business, etc.)

use anyhow::Result;
use lib_crypto::{hash_blake3, derive_keys};
use crate::wallets::WalletId;
use std::collections::HashMap;
use zeroize::Zeroize;

#[derive(Debug, Clone)]
pub enum WalletPasswordError {
    WalletNotFound,
    InvalidPassword,
    PasswordNotSet,
    WeakPassword,
    PasswordAlreadySet,
    TooShort,
    TooLong,
    NoUppercase,
    NoLowercase,
    NoDigit,
    ContainsSpaces,
    CommonPassword,
    SameAsOldPassword,
}

impl std::fmt::Display for WalletPasswordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletPasswordError::WalletNotFound => write!(f, "Wallet not found"),
            WalletPasswordError::InvalidPassword => write!(f, "Invalid wallet password"),
            WalletPasswordError::PasswordNotSet => write!(f, "No password set for this wallet"),
            WalletPasswordError::WeakPassword => write!(f, "Wallet password does not meet security requirements"),
            WalletPasswordError::PasswordAlreadySet => write!(f, "Wallet already has a password set"),
            WalletPasswordError::TooShort => write!(f, "Wallet password too short - minimum 6 characters required"),
            WalletPasswordError::TooLong => write!(f, "Wallet password too long - maximum 128 characters allowed"),
            WalletPasswordError::NoUppercase => write!(f, "Wallet password must contain at least one uppercase letter (A-Z)"),
            WalletPasswordError::NoLowercase => write!(f, "Wallet password must contain at least one lowercase letter (a-z)"),
            WalletPasswordError::NoDigit => write!(f, "Wallet password must contain at least one digit (0-9)"),
            WalletPasswordError::ContainsSpaces => write!(f, "Wallet password cannot contain spaces"),
            WalletPasswordError::CommonPassword => write!(f, "Wallet password is too common - please choose a more unique password"),
            WalletPasswordError::SameAsOldPassword => write!(f, "New wallet password must be different from old password"),
        }
    }
}

impl std::error::Error for WalletPasswordError {}

/// Wallet password validation result
#[derive(Debug, Clone)]
pub struct WalletPasswordValidation {
    pub valid: bool,
    pub wallet_id: WalletId,
    pub validated_at: u64,
}

/// Secure wallet password hash with salt
#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct WalletPasswordHash {
    pub hash: [u8; 32],
    pub salt: [u8; 32],
    pub created_at: u64,
}

/// Wallet password manager - handles optional passwords for individual wallets
#[derive(Debug, Clone, Default)]
pub struct WalletPasswordManager {
    /// Password hashes for wallets that have passwords enabled
    password_hashes: HashMap<WalletId, WalletPasswordHash>,
}

impl WalletPasswordManager {
    pub fn new() -> Self {
        Self {
            password_hashes: HashMap::new(),
        }
    }

    /// Validate wallet password strength (slightly relaxed compared to DID passwords)
    fn validate_password_strength(password: &str) -> Result<(), WalletPasswordError> {
        let length = password.len();
        
        // Check length constraints (6 min for wallets vs 8 for DIDs)
        if length < 6 {
            return Err(WalletPasswordError::TooShort);
        }
        if length > 128 {
            return Err(WalletPasswordError::TooLong);
        }
        
        // Check for spaces
        if password.contains(' ') {
            return Err(WalletPasswordError::ContainsSpaces);
        }
        
        // Check character requirements
        let has_uppercase = password.chars().any(|c| c.is_uppercase());
        let has_lowercase = password.chars().any(|c| c.is_lowercase());
        let has_digit = password.chars().any(|c| c.is_numeric());
        
        if !has_uppercase {
            return Err(WalletPasswordError::NoUppercase);
        }
        if !has_lowercase {
            return Err(WalletPasswordError::NoLowercase);
        }
        if !has_digit {
            return Err(WalletPasswordError::NoDigit);
        }
        
        // Check against common passwords
        if Self::is_common_password(password) {
            return Err(WalletPasswordError::CommonPassword);
        }
        
        Ok(())
    }

    /// Check if password is in common password list
    fn is_common_password(password: &str) -> bool {
        const COMMON_PASSWORDS: &[&str] = &[
            "wallet", "Wallet1", "Wallet123", "123456", "wallet1",
            "password", "Password1", "123456789", "qwerty", "abc123",
            "savings", "Savings1", "money", "Money123", "cash",
        ];
        
        let lower = password.to_lowercase();
        COMMON_PASSWORDS.iter().any(|&common| {
            password == common || lower == common.to_lowercase()
        })
    }

    /// Set password for a wallet (must not already have one)
    pub fn set_wallet_password(
        &mut self,
        wallet_id: &WalletId,
        password: &str,
        wallet_seed: &[u8],
    ) -> Result<(), WalletPasswordError> {
        // Check if password already set
        if self.has_password(wallet_id) {
            return Err(WalletPasswordError::PasswordAlreadySet);
        }

        // Validate password strength
        Self::validate_password_strength(password)?;

        // Generate salt using wallet seed for consistency
        let salt_material = [
            wallet_seed,
            wallet_id.0.as_slice(),
            b"wallet_password_salt"
        ].concat();
        let salt = hash_blake3(&salt_material);

        // Derive password hash using HKDF
        let password_key_material = [
            password.as_bytes(),
            &salt,
            wallet_seed,
            wallet_id.0.as_slice()
        ].concat();
        
        let derived_key = derive_keys(
            &password_key_material,
            b"ZHTP_wallet_password_v1",
            32
        ).map_err(|_| WalletPasswordError::WeakPassword)?;

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&derived_key[..32]);

        let password_hash = WalletPasswordHash {
            hash,
            salt,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        self.password_hashes.insert(wallet_id.clone(), password_hash);

        tracing::info!(
            "🔐 Wallet password set for wallet {}",
            hex::encode(&wallet_id.0[..8])
        );

        Ok(())
    }

    /// Change wallet password (requires old password verification)
    pub fn change_wallet_password(
        &mut self,
        wallet_id: &WalletId,
        old_password: &str,
        new_password: &str,
        wallet_seed: &[u8],
    ) -> Result<(), WalletPasswordError> {
        // Verify old password first
        let validation = self.validate_password(wallet_id, old_password, wallet_seed)?;
        if !validation.valid {
            return Err(WalletPasswordError::InvalidPassword);
        }

        // Check that new password is different from old
        if old_password == new_password {
            return Err(WalletPasswordError::SameAsOldPassword);
        }

        // Remove old password
        self.password_hashes.remove(wallet_id);

        // Set new password (this validates strength)
        self.set_wallet_password(wallet_id, new_password, wallet_seed)?;

        tracing::info!(
            "🔄 Wallet password changed for wallet {}",
            hex::encode(&wallet_id.0[..8])
        );

        Ok(())
    }

    /// Remove wallet password (requires current password verification)
    pub fn remove_wallet_password(
        &mut self,
        wallet_id: &WalletId,
        current_password: &str,
        wallet_seed: &[u8],
    ) -> Result<(), WalletPasswordError> {
        // Verify current password first
        let validation = self.validate_password(wallet_id, current_password, wallet_seed)?;
        if !validation.valid {
            return Err(WalletPasswordError::InvalidPassword);
        }

        // Remove password
        if let Some(mut hash) = self.password_hashes.remove(wallet_id) {
            hash.zeroize();
            tracing::info!(
                "🔓 Wallet password removed for wallet {}",
                hex::encode(&wallet_id.0[..8])
            );
            Ok(())
        } else {
            Err(WalletPasswordError::PasswordNotSet)
        }
    }

    /// Validate wallet password
    pub fn validate_password(
        &self,
        wallet_id: &WalletId,
        password: &str,
        wallet_seed: &[u8],
    ) -> Result<WalletPasswordValidation, WalletPasswordError> {
        // Get stored password hash
        let stored_hash = self.password_hashes.get(wallet_id)
            .ok_or(WalletPasswordError::PasswordNotSet)?;

        // Recreate password hash using same process
        let password_key_material = [
            password.as_bytes(),
            &stored_hash.salt,
            wallet_seed,
            wallet_id.0.as_slice()
        ].concat();

        // Derive hash using same method
        let derived_key = derive_keys(
            &password_key_material,
            b"ZHTP_wallet_password_v1",
            32
        ).map_err(|_| WalletPasswordError::InvalidPassword)?;

        let mut test_hash = [0u8; 32];
        test_hash.copy_from_slice(&derived_key[..32]);

        // Constant-time comparison
        let valid = constant_time_eq(&test_hash, &stored_hash.hash);

        if valid {
            tracing::debug!(
                "✅ Wallet password validated for wallet {}",
                hex::encode(&wallet_id.0[..8])
            );
        } else {
            tracing::warn!(
                "❌ Wallet password validation failed for wallet {}",
                hex::encode(&wallet_id.0[..8])
            );
        }

        Ok(WalletPasswordValidation {
            valid,
            wallet_id: wallet_id.clone(),
            validated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Check if wallet has password set
    pub fn has_password(&self, wallet_id: &WalletId) -> bool {
        self.password_hashes.contains_key(wallet_id)
    }

    /// Get list of wallets with passwords
    pub fn list_password_protected_wallets(&self) -> Vec<&WalletId> {
        self.password_hashes.keys().collect()
    }

    /// Get count of password-protected wallets
    pub fn password_protected_count(&self) -> usize {
        self.password_hashes.len()
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

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::Hash;

    #[test]
    fn test_wallet_password_set_and_validate() {
        let mut wpm = WalletPasswordManager::new();
        let wallet_id = Hash::from_bytes(&[1u8; 32]);
        let wallet_seed = [42u8; 32];
        let password = "WalletPass123!";
        
        // Set password
        assert!(wpm.set_wallet_password(&wallet_id, password, &wallet_seed).is_ok());
        
        // Validate correct password
        let validation = wpm.validate_password(&wallet_id, password, &wallet_seed).unwrap();
        assert!(validation.valid);
        
        // Validate wrong password
        let validation = wpm.validate_password(&wallet_id, "wrong", &wallet_seed).unwrap();
        assert!(!validation.valid);
    }

    #[test]
    fn test_wallet_password_change() {
        let mut wpm = WalletPasswordManager::new();
        let wallet_id = Hash::from_bytes(&[2u8; 32]);
        let wallet_seed = [84u8; 32];
        
        // Set initial password
        wpm.set_wallet_password(&wallet_id, "OldPass123!", &wallet_seed).unwrap();

        // Change password
        assert!(wpm.change_wallet_password(&wallet_id, "OldPass123!", "NewPass123!", &wallet_seed).is_ok());

        // Old password should not work
        let validation = wpm.validate_password(&wallet_id, "OldPass123!", &wallet_seed).unwrap();
        assert!(!validation.valid);

        // New password should work
        let validation = wpm.validate_password(&wallet_id, "NewPass123!", &wallet_seed).unwrap();
        assert!(validation.valid);
    }

    #[test]
    fn test_wallet_password_remove() {
        let mut wpm = WalletPasswordManager::new();
        let wallet_id = Hash::from_bytes(&[3u8; 32]);
        let wallet_seed = [126u8; 32];
        let password = "RemoveMe123!";
        
        // Set password
        wpm.set_wallet_password(&wallet_id, password, &wallet_seed).unwrap();
        assert!(wpm.has_password(&wallet_id));
        
        // Remove password
        assert!(wpm.remove_wallet_password(&wallet_id, password, &wallet_seed).is_ok());
        assert!(!wpm.has_password(&wallet_id));
    }

    #[test]
    fn test_wallet_password_weak_rejection() {
        let mut wpm = WalletPasswordManager::new();
        let wallet_id = Hash::from_bytes(&[4u8; 32]);
        let wallet_seed = [200u8; 32];
        
        // Should reject weak passwords
        assert!(matches!(
            wpm.set_wallet_password(&wallet_id, "short", &wallet_seed),
<<<<<<< HEAD
            Err(WalletPasswordError::TooShort)
=======
            Err(WalletPasswordError::TooShort | WalletPasswordError::WeakPassword)
>>>>>>> development
        ));
    }
}
