use serde::{Deserialize, Serialize};

/// Contract permissions and administrative controls
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractPermissions {
    /// Whether the contract can mint new tokens/assets
    pub can_mint: bool,
    /// Whether the contract can burn tokens/assets
    pub can_burn: bool,
    /// Whether the contract can be paused for emergency situations
    pub can_pause: bool,
    /// List of administrators who can perform privileged operations
    pub admins: Vec<crate::integration::crypto_integration::PublicKey>,
}

impl ContractPermissions {
    /// Create new permissions with default settings
    pub fn new() -> Self {
        Self {
            can_mint: false,
            can_burn: false,
            can_pause: false,
            admins: Vec::new(),
        }
    }

    /// Create permissions for a token contract
    pub fn for_token(creator: crate::integration::crypto_integration::PublicKey, can_mint: bool, can_burn: bool) -> Self {
        Self {
            can_mint,
            can_burn,
            can_pause: false,
            admins: vec![creator],
        }
    }

    /// Create permissions for SOV native token
    pub fn for_lib_token() -> Self {
        Self {
            can_mint: true, // For network rewards
            can_burn: false, // SOV is not deflationary
            can_pause: false,
            admins: vec![], // No single admin for native token
        }
    }

    /// Create permissions for messaging contracts
    pub fn for_messaging() -> Self {
        Self {
            can_mint: false,
            can_burn: true, // Messages can be burned
            can_pause: false,
            admins: vec![],
        }
    }

    /// Create permissions for social contracts (contacts, groups)
    pub fn for_social(creator: crate::integration::crypto_integration::PublicKey) -> Self {
        Self {
            can_mint: false,
            can_burn: false,
            can_pause: false,
            admins: vec![creator],
        }
    }

    /// Check if a public key is an admin
    pub fn is_admin(&self, public_key: &crate::integration::crypto_integration::PublicKey) -> bool {
        self.admins.contains(public_key)
    }

    /// Add a new admin
    pub fn add_admin(&mut self, admin: crate::integration::crypto_integration::PublicKey) {
        if !self.admins.contains(&admin) {
            self.admins.push(admin);
        }
    }

    /// Remove an admin
    pub fn remove_admin(&mut self, admin: &crate::integration::crypto_integration::PublicKey) {
        self.admins.retain(|a| a != admin);
    }

    /// Check if any privileged operation is allowed
    pub fn has_privileged_permissions(&self) -> bool {
        self.can_mint || self.can_burn || self.can_pause || !self.admins.is_empty()
    }

    /// Validate permissions for a specific operation
    pub fn can_perform_operation(&self, operation: &str, caller: &crate::integration::crypto_integration::PublicKey) -> bool {
        match operation {
            "mint" => self.can_mint && (self.admins.is_empty() || self.is_admin(caller)),
            "burn" => self.can_burn,
            "pause" => self.can_pause && self.is_admin(caller),
            "admin" => self.is_admin(caller),
            _ => false,
        }
    }
}

impl Default for ContractPermissions {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::PublicKey;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 32])
    }

    #[test]
    fn test_contract_permissions_new() {
        let permissions = ContractPermissions::new();
        assert!(!permissions.can_mint);
        assert!(!permissions.can_burn);
        assert!(!permissions.can_pause);
        assert!(permissions.admins.is_empty());
    }

    #[test]
    fn test_contract_permissions_for_token() {
        let public_key = create_test_public_key(1);
        let permissions = ContractPermissions::for_token(public_key.clone(), true, true);
        
        assert!(permissions.can_mint);
        assert!(permissions.can_burn);
        assert!(!permissions.can_pause);
        assert_eq!(permissions.admins.len(), 1);
        assert!(permissions.is_admin(&public_key));
    }

    #[test]
    fn test_contract_permissions_for_lib_token() {
        let permissions = ContractPermissions::for_lib_token();
        assert!(permissions.can_mint);
        assert!(!permissions.can_burn);
        assert!(!permissions.can_pause);
        assert!(permissions.admins.is_empty());
    }

    #[test]
    fn test_admin_management() {
        let public_key1 = create_test_public_key(1);
        let public_key2 = create_test_public_key(2);
        let mut permissions = ContractPermissions::new();

        assert!(!permissions.is_admin(&public_key1));
        
        permissions.add_admin(public_key1.clone());
        assert!(permissions.is_admin(&public_key1));
        assert!(!permissions.is_admin(&public_key2));

        permissions.add_admin(public_key2.clone());
        assert!(permissions.is_admin(&public_key2));
        assert_eq!(permissions.admins.len(), 2);

        permissions.remove_admin(&public_key1);
        assert!(!permissions.is_admin(&public_key1));
        assert!(permissions.is_admin(&public_key2));
        assert_eq!(permissions.admins.len(), 1);
    }

    #[test]
    fn test_operation_permissions() {
        let public_key = create_test_public_key(1);
        let mut permissions = ContractPermissions::for_token(public_key.clone(), true, true);

        assert!(permissions.can_perform_operation("mint", &public_key));
        assert!(permissions.can_perform_operation("burn", &public_key));
        assert!(!permissions.can_perform_operation("pause", &public_key));

        permissions.can_pause = true;
        assert!(permissions.can_perform_operation("pause", &public_key));

        let other_public_key = create_test_public_key(2);
        assert!(!permissions.can_perform_operation("mint", &other_public_key));
        assert!(permissions.can_perform_operation("burn", &other_public_key)); // burn doesn't require admin
    }

    #[test]
    fn test_privileged_permissions() {
        let mut permissions = ContractPermissions::new();
        assert!(!permissions.has_privileged_permissions());

        permissions.can_mint = true;
        assert!(permissions.has_privileged_permissions());

        permissions = ContractPermissions::new();
        let public_key = create_test_public_key(1);
        permissions.add_admin(public_key);
        assert!(permissions.has_privileged_permissions());
    }
}
