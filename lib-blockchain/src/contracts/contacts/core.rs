use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Contact registry entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactEntry {
    /// Unique contact identifier
    pub contact_id: [u8; 32],
    /// Owner of this contact entry
    pub owner: PublicKey,
    /// Display name for the contact
    pub display_name: String,
    /// Contact's public key
    pub public_key: PublicKey,
    /// Optional avatar hash ( hash)
    pub avatar_hash: Option<String>,
    /// Status message
    pub status_message: String,
    /// Whether the contact is verified
    pub verified: bool,
    /// Timestamp when contact was added
    pub added_timestamp: u64,
}

impl ContactEntry {
    /// Create a new contact entry
    pub fn new(owner: PublicKey, display_name: String, public_key: PublicKey) -> Self {
        let contact_id =
            crate::contracts::utils::generate_contact_id(&owner.key_id, &public_key.key_id);
        let added_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            contact_id,
            owner,
            display_name,
            public_key,
            avatar_hash: None,
            status_message: String::new(),
            verified: false,
            added_timestamp,
        }
    }

    /// Set avatar hash
    pub fn set_avatar(&mut self, avatar_hash: String) {
        self.avatar_hash = Some(avatar_hash);
    }

    /// Set status message
    pub fn set_status(&mut self, status_message: String) {
        self.status_message = status_message;
    }

    /// Mark contact as verified
    pub fn verify(&mut self) {
        self.verified = true;
    }

    /// Get storage key for this contact
    pub fn storage_key(&self) -> Vec<u8> {
        crate::contracts::utils::generate_indexed_storage_key(
            "contact",
            &[&self.owner.key_id, &self.contact_id],
        )
    }

    /// Validate contact entry
    pub fn validate(&self) -> Result<(), String> {
        if self.display_name.is_empty() {
            return Err("Display name cannot be empty".to_string());
        }

        if self.display_name.len() > 64 {
            return Err("Display name too long (max 64 characters)".to_string());
        }

        if self.status_message.len() > 256 {
            return Err("Status message too long (max 256 characters)".to_string());
        }

        Ok(())
    }
}

/// Contact management contract
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactContract {
    /// All contact entries indexed by contact_id
    pub contacts: HashMap<[u8; 32], ContactEntry>,
    /// User contact lists (owner -> contact_ids)
    pub user_contacts: HashMap<PublicKey, Vec<[u8; 32]>>,
    /// Reverse lookup (public_key -> owners who have this contact)
    pub public_key_index: HashMap<PublicKey, Vec<PublicKey>>,
}

impl ContactContract {
    /// Create a new contact contract
    pub fn new() -> Self {
        Self {
            contacts: HashMap::new(),
            user_contacts: HashMap::new(),
            public_key_index: HashMap::new(),
        }
    }

    /// Add a new contact
    pub fn add_contact(
        &mut self,
        owner: PublicKey,
        display_name: String,
        public_key: PublicKey,
    ) -> Result<[u8; 32], String> {
        // Check if contact already exists
        if let Some(existing_contacts) = self.user_contacts.get(&owner) {
            for contact_id in existing_contacts {
                if let Some(contact) = self.contacts.get(contact_id) {
                    if contact.public_key == public_key {
                        return Err("Contact already exists".to_string());
                    }
                }
            }
        }

        let contact = ContactEntry::new(owner.clone(), display_name, public_key.clone());
        contact.validate()?;

        let contact_id = contact.contact_id;

        // Add to user contacts list
        self.user_contacts
            .entry(owner.clone())
            .or_insert_with(Vec::new)
            .push(contact_id);

        // Add to public key index
        self.public_key_index
            .entry(public_key.clone())
            .or_insert_with(Vec::new)
            .push(owner);

        // Store the contact
        self.contacts.insert(contact_id, contact);

        Ok(contact_id)
    }

    /// Get a contact by ID
    pub fn get_contact(&self, contact_id: &[u8; 32]) -> Option<&ContactEntry> {
        self.contacts.get(contact_id)
    }

    /// Get all contacts for a user
    pub fn get_user_contacts(&self, owner: &PublicKey) -> Vec<&ContactEntry> {
        self.user_contacts
            .get(owner)
            .map(|contact_ids| {
                contact_ids
                    .iter()
                    .filter_map(|id| self.contacts.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Remove a contact
    pub fn remove_contact(
        &mut self,
        owner: &PublicKey,
        contact_id: &[u8; 32],
    ) -> Result<(), String> {
        // Check if contact exists and belongs to owner
        if let Some(contact) = self.contacts.get(contact_id) {
            if contact.owner != *owner {
                return Err("Contact does not belong to this owner".to_string());
            }
        } else {
            return Err("Contact not found".to_string());
        }

        let contact = self.contacts.remove(contact_id).unwrap();

        // Remove from user contacts list
        if let Some(user_contacts) = self.user_contacts.get_mut(owner) {
            user_contacts.retain(|id| id != contact_id);
            if user_contacts.is_empty() {
                self.user_contacts.remove(owner);
            }
        }

        // Remove from public key index
        if let Some(owners) = self.public_key_index.get_mut(&contact.public_key) {
            owners.retain(|o| o != owner);
            if owners.is_empty() {
                self.public_key_index.remove(&contact.public_key);
            }
        }

        Ok(())
    }

    /// Update contact information
    pub fn update_contact(
        &mut self,
        owner: &PublicKey,
        contact_id: &[u8; 32],
        display_name: Option<String>,
        avatar_hash: Option<String>,
        status_message: Option<String>,
    ) -> Result<(), String> {
        if let Some(contact) = self.contacts.get_mut(contact_id) {
            if contact.owner != *owner {
                return Err("Contact does not belong to this owner".to_string());
            }

            if let Some(name) = display_name {
                contact.display_name = name;
            }

            if let Some(hash) = avatar_hash {
                contact.set_avatar(hash);
            }

            if let Some(status) = status_message {
                contact.set_status(status);
            }

            contact.validate()?;
            Ok(())
        } else {
            Err("Contact not found".to_string())
        }
    }

    /// Verify a contact
    pub fn verify_contact(
        &mut self,
        owner: &PublicKey,
        contact_id: &[u8; 32],
    ) -> Result<(), String> {
        if let Some(contact) = self.contacts.get_mut(contact_id) {
            if contact.owner != *owner {
                return Err("Contact does not belong to this owner".to_string());
            }

            contact.verify();
            Ok(())
        } else {
            Err("Contact not found".to_string())
        }
    }

    /// Search contacts by display name
    pub fn search_contacts(&self, owner: &PublicKey, search_term: &str) -> Vec<&ContactEntry> {
        self.get_user_contacts(owner)
            .into_iter()
            .filter(|contact| {
                contact
                    .display_name
                    .to_lowercase()
                    .contains(&search_term.to_lowercase())
            })
            .collect()
    }

    /// Get contacts by verification status
    pub fn get_verified_contacts(&self, owner: &PublicKey) -> Vec<&ContactEntry> {
        self.get_user_contacts(owner)
            .into_iter()
            .filter(|contact| contact.verified)
            .collect()
    }

    /// Get contact count for a user
    pub fn get_contact_count(&self, owner: &PublicKey) -> usize {
        self.user_contacts
            .get(owner)
            .map(|contacts| contacts.len())
            .unwrap_or(0)
    }

    /// Check if two users have each other as contacts (mutual)
    pub fn are_mutual_contacts(&self, user1: &PublicKey, user2: &PublicKey) -> bool {
        let user1_has_user2 = self
            .user_contacts
            .get(user1)
            .map(|contacts| {
                contacts.iter().any(|contact_id| {
                    if let Some(contact) = self.contacts.get(contact_id) {
                        contact.public_key == *user2
                    } else {
                        false
                    }
                })
            })
            .unwrap_or(false);

        let user2_has_user1 = self
            .user_contacts
            .get(user2)
            .map(|contacts| {
                contacts.iter().any(|contact_id| {
                    if let Some(contact) = self.contacts.get(contact_id) {
                        contact.public_key == *user1
                    } else {
                        false
                    }
                })
            })
            .unwrap_or(false);

        user1_has_user2 && user2_has_user1
    }

    /// Get all users who have a specific public key as a contact
    pub fn get_users_with_contact(&self, public_key: &PublicKey) -> Vec<&PublicKey> {
        self.public_key_index
            .get(public_key)
            .map(|owners| owners.iter().collect())
            .unwrap_or_default()
    }

    /// Get recent contacts (sorted by added timestamp)
    pub fn get_recent_contacts(&self, owner: &PublicKey, limit: usize) -> Vec<&ContactEntry> {
        let mut contacts = self.get_user_contacts(owner);
        contacts.sort_by(|a, b| b.added_timestamp.cmp(&a.added_timestamp));
        contacts.into_iter().take(limit).collect()
    }

    /// Export contacts for backup
    pub fn export_contacts(&self, owner: &PublicKey) -> Vec<ContactEntry> {
        self.get_user_contacts(owner).into_iter().cloned().collect()
    }

    /// Import contacts from backup
    pub fn import_contacts(
        &mut self,
        owner: &PublicKey,
        contacts: Vec<ContactEntry>,
    ) -> Result<usize, String> {
        let mut imported_count = 0;

        for mut contact in contacts {
            // Update owner to match current user
            contact.owner = owner.clone();

            // Regenerate contact ID
            contact.contact_id = crate::contracts::utils::generate_contact_id(
                &owner.key_id,
                &contact.public_key.key_id,
            );

            // Check if contact already exists
            let already_exists = self
                .user_contacts
                .get(owner)
                .map(|existing_contacts| {
                    existing_contacts.iter().any(|id| {
                        if let Some(existing) = self.contacts.get(id) {
                            existing.public_key == contact.public_key
                        } else {
                            false
                        }
                    })
                })
                .unwrap_or(false);

            if !already_exists {
                contact.validate()?;
                let contact_id = contact.contact_id;

                // Add to user contacts list
                self.user_contacts
                    .entry(owner.clone())
                    .or_insert_with(Vec::new)
                    .push(contact_id);

                // Add to public key index
                self.public_key_index
                    .entry(contact.public_key.clone())
                    .or_insert_with(Vec::new)
                    .push(owner.clone());

                // Store the contact
                self.contacts.insert(contact_id, contact);
                imported_count += 1;
            }
        }

        Ok(imported_count)
    }

    /// Get total contact count across all users
    pub fn total_contact_count(&self) -> usize {
        self.contacts.len()
    }

    /// Get statistics about the contact system
    pub fn get_stats(&self) -> ContactStats {
        let total_contacts = self.contacts.len();
        let total_users = self.user_contacts.len();
        let verified_contacts = self.contacts.values().filter(|c| c.verified).count();

        let mut contact_counts: Vec<usize> = self
            .user_contacts
            .values()
            .map(|contacts| contacts.len())
            .collect();
        contact_counts.sort();

        let average_contacts_per_user = if total_users > 0 {
            total_contacts as f64 / total_users as f64
        } else {
            0.0
        };

        let median_contacts_per_user = if contact_counts.is_empty() {
            0
        } else {
            contact_counts[contact_counts.len() / 2]
        };

        ContactStats {
            total_contacts,
            total_users,
            verified_contacts,
            average_contacts_per_user,
            median_contacts_per_user,
        }
    }
}

/// Contact system statistics
#[derive(Debug, Clone)]
pub struct ContactStats {
    pub total_contacts: usize,
    pub total_users: usize,
    pub verified_contacts: usize,
    pub average_contacts_per_user: f64,
    pub median_contacts_per_user: usize,
}

impl Default for ContactContract {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    #[test]
    fn test_contact_entry_creation() {
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);

        let contact = ContactEntry::new(
            owner.clone(),
            "Test Contact".to_string(),
            contact_pk.clone(),
        );

        assert_eq!(contact.owner, owner);
        assert_eq!(contact.display_name, "Test Contact");
        assert_eq!(contact.public_key, contact_pk);
        assert_eq!(contact.avatar_hash, None);
        assert_eq!(contact.status_message, "");
        assert!(!contact.verified);
        assert!(contact.added_timestamp > 0);
    }

    #[test]
    fn test_contact_contract() {
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);
        let mut contract = ContactContract::new();

        // Add contact
        let contact_id = contract
            .add_contact(
                owner.clone(),
                "Test Contact".to_string(),
                contact_pk.clone(),
            )
            .unwrap();

        // Verify contact was added
        assert_eq!(contract.get_contact_count(&owner), 1);
        let contact = contract.get_contact(&contact_id).unwrap();
        assert_eq!(contact.display_name, "Test Contact");

        // Get user contacts
        let user_contacts = contract.get_user_contacts(&owner);
        assert_eq!(user_contacts.len(), 1);
    }

    #[test]
    fn test_duplicate_contact() {
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);
        let mut contract = ContactContract::new();

        // Add contact
        contract
            .add_contact(
                owner.clone(),
                "First Contact".to_string(),
                contact_pk.clone(),
            )
            .unwrap();

        // Try to add the same contact again
        let result = contract.add_contact(
            owner.clone(),
            "Second Contact".to_string(),
            contact_pk.clone(),
        );

        assert!(result.is_err());
        assert_eq!(contract.get_contact_count(&owner), 1);
    }

    #[test]
    fn test_contact_update() {
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);
        let mut contract = ContactContract::new();

        let contact_id = contract
            .add_contact(
                owner.clone(),
                "Original Name".to_string(),
                contact_pk.clone(),
            )
            .unwrap();

        // Update contact
        contract
            .update_contact(
                &owner,
                &contact_id,
                Some("Updated Name".to_string()),
                Some("avatar_hash".to_string()),
                Some("Online".to_string()),
            )
            .unwrap();

        let contact = contract.get_contact(&contact_id).unwrap();
        assert_eq!(contact.display_name, "Updated Name");
        assert_eq!(contact.avatar_hash, Some("avatar_hash".to_string()));
        assert_eq!(contact.status_message, "Online");
    }

    #[test]
    fn test_contact_removal() {
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);
        let mut contract = ContactContract::new();

        let contact_id = contract
            .add_contact(
                owner.clone(),
                "Test Contact".to_string(),
                contact_pk.clone(),
            )
            .unwrap();

        assert_eq!(contract.get_contact_count(&owner), 1);

        // Remove contact
        contract.remove_contact(&owner, &contact_id).unwrap();
        assert_eq!(contract.get_contact_count(&owner), 0);
        assert!(contract.get_contact(&contact_id).is_none());
    }

    #[test]
    fn test_mutual_contacts() {
        let user1 = create_test_public_key(1);
        let user2 = create_test_public_key(2);
        let mut contract = ContactContract::new();

        // User1 adds User2 as contact
        contract
            .add_contact(user1.clone(), "User2".to_string(), user2.clone())
            .unwrap();

        // Not mutual yet
        assert!(!contract.are_mutual_contacts(&user1, &user2));

        // User2 adds User1 as contact
        contract
            .add_contact(user2.clone(), "User1".to_string(), user1.clone())
            .unwrap();

        // Now they are mutual contacts
        assert!(contract.are_mutual_contacts(&user1, &user2));
    }

    #[test]
    fn test_contact_search() {
        let owner = create_test_public_key(1);
        let contact1_pk = create_test_public_key(2);
        let contact2_pk = create_test_public_key(3);
        let mut contract = ContactContract::new();

        contract
            .add_contact(owner.clone(), "Alice Smith".to_string(), contact1_pk)
            .unwrap();

        contract
            .add_contact(owner.clone(), "Bob Johnson".to_string(), contact2_pk)
            .unwrap();

        // Search for "alice"
        let results = contract.search_contacts(&owner, "alice");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].display_name, "Alice Smith");

        // Search for "o" (should match Bob)
        let results = contract.search_contacts(&owner, "o");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].display_name, "Bob Johnson");
    }

    #[test]
    fn test_contact_verification() {
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);
        let mut contract = ContactContract::new();

        let contact_id = contract
            .add_contact(owner.clone(), "Test Contact".to_string(), contact_pk)
            .unwrap();

        // Initially not verified
        let contact = contract.get_contact(&contact_id).unwrap();
        assert!(!contact.verified);

        // Verify contact
        contract.verify_contact(&owner, &contact_id).unwrap();

        let contact = contract.get_contact(&contact_id).unwrap();
        assert!(contact.verified);

        // Test verified contacts filter
        let verified = contract.get_verified_contacts(&owner);
        assert_eq!(verified.len(), 1);
    }
}
