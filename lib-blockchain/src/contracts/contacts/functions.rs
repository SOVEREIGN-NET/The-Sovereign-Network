use super::core::{ContactContract, ContactEntry, ContactStats};
use crate::integration::crypto_integration::PublicKey;

/// Contact management functions for contract system integration

/// Add a new contact
pub fn add_contact(
    contract: &mut ContactContract,
    owner: PublicKey,
    display_name: String,
    public_key: PublicKey,
) -> Result<[u8; 32], String> {
    contract.add_contact(owner, display_name, public_key)
}

/// Remove a contact
pub fn remove_contact(
    contract: &mut ContactContract,
    owner: &PublicKey,
    contact_id: &[u8; 32],
) -> Result<(), String> {
    contract.remove_contact(owner, contact_id)
}

/// Get a contact by ID
pub fn get_contact<'a>(
    contract: &'a ContactContract,
    contact_id: &[u8; 32],
) -> Option<&'a ContactEntry> {
    contract.get_contact(contact_id)
}

/// Get all contacts for a user
pub fn get_user_contacts<'a>(
    contract: &'a ContactContract,
    owner: &PublicKey,
) -> Vec<&'a ContactEntry> {
    contract.get_user_contacts(owner)
}

/// Update contact information
pub fn update_contact(
    contract: &mut ContactContract,
    owner: &PublicKey,
    contact_id: &[u8; 32],
    display_name: Option<String>,
    avatar_hash: Option<String>,
    status_message: Option<String>,
) -> Result<(), String> {
    contract.update_contact(owner, contact_id, display_name, avatar_hash, status_message)
}

/// Verify a contact
pub fn verify_contact(
    contract: &mut ContactContract,
    owner: &PublicKey,
    contact_id: &[u8; 32],
) -> Result<(), String> {
    contract.verify_contact(owner, contact_id)
}

/// Search contacts by display name
pub fn search_contacts<'a>(
    contract: &'a ContactContract,
    owner: &PublicKey,
    search_term: &str,
) -> Vec<&'a ContactEntry> {
    contract.search_contacts(owner, search_term)
}

/// Get verified contacts only
pub fn get_verified_contacts<'a>(
    contract: &'a ContactContract,
    owner: &PublicKey,
) -> Vec<&'a ContactEntry> {
    contract.get_verified_contacts(owner)
}

/// Get contact count for a user
pub fn get_contact_count(contract: &ContactContract, owner: &PublicKey) -> usize {
    contract.get_contact_count(owner)
}

/// Check if two users are mutual contacts
pub fn are_mutual_contacts(
    contract: &ContactContract,
    user1: &PublicKey,
    user2: &PublicKey,
) -> bool {
    contract.are_mutual_contacts(user1, user2)
}

/// Get all users who have a specific public key as a contact
pub fn get_users_with_contact<'a>(
    contract: &'a ContactContract,
    public_key: &PublicKey,
) -> Vec<&'a PublicKey> {
    contract.get_users_with_contact(public_key)
}

/// Get recent contacts (limited number)
pub fn get_recent_contacts<'a>(
    contract: &'a ContactContract,
    owner: &PublicKey,
    limit: usize,
) -> Vec<&'a ContactEntry> {
    contract.get_recent_contacts(owner, limit)
}

/// Export contacts for backup
pub fn export_contacts(contract: &ContactContract, owner: &PublicKey) -> Vec<ContactEntry> {
    contract.export_contacts(owner)
}

/// Import contacts from backup
pub fn import_contacts(
    contract: &mut ContactContract,
    owner: &PublicKey,
    contacts: Vec<ContactEntry>,
) -> Result<usize, String> {
    contract.import_contacts(owner, contacts)
}

/// Get contact system statistics
pub fn get_contact_stats(contract: &ContactContract) -> ContactStats {
    contract.get_stats()
}

/// Advanced contact operations

/// Bulk add contacts
pub fn bulk_add_contacts(
    contract: &mut ContactContract,
    owner: PublicKey,
    contacts: Vec<(String, PublicKey)>, // (display_name, public_key) pairs
) -> Result<Vec<[u8; 32]>, String> {
    let mut contact_ids = Vec::new();

    for (display_name, public_key) in contacts {
        let contact_id = contract.add_contact(owner.clone(), display_name, public_key)?;
        contact_ids.push(contact_id);
    }

    Ok(contact_ids)
}

/// Get contact suggestions based on mutual connections
pub fn get_contact_suggestions(
    contract: &ContactContract,
    user: &PublicKey,
    max_suggestions: usize,
) -> Vec<ContactSuggestion> {
    let mut suggestions = Vec::new();
    let user_contacts = contract.get_user_contacts(user);

    // Find contacts of contacts (second-degree connections)
    for contact in &user_contacts {
        let contact_contacts = contract.get_user_contacts(&contact.public_key);

        for suggested_contact in contact_contacts {
            // Don't suggest themselves or existing contacts
            if suggested_contact.public_key == *user {
                continue;
            }

            let already_contact = user_contacts
                .iter()
                .any(|c| c.public_key == suggested_contact.public_key);
            if already_contact {
                continue;
            }

            // Check if already in suggestions
            let already_suggested = suggestions
                .iter()
                .any(|s: &ContactSuggestion| s.public_key == suggested_contact.public_key);
            if already_suggested {
                // Increment mutual connection count
                if let Some(suggestion) = suggestions
                    .iter_mut()
                    .find(|s| s.public_key == suggested_contact.public_key)
                {
                    suggestion.mutual_connections += 1;
                    suggestion
                        .connection_names
                        .push(contact.display_name.clone());
                }
            } else {
                suggestions.push(ContactSuggestion {
                    display_name: suggested_contact.display_name.clone(),
                    public_key: suggested_contact.public_key.clone(),
                    mutual_connections: 1,
                    connection_names: vec![contact.display_name.clone()],
                    verified: suggested_contact.verified,
                });
            }
        }
    }

    // Sort by number of mutual connections (descending)
    suggestions.sort_by(|a, b| b.mutual_connections.cmp(&a.mutual_connections));

    suggestions.into_iter().take(max_suggestions).collect()
}

/// Get contacts sorted by interaction frequency (would need message data)
pub fn get_frequent_contacts<'a>(
    contract: &'a ContactContract,
    owner: &PublicKey,
    limit: usize,
) -> Vec<&'a ContactEntry> {
    // For now, just return recent contacts
    // In a implementation, this would consider message frequency
    contract.get_recent_contacts(owner, limit)
}

/// Get contacts by verification status with counts
pub fn get_contacts_by_verification(
    contract: &ContactContract,
    owner: &PublicKey,
) -> ContactVerificationStats {
    let all_contacts = contract.get_user_contacts(owner);
    let verified_count = all_contacts.iter().filter(|c| c.verified).count();
    let unverified_count = all_contacts.len() - verified_count;

    ContactVerificationStats {
        total_contacts: all_contacts.len(),
        verified_contacts: verified_count,
        unverified_contacts: unverified_count,
        verification_percentage: if all_contacts.is_empty() {
            0.0
        } else {
            (verified_count as f64 / all_contacts.len() as f64) * 100.0
        },
    }
}

/// Find contacts with similar names (fuzzy matching)
pub fn find_similar_contacts<'a>(
    contract: &'a ContactContract,
    owner: &PublicKey,
    name_pattern: &str,
    max_distance: usize,
) -> Vec<&'a ContactEntry> {
    let user_contacts = contract.get_user_contacts(owner);

    user_contacts
        .into_iter()
        .filter(|contact| {
            levenshtein_distance(
                &contact.display_name.to_lowercase(),
                &name_pattern.to_lowercase(),
            ) <= max_distance
        })
        .collect()
}

/// Get contact distribution by first letter
pub fn get_contact_distribution(
    contract: &ContactContract,
    owner: &PublicKey,
) -> ContactDistribution {
    let contacts = contract.get_user_contacts(owner);
    let total_contacts = contacts.len();
    let mut distribution = std::collections::HashMap::new();

    for contact in contacts {
        let first_char = contact
            .display_name
            .chars()
            .next()
            .unwrap_or('#')
            .to_uppercase()
            .next()
            .unwrap_or('#');
        *distribution.entry(first_char).or_insert(0) += 1;
    }

    ContactDistribution {
        total_contacts,
        distribution,
    }
}

/// Contact suggestion structure
#[derive(Debug, Clone)]
pub struct ContactSuggestion {
    pub display_name: String,
    pub public_key: PublicKey,
    pub mutual_connections: usize,
    pub connection_names: Vec<String>,
    pub verified: bool,
}

/// Contact verification statistics
#[derive(Debug, Clone)]
pub struct ContactVerificationStats {
    pub total_contacts: usize,
    pub verified_contacts: usize,
    pub unverified_contacts: usize,
    pub verification_percentage: f64,
}

/// Contact distribution by first letter
#[derive(Debug, Clone)]
pub struct ContactDistribution {
    pub total_contacts: usize,
    pub distribution: std::collections::HashMap<char, usize>,
}

/// Simple Levenshtein distance implementation for fuzzy matching
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let chars1: Vec<char> = s1.chars().collect();
    let chars2: Vec<char> = s2.chars().collect();
    let len1 = chars1.len();
    let len2 = chars2.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0; len2 + 1]; len1 + 1];

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
    }

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if chars1[i - 1] == chars2[j - 1] { 0 } else { 1 };
            matrix[i][j] = std::cmp::min(
                std::cmp::min(
                    matrix[i - 1][j] + 1, // deletion
                    matrix[i][j - 1] + 1, // insertion
                ),
                matrix[i - 1][j - 1] + cost, // substitution
            );
        }
    }

    matrix[len1][len2]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    #[test]
    fn test_contact_functions() {
        let mut contract = ContactContract::new();
        let owner = create_test_public_key(1);
        let contact_pk = create_test_public_key(2);

        // Add contact
        let contact_id = add_contact(
            &mut contract,
            owner.clone(),
            "Test Contact".to_string(),
            contact_pk.clone(),
        )
        .unwrap();

        // Get contact
        let contact = get_contact(&contract, &contact_id).unwrap();
        assert_eq!(contact.display_name, "Test Contact");

        // Get user contacts
        let user_contacts = get_user_contacts(&contract, &owner);
        assert_eq!(user_contacts.len(), 1);

        // Update contact
        update_contact(
            &mut contract,
            &owner,
            &contact_id,
            Some("Updated Name".to_string()),
            None,
            Some("Online".to_string()),
        )
        .unwrap();

        let updated_contact = get_contact(&contract, &contact_id).unwrap();
        assert_eq!(updated_contact.display_name, "Updated Name");
        assert_eq!(updated_contact.status_message, "Online");
    }

    #[test]
    fn test_bulk_add_contacts() {
        let mut contract = ContactContract::new();
        let owner = create_test_public_key(1);

        let contacts_to_add = vec![
            ("Alice".to_string(), create_test_public_key(2)),
            ("Bob".to_string(), create_test_public_key(3)),
            ("Charlie".to_string(), create_test_public_key(4)),
        ];

        let contact_ids = bulk_add_contacts(&mut contract, owner.clone(), contacts_to_add).unwrap();

        assert_eq!(contact_ids.len(), 3);
        assert_eq!(get_contact_count(&contract, &owner), 3);
    }

    #[test]
    fn test_contact_search() {
        let mut contract = ContactContract::new();
        let owner = create_test_public_key(1);

        add_contact(
            &mut contract,
            owner.clone(),
            "Alice Smith".to_string(),
            create_test_public_key(2),
        )
        .unwrap();

        add_contact(
            &mut contract,
            owner.clone(),
            "Bob Johnson".to_string(),
            create_test_public_key(3),
        )
        .unwrap();

        let results = search_contacts(&contract, &owner, "alice");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].display_name, "Alice Smith");
    }

    #[test]
    fn test_contact_verification_stats() {
        let mut contract = ContactContract::new();
        let owner = create_test_public_key(1);

        let contact_id1 = add_contact(
            &mut contract,
            owner.clone(),
            "Contact 1".to_string(),
            create_test_public_key(2),
        )
        .unwrap();

        let _contact_id2 = add_contact(
            &mut contract,
            owner.clone(),
            "Contact 2".to_string(),
            create_test_public_key(3),
        )
        .unwrap();

        // Verify one contact
        verify_contact(&mut contract, &owner, &contact_id1).unwrap();

        let stats = get_contacts_by_verification(&contract, &owner);
        assert_eq!(stats.total_contacts, 2);
        assert_eq!(stats.verified_contacts, 1);
        assert_eq!(stats.unverified_contacts, 1);
        assert_eq!(stats.verification_percentage, 50.0);
    }

    #[test]
    fn test_mutual_contacts_function() {
        let mut contract = ContactContract::new();
        let user1 = create_test_public_key(1);
        let user2 = create_test_public_key(2);

        // Add each other as contacts
        add_contact(
            &mut contract,
            user1.clone(),
            "User2".to_string(),
            user2.clone(),
        )
        .unwrap();

        add_contact(
            &mut contract,
            user2.clone(),
            "User1".to_string(),
            user1.clone(),
        )
        .unwrap();

        assert!(are_mutual_contacts(&contract, &user1, &user2));
    }

    #[test]
    fn test_contact_suggestions() {
        let mut contract = ContactContract::new();
        let user1 = create_test_public_key(1);
        let user2 = create_test_public_key(2);
        let user3 = create_test_public_key(3);

        // User1 knows User2
        add_contact(
            &mut contract,
            user1.clone(),
            "User2".to_string(),
            user2.clone(),
        )
        .unwrap();

        // User2 knows User3
        add_contact(
            &mut contract,
            user2.clone(),
            "User3".to_string(),
            user3.clone(),
        )
        .unwrap();

        // User1 should get User3 as a suggestion
        let suggestions = get_contact_suggestions(&contract, &user1, 5);
        assert_eq!(suggestions.len(), 1);
        assert_eq!(suggestions[0].public_key, user3);
        assert_eq!(suggestions[0].mutual_connections, 1);
    }

    #[test]
    fn test_levenshtein_distance() {
        assert_eq!(levenshtein_distance("kitten", "sitting"), 3);
        assert_eq!(levenshtein_distance("alice", "alicia"), 2);
        assert_eq!(levenshtein_distance("test", "test"), 0);
        assert_eq!(levenshtein_distance("", "abc"), 3);
        assert_eq!(levenshtein_distance("abc", ""), 3);
    }

    #[test]
    fn test_similar_contacts() {
        let mut contract = ContactContract::new();
        let owner = create_test_public_key(1);

        add_contact(
            &mut contract,
            owner.clone(),
            "Alice".to_string(),
            create_test_public_key(2),
        )
        .unwrap();

        add_contact(
            &mut contract,
            owner.clone(),
            "Alicia".to_string(),
            create_test_public_key(3),
        )
        .unwrap();

        add_contact(
            &mut contract,
            owner.clone(),
            "Bob".to_string(),
            create_test_public_key(4),
        )
        .unwrap();

        // Find contacts similar to "alice" with max distance 2
        let similar = find_similar_contacts(&contract, &owner, "alice", 2);
        assert_eq!(similar.len(), 2); // Should match "Alice" and "Alicia"
    }
}
