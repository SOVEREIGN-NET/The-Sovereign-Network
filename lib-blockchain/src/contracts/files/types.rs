use crate::integration::crypto_integration::PublicKey;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Shared file structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFile {
    /// Unique file identifier
    pub file_id: [u8; 32],
    /// Original filename
    pub filename: String,
    /// File description
    pub description: String,
    /// File owner
    pub owner: PublicKey,
    ///  hash or content hash
    pub content_hash: [u8; 32],
    /// File size in bytes
    pub file_size: u64,
    /// MIME type of the file
    pub mime_type: String,
    /// Timestamp when file was uploaded
    pub upload_timestamp: u64,
    /// Whether the file is publicly accessible
    pub is_public: bool,
    /// List of users who have access to the file
    pub access_list: Vec<PublicKey>,
    /// Number of downloads
    pub download_count: u64,
    /// Cost in ZHTP tokens to download (if not free)
    pub download_cost: u64,
    /// File encryption status
    pub is_encrypted: bool,
    /// Encryption key hash (if encrypted)
    pub encryption_key_hash: Option<[u8; 32]>,
    /// File tags for categorization
    pub tags: Vec<String>,
    /// Maximum downloads allowed (0 for unlimited)
    pub max_downloads: u64,
}

impl SharedFile {
    /// Create a new shared file
    pub fn new(
        filename: String,
        description: String,
        owner: PublicKey,
        content_hash: [u8; 32],
        file_size: u64,
        mime_type: String,
        is_public: bool,
        download_cost: u64,
        is_encrypted: bool,
        encryption_key_hash: Option<[u8; 32]>,
        tags: Vec<String>,
        max_downloads: u64,
    ) -> Self {
        let upload_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let file_id = crate::contracts::utils::id_generation::generate_file_id(
            &owner.key_id,
            &content_hash,
            upload_timestamp as u128 * 1_000_000_000,
        );

        Self {
            file_id,
            filename,
            description,
            owner: owner.clone(),
            content_hash,
            file_size,
            mime_type,
            upload_timestamp,
            is_public,
            access_list: vec![owner], // Owner always has access
            download_count: 0,
            download_cost,
            is_encrypted,
            encryption_key_hash,
            tags,
            max_downloads,
        }
    }

    /// Check if a user has access to the file
    pub fn has_access(&self, user: &PublicKey) -> bool {
        self.is_public || self.access_list.contains(user)
    }

    /// Grant access to a user
    pub fn grant_access(&mut self, user: PublicKey) -> Result<(), String> {
        if self.has_access(&user) {
            return Err("User already has access".to_string());
        }

        self.access_list.push(user);
        Ok(())
    }

    /// Revoke access from a user
    pub fn revoke_access(&mut self, user: &PublicKey) -> Result<(), String> {
        if *user == self.owner {
            return Err("Cannot revoke access from file owner".to_string());
        }

        if !self.has_access(user) {
            return Err("User does not have access".to_string());
        }

        self.access_list.retain(|u| u != user);
        Ok(())
    }

    /// Check if the file can still be downloaded
    pub fn can_download(&self) -> bool {
        if self.max_downloads == 0 {
            return true; // Unlimited downloads
        }
        self.download_count < self.max_downloads
    }

    /// Record a download
    pub fn record_download(&mut self) -> Result<(), String> {
        if !self.can_download() {
            return Err("Download limit reached".to_string());
        }

        self.download_count += 1;
        Ok(())
    }

    /// Add a tag to the file
    pub fn add_tag(&mut self, tag: String) -> Result<(), String> {
        if tag.is_empty() {
            return Err("Tag cannot be empty".to_string());
        }

        if tag.len() > 32 {
            return Err("Tag too long (max 32 characters)".to_string());
        }

        if self.tags.contains(&tag) {
            return Err("Tag already exists".to_string());
        }

        if self.tags.len() >= 20 {
            return Err("Too many tags (max 20)".to_string());
        }

        self.tags.push(tag);
        Ok(())
    }

    /// Remove a tag from the file
    pub fn remove_tag(&mut self, tag: &str) -> Result<(), String> {
        if !self.tags.contains(&tag.to_string()) {
            return Err("Tag not found".to_string());
        }

        self.tags.retain(|t| t != tag);
        Ok(())
    }

    /// Get file size in human-readable format
    pub fn get_formatted_size(&self) -> String {
        let size = self.file_size as f64;

        if size < 1024.0 {
            format!("{} B", size)
        } else if size < 1024.0 * 1024.0 {
            format!("{:.2} KB", size / 1024.0)
        } else if size < 1024.0 * 1024.0 * 1024.0 {
            format!("{:.2} MB", size / (1024.0 * 1024.0))
        } else {
            format!("{:.2} GB", size / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Get storage key for this file
    pub fn storage_key(&self) -> Vec<u8> {
        crate::contracts::utils::id_generation::generate_storage_key("file", &self.file_id)
    }

    /// Check if file is available for public download
    pub fn is_available_for_download(&self, user: &PublicKey) -> bool {
        self.has_access(user) && self.can_download()
    }

    /// Validate file structure
    pub fn validate(&self) -> Result<(), String> {
        if self.filename.is_empty() {
            return Err("Filename cannot be empty".to_string());
        }

        if self.filename.len() > 255 {
            return Err("Filename too long (max 255 characters)".to_string());
        }

        if self.description.len() > 1024 {
            return Err("Description too long (max 1024 characters)".to_string());
        }

        if self.file_size == 0 {
            return Err("File size cannot be zero".to_string());
        }

        if self.file_size > 100 * 1024 * 1024 * 1024 {
            return Err("File too large (max 100GB)".to_string());
        }

        if self.mime_type.is_empty() {
            return Err("MIME type cannot be empty".to_string());
        }

        if self.mime_type.len() > 128 {
            return Err("MIME type too long (max 128 characters)".to_string());
        }

        // Validate tags
        for tag in &self.tags {
            if tag.is_empty() {
                return Err("Tag cannot be empty".to_string());
            }
            if tag.len() > 32 {
                return Err("Tag too long (max 32 characters)".to_string());
            }
        }

        if self.tags.len() > 20 {
            return Err("Too many tags (max 20)".to_string());
        }

        // Check for duplicate tags
        let mut unique_tags = self.tags.clone();
        unique_tags.sort();
        unique_tags.dedup();
        if unique_tags.len() != self.tags.len() {
            return Err("Duplicate tags found".to_string());
        }

        // Owner must be in access list
        if !self.access_list.contains(&self.owner) {
            return Err("Owner must have access to the file".to_string());
        }

        // Check for duplicate access entries
        let mut unique_access = self.access_list.clone();
        unique_access.sort_by_key(|k| k.key_id);
        unique_access.dedup();
        if unique_access.len() != self.access_list.len() {
            return Err("Duplicate access entries found".to_string());
        }

        // If encrypted, must have encryption key hash
        if self.is_encrypted && self.encryption_key_hash.is_none() {
            return Err("Encrypted file must have encryption key hash".to_string());
        }

        // If not encrypted, should not have encryption key hash
        if !self.is_encrypted && self.encryption_key_hash.is_some() {
            return Err("Non-encrypted file should not have encryption key hash".to_string());
        }

        Ok(())
    }
}

/// File contract for managing shared files and storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContract {
    /// All files in the system
    pub files: HashMap<[u8; 32], SharedFile>,
    /// User file indexes (owner -> file IDs)
    pub user_files: HashMap<PublicKey, Vec<[u8; 32]>>,
    /// Public files index
    pub public_files: Vec<[u8; 32]>,
    /// Tag index (tag -> file IDs)
    pub tag_index: HashMap<String, Vec<[u8; 32]>>,
    /// File type index (MIME type -> file IDs)
    pub type_index: HashMap<String, Vec<[u8; 32]>>,
}

impl FileContract {
    /// Create a new file contract
    pub fn new() -> Self {
        Self {
            files: HashMap::new(),
            user_files: HashMap::new(),
            public_files: Vec::new(),
            tag_index: HashMap::new(),
            type_index: HashMap::new(),
        }
    }

    /// Add a file to the contract
    pub fn add_file(&mut self, file: SharedFile) -> Result<(), String> {
        file.validate()?;

        let file_id = file.file_id;

        // Add to user file index
        self.user_files
            .entry(file.owner.clone())
            .or_insert_with(Vec::new)
            .push(file_id);

        // Add to public files if public
        if file.is_public {
            self.public_files.push(file_id);
        }

        // Add to tag index
        for tag in &file.tags {
            self.tag_index
                .entry(tag.clone())
                .or_insert_with(Vec::new)
                .push(file_id);
        }

        // Add to type index
        self.type_index
            .entry(file.mime_type.clone())
            .or_insert_with(Vec::new)
            .push(file_id);

        // Store the file
        self.files.insert(file_id, file);

        Ok(())
    }

    /// Get a file by ID
    pub fn get_file(&self, file_id: &[u8; 32]) -> Option<&SharedFile> {
        self.files.get(file_id)
    }

    /// Get a mutable file by ID
    pub fn get_file_mut(&mut self, file_id: &[u8; 32]) -> Option<&mut SharedFile> {
        self.files.get_mut(file_id)
    }

    /// Get files owned by a user
    pub fn get_user_files(&self, user: &PublicKey) -> Vec<&SharedFile> {
        self.user_files
            .get(user)
            .map(|file_ids| {
                file_ids
                    .iter()
                    .filter_map(|id| self.files.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get public files
    pub fn get_public_files(&self) -> Vec<&SharedFile> {
        self.public_files
            .iter()
            .filter_map(|id| self.files.get(id))
            .collect()
    }

    /// Get files by tag
    pub fn get_files_by_tag(&self, tag: &str) -> Vec<&SharedFile> {
        self.tag_index
            .get(tag)
            .map(|file_ids| {
                file_ids
                    .iter()
                    .filter_map(|id| self.files.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get files by MIME type
    pub fn get_files_by_type(&self, mime_type: &str) -> Vec<&SharedFile> {
        self.type_index
            .get(mime_type)
            .map(|file_ids| {
                file_ids
                    .iter()
                    .filter_map(|id| self.files.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get files accessible to a user
    pub fn get_accessible_files(&self, user: &PublicKey) -> Vec<&SharedFile> {
        self.files
            .values()
            .filter(|file| file.has_access(user))
            .collect()
    }

    /// Remove a file
    pub fn remove_file(&mut self, file_id: &[u8; 32]) -> Option<SharedFile> {
        if let Some(file) = self.files.remove(file_id) {
            // Remove from user index
            if let Some(user_files) = self.user_files.get_mut(&file.owner) {
                user_files.retain(|id| id != file_id);
            }

            // Remove from public files
            self.public_files.retain(|id| id != file_id);

            // Remove from tag index
            for tag in &file.tags {
                if let Some(tag_files) = self.tag_index.get_mut(tag) {
                    tag_files.retain(|id| id != file_id);
                    if tag_files.is_empty() {
                        self.tag_index.remove(tag);
                    }
                }
            }

            // Remove from type index
            if let Some(type_files) = self.type_index.get_mut(&file.mime_type) {
                type_files.retain(|id| id != file_id);
                if type_files.is_empty() {
                    self.type_index.remove(&file.mime_type);
                }
            }

            Some(file)
        } else {
            None
        }
    }

    /// Update file visibility
    pub fn update_file_visibility(
        &mut self,
        file_id: &[u8; 32],
        is_public: bool,
    ) -> Result<(), String> {
        if let Some(file) = self.files.get_mut(file_id) {
            if file.is_public == is_public {
                return Ok(()); // No change needed
            }

            file.is_public = is_public;

            if is_public {
                // Add to public files
                if !self.public_files.contains(file_id) {
                    self.public_files.push(*file_id);
                }
            } else {
                // Remove from public files
                self.public_files.retain(|id| id != file_id);
            }

            Ok(())
        } else {
            Err("File not found".to_string())
        }
    }

    /// Grant access to a file
    pub fn grant_file_access(&mut self, file_id: &[u8; 32], user: PublicKey) -> Result<(), String> {
        if let Some(file) = self.files.get_mut(file_id) {
            file.grant_access(user)
        } else {
            Err("File not found".to_string())
        }
    }

    /// Revoke access from a file
    pub fn revoke_file_access(
        &mut self,
        file_id: &[u8; 32],
        user: &PublicKey,
    ) -> Result<(), String> {
        if let Some(file) = self.files.get_mut(file_id) {
            file.revoke_access(user)
        } else {
            Err("File not found".to_string())
        }
    }

    /// Record a file download
    pub fn record_download(&mut self, file_id: &[u8; 32]) -> Result<(), String> {
        if let Some(file) = self.files.get_mut(file_id) {
            file.record_download()
        } else {
            Err("File not found".to_string())
        }
    }

    /// Get file count
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Get user file count
    pub fn user_file_count(&self, user: &PublicKey) -> usize {
        self.user_files.get(user).map_or(0, |files| files.len())
    }

    /// Search files by name pattern
    pub fn search_files(&self, pattern: &str) -> Vec<&SharedFile> {
        let pattern_lower = pattern.to_lowercase();
        self.files
            .values()
            .filter(|file| {
                file.filename.to_lowercase().contains(&pattern_lower)
                    || file.description.to_lowercase().contains(&pattern_lower)
            })
            .collect()
    }
}

impl Default for FileContract {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::crypto_integration::KeyPair;

    #[test]
    fn test_file_creation() {
        let owner_keypair = KeyPair::generate().unwrap();
        let content_hash = [1u8; 32];

        let file = SharedFile::new(
            "test.txt".to_string(),
            "A test file".to_string(),
            owner_keypair.public_key.clone(),
            content_hash,
            1024,
            "text/plain".to_string(),
            true,
            0,
            false,
            None,
            vec!["test".to_string(), "document".to_string()],
            0,
        );

        assert_eq!(file.filename, "test.txt");
        assert_eq!(file.description, "A test file");
        assert_eq!(file.owner, owner_keypair.public_key);
        assert_eq!(file.content_hash, content_hash);
        assert_eq!(file.file_size, 1024);
        assert_eq!(file.mime_type, "text/plain");
        assert!(file.is_public);
        assert_eq!(file.download_cost, 0);
        assert!(!file.is_encrypted);
        assert!(file.encryption_key_hash.is_none());
        assert_eq!(file.tags, vec!["test", "document"]);
        assert_eq!(file.max_downloads, 0);

        // Owner should have access
        assert!(file.has_access(&owner_keypair.public_key));
        assert_eq!(file.download_count, 0);
    }

    #[test]
    fn test_file_contract() {
        let mut contract = FileContract::new();
        let owner_keypair = KeyPair::generate().unwrap();
        let content_hash = [1u8; 32];

        let file = SharedFile::new(
            "test.txt".to_string(),
            "A test file".to_string(),
            owner_keypair.public_key.clone(),
            content_hash,
            1024,
            "text/plain".to_string(),
            true,
            0,
            false,
            None,
            vec!["test".to_string()],
            0,
        );

        let file_id = file.file_id;
        assert!(contract.add_file(file).is_ok());
        assert_eq!(contract.file_count(), 1);

        // Should be able to retrieve the file
        assert!(contract.get_file(&file_id).is_some());

        // Should be in user files
        let user_files = contract.get_user_files(&owner_keypair.public_key);
        assert_eq!(user_files.len(), 1);

        // Should be in public files
        let public_files = contract.get_public_files();
        assert_eq!(public_files.len(), 1);

        // Should be in tag index
        let tagged_files = contract.get_files_by_tag("test");
        assert_eq!(tagged_files.len(), 1);
    }

    #[test]
    fn test_file_access_management() {
        let mut contract = FileContract::new();
        let owner_keypair = KeyPair::generate().unwrap();
        let user_keypair = KeyPair::generate().unwrap();
        let content_hash = [1u8; 32];

        let file = SharedFile::new(
            "private.txt".to_string(),
            "A private file".to_string(),
            owner_keypair.public_key.clone(),
            content_hash,
            1024,
            "text/plain".to_string(),
            false, // Private file
            0,
            false,
            None,
            vec![],
            0,
        );

        let file_id = file.file_id;
        assert!(contract.add_file(file).is_ok());

        // User should not have access initially
        let file = contract.get_file(&file_id).unwrap();
        assert!(!file.has_access(&user_keypair.public_key));

        // Grant access to user
        assert!(contract
            .grant_file_access(&file_id, user_keypair.public_key.clone())
            .is_ok());
        let file = contract.get_file(&file_id).unwrap();
        assert!(file.has_access(&user_keypair.public_key));

        // Revoke access
        assert!(contract
            .revoke_file_access(&file_id, &user_keypair.public_key)
            .is_ok());
        let file = contract.get_file(&file_id).unwrap();
        assert!(!file.has_access(&user_keypair.public_key));
    }
}
