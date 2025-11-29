use serde::{Deserialize, Serialize};
use crate::integration::crypto_integration::PublicKey;
use crate::types::MessageType;
use std::collections::HashMap;

/// Whisper message structure for encrypted messaging
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WhisperMessage {
    /// Unique message identifier
    pub message_id: [u8; 32],
    /// Message sender's public key
    pub sender: PublicKey,
    /// Message recipient's public key (None for group messages)
    pub recipient: Option<PublicKey>,
    /// Group ID if this is a group message
    pub group_id: Option<[u8; 32]>,
    /// Encrypted message content
    pub encrypted_content: Vec<u8>,
    /// Type of message (DirectMessage, GroupMessage, etc.)
    pub message_type: MessageType,
    /// Unix timestamp when message was created
    pub timestamp: u64,
    /// Block height when message should be automatically burned (None = no auto-burn)
    pub burn_height: Option<u64>,
    /// Amount of WHISPER tokens paid for this message
    pub whisper_tokens_paid: u64,
}

impl WhisperMessage {
    /// Create a new direct message
    pub fn new_direct_message(
        sender: PublicKey,
        recipient: PublicKey,
        encrypted_content: Vec<u8>,
        whisper_tokens_paid: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let message_id = crate::contracts::utils::id_generation::generate_message_id(
            &sender.key_id,
            timestamp as u128 * 1_000_000_000, // Convert to nanoseconds
        );

        Self {
            message_id,
            sender,
            recipient: Some(recipient),
            group_id: None,
            encrypted_content,
            message_type: MessageType::DirectMessage,
            timestamp,
            burn_height: None,
            whisper_tokens_paid,
        }
    }

    /// Create a new group message
    pub fn new_group_message(
        sender: PublicKey,
        group_id: [u8; 32],
        encrypted_content: Vec<u8>,
        whisper_tokens_paid: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let message_id = crate::contracts::utils::id_generation::generate_message_id(
            &sender.key_id,
            timestamp as u128 * 1_000_000_000,
        );

        Self {
            message_id,
            sender,
            recipient: None,
            group_id: Some(group_id),
            encrypted_content,
            message_type: MessageType::GroupMessage,
            timestamp,
            burn_height: None,
            whisper_tokens_paid,
        }
    }

    /// Create a file attachment message
    pub fn new_file_attachment(
        sender: PublicKey,
        recipient: Option<PublicKey>,
        group_id: Option<[u8; 32]>,
        encrypted_content: Vec<u8>,
        whisper_tokens_paid: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let message_id = crate::contracts::utils::id_generation::generate_message_id(
            &sender.key_id,
            timestamp as u128 * 1_000_000_000,
        );

        Self {
            message_id,
            sender,
            recipient,
            group_id,
            encrypted_content,
            message_type: MessageType::FileAttachment,
            timestamp,
            burn_height: None,
            whisper_tokens_paid,
        }
    }

    /// Create a system message
    pub fn new_system_message(
        sender: PublicKey,
        recipient: Option<PublicKey>,
        content: Vec<u8>, // System messages are not encrypted
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let message_id = crate::contracts::utils::id_generation::generate_message_id(
            &sender.key_id,
            timestamp as u128 * 1_000_000_000,
        );

        Self {
            message_id,
            sender,
            recipient,
            group_id: None,
            encrypted_content: content,
            message_type: MessageType::SystemMessage,
            timestamp,
            burn_height: None,
            whisper_tokens_paid: 0, // System messages are free
        }
    }

    /// Create a message with auto-burn enabled
    pub fn new_auto_burn(
        sender: PublicKey,
        recipient: Option<PublicKey>,
        group_id: Option<[u8; 32]>,
        encrypted_content: Vec<u8>,
        whisper_tokens_paid: u64,
        burn_height: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let message_id = crate::contracts::utils::id_generation::generate_message_id(
            &sender.key_id,
            timestamp as u128 * 1_000_000_000,
        );

        let message_type = if group_id.is_some() {
            MessageType::GroupMessage
        } else if recipient.is_some() {
            MessageType::DirectMessage
        } else {
            MessageType::SystemMessage
        };

        Self {
            message_id,
            sender,
            recipient,
            group_id,
            encrypted_content,
            message_type,
            timestamp,
            burn_height: Some(burn_height),
            whisper_tokens_paid,
        }
    }

    /// Check if the message is expired (past burn height)
    pub fn is_expired(&self, current_height: u64) -> bool {
        if let Some(burn_height) = self.burn_height {
            current_height >= burn_height
        } else {
            false
        }
    }

    /// Check if the message is a direct message
    pub fn is_direct_message(&self) -> bool {
        matches!(self.message_type, MessageType::DirectMessage) && self.recipient.is_some()
    }

    /// Check if the message is a group message
    pub fn is_group_message(&self) -> bool {
        matches!(self.message_type, MessageType::GroupMessage) && self.group_id.is_some()
    }

    /// Check if the message is a file attachment
    pub fn is_file_attachment(&self) -> bool {
        matches!(self.message_type, MessageType::FileAttachment)
    }

    /// Check if the message can be burned by a specific user
    pub fn can_be_burned_by(&self, user: &PublicKey) -> bool {
        // Sender can always burn their own messages
        if self.sender == *user {
            return true;
        }

        // For direct messages, recipient can also burn
        if let Some(recipient) = &self.recipient {
            if *recipient == *user {
                return true;
            }
        }

        false
    }

    /// Get the message size in bytes
    pub fn size(&self) -> usize {
        32 + // message_id
        self.sender.size() + // sender
        self.recipient.as_ref().map_or(1, |r| r.size() + 1) + // recipient (optional)
        33 + // group_id (optional)
        4 + self.encrypted_content.len() + // encrypted_content with length prefix
        bincode::serialized_size(&self.message_type).unwrap_or(0) as usize + // message_type
        8 + // timestamp
        9 + // burn_height (optional)
        8 // whisper_tokens_paid
    }

    /// Set auto-burn height for the message
    pub fn set_auto_burn(&mut self, burn_height: u64) {
        self.burn_height = Some(burn_height);
    }

    /// Clear auto-burn (message won't auto-burn)
    pub fn clear_auto_burn(&mut self) {
        self.burn_height = None;
    }

    /// Get storage key for this message
    pub fn storage_key(&self) -> Vec<u8> {
        crate::contracts::utils::id_generation::generate_storage_key("message", &self.message_id)
    }

    /// Get a summary of the message for logging
    pub fn summary(&self) -> String {
        format!(
            "WhisperMessage {{ id: {}, type: {}, sender: {}, size: {} bytes, tokens: {} }}",
            hex::encode(self.message_id),
            self.message_type.as_str(),
            hex::encode(&self.sender.key_id),
            self.size(),
            self.whisper_tokens_paid
        )
    }

    /// Validate message structure
    pub fn validate(&self) -> Result<(), String> {
        if self.encrypted_content.is_empty() {
            return Err("Message content cannot be empty".to_string());
        }

        if self.encrypted_content.len() > 1024 * 1024 {
            return Err("Message too large (max 1MB)".to_string());
        }

        match self.message_type {
            MessageType::DirectMessage => {
                if self.recipient.is_none() {
                    return Err("Direct message must have recipient".to_string());
                }
                if self.group_id.is_some() {
                    return Err("Direct message cannot have group ID".to_string());
                }
            }
            MessageType::GroupMessage => {
                if self.group_id.is_none() {
                    return Err("Group message must have group ID".to_string());
                }
            }
            MessageType::FileAttachment => {
                // File attachments can be either direct or group
                if self.recipient.is_none() && self.group_id.is_none() {
                    return Err("File attachment must have either recipient or group ID".to_string());
                }
            }
            MessageType::SystemMessage => {
                if self.whisper_tokens_paid > 0 {
                    return Err("System messages should not require token payment".to_string());
                }
            }
            MessageType::BurnRequest => {
                // Burn requests are special system messages
            }
        }

        if let Some(burn_height) = self.burn_height {
            if burn_height <= self.timestamp / 1000 {
                return Err("Burn height must be in the future".to_string());
            }
        }

        Ok(())
    }
}

/// Message contract for managing message threads and storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageContract {
    /// All messages in the system
    pub messages: HashMap<[u8; 32], WhisperMessage>,
    /// Message threads (conversation organization)
    pub threads: HashMap<[u8; 32], MessageThread>,
    /// Group message organization
    pub groups: HashMap<[u8; 32], GroupThread>,
    /// User message indexes
    pub user_messages: HashMap<PublicKey, Vec<[u8; 32]>>,
}

impl MessageContract {
    /// Create a new message contract
    pub fn new() -> Self {
        Self {
            messages: HashMap::new(),
            threads: HashMap::new(),
            groups: HashMap::new(),
            user_messages: HashMap::new(),
        }
    }

    /// Add a message to the contract
    pub fn add_message(&mut self, message: WhisperMessage) -> Result<(), String> {
        message.validate()?;

        let message_id = message.message_id;
        
        // Add to user message index
        self.user_messages
            .entry(message.sender.clone())
            .or_insert_with(Vec::new)
            .push(message_id);

        if let Some(recipient) = &message.recipient {
            self.user_messages
                .entry(recipient.clone())
                .or_insert_with(Vec::new)
                .push(message_id);
        }

        // Handle thread organization
        if let Some(recipient) = &message.recipient {
            let thread_id = self.get_or_create_thread_id(&message.sender, recipient);
            self.threads
                .entry(thread_id)
                .or_insert_with(|| MessageThread::new(message.sender.clone(), recipient.clone()))
                .add_message(message_id);
        }

        if let Some(group_id) = message.group_id {
            self.groups
                .entry(group_id)
                .or_insert_with(|| GroupThread::new(group_id))
                .add_message(message_id);
        }

        // Store the message
        self.messages.insert(message_id, message);

        Ok(())
    }

    /// Get a message by ID
    pub fn get_message(&self, message_id: &[u8; 32]) -> Option<&WhisperMessage> {
        self.messages.get(message_id)
    }

    /// Get messages for a user
    pub fn get_user_messages(&self, user: &PublicKey) -> Vec<&WhisperMessage> {
        self.user_messages
            .get(user)
            .map(|message_ids| {
                message_ids
                    .iter()
                    .filter_map(|id| self.messages.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get message thread between two users
    pub fn get_thread(&self, user1: &PublicKey, user2: &PublicKey) -> Option<&MessageThread> {
        let thread_id = self.get_thread_id(user1, user2);
        self.threads.get(&thread_id)
    }

    /// Get group messages
    pub fn get_group_messages(&self, group_id: &[u8; 32]) -> Vec<&WhisperMessage> {
        self.groups
            .get(group_id)
            .map(|group| {
                group.message_ids
                    .iter()
                    .filter_map(|id| self.messages.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Burn expired messages
    pub fn burn_expired_messages(&mut self, current_height: u64) -> usize {
        let expired_ids: Vec<[u8; 32]> = self.messages
            .iter()
            .filter(|(_, message)| message.is_expired(current_height))
            .map(|(id, _)| *id)
            .collect();

        for id in &expired_ids {
            self.remove_message(id);
        }

        expired_ids.len()
    }

    /// Remove a message
    pub fn remove_message(&mut self, message_id: &[u8; 32]) -> Option<WhisperMessage> {
        if let Some(message) = self.messages.remove(message_id) {
            // Remove from user indexes
            if let Some(user_messages) = self.user_messages.get_mut(&message.sender) {
                user_messages.retain(|id| id != message_id);
            }

            if let Some(recipient) = &message.recipient {
                if let Some(user_messages) = self.user_messages.get_mut(recipient) {
                    user_messages.retain(|id| id != message_id);
                }
            }

            // Remove from threads
            if let Some(recipient) = &message.recipient {
                let thread_id = self.get_thread_id(&message.sender, recipient);
                if let Some(thread) = self.threads.get_mut(&thread_id) {
                    thread.remove_message(message_id);
                }
            }

            if let Some(group_id) = message.group_id {
                if let Some(group) = self.groups.get_mut(&group_id) {
                    group.remove_message(message_id);
                }
            }

            Some(message)
        } else {
            None
        }
    }

    /// Get or create thread ID for two users
    fn get_or_create_thread_id(&self, user1: &PublicKey, user2: &PublicKey) -> [u8; 32] {
        self.get_thread_id(user1, user2)
    }

    /// Get thread ID for two users (deterministic)
    fn get_thread_id(&self, user1: &PublicKey, user2: &PublicKey) -> [u8; 32] {
        let mut data = Vec::new();
        
        // Ensure deterministic ordering
        if user1.key_id < user2.key_id {
            data.extend_from_slice(&user1.key_id);
            data.extend_from_slice(&user2.key_id);
        } else {
            data.extend_from_slice(&user2.key_id);
            data.extend_from_slice(&user1.key_id);
        }
        
        crate::contracts::utils::id_generation::hash_data(&data)
    }

    /// Get message count
    pub fn message_count(&self) -> usize {
        self.messages.len()
    }

    /// Get thread count
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }

    /// Get group count
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

/// Message thread between two users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageThread {
    pub participant1: PublicKey,
    pub participant2: PublicKey,
    pub message_ids: Vec<[u8; 32]>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl MessageThread {
    pub fn new(participant1: PublicKey, participant2: PublicKey) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            participant1,
            participant2,
            message_ids: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn add_message(&mut self, message_id: [u8; 32]) {
        self.message_ids.push(message_id);
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn remove_message(&mut self, message_id: &[u8; 32]) {
        self.message_ids.retain(|id| id != message_id);
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn message_count(&self) -> usize {
        self.message_ids.len()
    }
}

/// Group message thread
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupThread {
    pub group_id: [u8; 32],
    pub message_ids: Vec<[u8; 32]>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl GroupThread {
    pub fn new(group_id: [u8; 32]) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            group_id,
            message_ids: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    pub fn add_message(&mut self, message_id: [u8; 32]) {
        self.message_ids.push(message_id);
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn remove_message(&mut self, message_id: &[u8; 32]) {
        self.message_ids.retain(|id| id != message_id);
        self.updated_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    pub fn message_count(&self) -> usize {
        self.message_ids.len()
    }
}

/// Collection of message threads for export
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageThreads {
    pub threads: HashMap<[u8; 32], MessageThread>,
    pub groups: HashMap<[u8; 32], GroupThread>,
}

impl Default for MessageContract {
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
    fn test_message_creation() {
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        let content = b"Hello, world!".to_vec();

        let message = WhisperMessage::new_direct_message(
            sender.clone(),
            recipient.clone(),
            content.clone(),
            1000,
        );

        assert_eq!(message.sender, sender);
        assert_eq!(message.recipient, Some(recipient));
        assert_eq!(message.encrypted_content, content);
        assert_eq!(message.whisper_tokens_paid, 1000);
        assert!(message.is_direct_message());
    }

    #[test]
    fn test_message_contract() {
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        let mut contract = MessageContract::new();

        let message = WhisperMessage::new_direct_message(
            sender.clone(),
            recipient.clone(),
            b"test message".to_vec(),
            1000,
        );

        let message_id = message.message_id;
        assert!(contract.add_message(message).is_ok());
        assert_eq!(contract.message_count(), 1);

        let retrieved = contract.get_message(&message_id).unwrap();
        assert_eq!(retrieved.sender, sender);

        let user_messages = contract.get_user_messages(&sender);
        assert_eq!(user_messages.len(), 1);
    }

    #[test]
    fn test_message_threads() {
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        let mut contract = MessageContract::new();

        // Add multiple messages
        for i in 0..3 {
            let message = WhisperMessage::new_direct_message(
                sender.clone(),
                recipient.clone(),
                format!("message {}", i).into_bytes(),
                1000,
            );
            contract.add_message(message).unwrap();
        }

        let thread = contract.get_thread(&sender, &recipient).unwrap();
        assert_eq!(thread.message_count(), 3);
        assert_eq!(thread.participant1, sender);
        assert_eq!(thread.participant2, recipient);
    }

    #[test]
    fn test_auto_burn() {
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        let mut contract = MessageContract::new();

        // Create message with auto-burn - use future timestamp
        let future_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour from now

        let message = WhisperMessage::new_auto_burn(
            sender.clone(),
            Some(recipient.clone()),
            None,
            b"burn me".to_vec(),
            1000,
            future_timestamp,
        );

        contract.add_message(message).unwrap();
        assert_eq!(contract.message_count(), 1);

        // Burn expired messages with timestamp beyond burn_height
        let burned_count = contract.burn_expired_messages(future_timestamp + 1);
        assert_eq!(burned_count, 1);
        assert_eq!(contract.message_count(), 0);
    }
}
