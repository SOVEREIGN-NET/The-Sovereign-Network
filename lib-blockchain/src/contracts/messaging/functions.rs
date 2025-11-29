use super::core::{WhisperMessage, MessageContract, MessageThread, GroupThread};
use crate::integration::crypto_integration::PublicKey;
use crate::types::MessageType;
use std::collections::HashMap;

/// Message operation functions for contract system integration

/// Send a direct message
pub fn send_direct_message(
    contract: &mut MessageContract,
    sender: PublicKey,
    recipient: PublicKey,
    encrypted_content: Vec<u8>,
    whisper_tokens_paid: u64,
) -> Result<[u8; 32], String> {
    let message = WhisperMessage::new_direct_message(
        sender,
        recipient,
        encrypted_content,
        whisper_tokens_paid,
    );
    
    let message_id = message.message_id;
    contract.add_message(message)?;
    Ok(message_id)
}

/// Send a group message
pub fn send_group_message(
    contract: &mut MessageContract,
    sender: PublicKey,
    group_id: [u8; 32],
    encrypted_content: Vec<u8>,
    whisper_tokens_paid: u64,
) -> Result<[u8; 32], String> {
    let message = WhisperMessage::new_group_message(
        sender,
        group_id,
        encrypted_content,
        whisper_tokens_paid,
    );
    
    let message_id = message.message_id;
    contract.add_message(message)?;
    Ok(message_id)
}

/// Send a file attachment
pub fn send_file_attachment(
    contract: &mut MessageContract,
    sender: PublicKey,
    recipient: Option<PublicKey>,
    group_id: Option<[u8; 32]>,
    encrypted_content: Vec<u8>,
    whisper_tokens_paid: u64,
) -> Result<[u8; 32], String> {
    let message = WhisperMessage::new_file_attachment(
        sender,
        recipient,
        group_id,
        encrypted_content,
        whisper_tokens_paid,
    );
    
    let message_id = message.message_id;
    contract.add_message(message)?;
    Ok(message_id)
}

/// Send a system message
pub fn send_system_message(
    contract: &mut MessageContract,
    sender: PublicKey,
    recipient: Option<PublicKey>,
    content: Vec<u8>,
) -> Result<[u8; 32], String> {
    let message = WhisperMessage::new_system_message(sender, recipient, content);
    let message_id = message.message_id;
    contract.add_message(message)?;
    Ok(message_id)
}

/// Create an auto-burn message
pub fn send_auto_burn_message(
    contract: &mut MessageContract,
    sender: PublicKey,
    recipient: Option<PublicKey>,
    group_id: Option<[u8; 32]>,
    encrypted_content: Vec<u8>,
    whisper_tokens_paid: u64,
    burn_height: u64,
) -> Result<[u8; 32], String> {
    let message = WhisperMessage::new_auto_burn(
        sender,
        recipient,
        group_id,
        encrypted_content,
        whisper_tokens_paid,
        burn_height,
    );
    
    let message_id = message.message_id;
    contract.add_message(message)?;
    Ok(message_id)
}

/// Get a message by its ID
pub fn get_message<'a>(
    contract: &'a MessageContract,
    message_id: &[u8; 32],
) -> Option<&'a WhisperMessage> {
    contract.get_message(message_id)
}

/// Get all messages for a user
pub fn get_user_messages<'a>(
    contract: &'a MessageContract,
    user: &PublicKey,
) -> Vec<&'a WhisperMessage> {
    contract.get_user_messages(user)
}

/// Get message thread between two users
pub fn get_conversation_thread<'a>(
    contract: &'a MessageContract,
    user1: &PublicKey,
    user2: &PublicKey,
) -> Option<&'a MessageThread> {
    contract.get_thread(user1, user2)
}

/// Get all group messages
pub fn get_group_messages<'a>(
    contract: &'a MessageContract,
    group_id: &[u8; 32],
) -> Vec<&'a WhisperMessage> {
    contract.get_group_messages(group_id)
}

/// Burn a specific message (if user has permission)
pub fn burn_message(
    contract: &mut MessageContract,
    message_id: &[u8; 32],
    user: &PublicKey,
) -> Result<(), String> {
    if let Some(message) = contract.get_message(message_id) {
        if !message.can_be_burned_by(user) {
            return Err("User does not have permission to burn this message".to_string());
        }
    } else {
        return Err("Message not found".to_string());
    }
    
    contract.remove_message(message_id);
    Ok(())
}

/// Burn all expired messages
pub fn burn_expired_messages(
    contract: &mut MessageContract,
    current_height: u64,
) -> usize {
    contract.burn_expired_messages(current_height)
}

/// Get message statistics
pub fn get_message_stats(contract: &MessageContract) -> MessageStats {
    let total_messages = contract.message_count();
    let total_threads = contract.thread_count();
    let total_groups = contract.group_count();
    
    let mut message_type_counts = HashMap::new();
    let mut total_size = 0;
    let mut total_tokens_paid = 0;
    
    for message in contract.messages.values() {
        *message_type_counts.entry(message.message_type.clone()).or_insert(0) += 1;
        total_size += message.size();
        total_tokens_paid += message.whisper_tokens_paid;
    }
    
    MessageStats {
        total_messages,
        total_threads,
        total_groups,
        message_type_counts,
        total_size_bytes: total_size,
        total_tokens_paid,
    }
}

/// Get messages in a specific time range
pub fn get_messages_in_range(
    contract: &MessageContract,
    start_timestamp: u64,
    end_timestamp: u64,
) -> Vec<&WhisperMessage> {
    contract.messages
        .values()
        .filter(|message| {
            message.timestamp >= start_timestamp && message.timestamp <= end_timestamp
        })
        .collect()
}

/// Get messages by type
pub fn get_messages_by_type(
    contract: &MessageContract,
    message_type: MessageType,
) -> Vec<&WhisperMessage> {
    contract.messages
        .values()
        .filter(|message| message.message_type == message_type)
        .collect()
}

/// Get recent messages for a user (last N messages)
pub fn get_recent_user_messages<'a>(
    contract: &'a MessageContract,
    user: &PublicKey,
    limit: usize,
) -> Vec<&'a WhisperMessage> {
    let mut messages = contract.get_user_messages(user);
    messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Sort by timestamp descending
    messages.into_iter().take(limit).collect()
}

/// Search messages by content (requires decryption)
pub fn search_messages<'a>(
    contract: &'a MessageContract,
    user: &PublicKey,
    search_term: &str,
) -> Vec<&'a WhisperMessage> {
    // Note: In a implementation, this would require decrypting messages
    // For now, we'll search in the encrypted content (not very useful)
    let search_bytes = search_term.as_bytes();
    
    contract.get_user_messages(user)
        .into_iter()
        .filter(|message| {
            // This is a placeholder - in reality you'd decrypt first
            message.encrypted_content.windows(search_bytes.len())
                .any(|window| window == search_bytes)
        })
        .collect()
}

/// Get message thread statistics
pub fn get_thread_stats(
    contract: &MessageContract,
    user1: &PublicKey,
    user2: &PublicKey,
) -> Option<ThreadStats> {
    if let Some(thread) = contract.get_thread(user1, user2) {
        let messages: Vec<&WhisperMessage> = thread.message_ids
            .iter()
            .filter_map(|id| contract.get_message(id))
            .collect();
        
        let total_messages = messages.len();
        let total_size: usize = messages.iter().map(|m| m.size()).sum();
        let total_tokens: u64 = messages.iter().map(|m| m.whisper_tokens_paid).sum();
        
        let sent_by_user1 = messages.iter()
            .filter(|m| m.sender == *user1)
            .count();
        let sent_by_user2 = total_messages - sent_by_user1;
        
        Some(ThreadStats {
            total_messages,
            sent_by_user1,
            sent_by_user2,
            total_size_bytes: total_size,
            total_tokens_paid: total_tokens,
            created_at: thread.created_at,
            updated_at: thread.updated_at,
        })
    } else {
        None
    }
}

/// Get group thread statistics
pub fn get_group_stats(
    contract: &MessageContract,
    group_id: &[u8; 32],
) -> Option<GroupStats> {
    if let Some(group) = contract.groups.get(group_id) {
        let messages: Vec<&WhisperMessage> = group.message_ids
            .iter()
            .filter_map(|id| contract.get_message(id))
            .collect();
        
        let total_messages = messages.len();
        let total_size: usize = messages.iter().map(|m| m.size()).sum();
        let total_tokens: u64 = messages.iter().map(|m| m.whisper_tokens_paid).sum();
        
        let mut participants = HashMap::new();
        for message in &messages {
            *participants.entry(message.sender.clone()).or_insert(0) += 1;
        }
        
        Some(GroupStats {
            group_id: *group_id,
            total_messages,
            total_participants: participants.len(),
            message_distribution: participants,
            total_size_bytes: total_size,
            total_tokens_paid: total_tokens,
            created_at: group.created_at,
            updated_at: group.updated_at,
        })
    } else {
        None
    }
}

/// Archive old messages (remove from active storage but keep references)
pub fn archive_old_messages(
    contract: &mut MessageContract,
    older_than_timestamp: u64,
) -> usize {
    let old_messages: Vec<[u8; 32]> = contract.messages
        .iter()
        .filter(|(_, message)| message.timestamp < older_than_timestamp)
        .map(|(id, _)| *id)
        .collect();
    
    for message_id in &old_messages {
        contract.remove_message(message_id);
    }
    
    old_messages.len()
}

/// Message statistics structure
#[derive(Debug, Clone)]
pub struct MessageStats {
    pub total_messages: usize,
    pub total_threads: usize,
    pub total_groups: usize,
    pub message_type_counts: HashMap<MessageType, usize>,
    pub total_size_bytes: usize,
    pub total_tokens_paid: u64,
}

/// Thread statistics structure
#[derive(Debug, Clone)]
pub struct ThreadStats {
    pub total_messages: usize,
    pub sent_by_user1: usize,
    pub sent_by_user2: usize,
    pub total_size_bytes: usize,
    pub total_tokens_paid: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Group statistics structure
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub group_id: [u8; 32],
    pub total_messages: usize,
    pub total_participants: usize,
    pub message_distribution: HashMap<PublicKey, usize>,
    pub total_size_bytes: usize,
    pub total_tokens_paid: u64,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Bulk message operations

/// Send multiple messages in a batch
pub fn send_batch_messages(
    contract: &mut MessageContract,
    messages: Vec<WhisperMessage>,
) -> Result<Vec<[u8; 32]>, String> {
    let mut message_ids = Vec::new();
    
    for message in messages {
        let message_id = message.message_id;
        contract.add_message(message)?;
        message_ids.push(message_id);
    }
    
    Ok(message_ids)
}

/// Get paginated messages for a user
pub fn get_paginated_user_messages<'a>(
    contract: &'a MessageContract,
    user: &PublicKey,
    page: usize,
    page_size: usize,
) -> Vec<&'a WhisperMessage> {
    let mut messages = contract.get_user_messages(user);
    messages.sort_by(|a, b| b.timestamp.cmp(&a.timestamp)); // Most recent first
    
    let start = page * page_size;
    let end = std::cmp::min(start + page_size, messages.len());
    
    if start >= messages.len() {
        Vec::new()
    } else {
        messages[start..end].to_vec()
    }
}

/// Get conversation preview (latest message from each thread)
pub fn get_conversation_previews(
    contract: &MessageContract,
    user: &PublicKey,
) -> Vec<ConversationPreview> {
    let mut previews = Vec::new();
    
    for thread in contract.threads.values() {
        // Check if user is part of this thread
        if thread.participant1 == *user || thread.participant2 == *user {
            if let Some(latest_message_id) = thread.message_ids.last() {
                if let Some(latest_message) = contract.get_message(latest_message_id) {
                    let other_participant = if thread.participant1 == *user {
                        thread.participant2.clone()
                    } else {
                        thread.participant1.clone()
                    };
                    
                    previews.push(ConversationPreview {
                        other_participant,
                        latest_message_id: *latest_message_id,
                        latest_message_timestamp: latest_message.timestamp,
                        message_count: thread.message_count(),
                        is_encrypted: true, // All messages are encrypted
                    });
                }
            }
        }
    }
    
    // Sort by most recent activity
    previews.sort_by(|a, b| b.latest_message_timestamp.cmp(&a.latest_message_timestamp));
    
    previews
}

/// Conversation preview structure
#[derive(Debug, Clone)]
pub struct ConversationPreview {
    pub other_participant: PublicKey,
    pub latest_message_id: [u8; 32],
    pub latest_message_timestamp: u64,
    pub message_count: usize,
    pub is_encrypted: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_public_key(id: u8) -> PublicKey {
        PublicKey::new(vec![id; 1312])
    }

    #[test]
    fn test_send_direct_message() {
        let mut contract = MessageContract::new();
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        
        let message_id = send_direct_message(
            &mut contract,
            sender.clone(),
            recipient.clone(),
            b"Hello!".to_vec(),
            1000,
        ).unwrap();
        
        let message = get_message(&contract, &message_id).unwrap();
        assert_eq!(message.sender, sender);
        assert_eq!(message.recipient, Some(recipient));
        assert!(message.is_direct_message());
    }

    #[test]
    fn test_send_group_message() {
        let mut contract = MessageContract::new();
        let sender = create_test_public_key(1);
        let group_id = [42u8; 32];
        
        let message_id = send_group_message(
            &mut contract,
            sender.clone(),
            group_id,
            b"Hello group!".to_vec(),
            2000,
        ).unwrap();
        
        let message = get_message(&contract, &message_id).unwrap();
        assert_eq!(message.sender, sender);
        assert_eq!(message.group_id, Some(group_id));
        assert!(message.is_group_message());
    }

    #[test]
    fn test_message_burning() {
        let mut contract = MessageContract::new();
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        
        let message_id = send_direct_message(
            &mut contract,
            sender.clone(),
            recipient.clone(),
            b"Burn me".to_vec(),
            1000,
        ).unwrap();
        
        // Sender can burn their own message
        assert!(burn_message(&mut contract, &message_id, &sender).is_ok());
        assert!(get_message(&contract, &message_id).is_none());
    }

    #[test]
    fn test_auto_burn_messages() {
        let mut contract = MessageContract::new();
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        
        // Use future timestamp for burn height
        let future_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600; // 1 hour from now
        
        let _message_id = send_auto_burn_message(
            &mut contract,
            sender.clone(),
            Some(recipient.clone()),
            None,
            b"Auto burn".to_vec(),
            1000,
            future_timestamp,
        ).unwrap();
        
        assert_eq!(contract.message_count(), 1);
        
        // Burn expired messages with timestamp beyond burn_height
        let burned_count = burn_expired_messages(&mut contract, future_timestamp + 1);
        assert_eq!(burned_count, 1);
        assert_eq!(contract.message_count(), 0);
    }

    #[test]
    fn test_message_stats() {
        let mut contract = MessageContract::new();
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        
        // Send a few messages
        for i in 0..3 {
            send_direct_message(
                &mut contract,
                sender.clone(),
                recipient.clone(),
                format!("Message {}", i).into_bytes(),
                1000,
            ).unwrap();
        }
        
        let stats = get_message_stats(&contract);
        assert_eq!(stats.total_messages, 3);
        assert_eq!(stats.total_threads, 1);
        assert_eq!(stats.total_tokens_paid, 3000);
    }

    #[test]
    fn test_conversation_previews() {
        let mut contract = MessageContract::new();
        let user1 = create_test_public_key(1);
        let user2 = create_test_public_key(2);
        let user3 = create_test_public_key(3);
        
        // Create conversations with different users
        send_direct_message(
            &mut contract,
            user1.clone(),
            user2.clone(),
            b"Hello user2".to_vec(),
            1000,
        ).unwrap();
        
        send_direct_message(
            &mut contract,
            user1.clone(),
            user3.clone(),
            b"Hello user3".to_vec(),
            1000,
        ).unwrap();
        
        let previews = get_conversation_previews(&contract, &user1);
        assert_eq!(previews.len(), 2);
        
        // Should be sorted by most recent
        assert!(previews[0].latest_message_timestamp >= previews[1].latest_message_timestamp);
    }

    #[test]
    fn test_paginated_messages() {
        let mut contract = MessageContract::new();
        let sender = create_test_public_key(1);
        let recipient = create_test_public_key(2);
        
        // Send 10 messages
        for i in 0..10 {
            send_direct_message(
                &mut contract,
                sender.clone(),
                recipient.clone(),
                format!("Message {}", i).into_bytes(),
                1000,
            ).unwrap();
        }
        
        // Get first page (5 messages)
        let page1 = get_paginated_user_messages(&contract, &sender, 0, 5);
        assert_eq!(page1.len(), 5);
        
        // Get second page
        let page2 = get_paginated_user_messages(&contract, &sender, 1, 5);
        assert_eq!(page2.len(), 5);
        
        // Get empty page
        let page3 = get_paginated_user_messages(&contract, &sender, 2, 5);
        assert_eq!(page3.len(), 0);
    }
}
