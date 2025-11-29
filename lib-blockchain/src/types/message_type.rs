use serde::{Deserialize, Serialize};

/// Message types for Whisper messaging system
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Direct message between two users
    DirectMessage,
    /// Message sent to a group
    GroupMessage,
    /// File attachment message
    FileAttachment,
    /// System-generated message
    SystemMessage,
    /// Message burn request
    BurnRequest,
}

impl MessageType {
    /// Get string representation of message type
    pub fn as_str(&self) -> &'static str {
        match self {
            MessageType::DirectMessage => "DirectMessage",
            MessageType::GroupMessage => "GroupMessage",
            MessageType::FileAttachment => "FileAttachment",
            MessageType::SystemMessage => "SystemMessage",
            MessageType::BurnRequest => "BurnRequest",
        }
    }

    /// Check if this message type supports encryption
    pub fn supports_encryption(&self) -> bool {
        matches!(
            self,
            MessageType::DirectMessage | MessageType::GroupMessage | MessageType::FileAttachment
        )
    }

    /// Check if this message type can be burned
    pub fn can_be_burned(&self) -> bool {
        matches!(
            self,
            MessageType::DirectMessage | MessageType::GroupMessage | MessageType::FileAttachment
        )
    }

    /// Get the base gas cost for this message type
    pub fn base_gas_cost(&self) -> u64 {
        match self {
            MessageType::DirectMessage => 3000,
            MessageType::GroupMessage => 4000, // Higher cost for group distribution
            MessageType::FileAttachment => 5000, // Highest cost for file handling
            MessageType::SystemMessage => 1000, // Lower cost for system messages
            MessageType::BurnRequest => 1500, // Moderate cost for burning
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_type_properties() {
        assert_eq!(MessageType::DirectMessage.as_str(), "DirectMessage");
        assert!(MessageType::DirectMessage.supports_encryption());
        assert!(MessageType::DirectMessage.can_be_burned());
        assert_eq!(MessageType::DirectMessage.base_gas_cost(), 3000);

        assert_eq!(MessageType::GroupMessage.as_str(), "GroupMessage");
        assert!(MessageType::GroupMessage.supports_encryption());
        assert!(MessageType::GroupMessage.can_be_burned());
        assert_eq!(MessageType::GroupMessage.base_gas_cost(), 4000);

        assert_eq!(MessageType::FileAttachment.as_str(), "FileAttachment");
        assert!(MessageType::FileAttachment.supports_encryption());
        assert!(MessageType::FileAttachment.can_be_burned());
        assert_eq!(MessageType::FileAttachment.base_gas_cost(), 5000);

        assert_eq!(MessageType::SystemMessage.as_str(), "SystemMessage");
        assert!(!MessageType::SystemMessage.supports_encryption());
        assert!(!MessageType::SystemMessage.can_be_burned());
        assert_eq!(MessageType::SystemMessage.base_gas_cost(), 1000);

        assert_eq!(MessageType::BurnRequest.as_str(), "BurnRequest");
        assert!(!MessageType::BurnRequest.supports_encryption());
        assert!(!MessageType::BurnRequest.can_be_burned());
        assert_eq!(MessageType::BurnRequest.base_gas_cost(), 1500);
    }

    #[test]
    fn test_message_type_serialization() {
        let message_type = MessageType::DirectMessage;
        let serialized = bincode::serialize(&message_type).unwrap();
        let deserialized: MessageType = bincode::deserialize(&serialized).unwrap();
        assert_eq!(message_type, deserialized);
    }
}
