use serde::{Deserialize, Serialize};

/// Contract event log for efficient querying and monitoring
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractLog {
    /// ID of the contract that emitted this log
    pub contract_id: [u8; 32],
    /// Event name (e.g., "Transfer", "MessageSent", "GroupCreated")
    pub event: String,
    /// Event data (serialized event parameters)
    pub data: Vec<u8>,
    /// Indexed fields for efficient filtering and searching
    pub indexed_fields: Vec<Vec<u8>>,
}

impl ContractLog {
    /// Create a new contract log
    pub fn new(
        contract_id: [u8; 32],
        event: String,
        data: Vec<u8>,
        indexed_fields: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            contract_id,
            event,
            data,
            indexed_fields,
        }
    }

    /// Create a log with serialized data
    pub fn with_data<T: Serialize>(
        contract_id: [u8; 32],
        event: String,
        data: &T,
        indexed_fields: Vec<Vec<u8>>,
    ) -> Result<Self, bincode::Error> {
        Ok(Self {
            contract_id,
            event,
            data: bincode::serialize(data)?,
            indexed_fields,
        })
    }

    /// Create a Transfer event log
    pub fn transfer_event(
        contract_id: [u8; 32],
        from: &[u8],
        to: &[u8],
        amount: u64,
    ) -> Result<Self, bincode::Error> {
        let data = (from, to, amount);
        Self::with_data(
            contract_id,
            "Transfer".to_string(),
            &data,
            vec![from.to_vec(), to.to_vec()],
        )
    }

    /// Create a MessageSent event log
    pub fn message_sent_event(
        contract_id: [u8; 32],
        sender: &[u8],
        recipient: Option<&[u8]>,
        message_id: &[u8; 32],
    ) -> Result<Self, bincode::Error> {
        let data = (sender, recipient, message_id);
        let mut indexed_fields = vec![sender.to_vec()];
        if let Some(recipient) = recipient {
            indexed_fields.push(recipient.to_vec());
        }

        Self::with_data(
            contract_id,
            "MessageSent".to_string(),
            &data,
            indexed_fields,
        )
    }

    /// Create a GroupCreated event log
    pub fn group_created_event(
        contract_id: [u8; 32],
        creator: &[u8],
        group_id: &[u8; 32],
        group_name: &str,
    ) -> Result<Self, bincode::Error> {
        let data = (creator, group_id, group_name);
        Self::with_data(
            contract_id,
            "GroupCreated".to_string(),
            &data,
            vec![creator.to_vec()],
        )
    }

    /// Create a ContactAdded event log
    pub fn contact_added_event(
        contract_id: [u8; 32],
        owner: &[u8],
        contact_id: &[u8; 32],
        contact_key: &[u8],
    ) -> Result<Self, bincode::Error> {
        let data = (owner, contact_id, contact_key);
        Self::with_data(
            contract_id,
            "ContactAdded".to_string(),
            &data,
            vec![owner.to_vec(), contact_key.to_vec()],
        )
    }

    /// Get the event data as a specific type
    pub fn get_data<T: for<'de> Deserialize<'de>>(&self) -> Result<T, bincode::Error> {
        bincode::deserialize(&self.data)
    }

    /// Check if this log contains a specific indexed field
    pub fn has_indexed_field(&self, field: &[u8]) -> bool {
        self.indexed_fields.iter().any(|f| f == field)
    }

    /// Get the size of the log in bytes (for storage calculations)
    pub fn size(&self) -> usize {
        32 + // contract_id
        4 + self.event.len() + // event string with length prefix
        4 + self.data.len() + // data with length prefix
        4 + self.indexed_fields.iter().map(|f| 4 + f.len()).sum::<usize>() // indexed_fields with length prefixes
    }

    /// Check if this is a specific event type
    pub fn is_event(&self, event_name: &str) -> bool {
        self.event == event_name
    }

    /// Get a summary of the log for debugging
    pub fn summary(&self) -> String {
        format!(
            "ContractLog {{ contract: {}, event: {}, data_size: {}, indexed_fields: {} }}",
            hex::encode(self.contract_id),
            self.event,
            self.data.len(),
            self.indexed_fields.len()
        )
    }
}

/// Event types commonly used in ZHTP contracts
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    // Token events
    Transfer,
    Mint,
    Burn,
    Approval,

    // Messaging events
    MessageSent,
    MessageBurned,
    MessageDelivered,

    // Contact events
    ContactAdded,
    ContactRemoved,
    ContactVerified,

    // Group events
    GroupCreated,
    MemberJoined,
    MemberLeft,
    AdminAdded,

    // File events
    FileShared,
    FileAccessed,
    FileRemoved,

    // Governance events
    ProposalCreated,
    VoteCast,
    ProposalExecuted,

    // System events
    ContractUpgraded,
    ContractPaused,
    ContractUnpaused,
}

impl EventType {
    /// Get the string representation of the event type
    pub fn as_str(&self) -> &'static str {
        match self {
            EventType::Transfer => "Transfer",
            EventType::Mint => "Mint",
            EventType::Burn => "Burn",
            EventType::Approval => "Approval",
            EventType::MessageSent => "MessageSent",
            EventType::MessageBurned => "MessageBurned",
            EventType::MessageDelivered => "MessageDelivered",
            EventType::ContactAdded => "ContactAdded",
            EventType::ContactRemoved => "ContactRemoved",
            EventType::ContactVerified => "ContactVerified",
            EventType::GroupCreated => "GroupCreated",
            EventType::MemberJoined => "MemberJoined",
            EventType::MemberLeft => "MemberLeft",
            EventType::AdminAdded => "AdminAdded",
            EventType::FileShared => "FileShared",
            EventType::FileAccessed => "FileAccessed",
            EventType::FileRemoved => "FileRemoved",
            EventType::ProposalCreated => "ProposalCreated",
            EventType::VoteCast => "VoteCast",
            EventType::ProposalExecuted => "ProposalExecuted",
            EventType::ContractUpgraded => "ContractUpgraded",
            EventType::ContractPaused => "ContractPaused",
            EventType::ContractUnpaused => "ContractUnpaused",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contract_log_creation() {
        let contract_id = [1u8; 32];
        let event = "Transfer".to_string();
        let data = vec![1, 2, 3, 4];
        let indexed_fields = vec![vec![5, 6], vec![7, 8]];

        let log = ContractLog::new(
            contract_id,
            event.clone(),
            data.clone(),
            indexed_fields.clone(),
        );

        assert_eq!(log.contract_id, contract_id);
        assert_eq!(log.event, event);
        assert_eq!(log.data, data);
        assert_eq!(log.indexed_fields, indexed_fields);
    }

    #[test]
    fn test_contract_log_with_data() {
        let contract_id = [1u8; 32];
        let test_data = (42u64, "test".to_string());
        let indexed_fields = vec![vec![1, 2, 3]];

        let log = ContractLog::with_data(
            contract_id,
            "TestEvent".to_string(),
            &test_data,
            indexed_fields,
        )
        .unwrap();

        let recovered_data: (u64, String) = log.get_data().unwrap();
        assert_eq!(recovered_data, test_data);
    }

    #[test]
    fn test_transfer_event_log() {
        let contract_id = [1u8; 32];
        let from = b"from_address";
        let to = b"to_address";
        let amount = 1000u64;

        let log = ContractLog::transfer_event(contract_id, from, to, amount).unwrap();

        assert_eq!(log.event, "Transfer");
        assert_eq!(log.indexed_fields.len(), 2);
        assert!(log.has_indexed_field(from));
        assert!(log.has_indexed_field(to));

        let (recovered_from, recovered_to, recovered_amount): (Vec<u8>, Vec<u8>, u64) =
            log.get_data().unwrap();
        assert_eq!(recovered_from.as_slice(), from);
        assert_eq!(recovered_to.as_slice(), to);
        assert_eq!(recovered_amount, amount);
    }

    #[test]
    fn test_message_sent_event() {
        let contract_id = [2u8; 32];
        let sender = b"sender_key";
        let recipient = Some(b"recipient_key".as_slice());
        let message_id = [3u8; 32];

        let log =
            ContractLog::message_sent_event(contract_id, sender, recipient, &message_id).unwrap();

        assert_eq!(log.event, "MessageSent");
        assert_eq!(log.indexed_fields.len(), 2);
        assert!(log.has_indexed_field(sender));
        assert!(log.has_indexed_field(b"recipient_key"));
    }

    #[test]
    fn test_group_created_event() {
        let contract_id = [4u8; 32];
        let creator = b"creator_key";
        let group_id = [5u8; 32];
        let group_name = "Test Group";

        let log =
            ContractLog::group_created_event(contract_id, creator, &group_id, group_name).unwrap();

        assert_eq!(log.event, "GroupCreated");
        assert_eq!(log.indexed_fields.len(), 1);
        assert!(log.has_indexed_field(creator));
    }

    #[test]
    fn test_log_utilities() {
        let contract_id = [1u8; 32];
        let log = ContractLog::new(
            contract_id,
            "TestEvent".to_string(),
            vec![1, 2, 3, 4, 5],
            vec![vec![6, 7], vec![8, 9, 10]],
        );

        assert!(log.is_event("TestEvent"));
        assert!(!log.is_event("OtherEvent"));

        assert!(log.has_indexed_field(&[6, 7]));
        assert!(!log.has_indexed_field(&[11, 12]));

        let size = log.size();
        assert!(size > 0);

        let summary = log.summary();
        assert!(summary.contains("TestEvent"));
        assert!(summary.contains("data_size: 5"));
        assert!(summary.contains("indexed_fields: 2"));
    }

    #[test]
    fn test_event_type_strings() {
        assert_eq!(EventType::Transfer.as_str(), "Transfer");
        assert_eq!(EventType::MessageSent.as_str(), "MessageSent");
        assert_eq!(EventType::GroupCreated.as_str(), "GroupCreated");
        assert_eq!(EventType::ProposalCreated.as_str(), "ProposalCreated");
    }
}
