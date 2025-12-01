//! Multi-layer addressing system for ZHTP network
//! 
//! This module provides a universal addressing scheme that supports:
//! - IP addresses for traditional networking
//! - DHT hashes for content-based addressing
//! - Quantum identities for cryptographic addressing
//! - Wallet identities for wallet-to-node communication
//! - Hybrid addresses for maximum flexibility
//!
//! ## Wallet Addressing Features
//!
//! Wallet addressing enables:
//! - Wallet-to-node communication and control
//! - Different wallet types: User, NodeOperator, Validator, Governance, System
//! - Node control permissions based on wallet type
//! - Governance participation capabilities
//! - `wallet://` URI scheme for addressing

use std::net::SocketAddr;
use std::fmt;
use serde::{Deserialize, Serialize};
use lib_crypto::{Hash, PublicKey};

/// Quantum Identity Descriptor - cryptographic identity address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct QuantumIdentity {
    /// Public key for the quantum identity
    pub public_key: PublicKey,
    /// Optional human-readable name
    pub display_name: Option<String>,
    /// Identity verification hash
    pub identity_hash: Hash,
}

/// Wallet Identity Descriptor - wallet-to-node addressing
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WalletIdentity {
    /// Wallet public key for identification
    pub wallet_public_key: PublicKey,
    /// Wallet address derived from public key
    pub wallet_address: Hash,
    /// Optional wallet name/label
    pub wallet_name: Option<String>,
    /// Associated node public key (if this wallet controls a node)
    pub node_public_key: Option<PublicKey>,
    /// Wallet type descriptor
    pub wallet_type: WalletType,
}

/// Types of wallets that can address nodes
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WalletType {
    /// Standard user wallet
    User,
    /// Node operator wallet (controls a node)
    NodeOperator,
    /// Validator wallet (participates in consensus)
    Validator,
    /// DAO governance wallet
    Governance,
    /// System/contract wallet
    System,
}

/// Individual address type within a hybrid address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AddressType {
    /// IP socket address
    Ip(SocketAddr),
    /// DHT content hash
    Dht(Hash),
    /// Quantum cryptographic identity
    Quantum(QuantumIdentity),
    /// Wallet identity for wallet-to-node addressing
    Wallet(WalletIdentity),
}

/// Universal addressing system for ZHTP network
/// 
/// This enum allows any network entity (nodes, wallets, content) to be 
/// addressed through multiple mechanisms, providing flexibility and 
/// redundancy in network operations.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeAddress {
    /// Direct IP address - traditional networking
    /// 
    /// Example: `NodeAddress::IpAddress("192.168.1.100:9333".parse().unwrap())`
    IpAddress(SocketAddr),
    
    /// DHT hash address - content-based addressing
    /// 
    /// Used for content-addressable storage and routing based on 
    /// cryptographic hashes rather than network locations.
    DHTHash(Hash),
    
    /// Quantum identity address - cryptographic identity
    /// 
    /// Addresses entities by their cryptographic identity, enabling
    /// privacy-preserving communications and identity-based routing.
    QuantumIdentity(QuantumIdentity),
    
    /// Wallet identity address - wallet-to-node addressing
    /// 
    /// Enables wallets to directly address and communicate with nodes,
    /// supporting wallet-controlled node operations and governance.
    WalletIdentity(WalletIdentity),
    
    /// Hybrid address - multiple addressing methods
    /// 
    /// Allows an entity to be reachable through multiple address types,
    /// providing redundancy and flexibility in network operations.
    HybridAddress(Vec<AddressType>),
}

impl NodeAddress {
    /// Create a new IP address
    pub fn new_ip(addr: SocketAddr) -> Self {
        Self::IpAddress(addr)
    }
    
    /// Create a new DHT hash address
    pub fn new_dht_hash(hash: Hash) -> Self {
        Self::DHTHash(hash)
    }
    
    /// Create a new quantum identity address
    pub fn new_quantum_identity(public_key: PublicKey, display_name: Option<String>) -> Self {
        let identity_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&public_key.as_bytes()));
        let quantum_id = QuantumIdentity {
            public_key,
            display_name,
            identity_hash,
        };
        Self::QuantumIdentity(quantum_id)
    }
    
    /// Create a new wallet identity address
    pub fn new_wallet_identity(
        wallet_public_key: PublicKey, 
        wallet_name: Option<String>,
        node_public_key: Option<PublicKey>,
        wallet_type: WalletType
    ) -> Self {
        let wallet_address = Hash::from_bytes(&lib_crypto::hash_blake3(&wallet_public_key.as_bytes()));
        let wallet_id = WalletIdentity {
            wallet_public_key,
            wallet_address,
            wallet_name,
            node_public_key,
            wallet_type,
        };
        Self::WalletIdentity(wallet_id)
    }
    
    /// Create a hybrid address from multiple address types
    pub fn new_hybrid(addresses: Vec<AddressType>) -> Self {
        Self::HybridAddress(addresses)
    }
    
    /// Check if this address contains an IP component
    pub fn has_ip(&self) -> bool {
        match self {
            Self::IpAddress(_) => true,
            Self::HybridAddress(addrs) => {
                addrs.iter().any(|addr| matches!(addr, AddressType::Ip(_)))
            }
            _ => false,
        }
    }
    
    /// Get the IP address if this address contains one
    pub fn get_ip(&self) -> Option<SocketAddr> {
        match self {
            Self::IpAddress(addr) => Some(*addr),
            Self::HybridAddress(addrs) => {
                for addr in addrs {
                    if let AddressType::Ip(socket_addr) = addr {
                        return Some(*socket_addr);
                    }
                }
                None
            }
            _ => None,
        }
    }
    
    /// Check if this address contains a DHT hash component
    pub fn has_dht_hash(&self) -> bool {
        match self {
            Self::DHTHash(_) => true,
            Self::HybridAddress(addrs) => {
                addrs.iter().any(|addr| matches!(addr, AddressType::Dht(_)))
            }
            _ => false,
        }
    }
    
    /// Get the DHT hash if this address contains one
    pub fn get_dht_hash(&self) -> Option<Hash> {
        match self {
            Self::DHTHash(hash) => Some(hash.clone()),
            Self::HybridAddress(addrs) => {
                for addr in addrs {
                    if let AddressType::Dht(hash) = addr {
                        return Some(hash.clone());
                    }
                }
                None
            }
            _ => None,
        }
    }
    
    /// Check if this address contains a quantum identity component
    pub fn has_quantum_identity(&self) -> bool {
        match self {
            Self::QuantumIdentity(_) => true,
            Self::HybridAddress(addrs) => {
                addrs.iter().any(|addr| matches!(addr, AddressType::Quantum(_)))
            }
            _ => false,
        }
    }
    
    /// Check if this address contains a wallet identity component
    pub fn has_wallet_identity(&self) -> bool {
        match self {
            Self::WalletIdentity(_) => true,
            Self::HybridAddress(addrs) => {
                addrs.iter().any(|addr| matches!(addr, AddressType::Wallet(_)))
            }
            _ => false,
        }
    }
    
    /// Get the quantum identity if this address contains one
    pub fn get_quantum_identity(&self) -> Option<&QuantumIdentity> {
        match self {
            Self::QuantumIdentity(qid) => Some(qid),
            Self::HybridAddress(addrs) => {
                for addr in addrs {
                    if let AddressType::Quantum(qid) = addr {
                        return Some(qid);
                    }
                }
                None
            }
            _ => None,
        }
    }
    
    /// Get the wallet identity if this address contains one
    pub fn get_wallet_identity(&self) -> Option<&WalletIdentity> {
        match self {
            Self::WalletIdentity(wid) => Some(wid),
            Self::HybridAddress(addrs) => {
                for addr in addrs {
                    if let AddressType::Wallet(wid) = addr {
                        return Some(wid);
                    }
                }
                None
            }
            _ => None,
        }
    }
    
    /// Get all address types in this NodeAddress
    pub fn get_all_addresses(&self) -> Vec<AddressType> {
        match self {
            Self::IpAddress(addr) => vec![AddressType::Ip(*addr)],
            Self::DHTHash(hash) => vec![AddressType::Dht(hash.clone())],
            Self::QuantumIdentity(qid) => vec![AddressType::Quantum(qid.clone())],
            Self::WalletIdentity(wid) => vec![AddressType::Wallet(wid.clone())],
            Self::HybridAddress(addrs) => addrs.clone(),
        }
    }
    
    /// Check if this address can be used for direct networking
    pub fn is_networkable(&self) -> bool {
        self.has_ip()
    }
    
    /// Check if this address supports content-based routing
    pub fn is_content_addressable(&self) -> bool {
        self.has_dht_hash()
    }
    
    /// Check if this address supports identity-based operations
    pub fn is_identity_based(&self) -> bool {
        self.has_quantum_identity() || self.has_wallet_identity()
    }
    
    /// Check if this address supports wallet operations
    pub fn is_wallet_controlled(&self) -> bool {
        self.has_wallet_identity()
    }
    
    /// Check if this wallet controls a node (for node operator wallets)
    pub fn controls_node(&self) -> bool {
        if let Some(wallet) = self.get_wallet_identity() {
            wallet.node_public_key.is_some() && 
            matches!(wallet.wallet_type, WalletType::NodeOperator | WalletType::Validator)
        } else {
            false
        }
    }
    
    /// Check if this address can participate in governance
    pub fn can_govern(&self) -> bool {
        if let Some(wallet) = self.get_wallet_identity() {
            wallet.can_govern()
        } else {
            false
        }
    }
    
    /// Get the URI scheme for this address type
    pub fn to_uri_scheme(&self) -> &'static str {
        match self {
            NodeAddress::IpAddress(_) => "ip://",
            NodeAddress::DHTHash(_) => "dht://", 
            NodeAddress::QuantumIdentity(_) => "qid://",
            NodeAddress::WalletIdentity(_) => "wallet://",
            NodeAddress::HybridAddress(_) => "hybrid://",
        }
    }
}

impl fmt::Display for NodeAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IpAddress(addr) => write!(f, "ip://{}", addr),
            Self::DHTHash(hash) => write!(f, "dht://{}", hex::encode(hash.as_bytes())),
            Self::QuantumIdentity(qid) => {
                if let Some(name) = &qid.display_name {
                    write!(f, "qid://{}@{}", name, hex::encode(qid.identity_hash.as_bytes()))
                } else {
                    write!(f, "qid://{}", hex::encode(qid.identity_hash.as_bytes()))
                }
            }
            Self::WalletIdentity(wid) => {
                if let Some(name) = &wid.wallet_name {
                    write!(f, "wallet://{}@{}", name, hex::encode(wid.wallet_address.as_bytes()))
                } else {
                    write!(f, "wallet://{}", hex::encode(wid.wallet_address.as_bytes()))
                }
            }
            Self::HybridAddress(addrs) => {
                let addr_strs: Vec<String> = addrs.iter().map(|addr| {
                    match addr {
                        AddressType::Ip(ip) => format!("ip://{}", ip),
                        AddressType::Dht(hash) => format!("dht://{}", hex::encode(hash.as_bytes())),
                        AddressType::Quantum(qid) => {
                            if let Some(name) = &qid.display_name {
                                format!("qid://{}@{}", name, hex::encode(qid.identity_hash.as_bytes()))
                            } else {
                                format!("qid://{}", hex::encode(qid.identity_hash.as_bytes()))
                            }
                        }
                        AddressType::Wallet(wid) => {
                            if let Some(name) = &wid.wallet_name {
                                format!("wallet://{}@{}", name, hex::encode(wid.wallet_address.as_bytes()))
                            } else {
                                format!("wallet://{}", hex::encode(wid.wallet_address.as_bytes()))
                            }
                        }
                    }
                }).collect();
                write!(f, "hybrid://[{}]", addr_strs.join(","))
            }
        }
    }
}

impl QuantumIdentity {
    /// Create a new quantum identity
    pub fn new(public_key: PublicKey, display_name: Option<String>) -> Self {
        let identity_hash = Hash::from_bytes(&lib_crypto::hash_blake3(&public_key.as_bytes()));
        Self {
            public_key,
            display_name,
            identity_hash,
        }
    }
    
    /// Get the short identity hash (first 8 bytes for display)
    pub fn short_hash(&self) -> String {
        hex::encode(&self.identity_hash.as_bytes()[..8])
    }
    
    /// Get the full identity hash as hex string
    pub fn full_hash(&self) -> String {
        hex::encode(self.identity_hash.as_bytes())
    }
}

impl fmt::Display for QuantumIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.display_name {
            write!(f, "{}@{}", name, self.short_hash())
        } else {
            write!(f, "{}", self.short_hash())
        }
    }
}

impl WalletIdentity {
    /// Create a new wallet identity
    pub fn new(
        wallet_public_key: PublicKey, 
        wallet_name: Option<String>,
        node_public_key: Option<PublicKey>,
        wallet_type: WalletType
    ) -> Self {
        let wallet_address = Hash::from_bytes(&lib_crypto::hash_blake3(&wallet_public_key.as_bytes()));
        Self {
            wallet_public_key,
            wallet_address,
            wallet_name,
            node_public_key,
            wallet_type,
        }
    }
    
    /// Get the short wallet address (first 8 bytes for display)
    pub fn short_address(&self) -> String {
        hex::encode(&self.wallet_address.as_bytes()[..8])
    }
    
    /// Get the full wallet address as hex string
    pub fn full_address(&self) -> String {
        hex::encode(self.wallet_address.as_bytes())
    }
    
    /// Check if this wallet controls a node
    pub fn controls_node(&self) -> bool {
        self.node_public_key.is_some() && 
        matches!(self.wallet_type, WalletType::NodeOperator | WalletType::Validator)
    }
    
    /// Check if this wallet can participate in governance
    pub fn can_govern(&self) -> bool {
        matches!(self.wallet_type, WalletType::Governance | WalletType::Validator)
    }
}

impl fmt::Display for WalletIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = &self.wallet_name {
            write!(f, "{}@{}", name, self.short_address())
        } else {
            write!(f, "{}", self.short_address())
        }
    }
}

impl fmt::Display for WalletType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WalletType::User => write!(f, "user"),
            WalletType::NodeOperator => write!(f, "node_operator"),
            WalletType::Validator => write!(f, "validator"),
            WalletType::Governance => write!(f, "governance"),
            WalletType::System => write!(f, "system"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    
    #[test]
    fn test_ip_address() {
        let addr = SocketAddr::from_str("192.168.1.100:9333").unwrap();
        let node_addr = NodeAddress::new_ip(addr);
        
        assert!(node_addr.has_ip());
        assert_eq!(node_addr.get_ip(), Some(addr));
        assert!(node_addr.is_networkable());
        assert!(!node_addr.is_content_addressable());
        assert!(!node_addr.is_identity_based());
    }
    
    #[test]
    fn test_dht_hash() {
        let hash = Hash::from_bytes(b"test_content_hash_32_bytes_long!");
        let node_addr = NodeAddress::new_dht_hash(hash.clone());
        
        assert!(node_addr.has_dht_hash());
        assert_eq!(node_addr.get_dht_hash(), Some(hash));
        assert!(!node_addr.is_networkable());
        assert!(node_addr.is_content_addressable());
        assert!(!node_addr.is_identity_based());
    }
    
    #[test]
    fn test_quantum_identity() {
        let public_key = PublicKey::new([1u8; 32].to_vec());
        let node_addr = NodeAddress::new_quantum_identity(
            public_key, 
            Some("alice".to_string())
        );
        
        assert!(node_addr.has_quantum_identity());
        assert!(node_addr.get_quantum_identity().is_some());
        assert!(!node_addr.is_networkable());
        assert!(!node_addr.is_content_addressable());
        assert!(node_addr.is_identity_based());
    }
    
    #[test]
    fn test_wallet_identity() {
        let wallet_key = PublicKey::new([2u8; 32].to_vec());
        let node_key = PublicKey::new([3u8; 32].to_vec());
        let node_addr = NodeAddress::new_wallet_identity(
            wallet_key,
            Some("operator_wallet".to_string()),
            Some(node_key),
            WalletType::NodeOperator
        );
        
        assert!(node_addr.has_wallet_identity());
        assert!(node_addr.get_wallet_identity().is_some());
        assert!(!node_addr.is_networkable());
        assert!(!node_addr.is_content_addressable());
        assert!(node_addr.is_identity_based());
        assert!(node_addr.is_wallet_controlled());
        assert!(node_addr.controls_node());
    }
    
    #[test]
    fn test_wallet_to_node_communication() {
        // Create different wallet types
        let user_wallet_key = PublicKey::new([10u8; 32].to_vec());
        let operator_wallet_key = PublicKey::new([11u8; 32].to_vec());
        let validator_wallet_key = PublicKey::new([12u8; 32].to_vec());
        let governance_wallet_key = PublicKey::new([13u8; 32].to_vec());
        
        // Create corresponding node keys
        let operator_node_key = PublicKey::new([20u8; 32].to_vec());
        let validator_node_key = PublicKey::new([21u8; 32].to_vec());
        
        // User wallet (no node control)
        let user_addr = NodeAddress::new_wallet_identity(
            user_wallet_key,
            Some("alice_wallet".to_string()),
            None,
            WalletType::User
        );
        
        // Node operator wallet
        let operator_addr = NodeAddress::new_wallet_identity(
            operator_wallet_key,
            Some("node_operator".to_string()),
            Some(operator_node_key),
            WalletType::NodeOperator
        );
        
        // Validator wallet
        let validator_addr = NodeAddress::new_wallet_identity(
            validator_wallet_key.clone(),
            Some("validator_1".to_string()),
            Some(validator_node_key.clone()),
            WalletType::Validator
        );
        
        // Governance wallet
        let governance_addr = NodeAddress::new_wallet_identity(
            governance_wallet_key,
            Some("gov_council".to_string()),
            None,
            WalletType::Governance
        );
        
        // Test wallet capabilities
        assert!(!user_addr.controls_node());
        assert!(!user_addr.can_govern());
        
        assert!(operator_addr.controls_node());
        assert!(!operator_addr.can_govern());
        
        assert!(validator_addr.controls_node());
        assert!(validator_addr.can_govern());
        
        assert!(!governance_addr.controls_node());
        assert!(governance_addr.can_govern());
        
        // Test address formats
        assert!(format!("{}", user_addr).contains("alice_wallet"));
        assert!(format!("{}", operator_addr).contains("node_operator"));
        
        // Test wallet address schemes
        assert_eq!(user_addr.to_uri_scheme(), "wallet://");
        assert_eq!(operator_addr.to_uri_scheme(), "wallet://");
        assert_eq!(validator_addr.to_uri_scheme(), "wallet://");
        assert_eq!(governance_addr.to_uri_scheme(), "wallet://");
        
        // Test hybrid wallet-node addressing
        let ip_addr = "192.168.1.100:8000".parse().unwrap();
        let dht_hash = Hash::from_bytes(&[5u8; 32]);
        
        // Create new keys for hybrid test to avoid move errors
        let hybrid_wallet_key = PublicKey::new([22u8; 32].to_vec());
        let hybrid_node_key = PublicKey::new([23u8; 32].to_vec());
        
        let hybrid_wallet_node = NodeAddress::new_hybrid(vec![
            AddressType::Ip(ip_addr),
            AddressType::Dht(dht_hash),
            AddressType::Wallet(WalletIdentity::new(
                hybrid_wallet_key,
                Some("hybrid_validator".to_string()),
                Some(hybrid_node_key),
                WalletType::Validator
            )),
        ]);
        
        assert!(hybrid_wallet_node.is_networkable());
        assert!(hybrid_wallet_node.is_content_addressable());
        assert!(hybrid_wallet_node.is_wallet_controlled());
        assert!(hybrid_wallet_node.controls_node());
        assert!(hybrid_wallet_node.can_govern());
    }
    
    #[test]
    fn test_hybrid_address() {
        let ip_addr = SocketAddr::from_str("192.168.1.100:9333").unwrap();
        let hash = Hash::from_bytes(b"test_content_hash_32_bytes_long!");
        let public_key = PublicKey::new([1u8; 32].to_vec());
        
        let wallet_key = PublicKey::new([4u8; 32].to_vec());
        
        let addresses = vec![
            AddressType::Ip(ip_addr),
            AddressType::Dht(hash.clone()),
            AddressType::Quantum(QuantumIdentity::new(public_key, Some("alice".to_string()))),
            AddressType::Wallet(WalletIdentity::new(wallet_key, Some("test_wallet".to_string()), None, WalletType::User)),
        ];
        
        let node_addr = NodeAddress::new_hybrid(addresses);
        
        assert!(node_addr.has_ip());
        assert!(node_addr.has_dht_hash());
        assert!(node_addr.has_quantum_identity());
        assert!(node_addr.has_wallet_identity());
        assert!(node_addr.is_networkable());
        assert!(node_addr.is_content_addressable());
        assert!(node_addr.is_identity_based());
        assert!(node_addr.is_wallet_controlled());
        
        assert_eq!(node_addr.get_ip(), Some(ip_addr));
        assert_eq!(node_addr.get_dht_hash(), Some(hash));
        assert!(node_addr.get_quantum_identity().is_some());
    }
    
    #[test]
    fn test_address_display() {
        let ip_addr = SocketAddr::from_str("192.168.1.100:9333").unwrap();
        let node_addr = NodeAddress::new_ip(ip_addr);
        assert_eq!(format!("{}", node_addr), "ip://192.168.1.100:9333");
        
        let hash = Hash::from_bytes(b"test_content_hash_32_bytes_long!");
        let node_addr = NodeAddress::new_dht_hash(hash.clone());
        assert!(format!("{}", node_addr).starts_with("dht://"));
        
        let public_key = PublicKey::new([1u8; 32].to_vec());
        let node_addr = NodeAddress::new_quantum_identity(
            public_key, 
            Some("alice".to_string())
        );
        assert!(format!("{}", node_addr).contains("alice@"));
    }
}
