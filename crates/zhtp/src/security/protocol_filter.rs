//! Protocol-Level Filtering for Bootstrap Nodes
//! 
//! Ensures bootstrap nodes only serve blockchain data, not general internet routing.
//! Users can connect through ISPs but can ONLY access blockchain protocols.

use anyhow::{Result, bail};
use tracing::{warn, debug};

/// Protocol types recognized by the system
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    /// ZHTP blockchain protocol
    Zhtp,
    /// DHT for blockchain storage/discovery
    Dht,
    /// Blockchain sync (blocks, headers, proofs)
    Blockchain,
    /// Mesh networking
    Mesh,
    /// QUIC transport
    Quic,
    /// HTTP (generally blocked on bootstrap)
    Http,
    /// HTTPS (generally blocked on bootstrap)
    Https,
    /// SOCKS proxy (blocked)
    Socks,
    /// DNS (blockchain DNS only)
    Dns,
    /// Email relay (blocked)
    Smtp,
    /// FTP (blocked)
    Ftp,
    /// SSH (admin only)
    Ssh,
    /// Unknown protocol
    Unknown,
}

impl Protocol {
    /// Parse protocol from string
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "zhtp" => Protocol::Zhtp,
            "dht" => Protocol::Dht,
            "blockchain" | "block" | "chain" => Protocol::Blockchain,
            "mesh" => Protocol::Mesh,
            "quic" => Protocol::Quic,
            "http" => Protocol::Http,
            "https" => Protocol::Https,
            "socks" | "socks5" | "socks4" => Protocol::Socks,
            "dns" => Protocol::Dns,
            "smtp" => Protocol::Smtp,
            "ftp" | "ftps" => Protocol::Ftp,
            "ssh" => Protocol::Ssh,
            _ => Protocol::Unknown,
        }
    }
    
    /// Check if this is a blockchain protocol
    pub fn is_blockchain_protocol(&self) -> bool {
        matches!(
            self,
            Protocol::Zhtp | Protocol::Dht | Protocol::Blockchain | Protocol::Mesh | Protocol::Quic
        )
    }
    
    /// Check if this is a general internet protocol (should be blocked on bootstrap)
    pub fn is_internet_protocol(&self) -> bool {
        matches!(
            self,
            Protocol::Http | Protocol::Https | Protocol::Socks | Protocol::Smtp | Protocol::Ftp
        )
    }
}

/// Protocol filter for bootstrap nodes
pub struct ProtocolFilter {
    /// Allow blockchain protocols
    allow_blockchain: bool,
    /// Block general internet protocols
    block_internet: bool,
    /// Custom allowed protocols
    allowed_protocols: Vec<String>,
    /// Custom blocked protocols
    blocked_protocols: Vec<String>,
}

impl ProtocolFilter {
    /// Create new protocol filter for bootstrap nodes
    pub fn new_bootstrap() -> Self {
        Self {
            allow_blockchain: true,
            block_internet: true,
            allowed_protocols: vec![
                "zhtp".to_string(),
                "dht".to_string(),
                "blockchain".to_string(),
                "mesh".to_string(),
                "quic".to_string(),
            ],
            blocked_protocols: vec![
                "http".to_string(),
                "https".to_string(),
                "socks".to_string(),
                "dns".to_string(), // Except blockchain DNS
                "smtp".to_string(),
                "ftp".to_string(),
            ],
        }
    }
    
    /// Create permissive filter (allow all)
    pub fn new_permissive() -> Self {
        Self {
            allow_blockchain: true,
            block_internet: false,
            allowed_protocols: vec![],
            blocked_protocols: vec![],
        }
    }
    
    /// Check if a protocol is allowed
    pub fn is_allowed(&self, protocol_str: &str) -> bool {
        let protocol = Protocol::from_str(protocol_str);
        
        // Check custom whitelist first
        if !self.allowed_protocols.is_empty() {
            return self.allowed_protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol_str));
        }
        
        // Check custom blacklist
        if self.blocked_protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol_str)) {
            return false;
        }
        
        // Apply general rules
        if protocol.is_blockchain_protocol() && self.allow_blockchain {
            return true;
        }
        
        if protocol.is_internet_protocol() && self.block_internet {
            return false;
        }
        
        // Unknown protocols: block if we're in strict mode
        if self.block_internet {
            return false;
        }
        
        true
    }
    
    /// Validate and filter a connection request
    pub fn validate_connection(&self, protocol: &str, purpose: &str) -> Result<()> {
        if !self.is_allowed(protocol) {
            warn!("🚫 Protocol blocked: {} (purpose: {})", protocol, purpose);
            bail!("Protocol '{}' is not allowed on this bootstrap node. Only blockchain protocols are supported.", protocol);
        }
        
        debug!(" Protocol allowed: {} (purpose: {})", protocol, purpose);
        Ok(())
    }
    
    /// Check if request is attempting to route general internet traffic
    pub fn is_routing_attempt(&self, uri: &str) -> bool {
        // Check for common proxy/routing patterns
        if uri.starts_with("http://") || uri.starts_with("https://") {
            return true;
        }
        
        // Check for IP addresses (potential routing)
        if uri.contains("://") {
            if let Some(host) = uri.split("://").nth(1).and_then(|s| s.split('/').next()) {
                // Check if it's an external domain (not blockchain-related)
                if !host.contains("blockchain") 
                    && !host.contains("sovereign") 
                    && !host.contains("zhtp")
                    && !host.starts_with("192.168.")
                    && !host.starts_with("10.")
                    && !host.starts_with("172.16.") {
                    return true;
                }
            }
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_parsing() {
        assert_eq!(Protocol::from_str("zhtp"), Protocol::Zhtp);
        assert_eq!(Protocol::from_str("ZHTP"), Protocol::Zhtp);
        assert_eq!(Protocol::from_str("http"), Protocol::Http);
        assert_eq!(Protocol::from_str("blockchain"), Protocol::Blockchain);
    }

    #[test]
    fn test_blockchain_protocol_detection() {
        assert!(Protocol::Zhtp.is_blockchain_protocol());
        assert!(Protocol::Dht.is_blockchain_protocol());
        assert!(!Protocol::Http.is_blockchain_protocol());
        assert!(!Protocol::Https.is_blockchain_protocol());
    }

    #[test]
    fn test_bootstrap_filter() {
        let filter = ProtocolFilter::new_bootstrap();
        
        // Blockchain protocols should be allowed
        assert!(filter.is_allowed("zhtp"));
        assert!(filter.is_allowed("dht"));
        assert!(filter.is_allowed("blockchain"));
        
        // Internet protocols should be blocked
        assert!(!filter.is_allowed("http"));
        assert!(!filter.is_allowed("https"));
        assert!(!filter.is_allowed("socks"));
    }

    #[test]
    fn test_routing_detection() {
        let filter = ProtocolFilter::new_bootstrap();
        
        // These should be detected as routing attempts
        assert!(filter.is_routing_attempt("http://google.com"));
        assert!(filter.is_routing_attempt("https://example.com/api"));
        
        // These should NOT be detected as routing (blockchain-related)
        assert!(!filter.is_routing_attempt("zhtp://blockchain.local/block/123"));
        assert!(!filter.is_routing_attempt("dht://192.168.1.1/store"));
    }

    #[test]
    fn test_permissive_filter() {
        let filter = ProtocolFilter::new_permissive();
        
        // Everything should be allowed in permissive mode
        assert!(filter.is_allowed("zhtp"));
        assert!(filter.is_allowed("http"));
        assert!(filter.is_allowed("unknown"));
    }
}
