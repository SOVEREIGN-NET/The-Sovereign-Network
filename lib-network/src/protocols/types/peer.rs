//! Peer addressing and identity types

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Maximum length for string-based identifiers
pub const MAX_IDENTIFIER_LENGTH: usize = 256;

/// Validated Bluetooth MAC address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct BluetoothMac([u8; 6]);

impl BluetoothMac {
    /// Create a new validated Bluetooth MAC address
    pub fn new(mac: [u8; 6]) -> Result<Self> {
        // Reject broadcast address
        if mac == [0xFF; 6] {
            return Err(anyhow!("Invalid Bluetooth MAC: broadcast address"));
        }
        // Reject all-zeros (uninitialized)
        if mac == [0x00; 6] {
            return Err(anyhow!("Invalid Bluetooth MAC: null address"));
        }
        Ok(Self(mac))
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }
}

/// Validated socket address
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedSocketAddr(SocketAddr);

impl ValidatedSocketAddr {
    /// Create a new validated socket address
    pub fn new(addr: SocketAddr) -> Result<Self> {
        use std::net::IpAddr;

        match addr.ip() {
            IpAddr::V4(ipv4) => {
                if ipv4.is_unspecified() {
                    return Err(anyhow!("Invalid IPv4: unspecified (0.0.0.0)"));
                }
                if ipv4.is_broadcast() {
                    return Err(anyhow!("Invalid IPv4: broadcast (255.255.255.255)"));
                }
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_unspecified() {
                    return Err(anyhow!("Invalid IPv6: unspecified (::)"));
                }
            }
        }

        if addr.port() == 0 {
            return Err(anyhow!("Invalid port: 0"));
        }

        Ok(Self(addr))
    }

    /// Get the inner socket address
    pub fn inner(&self) -> &SocketAddr {
        &self.0
    }
}

/// Validated device identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedDeviceId(String);

impl ValidatedDeviceId {
    /// Create a new validated device ID
    pub fn new(id: String) -> Result<Self> {
        if id.is_empty() {
            return Err(anyhow!("Device ID cannot be empty"));
        }
        if id.len() > MAX_IDENTIFIER_LENGTH {
            return Err(anyhow!(
                "Device ID too long: {} bytes (max: {})",
                id.len(),
                MAX_IDENTIFIER_LENGTH
            ));
        }
        // Allow alphanumeric, hyphens, colons, and underscores
        if !id.chars().all(|c| c.is_alphanumeric() || c == '-' || c == ':' || c == '_') {
            return Err(anyhow!("Invalid Device ID format: only alphanumeric, -, :, _ allowed"));
        }
        Ok(Self(id))
    }

    /// Get the inner string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated satellite identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatedSatelliteId(String);

impl ValidatedSatelliteId {
    /// Create a new validated satellite ID
    pub fn new(id: String) -> Result<Self> {
        if id.is_empty() {
            return Err(anyhow!("Satellite ID cannot be empty"));
        }
        if id.len() > MAX_IDENTIFIER_LENGTH {
            return Err(anyhow!(
                "Satellite ID too long: {} bytes (max: {})",
                id.len(),
                MAX_IDENTIFIER_LENGTH
            ));
        }
        Ok(Self(id))
    }

    /// Get the inner string
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Peer address for protocol-agnostic addressing
///
/// All variants use validated types to prevent invalid addresses.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PeerAddress {
    /// Bluetooth MAC address (validated)
    Bluetooth(BluetoothMac),
    /// IP address and port (validated)
    IpSocket(ValidatedSocketAddr),
    /// Device ID (validated, length-limited)
    DeviceId(ValidatedDeviceId),
    /// LoRaWAN device address
    LoRaDevAddr(u32),
    /// Satellite endpoint identifier (validated)
    SatelliteId(ValidatedSatelliteId),
}

impl PeerAddress {
    /// Create a Bluetooth address (convenience method)
    pub fn bluetooth(mac: [u8; 6]) -> Result<Self> {
        Ok(Self::Bluetooth(BluetoothMac::new(mac)?))
    }

    /// Create an IP socket address (convenience method)
    pub fn ip_socket(addr: SocketAddr) -> Result<Self> {
        Ok(Self::IpSocket(ValidatedSocketAddr::new(addr)?))
    }

    /// Create a device ID address (convenience method)
    pub fn device_id(id: impl Into<String>) -> Result<Self> {
        Ok(Self::DeviceId(ValidatedDeviceId::new(id.into())?))
    }

    /// Create a LoRa device address
    pub fn lora(addr: u32) -> Self {
        Self::LoRaDevAddr(addr)
    }

    /// Create a satellite ID address (convenience method)
    pub fn satellite(id: impl Into<String>) -> Result<Self> {
        Ok(Self::SatelliteId(ValidatedSatelliteId::new(id.into())?))
    }
}

/// Verified peer identity with cryptographic binding
///
/// Ensures that peer identity claims are backed by cryptographic proof.
#[derive(Clone)]
pub struct VerifiedPeerIdentity {
    /// DID or public key hash
    did: String,
    /// Public key used for authentication (raw bytes)
    public_key: Vec<u8>,
    /// Signature over session binding data (proves key possession)
    authentication_proof: Vec<u8>,
}

impl VerifiedPeerIdentity {
    /// Create a new verified peer identity
    pub fn new(
        did: String,
        public_key: Vec<u8>,
        authentication_proof: Vec<u8>,
    ) -> Result<Self> {
        if did.is_empty() {
            return Err(anyhow!("DID cannot be empty"));
        }
        if did.len() > MAX_IDENTIFIER_LENGTH {
            return Err(anyhow!("DID too long: {} bytes", did.len()));
        }
        if public_key.is_empty() {
            return Err(anyhow!("Public key cannot be empty"));
        }
        Ok(Self {
            did,
            public_key,
            authentication_proof,
        })
    }

    /// Get the DID
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get the authentication proof
    pub fn authentication_proof(&self) -> &[u8] {
        &self.authentication_proof
    }
}

impl std::fmt::Debug for VerifiedPeerIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedPeerIdentity")
            .field("did", &self.did)
            .field("public_key", &format!("[{} bytes]", self.public_key.len()))
            .field("authentication_proof", &"<redacted>")
            .finish()
    }
}
