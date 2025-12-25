//! Protocol capabilities and power profiles

use serde::{Deserialize, Serialize};
use super::security::{AuthScheme, CipherSuite, PqcMode};

/// Capability structure version
pub const CAPABILITY_VERSION: u8 = 2;

/// Protocol capabilities describing both performance characteristics and security posture
///
/// Includes traditional metrics (MTU, throughput, latency, range, power) and
/// security properties (authentication schemes, encryption ciphers, PQC support,
/// replay protection, identity binding, forward secrecy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolCapabilities {
    /// Capability structure version for forward compatibility
    pub version: u8,
    /// Maximum Transmission Unit in bytes
    pub mtu: u16,
    /// Estimated throughput in Mbps
    pub throughput_mbps: f64,
    /// Estimated latency in milliseconds
    pub latency_ms: u32,
    /// Effective range in meters (None for global protocols like satellite)
    pub range_meters: Option<u32>,
    /// Power consumption profile
    pub power_profile: PowerProfile,
    /// Whether the protocol supports reliable delivery
    pub reliable: bool,
    /// Whether the protocol requires internet connectivity to function
    ///
    /// Semantics:
    /// - `true`: The protocol fundamentally depends on internet connectivity and cannot
    ///   operate in a purely local/offline environment (e.g., satellite backhaul or
    ///   cloud-routed services).
    /// - `false`: The protocol can operate without internet connectivity. This includes
    ///   strictly local protocols and hybrid protocols that support both local and
    ///   internet-connected operation (e.g., QUIC or TCP used on a local network).
    pub requires_internet: bool,

    // ============ Security Capabilities ============
    /// Authentication schemes supported by this protocol
    pub auth_schemes: Vec<AuthScheme>,
    /// Encryption cipher suite (None if integrity-only or unauthenticated)
    pub encryption: Option<CipherSuite>,
    /// Post-quantum cryptography mode
    pub pqc_mode: PqcMode,
    /// Whether protocol provides replay protection
    pub replay_protection: bool,
    /// Whether messages are bound to authenticated peer/session
    pub identity_binding: bool,
    /// True if integrity-only (no confidentiality)
    pub integrity_only: bool,
    /// Whether protocol provides forward secrecy
    pub forward_secrecy: bool,
}

impl ProtocolCapabilities {
    /// Create new capabilities with current version
    pub fn new(
        mtu: u16,
        throughput_mbps: f64,
        latency_ms: u32,
        power_profile: PowerProfile,
    ) -> Self {
        Self {
            version: CAPABILITY_VERSION,
            mtu,
            throughput_mbps,
            latency_ms,
            range_meters: None,
            power_profile,
            reliable: true,
            requires_internet: false,
            auth_schemes: vec![AuthScheme::MutualHandshake],
            encryption: Some(CipherSuite::ChaCha20Poly1305),
            pqc_mode: PqcMode::Hybrid,
            replay_protection: true,
            identity_binding: true,
            integrity_only: false,
            forward_secrecy: true,
        }
    }
}

/// Power consumption profile for protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PowerProfile {
    /// Ultra-low power (< 10mW average)
    UltraLow,
    /// Low power (10-100mW)
    Low,
    /// Medium power (100mW-1W)
    Medium,
    /// High power (1W-10W)
    High,
    /// Very high power (> 10W)
    VeryHigh,
}
