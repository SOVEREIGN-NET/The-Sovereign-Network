//! LoRaWAN trust anchor model (ARCH-D-1.9).
//!
//! Provides a lightweight gateway-mediated authentication flow that fits within
//! LoRaWAN MTU constraints and can be bridged to the full UHP handshake on the
//! mesh side. This is platform-agnostic and avoids macOS-specific code paths.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

/// 49-byte device message (fits DR0=51 bytes).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRaDeviceMessage {
    /// 8-byte device EUI
    pub device_eui: [u8; 8],
    /// 8-byte application EUI
    pub app_eui: [u8; 8],
    /// 16-byte nonce for replay protection
    pub nonce: [u8; 16],
    /// 1-byte version
    pub version: u8,
    /// 16-byte MAC/tag (placeholder; to be produced by gateway)
    pub mac: [u8; 16],
}

/// Gateway attestation bridging device → mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayAttestation {
    /// Gateway identifier (could be DID or NodeId bytes)
    pub gateway_id: [u8; 32],
    /// Device EUI being vouched for
    pub device_eui: [u8; 8],
    /// MAC/tag computed by the gateway for the device message
    pub mac: [u8; 16],
    /// Signature over the attestation (placeholder; produced with UHP keys)
    pub signature: Vec<u8>,
}

/// Binding between LoRa device identity and UHP peer identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoRaWanUhpBinding {
    /// Device EUI
    pub device_eui: [u8; 8],
    /// Mesh-side peer identifier (NodeId bytes)
    pub peer_id: [u8; 32],
    /// Attestation from gateway proving the binding
    pub attestation: GatewayAttestation,
}

/// Gateway-side auth helper.
#[derive(Debug, Clone)]
pub struct LoRaWANGatewayAuth;

impl LoRaWANGatewayAuth {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }

    /// Build the device → gateway message that fits within LoRaWAN MTU.
    pub fn build_device_message(
        &self,
        device_eui: [u8; 8],
        app_eui: [u8; 8],
        nonce: [u8; 16],
    ) -> LoRaDeviceMessage {
        LoRaDeviceMessage {
            device_eui,
            app_eui,
            nonce,
            version: 1,
            mac: [0u8; 16], // Filled by gateway upon verification
        }
    }

    /// Gateway verifies device message and produces an attestation that can be
    /// forwarded into the mesh to perform full UHP with peers.
    pub fn attest_device(
        &self,
        gateway_id: [u8; 32],
        device_msg: &LoRaDeviceMessage,
    ) -> GatewayAttestation {
        // TODO: Replace placeholder MAC/signature with real cryptography wired to UHP keys.
        GatewayAttestation {
            gateway_id,
            device_eui: device_msg.device_eui,
            mac: device_msg.mac,
            signature: Vec::new(),
        }
    }

    /// Bind the device to a mesh peer identity for downstream routing/handshake.
    pub fn bind_device_to_peer(
        &self,
        peer_id: [u8; 32],
        attestation: GatewayAttestation,
    ) -> LoRaWanUhpBinding {
        LoRaWanUhpBinding {
            device_eui: attestation.device_eui,
            peer_id,
            attestation,
        }
    }

    /// Placeholder validation hook for upstream integration tests.
    pub fn validate_binding(&self, binding: &LoRaWanUhpBinding) -> Result<bool> {
        info!(
            device = %hex::encode(binding.device_eui),
            peer = %hex::encode(binding.peer_id),
            "Validated LoRaWAN→UHP binding (placeholder)"
        );
        Ok(true)
    }
}
