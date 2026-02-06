//! LoRaWAN trust anchor model (ARCH-D-1.9).
//!
//! Provides a lightweight gateway-mediated authentication flow that fits within
//! LoRaWAN MTU constraints and can be bridged to the full UHP handshake on the
//! mesh side. This is platform-agnostic and avoids macOS-specific code paths.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;
use lib_crypto::hash_sha3_256;
use lib_crypto::post_quantum::dilithium::{dilithium_sign, dilithium_verify};

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
    /// 16-byte MAC/tag (HMAC-SHA3 computed by gateway)
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
    /// Signature over the attestation (Dilithium5 signature)
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

/// Gateway-side auth helper with cryptographic key management.
#[derive(Debug, Clone)]
pub struct LoRaWANGatewayAuth {
    /// Gateway's Dilithium5 public key (for attestation verification by peers)
    pub public_key: Vec<u8>,
    /// Gateway's Dilithium5 secret key (for signing attestations)
    secret_key: Vec<u8>,
}

impl LoRaWANGatewayAuth {
    /// Create new gateway auth (uninitialized with keys).
    ///
    /// Keys must be set separately with `set_keypair()` for attestation signing.
    /// Attestations signed before key initialization will fail verification.
    pub fn new() -> Result<Self> {
        Ok(Self {
            public_key: Vec::new(),
            secret_key: Vec::new(),
        })
    }

    /// Set gateway Dilithium5 keypair for cryptographic attestations.
    ///
    /// # Arguments
    /// * `public_key` - Dilithium5 public key (2592 bytes)
    /// * `secret_key` - Dilithium5 secret key (4864 or 4896 bytes)
    ///
    /// # Errors
    /// Returns error if key lengths are invalid
    pub fn set_keypair(&mut self, public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<()> {
        if public_key.len() != 2592 {
            return Err(anyhow::anyhow!(
                "Invalid Dilithium5 public key length: {} bytes (expected 2592)",
                public_key.len()
            ));
        }
        if secret_key.len() != 4864 && secret_key.len() != 4896 {
            return Err(anyhow::anyhow!(
                "Invalid Dilithium5 secret key length: {} bytes (expected 4864 or 4896)",
                secret_key.len()
            ));
        }
        self.public_key = public_key;
        self.secret_key = secret_key;
        Ok(())
    }

    /// Create new gateway auth with full keypair.
    ///
    /// # Arguments
    /// * `public_key` - Dilithium5 public key (2592 bytes)
    /// * `secret_key` - Dilithium5 secret key (4864 or 4896 bytes)
    pub fn with_keypair(public_key: Vec<u8>, secret_key: Vec<u8>) -> Result<Self> {
        if public_key.len() != 2592 {
            return Err(anyhow::anyhow!(
                "Invalid Dilithium5 public key length: {} bytes (expected 2592)",
                public_key.len()
            ));
        }
        if secret_key.len() != 4864 && secret_key.len() != 4896 {
            return Err(anyhow::anyhow!(
                "Invalid Dilithium5 secret key length: {} bytes (expected 4864 or 4896)",
                secret_key.len()
            ));
        }
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Build the device → gateway message that fits within LoRaWAN MTU.
    ///
    /// # Arguments
    /// * `device_eui` - 8-byte device identifier
    /// * `app_eui` - 8-byte application identifier
    /// * `nonce` - 16-byte nonce for replay protection (should be random)
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
            mac: [0u8; 16], // Will be filled by gateway upon verification
        }
    }

    /// Compute HMAC-SHA3 for device message.
    ///
    /// Uses SHA3-256 in HMAC mode for message authentication.
    ///
    /// # Arguments
    /// * `device_msg` - Device message to authenticate
    /// * `gateway_key` - 32-byte gateway secret key for HMAC
    fn compute_mac(&self, device_msg: &LoRaDeviceMessage, gateway_key: &[u8; 32]) -> [u8; 16] {
        // Build message to authenticate
        let mut msg = Vec::new();
        msg.extend_from_slice(&device_msg.device_eui);
        msg.extend_from_slice(&device_msg.app_eui);
        msg.extend_from_slice(&device_msg.nonce);
        msg.push(device_msg.version);

        // Compute HMAC-SHA3-256 using XOR construction
        // HMAC(key, msg) = H((key ⊕ opad) || H((key ⊕ ipad) || msg))
        const IPAD: u8 = 0x36;
        const OPAD: u8 = 0x5c;

        let mut ipad_key = [0u8; 32];
        let mut opad_key = [0u8; 32];
        for i in 0..32 {
            ipad_key[i] = gateway_key[i] ^ IPAD;
            opad_key[i] = gateway_key[i] ^ OPAD;
        }

        let mut inner_msg = Vec::new();
        inner_msg.extend_from_slice(&ipad_key);
        inner_msg.extend_from_slice(&msg);
        let inner_hash = hash_sha3_256(&inner_msg);

        let mut outer_msg = Vec::new();
        outer_msg.extend_from_slice(&opad_key);
        outer_msg.extend_from_slice(&inner_hash);
        let outer_hash = hash_sha3_256(&outer_msg);

        // Truncate to 16 bytes
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&outer_hash[..16]);
        mac
    }

    /// Gateway verifies device message and produces an attestation that can be
    /// forwarded into the mesh to perform full UHP with peers.
    ///
    /// # Arguments
    /// * `gateway_id` - 32-byte gateway identifier
    /// * `device_msg` - Device message with computed MAC
    /// * `gateway_key` - 32-byte gateway secret key for HMAC computation
    pub fn attest_device(
        &self,
        gateway_id: [u8; 32],
        device_msg: &LoRaDeviceMessage,
        gateway_key: &[u8; 32],
    ) -> Result<GatewayAttestation> {
        // Verify MAC matches
        let expected_mac = self.compute_mac(device_msg, gateway_key);
        if device_msg.mac != expected_mac {
            return Err(anyhow::anyhow!(
                "Device MAC verification failed: got {:?}, expected {:?}",
                device_msg.mac,
                expected_mac
            ));
        }

        // Build attestation message to sign
        let mut attestation_msg = Vec::new();
        attestation_msg.extend_from_slice(&gateway_id);
        attestation_msg.extend_from_slice(&device_msg.device_eui);
        attestation_msg.extend_from_slice(&device_msg.mac);
        attestation_msg.extend_from_slice(&device_msg.nonce);

        // Sign attestation with Dilithium5
        let signature = dilithium_sign(&attestation_msg, &self.secret_key)?;

        Ok(GatewayAttestation {
            gateway_id,
            device_eui: device_msg.device_eui,
            mac: device_msg.mac,
            signature,
        })
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

    /// Validate LoRaWAN→UHP binding by verifying cryptographic signatures.
    ///
    /// # Arguments
    /// * `binding` - Binding to validate
    /// * `gateway_public_key` - Dilithium5 public key of the attesting gateway
    pub fn validate_binding(
        &self,
        binding: &LoRaWanUhpBinding,
        gateway_public_key: &[u8],
    ) -> Result<bool> {
        // Build attestation message
        let mut attestation_msg = Vec::new();
        attestation_msg.extend_from_slice(&binding.attestation.gateway_id);
        attestation_msg.extend_from_slice(&binding.device_eui);
        attestation_msg.extend_from_slice(&binding.attestation.mac);

        // Extract nonce from attestation (need to reconstruct device message)
        // For now, we verify signature without nonce
        // In production, nonce should be stored in attestation or retrieved separately

        // Verify Dilithium5 signature
        match dilithium_verify(&attestation_msg, &binding.attestation.signature, gateway_public_key) {
            Ok(valid) => {
                info!(
                    device = %hex::encode(binding.device_eui),
                    peer = %hex::encode(binding.peer_id),
                    signature_valid = valid,
                    "Validated LoRaWAN→UHP binding with cryptographic verification"
                );
                Ok(valid)
            }
            Err(e) => {
                info!(
                    device = %hex::encode(binding.device_eui),
                    error = %e,
                    "LoRaWAN→UHP binding validation failed"
                );
                Ok(false)
            }
        }
    }
}
