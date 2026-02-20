//! Identity messaging helpers (Phase 2: per-device fan-out)

use crate::types::{
    DevicePayload,
    IdentityEnvelope,
    MessageTtl,
    DeliveryReceipt,
    ReadReceipt,
    SealedSenderEnvelope,
};
use crate::types::PoUwStamp;
use crate::types::IdentityPayload;
use lib_crypto::hash_blake3;
use lib_crypto::{encrypt_with_public_key, PublicKey, Signature};
use lib_crypto::keypair::generation::KeyPair;
use lib_identity::{resolve_did, list_active_devices, get_device_keys};
use lib_identity::DidDocument;
use crate::types::{
    DEFAULT_GROUP_CAP,
    MAX_GROUP_CAP,
    GroupId,
    GroupChange,
    GroupStateUpdate,
    GroupEpochKey,
};
use lib_identity::DidDocumentUpdate;

/// Build an identity envelope for a recipient DID (per-device fan-out)
pub fn build_identity_envelope(
    sender_did: &str,
    recipient_did: &str,
    plaintext: &[u8],
    ttl: MessageTtl,
) -> Result<IdentityEnvelope, String> {
    let document = resolve_did(recipient_did)?;
    let devices = list_active_devices(&document);
    if devices.is_empty() {
        return Err("No active devices for DID".to_string());
    }

    let mut payloads = Vec::with_capacity(devices.len());
    let ad = associated_data(sender_did, recipient_did);

    for device in devices {
        let (_signing, encryption_pk) = get_device_keys(&document, &device.device_id)?;
        let recipient_pk = PublicKey::from_kyber_public_key(encryption_pk);
        let ciphertext = encrypt_with_public_key(&recipient_pk, plaintext, ad.as_bytes())
            .map_err(|e| format!("Encrypt failed for device {}: {}", device.device_id, e))?;
        payloads.push(DevicePayload {
            device_id: device.device_id,
            ciphertext,
        });
    }

    Ok(IdentityEnvelope {
        message_id: generate_message_id(),
        sender_did: sender_did.to_string(),
        recipient_did: recipient_did.to_string(),
        created_at: current_unix_timestamp()?,
        ttl,
        retain_until_ttl: false,
        pouw_stamp: None,
        payloads,
    })
}

/// Build identity envelope from a structured payload
pub fn build_identity_envelope_with_payload(
    sender_did: &str,
    recipient_did: &str,
    payload: &IdentityPayload,
    ttl: MessageTtl,
) -> Result<IdentityEnvelope, String> {
    let bytes = bincode::serialize(payload)
        .map_err(|e| format!("Failed to serialize payload: {}", e))?;
    build_identity_envelope(sender_did, recipient_did, &bytes, ttl)
}

/// Build identity envelope with PoUW stamp attached
pub fn build_identity_envelope_with_pouw(
    sender_did: &str,
    recipient_did: &str,
    payload: &IdentityPayload,
    ttl: MessageTtl,
    pouw_stamp: PoUwStamp,
) -> Result<IdentityEnvelope, String> {
    let mut envelope = build_identity_envelope_with_payload(sender_did, recipient_did, payload, ttl)?;
    envelope.pouw_stamp = Some(pouw_stamp);
    Ok(envelope)
}

/// Build identity envelope with retention policy
pub fn build_identity_envelope_with_retention(
    sender_did: &str,
    recipient_did: &str,
    payload: &IdentityPayload,
    ttl: MessageTtl,
    retain_until_ttl: bool,
) -> Result<IdentityEnvelope, String> {
    let mut envelope = build_identity_envelope_with_payload(sender_did, recipient_did, payload, ttl)?;
    envelope.retain_until_ttl = retain_until_ttl;
    Ok(envelope)
}

/// Extract ciphertext for a specific device_id from an envelope
pub fn extract_device_ciphertext(
    envelope: &IdentityEnvelope,
    device_id: &str,
) -> Option<Vec<u8>> {
    envelope
        .payloads
        .iter()
        .find(|p| p.device_id == device_id)
        .map(|p| p.ciphertext.clone())
}

/// Build delivery receipt envelope (E2E to recipient DID)
pub fn build_delivery_receipt_envelope(
    sender_did: &str,
    recipient_did: &str,
    receipt: &DeliveryReceipt,
    ttl: MessageTtl,
) -> Result<IdentityEnvelope, String> {
    let payload = IdentityPayload::delivery_receipt(receipt)?;
    build_identity_envelope_with_payload(sender_did, recipient_did, &payload, ttl)
}

/// Build read receipt envelope (E2E to recipient DID)
pub fn build_read_receipt_envelope(
    sender_did: &str,
    recipient_did: &str,
    receipt: &ReadReceipt,
    ttl: MessageTtl,
) -> Result<IdentityEnvelope, String> {
    let payload = IdentityPayload::read_receipt(receipt)?;
    build_identity_envelope_with_payload(sender_did, recipient_did, &payload, ttl)
}

/// Build control payload from DID device update
pub fn control_payload_from_device_update(
    update: &DidDocumentUpdate,
) -> Result<IdentityPayload, String> {
    let is_add = !update.diff.adds.is_empty() && update.diff.removes.is_empty();
    let is_remove = update.diff.adds.is_empty() && !update.diff.removes.is_empty();
    if !is_add && !is_remove {
        return Err("Device update must be purely add or remove".to_string());
    }
    let body = bincode::serialize(update)
        .map_err(|e| format!("Failed to serialize DID update: {}", e))?;
    let kind = if is_add {
        crate::types::ControlMessageType::DeviceAdd
    } else {
        crate::types::ControlMessageType::DeviceRemove
    };
    Ok(IdentityPayload::control_message(kind, body))
}

/// Seal an envelope for next-hop routing with optional padding
pub fn seal_sender_envelope(
    next_hop: &str,
    next_hop_pk: &PublicKey,
    payload: &[u8],
    padding_len: usize,
) -> Result<SealedSenderEnvelope, String> {
    let mut padded = Vec::with_capacity(payload.len() + padding_len);
    padded.extend_from_slice(payload);
    if padding_len > 0 {
        padded.extend(std::iter::repeat(0u8).take(padding_len));
    }

    let ciphertext = encrypt_with_public_key(next_hop_pk, &padded, b"sealed-sender")
        .map_err(|e| format!("Failed to seal envelope: {}", e))?;

    Ok(SealedSenderEnvelope {
        next_hop: next_hop.to_string(),
        ciphertext,
        padding_len: padding_len as u32,
    })
}

/// Build layered sealed-sender envelopes for a route (outermost first)
pub fn build_layered_envelopes(
    route: &[(&str, &PublicKey)],
    payload: &[u8],
    padding_len: usize,
) -> Result<Vec<SealedSenderEnvelope>, String> {
    let mut current_payload = payload.to_vec();
    let mut envelopes = Vec::new();

    for (next_hop, pk) in route.iter().rev() {
        let sealed = seal_sender_envelope(next_hop, pk, &current_payload, padding_len)?;
        current_payload = sealed.ciphertext.clone();
        envelopes.push(sealed);
    }

    envelopes.reverse();
    Ok(envelopes)
}

/// Create a signed delivery receipt
pub fn create_delivery_receipt(
    message_id: u64,
    device_id: &str,
    signer: &KeyPair,
) -> Result<DeliveryReceipt, String> {
    let delivered_at = current_unix_timestamp()?;
    let signing_bytes = receipt_signing_bytes(message_id, device_id, delivered_at)?;
    let signature = signer
        .sign(&signing_bytes)
        .map_err(|e| format!("Failed to sign receipt: {}", e))?;

    Ok(DeliveryReceipt {
        message_id,
        device_id: device_id.to_string(),
        delivered_at,
        signature: signature.signature,
        signature_algorithm: signature.algorithm,
    })
}

/// Create a signed read receipt
pub fn create_read_receipt(
    message_id: u64,
    device_id: &str,
    signer: &KeyPair,
) -> Result<ReadReceipt, String> {
    let read_at = current_unix_timestamp()?;
    let signing_bytes = receipt_signing_bytes(message_id, device_id, read_at)?;
    let signature = signer
        .sign(&signing_bytes)
        .map_err(|e| format!("Failed to sign receipt: {}", e))?;

    Ok(ReadReceipt {
        message_id,
        device_id: device_id.to_string(),
        read_at,
        signature: signature.signature,
        signature_algorithm: signature.algorithm,
    })
}

/// Verify a delivery receipt signature
pub fn verify_delivery_receipt(
    receipt: &DeliveryReceipt,
    signer_pk: &PublicKey,
) -> Result<bool, String> {
    let signing_bytes = receipt_signing_bytes(receipt.message_id, &receipt.device_id, receipt.delivered_at)?;
    let signature = Signature {
        signature: receipt.signature.clone(),
        public_key: signer_pk.clone(),
        algorithm: receipt.signature_algorithm.clone(),
        timestamp: receipt.delivered_at,
    };
    signer_pk
        .verify(&signing_bytes, &signature)
        .map_err(|e| format!("Receipt verification failed: {}", e))
}

/// Verify a read receipt signature
pub fn verify_read_receipt(
    receipt: &ReadReceipt,
    signer_pk: &PublicKey,
) -> Result<bool, String> {
    let signing_bytes = receipt_signing_bytes(receipt.message_id, &receipt.device_id, receipt.read_at)?;
    let signature = Signature {
        signature: receipt.signature.clone(),
        public_key: signer_pk.clone(),
        algorithm: receipt.signature_algorithm.clone(),
        timestamp: receipt.read_at,
    };
    signer_pk
        .verify(&signing_bytes, &signature)
        .map_err(|e| format!("Receipt verification failed: {}", e))
}

fn receipt_signing_bytes(message_id: u64, device_id: &str, timestamp: u64) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize)]
    struct ReceiptSigningPayload<'a> {
        message_id: u64,
        device_id: &'a str,
        timestamp: u64,
    }

    let payload = ReceiptSigningPayload {
        message_id,
        device_id,
        timestamp,
    };

    bincode::serialize(&payload).map_err(|e| format!("Failed to serialize receipt: {}", e))
}

fn associated_data(sender_did: &str, recipient_did: &str) -> String {
    format!("{}:{}", sender_did, recipient_did)
}

fn current_unix_timestamp() -> Result<u64, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| "System time before Unix epoch".to_string())
}

fn generate_message_id() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_nanos() as u64;
    ts ^ (rand::random::<u64>() >> 16)
}

/// Validate group size against caps
pub fn validate_group_size(member_count: usize) -> Result<(), String> {
    if member_count > MAX_GROUP_CAP {
        return Err(format!("Group size exceeds maximum cap: {}", MAX_GROUP_CAP));
    }
    if member_count > DEFAULT_GROUP_CAP {
        return Err(format!("Group size exceeds default cap: {} (requires explicit override)", DEFAULT_GROUP_CAP));
    }
    Ok(())
}

/// Create signed group state update
pub fn create_group_state_update(
    group_id: GroupId,
    epoch: u64,
    admin_key: &str,
    change: GroupChange,
    signer: &KeyPair,
) -> Result<GroupStateUpdate, String> {
    let signing_bytes = group_state_signing_bytes(&group_id, epoch, admin_key, &change)?;
    let signature = signer
        .sign(&signing_bytes)
        .map_err(|e| format!("Failed to sign group update: {}", e))?;

    Ok(GroupStateUpdate {
        group_id,
        epoch,
        admin_key: admin_key.to_string(),
        change,
        signed_payload: signature.signature,
        signature_algorithm: signature.algorithm,
    })
}

/// Verify group state update signature
pub fn verify_group_state_update(
    update: &GroupStateUpdate,
    signer_pk: &PublicKey,
) -> Result<bool, String> {
    let signing_bytes = group_state_signing_bytes(&update.group_id, update.epoch, &update.admin_key, &update.change)?;
    let signature = Signature {
        signature: update.signed_payload.clone(),
        public_key: signer_pk.clone(),
        algorithm: update.signature_algorithm.clone(),
        timestamp: 0,
    };
    signer_pk
        .verify(&signing_bytes, &signature)
        .map_err(|e| format!("Group update verification failed: {}", e))
}

/// Derive epoch sender key (deterministic, no secrecy assumed here)
pub fn derive_group_epoch_key(group_id: &GroupId, epoch: u64) -> GroupEpochKey {
    let mut input = Vec::new();
    input.extend_from_slice(group_id.0.as_bytes());
    input.extend_from_slice(&epoch.to_be_bytes());
    let key_material = hash_blake3(&input);
    GroupEpochKey { epoch, key_material }
}

/// Increment epoch on membership or device change
pub fn next_group_epoch(current_epoch: u64) -> u64 {
    current_epoch.saturating_add(1)
}

fn group_state_signing_bytes(
    group_id: &GroupId,
    epoch: u64,
    admin_key: &str,
    change: &GroupChange,
) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize)]
    struct GroupUpdatePayload<'a> {
        group_id: &'a GroupId,
        epoch: u64,
        admin_key: &'a str,
        change: &'a GroupChange,
    }

    let payload = GroupUpdatePayload {
        group_id,
        epoch,
        admin_key,
        change,
    };

    bincode::serialize(&payload).map_err(|e| format!("Failed to serialize group update: {}", e))
}

/// Create PoUW stamp bound to sender device key, challenge, and message hash
pub fn create_pouw_stamp(
    sender_keypair: &KeyPair,
    challenge: &[u8],
    message_hash: [u8; 32],
) -> Result<PoUwStamp, String> {
    let mut stamp_input = Vec::new();
    stamp_input.extend_from_slice(&sender_keypair.public_key.key_id);
    stamp_input.extend_from_slice(challenge);
    stamp_input.extend_from_slice(&message_hash);
    let stamp_hash = hash_blake3(&stamp_input);

    let signature = sender_keypair
        .sign(&stamp_hash)
        .map_err(|e| format!("Failed to sign PoUW stamp: {}", e))?;

    Ok(PoUwStamp {
        sender_device_key_id: sender_keypair.public_key.key_id,
        challenge: challenge.to_vec(),
        message_hash,
        stamp_hash,
        signature: signature.signature,
        signature_algorithm: signature.algorithm,
    })
}

/// Verify PoUW stamp with sender public key
pub fn verify_pouw_stamp(stamp: &PoUwStamp, sender_pk: &PublicKey) -> Result<bool, String> {
    if sender_pk.key_id != stamp.sender_device_key_id {
        return Err("Sender key id mismatch".to_string());
    }
    let mut stamp_input = Vec::new();
    stamp_input.extend_from_slice(&stamp.sender_device_key_id);
    stamp_input.extend_from_slice(&stamp.challenge);
    stamp_input.extend_from_slice(&stamp.message_hash);
    let expected_hash = hash_blake3(&stamp_input);
    if expected_hash != stamp.stamp_hash {
        return Ok(false);
    }
    let signature = Signature {
        signature: stamp.signature.clone(),
        public_key: sender_pk.clone(),
        algorithm: stamp.signature_algorithm.clone(),
        timestamp: 0,
    };
    sender_pk
        .verify(&stamp.stamp_hash, &signature)
        .map_err(|e| format!("PoUW signature verify failed: {}", e))
}

/// Verify PoUW stamp by resolving sender DID and matching device key id
pub fn verify_pouw_stamp_with_sender_did(
    stamp: &PoUwStamp,
    sender_did: &str,
) -> Result<bool, String> {
    let doc = resolve_did(sender_did)?;
    verify_pouw_stamp_with_document(stamp, &doc)
}

fn verify_pouw_stamp_with_document(
    stamp: &PoUwStamp,
    doc: &DidDocument,
) -> Result<bool, String> {
    let devices = list_active_devices(doc);
    for device in devices {
        let (signing_pk, _encryption_pk) = get_device_keys(doc, &device.device_id)?;
        let pk = PublicKey::new(signing_pk);
        if pk.key_id == stamp.sender_device_key_id {
            return verify_pouw_stamp(stamp, &pk);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::{
        set_did_store_memory, store_did_document, apply_did_update, create_device_add_update,
    };
    use lib_identity::{ZhtpIdentity, IdentityType};

    #[test]
    fn test_build_identity_envelope_fanout() -> Result<(), String> {
        set_did_store_memory()?;

        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let mut doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "phone-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        doc = apply_did_update(doc, &add_update)?;
        store_did_document(doc.clone())?;

        let envelope = build_identity_envelope(
            "did:zhtp:sender",
            &doc.id,
            b"hello",
            MessageTtl::Days7,
        )?;

        assert_eq!(envelope.payloads.len(), 1);
        assert_eq!(envelope.payloads[0].device_id, "phone-1");
        assert!(!envelope.retain_until_ttl);
        assert!(envelope.pouw_stamp.is_none());
        Ok(())
    }

    #[test]
    fn test_delivery_receipt_sign_verify() -> Result<(), String> {
        let kp = KeyPair::generate().map_err(|e| e.to_string())?;
        let receipt = create_delivery_receipt(7, "device-x", &kp)?;
        let is_valid = verify_delivery_receipt(&receipt, &kp.public_key)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_build_envelope_with_structured_payload() -> Result<(), String> {
        set_did_store_memory()?;

        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let doc = apply_did_update(doc, &add_update)?;
        store_did_document(doc.clone())?;

        let payload = IdentityPayload::user_message(b"payload".to_vec());
        let envelope = build_identity_envelope_with_payload(
            "did:zhtp:sender",
            &doc.id,
            &payload,
            MessageTtl::Days7,
        )?;
        assert_eq!(envelope.payloads.len(), 1);
        Ok(())
    }

    #[test]
    fn test_pouw_stamp_create_verify() -> Result<(), String> {
        let kp = KeyPair::generate().map_err(|e| e.to_string())?;
        let message_hash = lib_crypto::hash_blake3(b"msg");
        let stamp = create_pouw_stamp(&kp, b"challenge", message_hash)?;
        let is_valid = verify_pouw_stamp(&stamp, &kp.public_key)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_read_receipt_sign_verify() -> Result<(), String> {
        let kp = KeyPair::generate().map_err(|e| e.to_string())?;
        let receipt = create_read_receipt(9, "device-y", &kp)?;
        let is_valid = verify_read_receipt(&receipt, &kp.public_key)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_envelope_with_pouw() -> Result<(), String> {
        set_did_store_memory()?;

        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let doc = apply_did_update(doc, &add_update)?;
        store_did_document(doc.clone())?;

        let payload = IdentityPayload::user_message(b"payload".to_vec());
        let msg_hash = lib_crypto::hash_blake3(b"payload");
        let stamp = create_pouw_stamp(&KeyPair::generate().map_err(|e| e.to_string())?, b"challenge", msg_hash)?;

        let envelope = build_identity_envelope_with_pouw(
            "did:zhtp:sender",
            &doc.id,
            &payload,
            MessageTtl::Days7,
            stamp,
        )?;
        assert!(envelope.pouw_stamp.is_some());
        Ok(())
    }

    #[test]
    fn test_pouw_verify_with_sender_did() -> Result<(), String> {
        set_did_store_memory()?;

        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let doc = apply_did_update(doc, &add_update)?;
        store_did_document(doc.clone())?;

        let kp = KeyPair {
            public_key: identity.public_key.clone(),
            private_key: identity.private_key.clone().ok_or("missing key")?,
        };
        let message_hash = lib_crypto::hash_blake3(b"msg");
        let stamp = create_pouw_stamp(&kp, b"challenge", message_hash)?;
        let is_valid = verify_pouw_stamp_with_sender_did(&stamp, &doc.id)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_group_state_update_sign_verify() -> Result<(), String> {
        let kp = KeyPair::generate().map_err(|e| e.to_string())?;
        let group_id = GroupId("group-1".to_string());
        let change = GroupChange::Add(vec![]);
        let update = create_group_state_update(group_id, 1, "admin-key", change, &kp)?;
        let is_valid = verify_group_state_update(&update, &kp.public_key)?;
        assert!(is_valid);
        Ok(())
    }

    #[test]
    fn test_group_epoch_key_derivation() {
        let group_id = GroupId("group-1".to_string());
        let key1 = derive_group_epoch_key(&group_id, 1);
        let key2 = derive_group_epoch_key(&group_id, 2);
        assert_ne!(key1.key_material, key2.key_material);
    }

    #[test]
    fn test_control_payload_from_device_update() -> Result<(), String> {
        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let update = create_device_add_update(
            &identity,
            &doc,
            "device-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;

        let payload = control_payload_from_device_update(&update)?;
        assert!(matches!(payload.kind, crate::types::IdentityMessageKind::Control(_)));
        Ok(())
    }

    #[test]
    fn test_receipt_envelope_builders() -> Result<(), String> {
        set_did_store_memory()?;

        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let doc = apply_did_update(doc, &add_update)?;
        store_did_document(doc.clone())?;

        let signer = KeyPair::generate().map_err(|e| e.to_string())?;
        let delivery = create_delivery_receipt(1, "device-1", &signer)?;
        let read = create_read_receipt(1, "device-1", &signer)?;
        let env1 = build_delivery_receipt_envelope("did:zhtp:sender", &doc.id, &delivery, MessageTtl::Days7)?;
        let env2 = build_read_receipt_envelope("did:zhtp:sender", &doc.id, &read, MessageTtl::Days7)?;
        assert_eq!(env1.payloads.len(), 1);
        assert_eq!(env2.payloads.len(), 1);
        Ok(())
    }

    #[test]
    fn test_extract_device_ciphertext() -> Result<(), String> {
        set_did_store_memory()?;

        let identity = ZhtpIdentity::new_unified(
            IdentityType::Human,
            Some(30),
            Some("US".to_string()),
            "laptop",
            None,
        ).map_err(|e| e.to_string())?;

        let doc = lib_identity::DidDocument::from_identity(&identity, None)?;
        let add_update = create_device_add_update(
            &identity,
            &doc,
            "device-1",
            &identity.public_key.dilithium_pk,
            &identity.public_key.kyber_pk,
        )?;
        let doc = apply_did_update(doc, &add_update)?;
        store_did_document(doc.clone())?;

        let payload = IdentityPayload::user_message(b"payload".to_vec());
        let envelope = build_identity_envelope_with_payload(
            "did:zhtp:sender",
            &doc.id,
            &payload,
            MessageTtl::Days7,
        )?;
        let ct = extract_device_ciphertext(&envelope, "device-1");
        assert!(ct.is_some());
        Ok(())
    }

    #[test]
    fn test_sealed_sender_envelope() -> Result<(), String> {
        let kp = KeyPair::generate().map_err(|e| e.to_string())?;
        let sealed = seal_sender_envelope("next-hop", &kp.public_key, b"payload", 8)?;
        assert_eq!(sealed.next_hop, "next-hop");
        assert!(sealed.ciphertext.len() > 0);
        assert_eq!(sealed.padding_len, 8);
        Ok(())
    }

    #[test]
    fn test_layered_envelopes() -> Result<(), String> {
        let kp1 = KeyPair::generate().map_err(|e| e.to_string())?;
        let kp2 = KeyPair::generate().map_err(|e| e.to_string())?;
        let route = vec![("hop1", &kp1.public_key), ("hop2", &kp2.public_key)];
        let envelopes = build_layered_envelopes(&route, b"payload", 4)?;
        assert_eq!(envelopes.len(), 2);
        assert_eq!(envelopes[0].next_hop, "hop1");
        assert_eq!(envelopes[1].next_hop, "hop2");
        Ok(())
    }
}
