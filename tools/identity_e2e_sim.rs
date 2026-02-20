//! Identity E2E simulation: DID fan-out + store-and-forward + receipts

use lib_identity::{
    ZhtpIdentity, IdentityType,
    create_device_add_update, apply_did_update, store_did_document, set_did_store_memory,
};
use lib_protocols::identity_messaging::{
    build_delivery_receipt_envelope, build_identity_envelope_with_payload,
    create_delivery_receipt, create_pouw_stamp,
    build_identity_envelope_with_pouw,
};
use lib_protocols::types::{IdentityPayload, MessageTtl};
use lib_network::identity_store_forward::IdentityStoreForward;
use lib_crypto::keypair::generation::KeyPair;

fn main() -> Result<(), String> {
    set_did_store_memory()?;

    let sender = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),
        Some("US".to_string()),
        "sender-device",
        None,
    ).map_err(|e| e.to_string())?;

    let sender_doc = lib_identity::DidDocument::from_identity(&sender, None)?;
    let sender_add = create_device_add_update(
        &sender,
        &sender_doc,
        "sender-device",
        &sender.public_key.dilithium_pk,
        &sender.public_key.kyber_pk,
    )?;
    let sender_doc = apply_did_update(sender_doc, &sender_add)?;
    store_did_document(sender_doc.clone())?;

    let recipient = ZhtpIdentity::new_unified(
        IdentityType::Human,
        Some(30),
        Some("US".to_string()),
        "laptop",
        None,
    ).map_err(|e| e.to_string())?;

    let doc = lib_identity::DidDocument::from_identity(&recipient, None)?;
    let add_update = create_device_add_update(
        &recipient,
        &doc,
        "phone-1",
        &recipient.public_key.dilithium_pk,
        &recipient.public_key.kyber_pk,
    )?;
    let doc = apply_did_update(doc, &add_update)?;
    store_did_document(doc.clone())?;

    let payload = IdentityPayload::user_message(b"hello-e2e".to_vec());
    let msg_hash = lib_crypto::hash_blake3(b"hello-e2e");
    let sender_kp = KeyPair {
        public_key: sender.public_key.clone(),
        private_key: sender.private_key.clone().ok_or("missing sender key")?,
    };
    let stamp = create_pouw_stamp(&sender_kp, b"challenge", msg_hash)?;
    let envelope = build_identity_envelope_with_pouw(
        &sender_doc.id,
        &doc.id,
        &payload,
        MessageTtl::Days7,
        stamp,
    )?;

    let mut queue = IdentityStoreForward::new(10);
    queue.set_pouw_verifier(IdentityStoreForward::default_pouw_verifier());
    queue.enqueue(envelope.clone())?;
    let pending = queue.get_pending(&doc.id)?;
    println!("queued: {}", pending.len());

    let pending_for_device = queue.get_pending_for_device(&doc.id, "phone-1")?;
    println!("pending for phone-1: {}", pending_for_device.len());

    let recipient_kp = KeyPair {
        public_key: recipient.public_key.clone(),
        private_key: recipient.private_key.clone().ok_or("missing recipient key")?,
    };
    let receipt = create_delivery_receipt(envelope.message_id, "phone-1", &recipient_kp)?;
    let receipt_envelope = build_delivery_receipt_envelope(
        &doc.id,
        &sender_doc.id,
        &receipt,
        MessageTtl::Days7,
    )?;
    println!("receipt envelope payloads: {}", receipt_envelope.payloads.len());

    let removed = queue.acknowledge_delivery(&doc.id, envelope.message_id)?;
    println!("delivery ack removed: {}", removed);

    Ok(())
}
