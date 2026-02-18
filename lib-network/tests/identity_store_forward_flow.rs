use lib_identity::{
    ZhtpIdentity, IdentityType,
    create_device_add_update, apply_did_update, store_did_document, set_did_store_memory,
};
use lib_protocols::identity_messaging::{
    build_identity_envelope_with_payload, create_delivery_receipt,
};
use lib_protocols::types::{IdentityPayload, MessageTtl};
use lib_network::identity_store_forward::IdentityStoreForward;
use lib_crypto::keypair::generation::KeyPair;

#[test]
fn test_identity_store_forward_flow() -> Result<(), String> {
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

    let payload = IdentityPayload::user_message(b"hello".to_vec());
    let envelope = build_identity_envelope_with_payload(
        "did:zhtp:sender",
        &doc.id,
        &payload,
        MessageTtl::Days7,
    )?;

    let mut queue = IdentityStoreForward::new(10);
    queue.enqueue(envelope.clone())?;
    let pending = queue.get_pending(&doc.id)?;
    assert_eq!(pending.len(), 1);

    let receipt = create_delivery_receipt(envelope.message_id, "device-1", &KeyPair::generate().map_err(|e| e.to_string())?)?;
    let removed = queue.acknowledge_delivery_receipt(&doc.id, &receipt)?;
    assert!(removed);
    let pending = queue.get_pending(&doc.id)?;
    assert!(pending.is_empty());
    Ok(())
}

