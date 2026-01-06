use super::*;
use crate::integration::crypto_integration::PublicKey;
use crate::contracts::dao_registry::DAORegistry;

fn test_public_key(id: u8) -> PublicKey {
    PublicKey::new(vec![id; 32])
}

#[test]
fn test_register_and_get_dao() {
    let mut reg = DAORegistry::new();
    let token = [1u8; 32];
    let owner = test_public_key(1);
    let treasury = test_public_key(2);

    let (dao_id, event) = reg
        .register_dao(token, "NP".to_string(), None, treasury.clone(), owner.clone())
        .expect("should register");

    assert_eq!(event.event_type(), "DaoRegistered");

    let meta = reg.get_dao(token).expect("should find dao");
    assert_eq!(meta.dao_id, dao_id);
    assert_eq!(meta.owner, owner);
}

#[test]
fn test_list_daos_sorted() {
    let mut reg = DAORegistry::new();
    let t1 = [1u8; 32];
    let t2 = [2u8; 32];
    let owner = test_public_key(1);
    let treasury = test_public_key(2);

    let _ = reg.register_dao(t2, "NP".to_string(), None, treasury.clone(), owner.clone());
    std::thread::sleep(std::time::Duration::from_millis(5));
    let _ = reg.register_dao(t1, "NP".to_string(), None, treasury.clone(), owner.clone());

    let list = reg.list_daos();
    assert!(list.len() >= 2);
    assert!(list[0].created_at <= list[1].created_at);
}

#[test]
fn test_update_metadata_access_control() {
    let mut reg = DAORegistry::new();
    let token = [3u8; 32];
    let owner = test_public_key(1);
    let other = test_public_key(9);
    let treasury = test_public_key(2);

    let (dao_id, _) = reg
        .register_dao(token, "NP".to_string(), None, treasury.clone(), owner.clone())
        .expect("register");

    // Unauthorized update
    let res = reg.update_metadata(dao_id, other.clone(), Some([9u8; 32]));
    assert!(res.is_err());

    // Authorized update
    let res = reg.update_metadata(dao_id, owner.clone(), Some([7u8; 32]));
    assert!(res.is_ok());
    let event = res.unwrap();
    assert_eq!(event.event_type(), "DaoUpdated");
}

#[test]
fn test_register_duplicate_token_error() {
    let mut reg = DAORegistry::new();
    let token = [4u8; 32];
    let owner1 = test_public_key(1);
    let owner2 = test_public_key(2);
    let treasury = test_public_key(3);

    let _ = reg.register_dao(token, "NP".to_string(), None, treasury.clone(), owner1.clone()).unwrap();
    let res = reg.register_dao(token, "NP".to_string(), None, treasury.clone(), owner2.clone());
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), "DAO for token already registered".to_string());
}

#[test]
fn test_get_dao_not_found() {
    let reg = DAORegistry::new();
    let token = [0u8; 32];
    let res = reg.get_dao(token);
    assert!(res.is_err());
}

#[test]
fn test_update_metadata_nonexistent_dao() {
    let mut reg = DAORegistry::new();
    let random_id = [9u8; 32];
    let updater = test_public_key(1);

    let res = reg.update_metadata(random_id, updater, Some([1u8; 32]));
    assert!(res.is_err());
}

#[test]
fn test_register_with_metadata_hash() {
    let mut reg = DAORegistry::new();
    let token = [6u8; 32];
    let owner = test_public_key(7);
    let treasury = test_public_key(8);
    let metadata_hash = Some([5u8; 32]);

    let (dao_id, _) = reg.register_dao(token, "Service".to_string(), metadata_hash, treasury.clone(), owner.clone()).unwrap();
    let meta = reg.get_dao(token).unwrap();
    assert_eq!(meta.dao_id, dao_id);
    assert_eq!(meta.metadata_hash, metadata_hash);
}

#[test]
fn test_daos_unique_ids() {
    let mut reg = DAORegistry::new();
    let t1 = [11u8; 32];
    let t2 = [12u8; 32];
    let owner = test_public_key(1);
    let treasury = test_public_key(2);

    let (id1, _) = reg.register_dao(t1, "Community".to_string(), None, treasury.clone(), owner.clone()).unwrap();
    let (id2, _) = reg.register_dao(t2, "Community".to_string(), None, treasury.clone(), owner.clone()).unwrap();
    assert_ne!(id1, id2);
}

#[test]
fn test_token_index_consistency() {
    let mut reg = DAORegistry::new();
    let token = [15u8; 32];
    let owner = test_public_key(1);
    let treasury = test_public_key(2);

    let (id, _) = reg.register_dao(token, "Investment".to_string(), None, treasury.clone(), owner.clone()).unwrap();
    // internal index should map token -> id
    let idx = reg.token_index.get(&token).copied();
    assert_eq!(idx, Some(id));
}

#[test]
fn test_list_daos_empty() {
    let reg = DAORegistry::new();
    let list = reg.list_daos();
    assert!(list.is_empty());
}

#[test]
fn test_list_daos_multiple_order() {
    let mut reg = DAORegistry::new();
    let owner = test_public_key(1);
    let treasury = test_public_key(2);

    for i in 0..5 {
        let mut token = [0u8; 32];
        token[0] = i as u8 + 1;
        reg.register_dao(token, format!("Service{}", i), None, treasury.clone(), owner.clone()).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1));
    }

    let list = reg.list_daos();
    assert_eq!(list.len(), 5);
    for i in 0..4 {
        assert!(list[i].created_at <= list[i + 1].created_at);
    }
}

#[test]
fn test_wasm_wrappers_register_and_get() {
    let mut reg = DAORegistry::new();
    let token = [21u8; 32];
    let owner = test_public_key(21);
    let treasury = test_public_key(22);

    let dao_id = crate::contracts::dao_registry::wasm::register_dao_wasm(&mut reg, token, "Service".to_string(), None, treasury.clone(), owner.clone()).unwrap();
    let meta = crate::contracts::dao_registry::wasm::get_dao_wasm(&reg, token).unwrap();
    assert_eq!(meta.dao_id, dao_id);
}

#[test]
fn test_metadata_event_contents() {
    let mut reg = DAORegistry::new();
    let token = [31u8; 32];
    let owner = test_public_key(31);
    let treasury = test_public_key(32);

    let (dao_id, event) = reg.register_dao(token, "Protocol".to_string(), None, treasury.clone(), owner.clone()).unwrap();
    match event {
        crate::contracts::integration::ContractEvent::DaoRegistered { dao_id: id, token_addr, owner: o, treasury: t, class, metadata_hash } => {
            assert_eq!(id, dao_id);
            assert_eq!(token_addr, token);
            assert_eq!(o, owner);
            assert_eq!(t, treasury);
            assert_eq!(class, "Protocol".to_string());
            assert_eq!(metadata_hash, None);
        }
        _ => panic!("unexpected event type"),
    }
}

#[test]
fn test_register_various_classes() {
    let mut reg = DAORegistry::new();
    let classes = vec!["Protocol", "Service", "Community", "Investment", "Other"];
    let owner = test_public_key(45);
    let treasury = test_public_key(46);

    for (i, c) in classes.iter().enumerate() {
        let mut token = [0u8; 32];
        token[0] = (100 + i) as u8;
        let (dao_id, _) = reg.register_dao(token, c.to_string(), None, treasury.clone(), owner.clone()).unwrap();
        let meta = reg.get_dao(token).unwrap();
        assert_eq!(meta.class, c.to_string());
        assert_eq!(meta.dao_id, dao_id);
    }
}

#[test]
fn test_serialization_roundtrip() {
    let mut reg = DAORegistry::new();
    let token = [51u8; 32];
    let owner = test_public_key(51);
    let treasury = test_public_key(52);

    let (dao_id, _) = reg.register_dao(token, "Community".to_string(), Some([3u8; 32]), treasury.clone(), owner.clone()).unwrap();
    let meta = reg.get_dao(token).unwrap();
    let serialized = serde_json::to_string(&meta).unwrap();
    let deserialized: crate::contracts::dao_registry::DAOMetadata = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized.dao_id, dao_id);
    assert_eq!(deserialized.class, "Community".to_string());
}
