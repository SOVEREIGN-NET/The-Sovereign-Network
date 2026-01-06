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
