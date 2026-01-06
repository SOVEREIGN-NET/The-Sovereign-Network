use crate::contracts::dao_registry::{DAORegistry, DAOMetadata};
use crate::integration::crypto_integration::PublicKey;

/// WASM friendly wrappers. These simply call into `DAORegistry` methods and
/// return basic serializable results. The actual wasm ABI wiring is handled by
/// the contracts runtime builder which can call these functions and publish
/// events accordingly.

pub fn register_dao_wasm(
    registry: &mut DAORegistry,
    token_addr: [u8; 32],
    class: String,
    metadata_hash: Option<[u8; 32]>,
    treasury: PublicKey,
    owner: PublicKey,
) -> Result<[u8; 32], String> {
    let (dao_id, _event) = registry.register_dao(token_addr, class, metadata_hash, treasury, owner)?;
    Ok(dao_id)
}

pub fn get_dao_wasm(registry: &DAORegistry, token_addr: [u8; 32]) -> Result<DAOMetadata, String> {
    registry.get_dao(token_addr)
}

pub fn list_daos_wasm(registry: &DAORegistry) -> Vec<crate::contracts::dao_registry::DAOEntry> {
    registry.list_daos()
}

pub fn update_metadata_wasm(
    registry: &mut DAORegistry,
    dao_id: [u8; 32],
    updater: PublicKey,
    metadata_hash: Option<[u8; 32]>,
) -> Result<(), String> {
    let _ = registry.update_metadata(dao_id, updater, metadata_hash)?;
    Ok(())
}
