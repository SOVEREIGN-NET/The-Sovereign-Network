use anyhow::Result;
use tracing::warn;

use lib_blockchain::block::Block;

/// Index a block into the shared DHT if a mesh router is available.
/// Falls back silently when the mesh router or DHT storage is not yet wired.
pub async fn index_block_in_dht(block: &Block) -> Result<()> {
    let mesh_router = match crate::runtime::mesh_router_provider::get_global_mesh_router().await {
        Ok(router) => router,
        Err(_) => return Ok(()), // No mesh router registered; skip indexing
    };

    let dht_storage = mesh_router.dht_storage();
    let mut guard = dht_storage.lock().await;
    if let Err(e) = lib_blockchain::dht_index::index_block(&mut *guard, block).await {
        warn!("DHT indexing skipped: {}", e);
    }

    Ok(())
}
