pub mod blockchain;
pub mod browser;
pub mod contracts;
pub mod network;
pub mod storage;
pub mod zhtp;
pub mod discovery;
pub mod input_validation; // Add input validation module

// Backward compatibility consensus module alias
pub mod consensus {
    pub use crate::zhtp::consensus_engine::{
        ZkNetworkMetrics, ZhtpConsensusEngine, ZkValidator, ZkBlock
    };
}

pub use blockchain::{Block, Blockchain, Transaction, ZkBlockchainStats};
pub use zhtp::{
    consensus_engine::{ZhtpConsensusEngine, ZkValidator, ZkBlock, ZkNetworkMetrics},
    zk_transactions::{ZkTransaction, ZkBalance, ZkTransactionPool},
};
pub use network::{Network, NetworkCondition, NetworkId, Node, Packet};
pub use storage::{
    dht::{DhtNode, DhtNetwork as StorageManager},
    StorageConfig,
    ZhtpStorageManager,
    ContentMetadata,
    ContentId,
};
// Re-export key types
pub use std::sync::Arc;
pub use tokio::sync::Mutex;

// Re-export key components
pub use zhtp::{
    Keypair, ZhtpNode, ZhtpPacket, SharedNode,
    economics::{ZhtpEconomics, EconomicMetrics, TokenSupply, RewardPool, FeeMarket},
};
pub use browser::ZhtpBrowser;
pub use contracts::ContractExecutor;

#[cfg(test)]
mod tests {
    use super::*;
}

#[cfg(test)]
pub mod integration_tests;
