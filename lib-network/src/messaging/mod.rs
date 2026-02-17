//! Message handling for mesh network

pub mod gossip;
pub mod message_handler;

pub use gossip::{
    assert_block_size,
    assert_gossip_rate_limit,
    assert_tx_gossip_rate,
    GOSSIP_FANOUT,
    GOSSIP_ROUND_INTERVAL_MS,
    GOSSIP_SEEN_SET_MAX_ITEMS,
    GOSSIP_SEEN_TTL_SECS,
    MAX_BLOCK_SIZE_BYTES,
    MAX_MESSAGES_PER_PEER_PER_SEC,
    MAX_TX_GOSSIP_PER_ROUND,
};
pub use message_handler::MeshMessageHandler;
