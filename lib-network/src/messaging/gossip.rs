//! Gossip Protocol Model and Anti-Spam Rate-Limit Constants (closes #983)
//!
//! # Gossip Model Overview
//!
//! ZHTP uses an **epidemic (push/pull hybrid) gossip protocol** for disseminating
//! blocks, transactions, and peer-discovery information across the mesh network.
//!
//! ## Push Phase
//!
//! When a node learns of a new item (block announcement, transaction, peer record)
//! it immediately **pushes** that item to a random subset of its active peers.
//! Push is the primary path for low-latency propagation of fresh data.
//!
//! ## Pull Phase
//!
//! Periodically each node sends a compact **digest** (e.g. a Bloom filter or a
//! set of item hashes) to a random peer and requests any items the local node is
//! missing.  Pull corrects any gaps left by failed push attempts and ensures
//! eventual consistency even under churn.
//!
//! ## Epidemic / Fan-out
//!
//! Each push event fans out to `GOSSIP_FANOUT` peers chosen uniformly at random
//! from the local peer list.  With `F = 3` and a well-connected 100-node network
//! a new item reaches >99% of nodes within O(log N) rounds.  The fan-out value
//! is kept deliberately small to bound the per-node amplification factor and
//! prevent gossip storms.
//!
//! ## Deduplication
//!
//! Every received item is checked against a short-lived seen-set (TTL =
//! `GOSSIP_SEEN_TTL_SECS`) before being forwarded.  Duplicate items are silently
//! dropped, which prevents infinite re-gossip loops.
//!
//! # Anti-Spam Invariants
//!
//! All rate limits below are **hard invariants**.  The message handler MUST drop
//! (and optionally penalise) any peer that exceeds them within the stated window.
//! Exceeding a limit is treated as a DoS attempt, not a protocol error; the
//! handler should log the event, increment the peer's reputation penalty counter,
//! and return `Err` rather than silently discarding the message without feedback.
//!
//! ## Why these numbers?
//!
//! - `MAX_MESSAGES_PER_PEER_PER_SEC = 100`:
//!   A well-behaved node at peak load (high tx throughput) should never need to
//!   send more than ~50 mesh messages per second.  The limit is set to 100 to
//!   provide headroom for bursty traffic while still blocking flood attacks.
//!
//! - `MAX_BLOCK_SIZE_BYTES = 1 MiB`:
//!   Keeps individual block processing bounded, prevents memory exhaustion when
//!   many blocks arrive concurrently, and ensures that even a slow device can
//!   deserialise a block in < 1 s.
//!
//! - `MAX_TX_GOSSIP_PER_ROUND = 500`:
//!   A "round" here corresponds to one consensus epoch.  Allowing more than 500
//!   transaction gossip messages per round per peer would overwhelm the mempool
//!   and give an attacker a cheap way to consume CPU and network bandwidth.
//!
//! - `GOSSIP_FANOUT = 3`:
//!   Theoretical minimum to achieve rapid epidemic propagation while keeping the
//!   per-message amplification factor at 3× (manageable even at large network
//!   sizes).  Increasing this value increases resilience but also bandwidth cost.
//!
//! - `GOSSIP_ROUND_INTERVAL_MS = 500`:
//!   Half-second gossip rounds balance freshness against bandwidth.  A node
//!   initiates at most 2 pull rounds per second, giving plenty of time to process
//!   responses before the next round begins.
//!
//! # Enforcement
//!
//! `assert_gossip_rate_limit()` is the canonical check function.  It MUST be
//! called before processing every inbound peer message in `MeshMessageHandler`.
//! The function is intentionally `const`-friendly so the compiler can optimise
//! away trivially-false assertions.

// =============================================================================
// INVARIANT: Gossip Anti-Spam Rate Limits (closes #983)
// =============================================================================

/// Maximum number of mesh messages accepted from a single peer per second.
///
/// # Invariant
///
/// Any peer that sends more than `MAX_MESSAGES_PER_PEER_PER_SEC` messages
/// within a rolling one-second window MUST be rate-limited.  The excess
/// messages MUST be dropped and the peer's reputation score decremented.
///
/// This limit applies to **all** message types combined (blocks, transactions,
/// DHT, peer discovery, consensus).  Per-type limits are tighter; see
/// `MAX_TX_GOSSIP_PER_ROUND`.
pub const MAX_MESSAGES_PER_PEER_PER_SEC: u32 = 100;

/// Maximum size in bytes of a single gossiped block payload.
///
/// # Invariant
///
/// Any `NewBlock` gossip message whose block field exceeds this size MUST be
/// rejected before deserialization to prevent memory exhaustion.  The check
/// must be performed on the raw byte slice length, not on the deserialized
/// struct, to avoid allocating unbounded memory.
///
/// 1 MiB provides ample space for blocks with up to ~4 000 transactions at
/// average transaction sizes, while keeping per-block memory overhead bounded.
pub const MAX_BLOCK_SIZE_BYTES: usize = 1024 * 1024; // 1 MiB

/// Maximum number of transaction gossip messages accepted from a single peer
/// per consensus round.
///
/// # Invariant
///
/// A "round" is delimited by consecutive `NewBlock` messages (or by a fixed
/// wall-clock window based on `GOSSIP_ROUND_INTERVAL_MS`
/// when no blocks arrive).  Any peer that sends more than
/// `MAX_TX_GOSSIP_PER_ROUND` `NewTransaction` messages in a single round MUST
/// have the excess messages dropped and its reputation penalized.
///
/// This prevents a single peer from monopolizing the mempool intake queue and
/// crowding out transactions from honest peers.
pub const MAX_TX_GOSSIP_PER_ROUND: u32 = 500;

// =============================================================================
// INVARIANT: Gossip Protocol Parameters
// =============================================================================

/// Number of peers to which a new item is pushed in each gossip fan-out step.
///
/// # Invariant
///
/// The fan-out MUST be at least 1 (otherwise gossip never propagates) and
/// SHOULD NOT exceed 10 (to prevent amplification storms).  The default of 3
/// achieves O(log N) propagation with 3× per-hop bandwidth amplification.
pub const GOSSIP_FANOUT: usize = 3;

/// Duration of the gossip pull round in milliseconds.
///
/// # Invariant
///
/// A node MUST wait at least `GOSSIP_ROUND_INTERVAL_MS` between consecutive
/// pull rounds to the same peer.  Violating this would turn pull gossip into
/// a polling flood.
pub const GOSSIP_ROUND_INTERVAL_MS: u64 = 500;

/// Time-to-live for the gossip seen-set in seconds.
///
/// Items are evicted from the deduplication cache after this many seconds.
/// Setting this too low risks re-gossiping stale items; setting it too high
/// wastes memory.  60 seconds covers any reasonable propagation delay.
pub const GOSSIP_SEEN_TTL_SECS: u64 = 60;

/// Maximum number of items held in the gossip seen-set at any one time.
///
/// When the set would exceed this size, the oldest entries are evicted.
/// This bounds the memory footprint of the deduplication cache regardless
/// of item arrival rate.
pub const GOSSIP_SEEN_SET_MAX_ITEMS: usize = 10_000;

// =============================================================================
// Validation / Assertion Helpers
// =============================================================================

/// Assert that a per-peer message count is within the rate limit.
///
/// # Arguments
///
/// * `count` - Number of messages received from the peer in the current second.
/// * `peer_id_prefix` - Up to 8 bytes of the peer's key-id for log context.
///
/// # Errors
///
/// Returns `Err` with a human-readable description when the invariant is
/// violated.  The caller MUST drop the triggering message and SHOULD decrement
/// the peer's reputation score.
///
/// # Example
///
/// ```rust
/// use lib_network::messaging::gossip::assert_gossip_rate_limit;
///
/// // Within limit: should be Ok
/// assert!(assert_gossip_rate_limit(50, b"deadbeef").is_ok());
///
/// // At the limit: should be Ok
/// assert!(assert_gossip_rate_limit(100, b"deadbeef").is_ok());
///
/// // Over the limit: should be Err
/// assert!(assert_gossip_rate_limit(101, b"deadbeef").is_err());
/// ```
pub fn assert_gossip_rate_limit(
    count: u32,
    peer_id_prefix: &[u8],
) -> Result<(), String> {
    if count > MAX_MESSAGES_PER_PEER_PER_SEC {
        let display_len = peer_id_prefix.len().min(8);
        let display_prefix = &peer_id_prefix[..display_len];
        return Err(format!(
            "RATE LIMIT EXCEEDED: peer {} sent {} messages/s (max {})",
            hex::encode(display_prefix),
            count,
            MAX_MESSAGES_PER_PEER_PER_SEC,
        ));
    }
    Ok(())
}

/// Assert that an inbound block payload does not exceed the size invariant.
///
/// # Arguments
///
/// * `block_bytes` - The raw block bytes (before deserialization).
///
/// # Errors
///
/// Returns `Err` when the block exceeds `MAX_BLOCK_SIZE_BYTES`.  The caller
/// MUST NOT deserialize the block after receiving this error.
pub fn assert_block_size(block_bytes: &[u8]) -> Result<(), String> {
    if block_bytes.len() > MAX_BLOCK_SIZE_BYTES {
        return Err(format!(
            "BLOCK SIZE INVARIANT VIOLATED: {} bytes exceeds max {} bytes",
            block_bytes.len(),
            MAX_BLOCK_SIZE_BYTES,
        ));
    }
    Ok(())
}

/// Assert that the per-round transaction gossip count is within limits.
///
/// # Arguments
///
/// * `count` - Number of `NewTransaction` messages received from this peer
///   in the current consensus round.
/// * `peer_id_prefix` - Up to 8 bytes of the peer's key-id for log context.
///
/// # Errors
///
/// Returns `Err` when the count exceeds `MAX_TX_GOSSIP_PER_ROUND`.
pub fn assert_tx_gossip_rate(
    count: u32,
    peer_id_prefix: &[u8],
) -> Result<(), String> {
    if count > MAX_TX_GOSSIP_PER_ROUND {
        return Err(format!(
            "TX GOSSIP RATE LIMIT EXCEEDED: peer {} sent {} txs/round (max {})",
            hex::encode(peer_id_prefix),
            count,
            MAX_TX_GOSSIP_PER_ROUND,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- constant sanity checks ----

    #[test]
    fn max_messages_per_peer_per_sec_is_100() {
        assert_eq!(MAX_MESSAGES_PER_PEER_PER_SEC, 100);
    }

    #[test]
    fn max_block_size_bytes_is_1_mib() {
        assert_eq!(MAX_BLOCK_SIZE_BYTES, 1024 * 1024);
    }

    #[test]
    fn max_tx_gossip_per_round_is_500() {
        assert_eq!(MAX_TX_GOSSIP_PER_ROUND, 500);
    }

    #[test]
    fn gossip_fanout_is_at_least_1() {
        assert!(GOSSIP_FANOUT >= 1, "Fanout must be at least 1 for gossip to propagate");
    }

    #[test]
    fn gossip_seen_ttl_is_positive() {
        assert!(GOSSIP_SEEN_TTL_SECS > 0);
    }

    // ---- assert_gossip_rate_limit ----

    #[test]
    fn rate_limit_allows_within_bound() {
        assert!(assert_gossip_rate_limit(0, b"00000000").is_ok());
        assert!(assert_gossip_rate_limit(50, b"00000000").is_ok());
        assert!(assert_gossip_rate_limit(100, b"00000000").is_ok());
    }

    #[test]
    fn rate_limit_rejects_over_bound() {
        let result = assert_gossip_rate_limit(101, b"deadbeef");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("RATE LIMIT EXCEEDED"));
    }

    #[test]
    fn rate_limit_error_includes_peer_id() {
        let result = assert_gossip_rate_limit(200, b"\xca\xfe");
        let msg = result.unwrap_err();
        assert!(msg.contains("cafe"), "Error should contain hex peer id: {}", msg);
    }

    // ---- assert_block_size ----

    #[test]
    fn block_size_allows_within_bound() {
        let small_block = vec![0u8; 1024];
        assert!(assert_block_size(&small_block).is_ok());

        let exact_block = vec![0u8; MAX_BLOCK_SIZE_BYTES];
        assert!(assert_block_size(&exact_block).is_ok());
    }

    #[test]
    fn block_size_rejects_over_bound() {
        let large_block = vec![0u8; MAX_BLOCK_SIZE_BYTES + 1];
        let result = assert_block_size(&large_block);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("BLOCK SIZE INVARIANT VIOLATED"));
    }

    // ---- assert_tx_gossip_rate ----

    #[test]
    fn tx_gossip_rate_allows_within_bound() {
        assert!(assert_tx_gossip_rate(0, b"00000000").is_ok());
        assert!(assert_tx_gossip_rate(500, b"00000000").is_ok());
    }

    #[test]
    fn tx_gossip_rate_rejects_over_bound() {
        let result = assert_tx_gossip_rate(501, b"baadf00d");
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("TX GOSSIP RATE LIMIT EXCEEDED"));
    }
}
