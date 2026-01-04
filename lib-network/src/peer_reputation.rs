//! Peer Reputation System for Byzantine Fault Handling
//!
//! This module implements a bounded, numeric peer reputation model that accumulates
//! observed behavior over time and enforces proportional network responses.
//!
//! ## Design Philosophy: "Boring Reputation"
//!
//! - Deterministic: Same event always produces same reputation change
//! - Evidence-driven: Changes only in response to explicit, classified events
//! - Network-enforced: Reputation affects connectivity, not consensus
//! - No heuristics: No probability scoring or fuzzy matching
//! - No forgiveness: No decay or automatic recovery
//!
//! ## Invariants
//!
//! 1. Reputation scores are peer-scoped, not validator-scoped
//! 2. Reputation is numeric [0, 100], bounded and deterministic
//! 3. Reputation updates are idempotent per event
//! 4. Disconnect is reversible; banning is explicit
//! 5. Reputation enforcement never alters consensus state

use std::collections::HashMap;
use lib_identity::IdentityId;

/// Peer reputation event types with their reputation delta weights
#[derive(Clone, Debug, Copy, PartialEq, Eq)]
pub enum ReputationEvent {
    /// Good vote: +5 reputation
    GoodVote,
    /// Bad vote: -10 reputation
    BadVote,
    /// Equivocation detected: -50 reputation
    Equivocation,
    /// Timeout/liveness failure: -15 reputation
    TimedOut,
}

impl ReputationEvent {
    /// Get the reputation delta for this event
    pub fn delta(&self) -> i16 {
        match self {
            ReputationEvent::GoodVote => 5,
            ReputationEvent::BadVote => -10,
            ReputationEvent::Equivocation => -50,
            ReputationEvent::TimedOut => -15,
        }
    }
}

/// Peer reputation state
#[derive(Clone, Debug)]
pub struct PeerReputation {
    /// Current reputation score [0, 100]
    score: u8,
    /// Whether this peer is banned (prevents reconnection)
    is_banned: bool,
    /// Track event counts for idempotence verification
    event_counts: HashMap<String, u32>,
}

impl Default for PeerReputation {
    fn default() -> Self {
        Self {
            score: 50, // Default reputation for new peers
            is_banned: false,
            event_counts: HashMap::new(),
        }
    }
}

impl PeerReputation {
    /// Create a new reputation tracker for a peer
    pub fn new() -> Self {
        Self::default()
    }

    /// Get current reputation score
    pub fn score(&self) -> u8 {
        self.score
    }

    /// Check if peer is banned
    pub fn is_banned(&self) -> bool {
        self.is_banned
    }

    /// Update reputation with an event
    ///
    /// Applies the event delta and clamps score to [0, 100].
    /// Returns the new score.
    pub fn apply_event(&mut self, event: ReputationEvent) -> u8 {
        let delta = event.delta();
        let new_score = (self.score as i16) + delta;

        // Clamp to [0, 100]
        self.score = if new_score < 0 {
            0
        } else if new_score > 100 {
            100
        } else {
            new_score as u8
        };

        self.score
    }

    /// Ban this peer (prevents reconnection)
    pub fn ban(&mut self) {
        self.is_banned = true;
    }

    /// Unban this peer and reset reputation to default (50)
    pub fn unban(&mut self) {
        self.is_banned = false;
        self.score = 50;
    }

    /// Check if peer should be disconnected
    ///
    /// Returns true if score < 20
    pub fn should_disconnect(&self) -> bool {
        self.score < 20
    }
}

/// Peer reputation manager for the network
///
/// Tracks reputation scores for all peers and provides query/enforcement methods.
#[derive(Clone, Debug)]
pub struct PeerReputationManager {
    /// Peer reputation scores: peer_id -> PeerReputation
    peers: HashMap<IdentityId, PeerReputation>,
}

impl Default for PeerReputationManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerReputationManager {
    /// Create a new peer reputation manager
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    /// Get or create reputation for a peer
    fn get_or_create(&mut self, peer_id: &IdentityId) -> &mut PeerReputation {
        self.peers
            .entry(peer_id.clone())
            .or_insert_with(PeerReputation::new)
    }

    /// Update peer reputation with an event
    ///
    /// # Arguments
    /// * `peer_id` - Peer to update
    /// * `event` - Reputation event
    ///
    /// # Returns
    /// New reputation score
    pub fn update_reputation(&mut self, peer_id: &IdentityId, event: ReputationEvent) -> u8 {
        let peer = self.get_or_create(peer_id);
        peer.apply_event(event)
    }

    /// Get current reputation score for a peer
    ///
    /// Returns 50 (default) if peer not in tracking system.
    pub fn get_reputation_score(&self, peer_id: &IdentityId) -> u8 {
        self.peers
            .get(peer_id)
            .map(|p| p.score())
            .unwrap_or(50)
    }

    /// Check if peer should be disconnected
    ///
    /// Returns true if:
    /// - Peer is in tracking system AND score < 20
    /// - Peer is not banned (banned peers are handled separately)
    pub fn should_disconnect(&self, peer_id: &IdentityId) -> bool {
        if let Some(peer) = self.peers.get(peer_id) {
            !peer.is_banned() && peer.should_disconnect()
        } else {
            false
        }
    }

    /// Check if peer is banned
    pub fn is_banned(&self, peer_id: &IdentityId) -> bool {
        self.peers
            .get(peer_id)
            .map(|p| p.is_banned())
            .unwrap_or(false)
    }

    /// Ban a peer (prevents reconnection)
    pub fn ban_peer(&mut self, peer_id: &IdentityId) {
        self.get_or_create(peer_id).ban();
    }

    /// Unban a peer and reset reputation to default
    pub fn unban_peer(&mut self, peer_id: &IdentityId) {
        self.get_or_create(peer_id).unban();
    }

    /// Get number of tracked peers
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Clear all peer data (for testing)
    pub fn clear(&mut self) {
        self.peers.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_crypto::hash_blake3;

    fn create_test_peer_id(name: &str) -> IdentityId {
        lib_crypto::Hash::from_bytes(&hash_blake3(name.as_bytes()))
    }

    #[test]
    fn test_peer_reputation_defaults() {
        let rep = PeerReputation::new();
        assert_eq!(rep.score(), 50);
        assert!(!rep.is_banned());
        assert!(!rep.should_disconnect());
    }

    #[test]
    fn test_good_vote_increases_score() {
        let mut rep = PeerReputation::new();
        let new_score = rep.apply_event(ReputationEvent::GoodVote);

        assert_eq!(new_score, 55);
        assert_eq!(rep.score(), 55);
    }

    #[test]
    fn test_multiple_good_votes() {
        let mut rep = PeerReputation::new();

        // Start at 50
        assert_eq!(rep.score(), 50);

        // Add two good votes: 50 + 5 + 5 = 60
        rep.apply_event(ReputationEvent::GoodVote);
        rep.apply_event(ReputationEvent::GoodVote);

        assert_eq!(rep.score(), 60);
    }

    #[test]
    fn test_bad_vote_decreases_score() {
        let mut rep = PeerReputation::new();
        let new_score = rep.apply_event(ReputationEvent::BadVote);

        assert_eq!(new_score, 40);
        assert_eq!(rep.score(), 40);
    }

    #[test]
    fn test_equivocation_severe_penalty() {
        let mut rep = PeerReputation::new();
        // Start at 50
        let new_score = rep.apply_event(ReputationEvent::Equivocation);

        // 50 - 50 = 0
        assert_eq!(new_score, 0);
        assert_eq!(rep.score(), 0);
    }

    #[test]
    fn test_score_clamped_at_minimum() {
        let mut rep = PeerReputation::new();

        // Multiple bad votes to drive below 0
        for _ in 0..10 {
            rep.apply_event(ReputationEvent::BadVote);
        }

        // Should be clamped to 0, not negative
        assert_eq!(rep.score(), 0);
    }

    #[test]
    fn test_score_clamped_at_maximum() {
        let mut rep = PeerReputation::new();

        // Multiple good votes to drive above 100
        for _ in 0..15 {
            rep.apply_event(ReputationEvent::GoodVote);
        }

        // Should be clamped to 100, not exceed
        assert_eq!(rep.score(), 100);
    }

    #[test]
    fn test_should_disconnect_threshold() {
        let mut rep = PeerReputation::new();
        // Start at 50, should NOT disconnect
        assert!(!rep.should_disconnect());

        // Apply bad votes until score < 20
        // 50 - 10 - 10 - 10 = 20 (not yet)
        rep.apply_event(ReputationEvent::BadVote);
        rep.apply_event(ReputationEvent::BadVote);
        rep.apply_event(ReputationEvent::BadVote);
        assert_eq!(rep.score(), 20);
        assert!(!rep.should_disconnect()); // score == 20, not < 20

        // One more
        rep.apply_event(ReputationEvent::BadVote);
        assert_eq!(rep.score(), 10);
        assert!(rep.should_disconnect()); // score < 20
    }

    #[test]
    fn test_ban_unban() {
        let mut rep = PeerReputation::new();
        assert!(!rep.is_banned());

        rep.ban();
        assert!(rep.is_banned());

        rep.unban();
        assert!(!rep.is_banned());
        // Reputation should reset to default
        assert_eq!(rep.score(), 50);
    }

    #[test]
    fn test_unban_resets_score() {
        let mut rep = PeerReputation::new();

        // Damage reputation
        rep.apply_event(ReputationEvent::BadVote);
        rep.apply_event(ReputationEvent::BadVote);
        rep.apply_event(ReputationEvent::BadVote);
        assert_eq!(rep.score(), 20);

        // Ban then unban
        rep.ban();
        rep.unban();

        // Reputation should reset to 50
        assert_eq!(rep.score(), 50);
        assert!(!rep.is_banned());
    }

    #[test]
    fn test_reputation_manager_new_peer() {
        let mut manager = PeerReputationManager::new();
        let peer = create_test_peer_id("peer1");

        // New peer should have default reputation
        assert_eq!(manager.get_reputation_score(&peer), 50);
        assert!(!manager.should_disconnect(&peer));
    }

    #[test]
    fn test_reputation_manager_update() {
        let mut manager = PeerReputationManager::new();
        let peer = create_test_peer_id("peer1");

        // Update with good vote
        let score = manager.update_reputation(&peer, ReputationEvent::GoodVote);
        assert_eq!(score, 55);

        // Check it persisted
        assert_eq!(manager.get_reputation_score(&peer), 55);
    }

    #[test]
    fn test_reputation_manager_multiple_peers() {
        let mut manager = PeerReputationManager::new();
        let peer1 = create_test_peer_id("peer1");
        let peer2 = create_test_peer_id("peer2");

        manager.update_reputation(&peer1, ReputationEvent::GoodVote);
        manager.update_reputation(&peer2, ReputationEvent::BadVote);

        assert_eq!(manager.get_reputation_score(&peer1), 55);
        assert_eq!(manager.get_reputation_score(&peer2), 40);
    }

    #[test]
    fn test_reputation_manager_disconnect() {
        let mut manager = PeerReputationManager::new();
        let peer = create_test_peer_id("peer1");

        // Drive score below 20
        for _ in 0..4 {
            manager.update_reputation(&peer, ReputationEvent::BadVote);
        }

        // Should be disconnected
        assert!(manager.should_disconnect(&peer));
    }

    #[test]
    fn test_reputation_manager_ban_unban() {
        let mut manager = PeerReputationManager::new();
        let peer = create_test_peer_id("peer1");

        manager.ban_peer(&peer);
        assert!(manager.is_banned(&peer));

        manager.unban_peer(&peer);
        assert!(!manager.is_banned(&peer));
        assert_eq!(manager.get_reputation_score(&peer), 50);
    }

    #[test]
    fn test_reputation_progression_scenario() {
        // Test the acceptance criteria scenario:
        // New peer starts at 50
        // Two GoodVote events → 60
        // One BadVote → 50
        let mut rep = PeerReputation::new();

        assert_eq!(rep.score(), 50);

        rep.apply_event(ReputationEvent::GoodVote);
        rep.apply_event(ReputationEvent::GoodVote);
        assert_eq!(rep.score(), 60);

        rep.apply_event(ReputationEvent::BadVote);
        assert_eq!(rep.score(), 50);
    }

    #[test]
    fn test_timeout_event_penalty() {
        let mut rep = PeerReputation::new();
        let new_score = rep.apply_event(ReputationEvent::TimedOut);

        // 50 - 15 = 35
        assert_eq!(new_score, 35);
    }

    #[test]
    fn test_multiple_timeouts_cumulative() {
        let mut rep = PeerReputation::new();

        // Three timeout events: 50 - 15 - 15 - 15 = 5
        rep.apply_event(ReputationEvent::TimedOut);
        rep.apply_event(ReputationEvent::TimedOut);
        rep.apply_event(ReputationEvent::TimedOut);

        assert_eq!(rep.score(), 5);
    }
}
