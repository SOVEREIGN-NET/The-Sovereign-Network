//! Peer Reputation System
//! 
//! Tracks peer behavior and maintains reputation scores

use std::time::{SystemTime, UNIX_EPOCH};

/// Peer reputation scoring
#[derive(Debug, Clone)]
pub struct PeerReputation {
    pub peer_id: String,
    pub score: i32, // -100 (banned) to 100 (trusted)
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub txs_accepted: u64,
    pub txs_rejected: u64,
    pub violations: u32,
    pub first_seen: u64,
    pub last_seen: u64,
}

impl PeerReputation {
    pub fn new(peer_id: String) -> Self {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        Self {
            peer_id,
            score: 50, // Start neutral
            blocks_accepted: 0,
            blocks_rejected: 0,
            txs_accepted: 0,
            txs_rejected: 0,
            violations: 0,
            first_seen: now,
            last_seen: now,
        }
    }
    
    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    }
    
    pub fn record_block_accepted(&mut self) {
        self.blocks_accepted += 1;
        self.score = (self.score + 1).min(100);
        self.update_last_seen();
    }
    
    pub fn record_block_rejected(&mut self) {
        self.blocks_rejected += 1;
        self.score = (self.score - 2).max(-100);
        self.update_last_seen();
    }
    
    pub fn record_tx_accepted(&mut self) {
        self.txs_accepted += 1;
        self.score = (self.score + 1).min(100);
        self.update_last_seen();
    }
    
    pub fn record_tx_rejected(&mut self) {
        self.txs_rejected += 1;
        self.score = (self.score - 2).max(-100);
        self.update_last_seen();
    }
    
    pub fn record_violation(&mut self) {
        self.violations += 1;
        self.score = (self.score - 10).max(-100);
        self.update_last_seen();
    }
    
    pub fn is_banned(&self) -> bool {
        self.score <= -50 || self.violations >= 10
    }
    
    pub fn get_acceptance_rate(&self) -> f64 {
        let total = self.blocks_accepted + self.blocks_rejected + self.txs_accepted + self.txs_rejected;
        if total == 0 {
            return 100.0;
        }
        ((self.blocks_accepted + self.txs_accepted) as f64 / total as f64) * 100.0
    }
}

/// Peer rate limiting tracker
#[derive(Debug, Clone)]
pub struct PeerRateLimit {
    pub block_count: u32,
    pub tx_count: u32,
    pub last_reset: u64,
    pub violations: u32,
}

impl PeerRateLimit {
    pub fn new() -> Self {
        Self {
            block_count: 0,
            tx_count: 0,
            last_reset: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
            violations: 0,
        }
    }
    
    pub fn check_and_increment_block(&mut self, max_per_minute: u32) -> bool {
        self.reset_if_needed();
        if self.block_count >= max_per_minute {
            self.violations += 1;
            return false;
        }
        self.block_count += 1;
        true
    }
    
    pub fn check_and_increment_tx(&mut self, max_per_minute: u32) -> bool {
        self.reset_if_needed();
        if self.tx_count >= max_per_minute {
            self.violations += 1;
            return false;
        }
        self.tx_count += 1;
        true
    }
    
    pub fn reset_if_needed(&mut self) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        if now - self.last_reset >= 60 {
            self.block_count = 0;
            self.tx_count = 0;
            self.last_reset = now;
        }
    }
    
    pub fn get_violations(&self) -> u32 {
        self.violations
    }
}

/// Peer performance statistics (for API responses)
#[derive(Debug, Clone)]
pub struct PeerPerformanceStats {
    pub peer_id: String,
    pub reputation_score: i32,
    pub blocks_accepted: u64,
    pub blocks_rejected: u64,
    pub txs_accepted: u64,
    pub txs_rejected: u64,
    pub violations: u32,
    pub acceptance_rate: f64,
    pub first_seen: u64,
    pub last_seen: u64,
}
