//! Vector clock implementation for distributed causality tracking

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::types::NodeId;

/// Vector clock for tracking causality in distributed systems
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VectorClock {
    /// Map of node IDs to their logical clock values
    clocks: HashMap<NodeId, u64>,
}

impl VectorClock {
    /// Create a new empty vector clock
    pub fn new() -> Self {
        Self {
            clocks: HashMap::new(),
        }
    }

    /// Increment the clock for a specific node
    pub fn increment(&mut self, node_id: &NodeId) {
        let counter = self.clocks.entry(node_id.clone()).or_insert(0);
        *counter += 1;
    }

    /// Get the clock value for a node
    pub fn get(&self, node_id: &NodeId) -> u64 {
        *self.clocks.get(node_id).unwrap_or(&0)
    }

    /// Merge another vector clock into this one (take max of each clock)
    pub fn merge(&mut self, other: &VectorClock) {
        for (node_id, &clock_value) in &other.clocks {
            let current = self.clocks.entry(node_id.clone()).or_insert(0);
            *current = (*current).max(clock_value);
        }
    }

    /// Check if this clock happens before another (this < other)
    pub fn happens_before(&self, other: &VectorClock) -> bool {
        let mut strictly_less = false;

        // Check all nodes in self
        for (node_id, &self_clock) in &self.clocks {
            let other_clock = other.get(node_id);
            if self_clock > other_clock {
                return false; // Not happens-before
            }
            if self_clock < other_clock {
                strictly_less = true;
            }
        }

        // Check all nodes in other that might not be in self
        for (node_id, &other_clock) in &other.clocks {
            if !self.clocks.contains_key(node_id) && other_clock > 0 {
                strictly_less = true;
            }
        }

        strictly_less
    }

    /// Check if this clock happens after another (this > other)
    pub fn happens_after(&self, other: &VectorClock) -> bool {
        other.happens_before(self)
    }

    /// Check if two clocks are concurrent (neither happens before the other)
    pub fn concurrent(&self, other: &VectorClock) -> bool {
        !self.happens_before(other) && !other.happens_before(self) && self != other
    }

    /// Compare two vector clocks
    pub fn compare(&self, other: &VectorClock) -> ClockOrdering {
        if self == other {
            ClockOrdering::Equal
        } else if self.happens_before(other) {
            ClockOrdering::Before
        } else if self.happens_after(other) {
            ClockOrdering::After
        } else {
            ClockOrdering::Concurrent
        }
    }

    /// Get all node IDs in this clock
    pub fn node_ids(&self) -> Vec<NodeId> {
        self.clocks.keys().cloned().collect()
    }

    /// Get the maximum clock value across all nodes
    pub fn max_clock(&self) -> u64 {
        self.clocks.values().copied().max().unwrap_or(0)
    }

    /// Get the total of all clock values
    pub fn total_clock(&self) -> u64 {
        self.clocks.values().sum()
    }

    /// Create a vector clock from a node and value
    pub fn from_node(node_id: NodeId, value: u64) -> Self {
        let mut clocks = HashMap::new();
        clocks.insert(node_id, value);
        Self { clocks }
    }
}

impl Default for VectorClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Ordering relationship between vector clocks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClockOrdering {
    /// Clocks are equal
    Equal,
    /// First clock happens before second
    Before,
    /// First clock happens after second
    After,
    /// Clocks are concurrent
    Concurrent,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::NodeId as IdentityNodeId;

    fn node(id: u8) -> IdentityNodeId {
        IdentityNodeId::from_bytes([id; 32])
    }

    #[test]
    fn test_vector_clock_increment() {
        let mut clock = VectorClock::new();
        let n1 = node(1);
        let n2 = node(2);
        let n3 = node(3);

        clock.increment(&n1);
        clock.increment(&n1);
        clock.increment(&n2);

        assert_eq!(clock.get(&n1), 2);
        assert_eq!(clock.get(&n2), 1);
        assert_eq!(clock.get(&n3), 0);
    }

    #[test]
    fn test_vector_clock_merge() {
        let mut clock1 = VectorClock::new();
        let n1 = node(1);
        let n2 = node(2);
        clock1.increment(&n1);
        clock1.increment(&n1);

        let mut clock2 = VectorClock::new();
        clock2.increment(&n1);
        clock2.increment(&n2);

        clock1.merge(&clock2);

        assert_eq!(clock1.get(&n1), 2);
        assert_eq!(clock1.get(&n2), 1);
    }

    #[test]
    fn test_happens_before() {
        let mut clock1 = VectorClock::new();
        let n1 = node(1);
        clock1.increment(&n1);

        let mut clock2 = VectorClock::new();
        clock2.increment(&n1);
        clock2.increment(&n1);

        assert!(clock1.happens_before(&clock2));
        assert!(!clock2.happens_before(&clock1));
    }

    #[test]
    fn test_concurrent() {
        let mut clock1 = VectorClock::new();
        let n1 = node(1);
        let n2 = node(2);
        clock1.increment(&n1);

        let mut clock2 = VectorClock::new();
        clock2.increment(&n2);

        assert!(clock1.concurrent(&clock2));
        assert!(clock2.concurrent(&clock1));
    }

    #[test]
    fn test_compare() {
        let mut clock1 = VectorClock::new();
        let n1 = node(1);
        clock1.increment(&n1);

        let mut clock2 = clock1.clone();
        clock2.increment(&n1);

        assert_eq!(clock1.compare(&clock2), ClockOrdering::Before);
        assert_eq!(clock2.compare(&clock1), ClockOrdering::After);
        assert_eq!(clock1.compare(&clock1), ClockOrdering::Equal);
    }
}
