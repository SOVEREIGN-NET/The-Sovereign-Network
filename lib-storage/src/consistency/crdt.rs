//! Conflict-free Replicated Data Types (CRDTs)

use crate::consistency::vector_clock::VectorClock;
use crate::types::NodeId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Last-Write-Wins Register (LWW-Register)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LWWRegister<T: Clone> {
    value: T,
    timestamp: VectorClock,
    node_id: NodeId,
}

impl<T: Clone> LWWRegister<T> {
    /// Create a new LWW register
    pub fn new(value: T, node_id: NodeId) -> Self {
        let mut timestamp = VectorClock::new();
        timestamp.increment(&node_id);

        Self {
            value,
            timestamp,
            node_id,
        }
    }

    /// Update the register value
    pub fn set(&mut self, value: T) {
        self.value = value;
        self.timestamp.increment(&self.node_id);
    }

    /// Get the current value
    pub fn get(&self) -> &T {
        &self.value
    }

    /// Get the timestamp
    pub fn timestamp(&self) -> &VectorClock {
        &self.timestamp
    }

    /// Merge with another LWW register (keep the one with higher timestamp)
    pub fn merge(&mut self, other: &LWWRegister<T>) {
        if other.timestamp.happens_after(&self.timestamp) {
            self.value = other.value.clone();
            self.timestamp = other.timestamp.clone();
        } else if other.timestamp.concurrent(&self.timestamp) {
            // Break ties with node_id (lexicographic bytes)
            if other.node_id.as_bytes() > self.node_id.as_bytes() {
                self.value = other.value.clone();
                self.timestamp = other.timestamp.clone();
            }
        }
    }
}

/// Grow-only Counter (G-Counter)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GCounter {
    /// Per-node counters
    counters: HashMap<NodeId, u64>,
}

impl GCounter {
    /// Create a new G-Counter
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
        }
    }

    /// Increment the counter for a node
    pub fn increment(&mut self, node_id: &NodeId, amount: u64) {
        let counter = self.counters.entry(node_id.clone()).or_insert(0);
        *counter += amount;
    }

    /// Get the total value across all nodes
    pub fn value(&self) -> u64 {
        self.counters.values().sum()
    }

    /// Get the value for a specific node
    pub fn get_node_value(&self, node_id: &NodeId) -> u64 {
        *self.counters.get(node_id).unwrap_or(&0)
    }

    /// Merge with another G-Counter (take max for each node)
    pub fn merge(&mut self, other: &GCounter) {
        for (node_id, &count) in &other.counters {
            let current = self.counters.entry(node_id.clone()).or_insert(0);
            *current = (*current).max(count);
        }
    }
}

impl Default for GCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Positive-Negative Counter (PN-Counter)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PNCounter {
    /// Positive counter
    positive: GCounter,
    /// Negative counter
    negative: GCounter,
}

impl PNCounter {
    /// Create a new PN-Counter
    pub fn new() -> Self {
        Self {
            positive: GCounter::new(),
            negative: GCounter::new(),
        }
    }

    /// Increment the counter
    pub fn increment(&mut self, node_id: &NodeId, amount: u64) {
        self.positive.increment(node_id, amount);
    }

    /// Decrement the counter
    pub fn decrement(&mut self, node_id: &NodeId, amount: u64) {
        self.negative.increment(node_id, amount);
    }

    /// Get the current value (positive - negative)
    pub fn value(&self) -> i64 {
        self.positive.value() as i64 - self.negative.value() as i64
    }

    /// Get the positive count
    pub fn positive_value(&self) -> u64 {
        self.positive.value()
    }

    /// Get the negative count
    pub fn negative_value(&self) -> u64 {
        self.negative.value()
    }

    /// Merge with another PN-Counter
    pub fn merge(&mut self, other: &PNCounter) {
        self.positive.merge(&other.positive);
        self.negative.merge(&other.negative);
    }
}

impl Default for PNCounter {
    fn default() -> Self {
        Self::new()
    }
}

/// Observed-Remove Set (OR-Set)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ORSet<T: Clone + Eq + std::hash::Hash> {
    /// Elements with their unique tags
    elements: HashMap<T, Vec<(NodeId, u64)>>,
}

impl<T: Clone + Eq + std::hash::Hash> ORSet<T> {
    /// Create a new OR-Set
    pub fn new() -> Self {
        Self {
            elements: HashMap::new(),
        }
    }

    /// Add an element with a unique tag
    pub fn add(&mut self, element: T, node_id: NodeId, timestamp: u64) {
        let tags = self.elements.entry(element).or_insert_with(Vec::new);
        tags.push((node_id, timestamp));
    }

    /// Remove an element (removes all tags)
    pub fn remove(&mut self, element: &T) -> Option<Vec<(NodeId, u64)>> {
        self.elements.remove(element)
    }

    /// Check if element exists
    pub fn contains(&self, element: &T) -> bool {
        self.elements.contains_key(element)
    }

    /// Get all elements
    pub fn elements(&self) -> Vec<&T> {
        self.elements.keys().collect()
    }

    /// Merge with another OR-Set
    pub fn merge(&mut self, other: &ORSet<T>) {
        for (element, tags) in &other.elements {
            let our_tags = self.elements.entry(element.clone()).or_insert_with(Vec::new);
            for tag in tags {
                if !our_tags.contains(tag) {
                    our_tags.push(tag.clone());
                }
            }
        }
    }
}

impl<T: Clone + Eq + std::hash::Hash> Default for ORSet<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lib_identity::NodeId as IdentityNodeId;

    fn node(id: u8) -> IdentityNodeId {
        IdentityNodeId::from_bytes([id; 32])
    }

    #[test]
    fn test_lww_register() {
        let mut reg1 = LWWRegister::new(10, node(1));
        let mut reg2 = LWWRegister::new(20, node(2));

        reg1.set(15);
        reg2.set(25);

        reg1.merge(&reg2);
        // reg2 has higher timestamp, should win
        assert_eq!(*reg1.get(), 25);
    }

    #[test]
    fn test_gcounter() {
        let mut counter1 = GCounter::new();
        counter1.increment(&node(1), 5);
        counter1.increment(&node(2), 3);

        let mut counter2 = GCounter::new();
        counter2.increment(&node(1), 2);
        counter2.increment(&node(3), 4);

        counter1.merge(&counter2);

        assert_eq!(counter1.value(), 12); // max(5,2) + 3 + 4
    }

    #[test]
    fn test_pncounter() {
        let mut counter = PNCounter::new();
        counter.increment(&node(1), 10);
        counter.decrement(&node(1), 3);

        assert_eq!(counter.value(), 7);
    }

    #[test]
    fn test_orset() {
        let mut set1 = ORSet::new();
        set1.add("a", node(1), 1);
        set1.add("b", node(1), 2);

        let mut set2 = ORSet::new();
        set2.add("b", node(2), 3);
        set2.add("c", node(2), 4);

        set1.merge(&set2);

        assert!(set1.contains(&"a"));
        assert!(set1.contains(&"b"));
        assert!(set1.contains(&"c"));
    }
}
