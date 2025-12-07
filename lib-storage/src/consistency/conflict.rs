//! Conflict resolution strategies

use crate::consistency::vector_clock::VectorClock;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Conflict resolution strategy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictStrategy {
    /// Last write wins (based on timestamp)
    LastWriteWins,
    /// Keep all conflicting versions
    KeepAll,
    /// Use custom resolution logic
    Custom,
}

/// Conflict resolver
pub struct ConflictResolver {
    strategy: ConflictStrategy,
}

impl ConflictResolver {
    /// Create a new conflict resolver
    pub fn new(strategy: ConflictStrategy) -> Self {
        Self { strategy }
    }

    /// Resolve a conflict between two values
    pub fn resolve<T: Clone>(
        &self,
        value1: &T,
        clock1: &VectorClock,
        value2: &T,
        clock2: &VectorClock,
    ) -> Resolution<T> {
        match self.strategy {
            ConflictStrategy::LastWriteWins => self.resolve_lww(value1, clock1, value2, clock2),
            ConflictStrategy::KeepAll => Resolution::Multiple(vec![value1.clone(), value2.clone()]),
            ConflictStrategy::Custom => {
                // Default to keep all for custom
                Resolution::Multiple(vec![value1.clone(), value2.clone()])
            }
        }
    }

    /// Resolve using last-write-wins
    fn resolve_lww<T: Clone>(
        &self,
        value1: &T,
        clock1: &VectorClock,
        value2: &T,
        clock2: &VectorClock,
    ) -> Resolution<T> {
        use crate::consistency::vector_clock::ClockOrdering;

        match clock1.compare(clock2) {
            ClockOrdering::Before => Resolution::Single(value2.clone()),
            ClockOrdering::After => Resolution::Single(value1.clone()),
            ClockOrdering::Equal => Resolution::Single(value1.clone()),
            ClockOrdering::Concurrent => {
                // For concurrent updates, keep both
                Resolution::Multiple(vec![value1.clone(), value2.clone()])
            }
        }
    }

    /// Get the strategy
    pub fn strategy(&self) -> ConflictStrategy {
        self.strategy
    }
}

impl Default for ConflictResolver {
    fn default() -> Self {
        Self::new(ConflictStrategy::LastWriteWins)
    }
}

/// Resolution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Resolution<T> {
    /// Single resolved value
    Single(T),
    /// Multiple conflicting values
    Multiple(Vec<T>),
}

impl<T> Resolution<T> {
    /// Check if resolution resulted in a single value
    pub fn is_single(&self) -> bool {
        matches!(self, Resolution::Single(_))
    }

    /// Check if resolution resulted in multiple values
    pub fn is_multiple(&self) -> bool {
        matches!(self, Resolution::Multiple(_))
    }

    /// Get the single value if available
    pub fn single(&self) -> Option<&T> {
        match self {
            Resolution::Single(v) => Some(v),
            _ => None,
        }
    }

    /// Get all values (single or multiple)
    pub fn values(&self) -> Vec<&T> {
        match self {
            Resolution::Single(v) => vec![v],
            Resolution::Multiple(vs) => vs.iter().collect(),
        }
    }

    /// Get the number of values
    pub fn count(&self) -> usize {
        match self {
            Resolution::Single(_) => 1,
            Resolution::Multiple(vs) => vs.len(),
        }
    }
}

/// Merge strategy for combining multiple values
pub trait MergeStrategy<T> {
    /// Merge multiple values into one
    fn merge(&self, values: Vec<T>) -> Result<T>;
}

/// Numeric merge strategy (sum)
pub struct SumMergeStrategy;

impl MergeStrategy<i64> for SumMergeStrategy {
    fn merge(&self, values: Vec<i64>) -> Result<i64> {
        Ok(values.iter().sum())
    }
}

impl MergeStrategy<u64> for SumMergeStrategy {
    fn merge(&self, values: Vec<u64>) -> Result<u64> {
        Ok(values.iter().sum())
    }
}

/// Max value merge strategy
pub struct MaxMergeStrategy;

impl MergeStrategy<i64> for MaxMergeStrategy {
    fn merge(&self, values: Vec<i64>) -> Result<i64> {
        values
            .into_iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("No values to merge"))
    }
}

impl MergeStrategy<u64> for MaxMergeStrategy {
    fn merge(&self, values: Vec<u64>) -> Result<u64> {
        values
            .into_iter()
            .max()
            .ok_or_else(|| anyhow::anyhow!("No values to merge"))
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
    fn test_lww_resolution() {
        let resolver = ConflictResolver::new(ConflictStrategy::LastWriteWins);

        let mut clock1 = VectorClock::new();
        clock1.increment(&node(1));

        let mut clock2 = VectorClock::new();
        clock2.increment(&node(1));
        clock2.increment(&node(1));

        let resolution = resolver.resolve(&10, &clock1, &20, &clock2);
        assert!(resolution.is_single());
        assert_eq!(*resolution.single().unwrap(), 20);
    }

    #[test]
    fn test_keep_all_resolution() {
        let resolver = ConflictResolver::new(ConflictStrategy::KeepAll);

        let clock1 = VectorClock::new();
        let clock2 = VectorClock::new();

        let resolution = resolver.resolve(&10, &clock1, &20, &clock2);
        assert!(resolution.is_multiple());
        assert_eq!(resolution.count(), 2);
    }

    #[test]
    fn test_sum_merge() {
        let strategy = SumMergeStrategy;
        let result = strategy.merge(vec![10i64, 20, 30]).unwrap();
        assert_eq!(result, 60);
    }

    #[test]
    fn test_max_merge() {
        let strategy = MaxMergeStrategy;
        let result = strategy.merge(vec![10i64, 20, 15]).unwrap();
        assert_eq!(result, 20);
    }
}
