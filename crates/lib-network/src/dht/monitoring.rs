//! DHT Performance Monitoring Extensions
//! 
//! Extends existing lib-network monitoring with DHT-specific metrics

use std::time::{Duration, SystemTime, Instant};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde::{Serialize, Deserialize};

// Re-export existing monitoring functionality  
pub use crate::monitoring::{HealthMonitor, NetworkHealthSummary};

/// DHT-specific operation types for performance metrics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DHTOperation {
    Store,
    Retrieve,
    Resolve,
    PeerDiscover,
    PeerConnect,
    CacheHit,
    CacheMiss,
}

/// DHT-specific performance metric for a single operation
#[derive(Debug, Clone)]
struct DHTOperationMetric {
    operation: DHTOperation,
    duration: Duration,
    success: bool,
    timestamp: SystemTime,
    peer_count: usize,
}

/// DHT-specific performance statistics (extends existing monitoring)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DHTPerformanceStats {
    // DHT-specific latency metrics
    pub avg_latency_ms: f64,
    pub median_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    
    // DHT operation success rates
    pub success_rate: f64,
    pub error_rate: f64,
    
    // DHT operation counts
    pub total_operations: u64,
    pub operations_per_second: f64,
    
    // DHT cache performance (extends basic cache stats)
    pub cache_hit_rate: f64,
    pub cache_miss_rate: f64,
    pub cache_size: usize,
    
    // DHT-specific metrics
    pub content_resolution_time_ms: f64,
    pub peer_discovery_time_ms: f64,
    pub storage_operation_time_ms: f64,
    
    // Time range
    pub measurement_period_secs: u64,
    pub last_updated: SystemTime,
}

/// DHT-specific performance monitor (extends existing network monitoring)
pub struct DHTPerformanceMonitor {
    metrics: VecDeque<DHTOperationMetric>,
    max_metrics: usize,
    window_duration: Duration,
    start_time: SystemTime,
}

impl DHTPerformanceMonitor {
    /// Create new performance monitor
    pub fn new(max_metrics: usize, window_duration: Duration) -> Self {
        Self {
            metrics: VecDeque::with_capacity(max_metrics),
            max_metrics,
            window_duration,
            start_time: SystemTime::now(),
        }
    }

    /// Record a completed operation
    pub fn record_operation(
        &mut self, 
        operation: DHTOperation, 
        duration: Duration, 
        success: bool,
        peer_count: usize
    ) {
        let metric = DHTOperationMetric {
            operation,
            duration,
            success,
            timestamp: SystemTime::now(),
            peer_count,
        };

        // Add new metric
        self.metrics.push_back(metric);

        // Remove old metrics if at capacity
        if self.metrics.len() > self.max_metrics {
            self.metrics.pop_front();
        }

        // Clean up metrics outside time window
        self.cleanup_old_metrics();
    }

    /// Get current DHT performance statistics
    pub fn get_stats(&self) -> DHTPerformanceStats {
        if self.metrics.is_empty() {
            return DHTPerformanceStats {
                avg_latency_ms: 0.0,
                median_latency_ms: 0.0,
                p95_latency_ms: 0.0,
                p99_latency_ms: 0.0,
                success_rate: 1.0,
                error_rate: 0.0,
                total_operations: 0,
                operations_per_second: 0.0,
                cache_hit_rate: 0.0,
                cache_miss_rate: 0.0,
                cache_size: 0,
                content_resolution_time_ms: 0.0,
                peer_discovery_time_ms: 0.0,
                storage_operation_time_ms: 0.0,
                measurement_period_secs: self.window_duration.as_secs(),
                last_updated: SystemTime::now(),
            };
        }

        let current_metrics: Vec<_> = self.metrics.iter().collect();
        
        // Calculate latency metrics
        let mut durations: Vec<_> = current_metrics.iter()
            .map(|m| m.duration.as_millis() as f64)
            .collect();
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let avg_latency_ms = durations.iter().sum::<f64>() / durations.len() as f64;
        let median_latency_ms = percentile(&durations, 0.5);
        let p95_latency_ms = percentile(&durations, 0.95);
        let p99_latency_ms = percentile(&durations, 0.99);

        // Calculate success rate
        let successful = current_metrics.iter().filter(|m| m.success).count();
        let total = current_metrics.len();
        let success_rate = if total > 0 { 
            successful as f64 / total as f64 
        } else { 
            1.0 
        };

        // Calculate operations per second
        let time_span = self.start_time.elapsed().unwrap_or(Duration::from_secs(1));
        let operations_per_second = total as f64 / time_span.as_secs_f64();

        // Calculate network health (based on peer count and success rate)
        let avg_peers = if !current_metrics.is_empty() {
            current_metrics.iter().map(|m| m.peer_count).sum::<usize>() as f64 
                / current_metrics.len() as f64
        } else {
            0.0
        };
        
        let network_health = (success_rate * 0.7) + 
                           ((avg_peers.min(10.0) / 10.0) * 0.3);

        // Calculate cache performance
        let cache_hits = current_metrics.iter()
            .filter(|m| m.operation == DHTOperation::CacheHit)
            .count();
        let cache_misses = current_metrics.iter()
            .filter(|m| m.operation == DHTOperation::CacheMiss)
            .count();
        
        let cache_hit_rate = if cache_hits + cache_misses > 0 {
            cache_hits as f64 / (cache_hits + cache_misses) as f64
        } else {
            0.0
        };

        DHTPerformanceStats {
            avg_latency_ms,
            median_latency_ms,
            p95_latency_ms,
            p99_latency_ms,
            success_rate,
            error_rate: 1.0 - success_rate,
            total_operations: total as u64,
            operations_per_second,
            cache_hit_rate,
            cache_miss_rate: 1.0 - cache_hit_rate,
            cache_size: 0, // To be filled by caller
            content_resolution_time_ms: self.calculate_operation_latency(DHTOperation::Resolve),
            peer_discovery_time_ms: self.calculate_operation_latency(DHTOperation::PeerDiscover),
            storage_operation_time_ms: self.calculate_operation_latency(DHTOperation::Store),
            measurement_period_secs: self.window_duration.as_secs(),
            last_updated: SystemTime::now(),
        }
    }

    /// Get DHT operation-specific statistics
    pub fn get_operation_stats(&self, operation: DHTOperation) -> DHTPerformanceStats {
        let filtered_metrics: Vec<_> = self.metrics.iter()
            .filter(|m| m.operation == operation)
            .collect();

        if filtered_metrics.is_empty() {
            return DHTPerformanceStats {
                avg_latency_ms: 0.0,
                median_latency_ms: 0.0,
                p95_latency_ms: 0.0,
                p99_latency_ms: 0.0,
                success_rate: 1.0,
                error_rate: 0.0,
                total_operations: 0,
                operations_per_second: 0.0,
                cache_hit_rate: 0.0,
                cache_miss_rate: 0.0,
                cache_size: 0,
                content_resolution_time_ms: 0.0,
                peer_discovery_time_ms: 0.0,
                storage_operation_time_ms: 0.0,
                measurement_period_secs: self.window_duration.as_secs(),
                last_updated: SystemTime::now(),
            };
        }

        let durations: Vec<_> = filtered_metrics.iter()
            .map(|m| m.duration.as_millis() as f64)
            .collect();

        let successful = filtered_metrics.iter().filter(|m| m.success).count();
        let total = filtered_metrics.len();

        DHTPerformanceStats {
            avg_latency_ms: durations.iter().sum::<f64>() / durations.len() as f64,
            median_latency_ms: percentile(&durations, 0.5),
            p95_latency_ms: percentile(&durations, 0.95),
            p99_latency_ms: percentile(&durations, 0.99),
            success_rate: successful as f64 / total as f64,
            error_rate: 1.0 - (successful as f64 / total as f64),
            total_operations: total as u64,
            operations_per_second: 0.0, // Not meaningful for single operation type
            cache_hit_rate: 0.0,
            cache_miss_rate: 1.0,
            cache_size: 0,
            content_resolution_time_ms: self.calculate_operation_latency(DHTOperation::Resolve),
            peer_discovery_time_ms: self.calculate_operation_latency(DHTOperation::PeerDiscover),
            storage_operation_time_ms: self.calculate_operation_latency(DHTOperation::Store),
            measurement_period_secs: self.window_duration.as_secs(),
            last_updated: SystemTime::now(),
        }
    }

    /// Reset all metrics
    pub fn reset(&mut self) {
        self.metrics.clear();
        self.start_time = SystemTime::now();
    }

    /// Calculate average latency for a specific operation type
    fn calculate_operation_latency(&self, operation: DHTOperation) -> f64 {
        let op_metrics: Vec<_> = self.metrics.iter()
            .filter(|m| m.operation == operation)
            .collect();
        
        if op_metrics.is_empty() {
            return 0.0;
        }
        
        let total_ms: f64 = op_metrics.iter()
            .map(|m| m.duration.as_millis() as f64)
            .sum();
        
        total_ms / op_metrics.len() as f64
    }

    /// Clean up metrics outside the time window
    fn cleanup_old_metrics(&mut self) {
        let cutoff_time = SystemTime::now() - self.window_duration;
        
        while let Some(front) = self.metrics.front() {
            if front.timestamp < cutoff_time {
                self.metrics.pop_front();
            } else {
                break;
            }
        }
    }
}

/// Thread-safe performance monitor
pub struct ThreadSafeDHTMonitor {
    monitor: Arc<Mutex<DHTPerformanceMonitor>>,
}

impl ThreadSafeDHTMonitor {
    /// Create new thread-safe monitor
    pub fn new(max_metrics: usize, window_duration: Duration) -> Self {
        Self {
            monitor: Arc::new(Mutex::new(
                DHTPerformanceMonitor::new(max_metrics, window_duration)
            )),
        }
    }

    /// Record operation (async)
    pub async fn record_operation(
        &self, 
        operation: DHTOperation, 
        duration: Duration, 
        success: bool,
        peer_count: usize
    ) {
        self.monitor.lock().await.record_operation(operation, duration, success, peer_count);
    }

    /// Get statistics (async)
    pub async fn get_stats(&self) -> DHTPerformanceStats {
        self.monitor.lock().await.get_stats()
    }

    /// Get operation-specific stats (async)  
    pub async fn get_operation_stats(&self, operation: DHTOperation) -> DHTPerformanceStats {
        self.monitor.lock().await.get_operation_stats(operation)
    }

    /// Reset metrics (async)
    pub async fn reset(&self) {
        self.monitor.lock().await.reset();
    }
}

/// Utility for timing operations
pub struct OperationTimer {
    operation: DHTOperation,
    start_time: Instant,
    monitor: Arc<Mutex<DHTPerformanceMonitor>>,
    peer_count: usize,
}

impl OperationTimer {
    /// Start timing an operation
    pub fn start(
        operation: DHTOperation, 
        monitor: Arc<Mutex<DHTPerformanceMonitor>>,
        peer_count: usize
    ) -> Self {
        Self {
            operation,
            start_time: Instant::now(),
            monitor,
            peer_count,
        }
    }

    /// Complete the operation and record metrics
    pub async fn complete(self, success: bool) {
        let duration = self.start_time.elapsed();
        self.monitor.lock().await.record_operation(
            self.operation, 
            duration, 
            success,
            self.peer_count
        );
    }
}

// Helper function to calculate percentiles
fn percentile(sorted_data: &[f64], percentile: f64) -> f64 {
    if sorted_data.is_empty() {
        return 0.0;
    }
    
    let index = (sorted_data.len() as f64 * percentile) as usize;
    let index = index.min(sorted_data.len() - 1);
    sorted_data[index]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_performance_monitor() {
        let mut monitor = DHTPerformanceMonitor::new(100, Duration::from_secs(60));
        
        // Record some operations
        monitor.record_operation(DHTOperation::Store, Duration::from_millis(50), true, 5);
        monitor.record_operation(DHTOperation::Store, Duration::from_millis(75), true, 5);
        monitor.record_operation(DHTOperation::Retrieve, Duration::from_millis(25), false, 5);
        
        let stats = monitor.get_stats();
        
        assert_eq!(stats.total_operations, 3);
        assert_eq!(stats.success_rate, 2.0 / 3.0);
        assert!(stats.avg_latency_ms > 0.0);
    }

    #[test]
    fn test_percentile_calculation() {
        let data = vec![10.0, 20.0, 30.0, 40.0, 50.0];
        
        assert_eq!(percentile(&data, 0.5), 30.0); // median
        assert_eq!(percentile(&data, 0.95), 50.0); // 95th percentile
        assert_eq!(percentile(&[], 0.5), 0.0); // empty data
    }
}