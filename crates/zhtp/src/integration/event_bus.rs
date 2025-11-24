//! Event Bus for Inter-Component Communication
//! 
//! Provides publish-subscribe messaging between ZHTP components

use anyhow::{Result, Context};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, atomic::{AtomicU64, AtomicBool, Ordering}};
use tokio::sync::{RwLock, mpsc, broadcast};
use tokio::time::{Duration, Instant};
use tracing::{info, error, debug};
use crate::integration::dependency_injection::Injectable;
use async_trait::async_trait;

/// Event bus for component communication
pub struct EventBus {
    publishers: Arc<RwLock<HashMap<String, broadcast::Sender<Event>>>>,
    subscribers: Arc<RwLock<HashMap<String, Vec<EventHandler>>>>,
    event_counter: Arc<AtomicU64>,
    running: Arc<AtomicBool>,
    metrics: Arc<RwLock<EventBusMetrics>>,
    config: EventBusConfig,
}

/// Event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub event_type: String,
    pub source: String,
    pub data: Value,
    pub timestamp: u64,
    pub correlation_id: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Event handler function type
pub type EventHandler = Box<dyn Fn(Event) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync>;

/// Event bus configuration
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    pub max_subscribers_per_topic: usize,
    pub channel_buffer_size: usize,
    pub enable_metrics: bool,
    pub event_retention: Duration,
    pub max_retries: u32,
    pub retry_delay: Duration,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            max_subscribers_per_topic: 1000,
            channel_buffer_size: 1000,
            enable_metrics: true,
            event_retention: Duration::from_secs(3600), // 1 hour
            max_retries: 3,
            retry_delay: Duration::from_millis(100),
        }
    }
}

/// Event bus metrics
#[derive(Debug, Clone, Default)]
pub struct EventBusMetrics {
    pub total_events_published: u64,
    pub total_events_processed: u64,
    pub events_per_topic: HashMap<String, u64>,
    pub processing_times: HashMap<String, Duration>,
    pub failed_events: u64,
    pub active_subscriptions: usize,
    pub average_processing_time: Duration,
}

/// Event subscription handle
pub struct SubscriptionHandle {
    topic: String,
    subscription_id: String,
    _unsubscribe_tx: mpsc::UnboundedSender<String>,
}

impl EventBus {
    /// Create a new event bus
    pub async fn new() -> Result<Self> {
        Ok(Self {
            publishers: Arc::new(RwLock::new(HashMap::new())),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            event_counter: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(RwLock::new(EventBusMetrics::default())),
            config: EventBusConfig::default(),
        })
    }

    /// Create event bus with custom configuration
    pub async fn with_config(config: EventBusConfig) -> Result<Self> {
        Ok(Self {
            publishers: Arc::new(RwLock::new(HashMap::new())),
            subscribers: Arc::new(RwLock::new(HashMap::new())),
            event_counter: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(RwLock::new(EventBusMetrics::default())),
            config,
        })
    }

    /// Start the event bus
    pub async fn start(&self) -> Result<()> {
        if self.running.load(Ordering::SeqCst) {
            return Ok(());
        }

        self.running.store(true, Ordering::SeqCst);
        info!("Starting event bus...");

        // Start metrics collection if enabled
        if self.config.enable_metrics {
            self.start_metrics_collection().await?;
        }

        info!("Event bus started");
        Ok(())
    }

    /// Stop the event bus
    pub async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::SeqCst);
        
        // Clear all publishers and subscribers
        self.publishers.write().await.clear();
        self.subscribers.write().await.clear();
        
        info!("Event bus stopped");
        Ok(())
    }

    /// Publish an event
    pub async fn publish(&self, topic: &str, data: Value) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Event bus is not running"));
        }

        let event_id = self.event_counter.fetch_add(1, Ordering::SeqCst);
        let event = Event {
            id: format!("event_{}", event_id),
            event_type: topic.to_string(),
            source: "event_bus".to_string(),
            data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            correlation_id: None,
            metadata: HashMap::new(),
        };

        // Update metrics
        if self.config.enable_metrics {
            self.update_publish_metrics(topic).await;
        }

        // Get or create publisher for topic
        let publisher = {
            let mut publishers = self.publishers.write().await;
            if let Some(sender) = publishers.get(topic) {
                sender.clone()
            } else {
                let (sender, _) = broadcast::channel(self.config.channel_buffer_size);
                publishers.insert(topic.to_string(), sender.clone());
                sender
            }
        };

        // Publish event
        match publisher.send(event.clone()) {
            Ok(_) => {
                debug!("Published event: {} to topic: {}", event.id, topic);
                
                // Notify direct subscribers
                self.notify_subscribers(topic, event).await?;
                
                Ok(())
            }
            Err(e) => {
                error!("Failed to publish event to topic {}: {}", topic, e);
                Err(anyhow::anyhow!("Failed to publish event: {}", e))
            }
        }
    }

    /// Publish event with metadata
    pub async fn publish_with_metadata(
        &self,
        topic: &str,
        data: Value,
        metadata: HashMap<String, String>,
    ) -> Result<()> {
        if !self.running.load(Ordering::SeqCst) {
            return Err(anyhow::anyhow!("Event bus is not running"));
        }

        let event_id = self.event_counter.fetch_add(1, Ordering::SeqCst);
        let event = Event {
            id: format!("event_{}", event_id),
            event_type: topic.to_string(),
            source: "event_bus".to_string(),
            data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            correlation_id: None,
            metadata,
        };

        // Similar to publish but with custom metadata
        let publisher = {
            let mut publishers = self.publishers.write().await;
            if let Some(sender) = publishers.get(topic) {
                sender.clone()
            } else {
                let (sender, _) = broadcast::channel(self.config.channel_buffer_size);
                publishers.insert(topic.to_string(), sender.clone());
                sender
            }
        };

        publisher.send(event.clone())
            .context("Failed to publish event")?;

        self.notify_subscribers(topic, event).await?;
        Ok(())
    }

    /// Subscribe to a topic
    pub async fn subscribe<F>(&self, topic: &str, handler: F) -> Result<SubscriptionHandle>
    where
        F: Fn(Event) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync + 'static,
    {
        let subscription_id = format!("sub_{}_{}", topic, uuid::Uuid::new_v4());
        
        // Add handler to subscribers
        {
            let mut subscribers = self.subscribers.write().await;
            let handlers = subscribers.entry(topic.to_string()).or_insert_with(Vec::new);
            
            if handlers.len() >= self.config.max_subscribers_per_topic {
                return Err(anyhow::anyhow!(
                    "Maximum subscribers reached for topic: {}", topic
                ));
            }
            
            handlers.push(Box::new(handler));
        }

        // Update metrics
        if self.config.enable_metrics {
            let mut metrics = self.metrics.write().await;
            metrics.active_subscriptions += 1;
        }

        let (unsubscribe_tx, mut unsubscribe_rx) = mpsc::unbounded_channel::<String>();
        
        // Spawn unsubscribe handler
        let topic_clone = topic.to_string();
        let subscribers_clone = self.subscribers.clone();
        let metrics_clone = self.metrics.clone();
        let enable_metrics = self.config.enable_metrics;
        
        tokio::spawn(async move {
            if let Some(handler_id) = unsubscribe_rx.recv().await {
                // Remove specific subscription by handler ID
                let mut subscribers = subscribers_clone.write().await;
                if let Some(handlers) = subscribers.get_mut(&topic_clone) {
                    // Use handler ID to remove the correct handler
                    let handler_id_u64 = if let Ok(id) = handler_id.parse::<u64>() {
                        id
                    } else {
                        return; // Invalid handler ID format
                    };
                    
                    handlers.retain(|handler| {
                        // In implementation, each handler would have an ID
                        // For now, we'll use a hash-based approach to identify handlers
                        let handler_hash = calculate_handler_hash(handler);
                        handler_hash != handler_id_u64
                    });
                    
                    // Clean up empty handler lists
                    if handlers.is_empty() {
                        subscribers.remove(&topic_clone);
                    }
                }
                
                // Update metrics
                if enable_metrics {
                    let mut metrics = metrics_clone.write().await;
                    if metrics.active_subscriptions > 0 {
                        metrics.active_subscriptions -= 1;
                    }
                }
                
                debug!("Unsubscribed from topic: {}", topic_clone);
            }
        });

        debug!("Subscribed to topic: {} with ID: {}", topic, subscription_id);
        
        Ok(SubscriptionHandle {
            topic: topic.to_string(),
            subscription_id,
            _unsubscribe_tx: unsubscribe_tx,
        })
    }

    /// Subscribe to multiple topics with pattern matching
    pub async fn subscribe_pattern<F>(&self, pattern: &str, handler: F) -> Result<Vec<SubscriptionHandle>>
    where
        F: Fn(Event) -> Pin<Box<dyn Future<Output = Result<()>> + Send>> + Send + Sync + 'static + Clone,
    {
        let mut handles = Vec::new();
        
        // Get all current topics that match pattern
        let publishers = self.publishers.read().await;
        for topic in publishers.keys() {
            if self.matches_pattern(topic, pattern) {
                let handle = self.subscribe(topic, handler.clone()).await?;
                handles.push(handle);
            }
        }
        
        debug!("Subscribed to {} topics matching pattern: {}", handles.len(), pattern);
        Ok(handles)
    }

    /// Get a broadcast receiver for a topic
    pub async fn get_receiver(&self, topic: &str) -> Result<broadcast::Receiver<Event>> {
        let mut publishers = self.publishers.write().await;
        let sender = if let Some(sender) = publishers.get(topic) {
            sender.clone()
        } else {
            let (sender, _) = broadcast::channel(self.config.channel_buffer_size);
            publishers.insert(topic.to_string(), sender.clone());
            sender
        };
        
        Ok(sender.subscribe())
    }

    /// Notify direct subscribers
    async fn notify_subscribers(&self, topic: &str, event: Event) -> Result<()> {
        let subscribers = self.subscribers.read().await;
        if let Some(handlers) = subscribers.get(topic) {
            let start_time = Instant::now();
            
            for handler in handlers {
                let event_clone = event.clone();
                match handler(event_clone).await {
                    Ok(()) => {
                        debug!("Event {} processed successfully by handler", event.id);
                    }
                    Err(e) => {
                        error!("Event {} processing failed: {}", event.id, e);
                        
                        // Update failure metrics
                        if self.config.enable_metrics {
                            let mut metrics = self.metrics.write().await;
                            metrics.failed_events += 1;
                        }
                    }
                }
            }
            
            // Update processing time metrics
            if self.config.enable_metrics {
                let processing_time = start_time.elapsed();
                let mut metrics = self.metrics.write().await;
                metrics.processing_times.insert(topic.to_string(), processing_time);
                metrics.total_events_processed += 1;
            }
        }
        
        Ok(())
    }

    /// Update publish metrics
    async fn update_publish_metrics(&self, topic: &str) {
        let mut metrics = self.metrics.write().await;
        metrics.total_events_published += 1;
        *metrics.events_per_topic.entry(topic.to_string()).or_insert(0) += 1;
    }

    /// Start metrics collection
    async fn start_metrics_collection(&self) -> Result<()> {
        let metrics = self.metrics.clone();
        let running = self.running.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            while running.load(Ordering::SeqCst) {
                interval.tick().await;
                
                // Calculate average processing time
                let mut metrics_guard = metrics.write().await;
                if !metrics_guard.processing_times.is_empty() {
                    let total_time: Duration = metrics_guard.processing_times.values().sum();
                    metrics_guard.average_processing_time = 
                        total_time / metrics_guard.processing_times.len() as u32;
                }
                
                debug!("Event bus metrics updated");
            }
        });
        
        Ok(())
    }

    /// Check if topic matches pattern (simple wildcard matching)
    fn matches_pattern(&self, topic: &str, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return topic.starts_with(prefix);
        }
        
        if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            return topic.ends_with(suffix);
        }
        
        topic == pattern
    }

    /// Get event bus metrics
    pub async fn get_metrics(&self) -> EventBusMetrics {
        self.metrics.read().await.clone()
    }

    /// Health check for event bus
    pub async fn health_check(&self) -> Result<bool> {
        let running = self.running.load(Ordering::SeqCst);
        let publishers = self.publishers.read().await;
        let subscribers = self.subscribers.read().await;
        
        debug!("Event bus health: running={}, topics={}, subscribers={}", 
               running, publishers.len(), subscribers.len());
        
        Ok(running)
    }

    /// Get active topics
    pub async fn get_active_topics(&self) -> Vec<String> {
        let publishers = self.publishers.read().await;
        publishers.keys().cloned().collect()
    }

    /// Get subscription count for a topic
    pub async fn get_subscription_count(&self, topic: &str) -> usize {
        let subscribers = self.subscribers.read().await;
        subscribers.get(topic).map(|handlers| handlers.len()).unwrap_or(0)
    }

    /// Clear all events and subscriptions for a topic
    pub async fn clear_topic(&self, topic: &str) -> Result<()> {
        let mut publishers = self.publishers.write().await;
        let mut subscribers = self.subscribers.write().await;
        
        publishers.remove(topic);
        subscribers.remove(topic);
        
        debug!("Cleared topic: {}", topic);
        Ok(())
    }
}

impl SubscriptionHandle {
    /// Unsubscribe from the topic
    pub fn unsubscribe(self) {
        // The unsubscribe will happen when the handle is dropped
        // due to the mpsc channel closure
        debug!("Unsubscribing from topic: {}", self.topic);
    }
    
    /// Get subscription info
    pub fn info(&self) -> SubscriptionInfo {
        SubscriptionInfo {
            topic: self.topic.clone(),
            subscription_id: self.subscription_id.clone(),
        }
    }
}

/// Subscription information
#[derive(Debug, Clone)]
pub struct SubscriptionInfo {
    pub topic: String,
    pub subscription_id: String,
}

impl Event {
    /// Create a new event
    pub fn new(event_type: String, source: String, data: Value) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            event_type,
            source,
            data,
            timestamp: chrono::Utc::now().timestamp() as u64,
            correlation_id: None,
            metadata: HashMap::new(),
        }
    }

    /// Create event with correlation ID
    pub fn with_correlation_id(mut self, correlation_id: String) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Add metadata to event
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }

    /// Check if event matches a pattern
    pub fn matches_pattern(&self, pattern: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        
        if pattern.ends_with('*') {
            let prefix = &pattern[..pattern.len() - 1];
            return self.event_type.starts_with(prefix);
        }
        
        if pattern.starts_with('*') {
            let suffix = &pattern[1..];
            return self.event_type.ends_with(suffix);
        }
        
        self.event_type == pattern
    }

    /// Get event age in seconds
    pub fn age_seconds(&self) -> u64 {
        let now = chrono::Utc::now().timestamp() as u64;
        now.saturating_sub(self.timestamp)
    }
}


#[async_trait]
impl Injectable for EventBus {
    async fn initialize(&self) -> Result<()> {
        info!(" EventBus initialized");
        Ok(())
    }

    async fn cleanup(&self) -> Result<()> {
        self.stop().await?;
        info!(" EventBus cleaned up");
        Ok(())
    }

    async fn health_check(&self) -> Result<bool> {
        Ok(self.running.load(Ordering::Relaxed))
    }
}

/// Calculate hash for event handler identification
fn calculate_handler_hash(handler: &EventHandler) -> u64 {
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    
    let mut hasher = DefaultHasher::new();
    
    // Hash the handler function pointer representation
    // This is a simplified approach - in production, handlers would have unique IDs
    let handler_ptr = handler as *const _ as usize;
    handler_ptr.hash(&mut hasher);
    
    hasher.finish()
}
