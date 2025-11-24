//! Runtime Module Tests
//! 
//! Tests orchestrator, component lifecycle, and message passing

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use std::collections::HashMap;

use zhtp::runtime::{
    RuntimeOrchestrator, ComponentStatus, ComponentId, ComponentHealth,
    Component, ComponentMessage,
};
use zhtp::config::NodeConfig;

/// Mock component for testing
#[derive(Debug)]
struct MockComponent {
    id: ComponentId,
    started: std::sync::atomic::AtomicBool,
}

impl MockComponent {
    fn new(id: ComponentId) -> Self {
        Self {
            id,
            started: std::sync::atomic::AtomicBool::new(false),
        }
    }
    
    fn is_started(&self) -> bool {
        self.started.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl Component for MockComponent {
    fn id(&self) -> ComponentId {
        self.id.clone()
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    
    async fn start(&self) -> Result<()> {
        self.started.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        self.started.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    
    async fn health_check(&self) -> Result<ComponentHealth> {
        Ok(ComponentHealth {
            status: if self.is_started() { ComponentStatus::Running } else { ComponentStatus::Stopped },
            last_heartbeat: tokio::time::Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime: Duration::from_secs(10),
            memory_usage: 1024,
            cpu_usage: 5.0,
        })
    }
    
    async fn handle_message(&self, _message: ComponentMessage) -> Result<()> {
        Ok(())
    }
    
    async fn get_metrics(&self) -> Result<HashMap<String, f64>> {
        let mut metrics = HashMap::new();
        metrics.insert("uptime".to_string(), 10.0);
        metrics.insert("memory_mb".to_string(), 1.0);
        Ok(metrics)
    }

    fn as_any(&self) -> &(dyn std::any::Any + 'static) {
        self
    }
}

#[tokio::test]
async fn test_runtime_orchestrator_initialization() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Check basic status
    let status = orchestrator.get_component_status().await?;
    assert!(status.is_empty()); // No components registered yet
    
    // Test graceful shutdown
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_component_registration_and_lifecycle() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register a mock component
    let component = Arc::new(MockComponent::new(ComponentId::Crypto));
    orchestrator.register_component(component.clone()).await?;
    
    // Verify component was registered
    let status = orchestrator.get_component_status().await?;
    assert!(status.contains_key("crypto"));
    assert!(!status["crypto"]); // Should be stopped initially
    
    // Start the component
    orchestrator.start_component(ComponentId::Crypto).await?;
    
    // Verify component is running
    assert!(component.is_started());
    let status = orchestrator.get_component_status().await?;
    assert!(status["crypto"]);
    
    // Stop the component
    orchestrator.stop_component(ComponentId::Crypto).await?;
    
    // Verify component is stopped
    assert!(!component.is_started());
    let status = orchestrator.get_component_status().await?;
    assert!(!status["crypto"]);
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_message_sending() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register a component
    let component = Arc::new(MockComponent::new(ComponentId::Network));
    orchestrator.register_component(component.clone()).await?;
    orchestrator.start_component(ComponentId::Network).await?;
    
    // Send a message to the component
    let message = ComponentMessage::PeerConnected("test-peer".to_string());
    orchestrator.send_message(ComponentId::Network, message).await?;
    
    // Broadcast a message
    let broadcast_message = ComponentMessage::HealthCheck;
    orchestrator.broadcast_message(broadcast_message).await?;
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_health_monitoring() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register and start a component
    let component = Arc::new(MockComponent::new(ComponentId::Identity));
    orchestrator.register_component(component.clone()).await?;
    orchestrator.start_component(ComponentId::Identity).await?;
    
    // Get detailed health information
    let health = orchestrator.get_detailed_health().await?;
    assert!(health.contains_key(&ComponentId::Identity));
    
    let identity_health = &health[&ComponentId::Identity];
    assert!(matches!(identity_health.status, ComponentStatus::Running));
    assert_eq!(identity_health.error_count, 0);
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_component_restart() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register and start a component
    let component = Arc::new(MockComponent::new(ComponentId::Storage));
    orchestrator.register_component(component.clone()).await?;
    orchestrator.start_component(ComponentId::Storage).await?;
    
    // Verify component is running
    assert!(component.is_started());
    
    // Restart the component
    orchestrator.restart_component(ComponentId::Storage).await?;
    
    // Component should still be running after restart
    assert!(component.is_started());
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_system_metrics() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register multiple components
    let crypto_component = Arc::new(MockComponent::new(ComponentId::Crypto));
    let network_component = Arc::new(MockComponent::new(ComponentId::Network));
    
    orchestrator.register_component(crypto_component).await?;
    orchestrator.register_component(network_component).await?;
    
    orchestrator.start_component(ComponentId::Crypto).await?;
    orchestrator.start_component(ComponentId::Network).await?;
    
    // Get system metrics
    let metrics = orchestrator.get_system_metrics().await?;
    
    // Should have orchestrator metrics
    assert!(metrics.contains_key("total_components"));
    assert!(metrics.contains_key("running_components"));
    assert!(metrics.contains_key("error_components"));
    
    // Should have component-specific metrics
    assert!(metrics.contains_key("crypto_uptime"));
    assert!(metrics.contains_key("network_uptime"));
    
    assert_eq!(metrics["total_components"], 2.0);
    assert_eq!(metrics["running_components"], 2.0);
    assert_eq!(metrics["error_components"], 0.0);
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register multiple components concurrently
    let component_ids = vec![
        ComponentId::Crypto,
        ComponentId::ZK,
        ComponentId::Identity,
        ComponentId::Storage,
        ComponentId::Network,
    ];
    
    let mut registration_tasks = Vec::new();
    for id in &component_ids {
        let component = Arc::new(MockComponent::new(id.clone()));
        let orchestrator = orchestrator.clone();
        registration_tasks.push(tokio::spawn(async move {
            orchestrator.register_component(component).await
        }));
    }
    
    // Wait for all registrations
    for task in registration_tasks {
        task.await??;
    }
    
    // Start all components concurrently
    let mut start_tasks = Vec::new();
    for id in &component_ids {
        let orchestrator = orchestrator.clone();
        let id = id.clone();
        start_tasks.push(tokio::spawn(async move {
            orchestrator.start_component(id).await
        }));
    }
    
    // Wait for all starts
    for task in start_tasks {
        task.await??;
    }
    
    // Verify all components are running
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.len(), 5);
    assert!(status.values().all(|&running| running));
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_startup_sequence() -> Result<()> {
    let config = NodeConfig::default();
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register components in various orders
    let components = vec![
        (ComponentId::Network, Arc::new(MockComponent::new(ComponentId::Network))),
        (ComponentId::Crypto, Arc::new(MockComponent::new(ComponentId::Crypto))),
        (ComponentId::Storage, Arc::new(MockComponent::new(ComponentId::Storage))),
    ];
    
    for (_, component) in &components {
        orchestrator.register_component(component.clone()).await?;
    }
    
    // Start all components using the orchestrator's startup sequence
    orchestrator.start_all_components().await?;
    
    // Verify all registered components are running
    let status = orchestrator.get_component_status().await?;
    for (id, _) in &components {
        let id_str = id.to_string();
        assert!(status.contains_key(&id_str));
        assert!(status[&id_str]);
    }
    
    orchestrator.graceful_shutdown().await?;
    
    Ok(())
}
