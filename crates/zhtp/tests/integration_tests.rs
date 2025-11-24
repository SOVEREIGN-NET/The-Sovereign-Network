//! Integration Tests for ZHTP Node Orchestrator
//! 
//! Comprehensive tests for the complete ZHTP system integration

use anyhow::Result;
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::timeout;

use zhtp::{
    config::{NodeConfig, CliArgs, Environment, MeshMode, SecurityLevel},
    runtime::{RuntimeOrchestrator, ComponentId, ComponentStatus},
    monitoring::MonitoringSystem,
    integration::IntegrationManager,
};

/// Test configuration helper
async fn create_test_config() -> Result<NodeConfig> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("test-config.toml");
    
    let args = CliArgs {
        mesh_port: 33445, // Use different port for testing
        pure_mesh: false,
        config: config_path,
        environment: Environment::Development,
        log_level: "debug".to_string(),
        data_dir: temp_dir.path().to_path_buf(),
    };
    
    zhtp::config::load_configuration(&args).await
}

/// Mock component for testing
#[derive(Debug)]
struct MockComponent {
    id: ComponentId,
    started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    should_fail: bool,
}

impl MockComponent {
    fn new(id: ComponentId, should_fail: bool) -> Self {
        Self {
            id,
            started: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            should_fail,
        }
    }
}

#[async_trait::async_trait]
impl zhtp::runtime::Component for MockComponent {
    fn id(&self) -> ComponentId {
        self.id.clone()
    }
    
    async fn start(&self) -> Result<()> {
        if self.should_fail {
            return Err(anyhow::anyhow!("Mock component failure"));
        }
        
        self.started.store(true, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(10)).await; // Simulate startup time
        Ok(())
    }
    
    async fn stop(&self) -> Result<()> {
        self.started.store(false, std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(5)).await; // Simulate shutdown time
        Ok(())
    }
    
    async fn health_check(&self) -> Result<zhtp::runtime::ComponentHealth> {
        let is_running = self.started.load(std::sync::atomic::Ordering::SeqCst);
        
        Ok(zhtp::runtime::ComponentHealth {
            status: if is_running { ComponentStatus::Running } else { ComponentStatus::Stopped },
            last_heartbeat: tokio::time::Instant::now(),
            error_count: 0,
            restart_count: 0,
            uptime: Duration::from_secs(60),
            memory_usage: 1024 * 1024, // 1MB
            cpu_usage: 5.0, // 5%
        })
    }
    
    async fn handle_message(&self, _message: zhtp::runtime::ComponentMessage) -> Result<()> {
        Ok(())
    }
    
    async fn get_metrics(&self) -> Result<std::collections::HashMap<String, f64>> {
        let mut metrics = std::collections::HashMap::new();
        metrics.insert("requests_processed".to_string(), 100.0);
        metrics.insert("memory_usage_mb".to_string(), 1.0);
        Ok(metrics)
    }

    fn as_any(&self) -> &(dyn std::any::Any + 'static) {
        self
    }
}

#[tokio::test]
async fn test_runtime_orchestrator_creation() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Verify initial state
    let status = orchestrator.get_component_status().await?;
    assert!(status.is_empty(), "Should have no components initially");
    
    Ok(())
}

#[tokio::test]
async fn test_component_registration_and_lifecycle() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register mock components
    let crypto_component = std::sync::Arc::new(MockComponent::new(ComponentId::Crypto, false));
    let zk_component = std::sync::Arc::new(MockComponent::new(ComponentId::ZK, false));
    
    orchestrator.register_component(crypto_component.clone()).await?;
    orchestrator.register_component(zk_component.clone()).await?;
    
    // Start specific components
    orchestrator.start_component(ComponentId::Crypto).await?;
    orchestrator.start_component(ComponentId::ZK).await?;
    
    // Verify components are running
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.len(), 2);
    assert_eq!(status.get("crypto"), Some(&true));
    assert_eq!(status.get("zk"), Some(&true));
    
    // Test metrics collection
    let metrics = orchestrator.get_system_metrics().await?;
    assert!(metrics.contains_key("total_components"));
    assert!(metrics.contains_key("running_components"));
    assert_eq!(metrics.get("total_components"), Some(&2.0));
    assert_eq!(metrics.get("running_components"), Some(&2.0));
    
    // Stop components
    orchestrator.stop_component(ComponentId::Crypto).await?;
    orchestrator.stop_component(ComponentId::ZK).await?;
    
    // Verify components are stopped
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.get("crypto"), Some(&false));
    assert_eq!(status.get("zk"), Some(&false));
    
    Ok(())
}

#[tokio::test]
async fn test_component_failure_handling() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register a component that will fail
    let failing_component = std::sync::Arc::new(MockComponent::new(ComponentId::Network, true));
    orchestrator.register_component(failing_component).await?;
    
    // Attempt to start the failing component
    let result = orchestrator.start_component(ComponentId::Network).await;
    assert!(result.is_err(), "Should fail to start failing component");
    
    // Verify component is in error state
    let health = orchestrator.get_detailed_health().await?;
    let network_health = health.get(&ComponentId::Network).unwrap();
    assert!(matches!(network_health.status, ComponentStatus::Error(_)));
    
    Ok(())
}

#[tokio::test]
async fn test_component_restart() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register and start component
    let component = std::sync::Arc::new(MockComponent::new(ComponentId::Storage, false));
    orchestrator.register_component(component.clone()).await?;
    orchestrator.start_component(ComponentId::Storage).await?;
    
    // Restart component
    orchestrator.restart_component(ComponentId::Storage).await?;
    
    // Verify component is still running after restart
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.get("storage"), Some(&true));
    
    // Check restart count increased
    let health = orchestrator.get_detailed_health().await?;
    let storage_health = health.get(&ComponentId::Storage).unwrap();
    assert!(storage_health.restart_count > 0);
    
    Ok(())
}

#[tokio::test]
async fn test_message_passing() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register components
    let crypto_component = std::sync::Arc::new(MockComponent::new(ComponentId::Crypto, false));
    let network_component = std::sync::Arc::new(MockComponent::new(ComponentId::Network, false));
    
    orchestrator.register_component(crypto_component).await?;
    orchestrator.register_component(network_component).await?;
    
    // Start components
    orchestrator.start_component(ComponentId::Crypto).await?;
    orchestrator.start_component(ComponentId::Network).await?;
    
    // Send messages
    orchestrator.send_message(
        ComponentId::Crypto, 
        zhtp::runtime::ComponentMessage::Start
    ).await?;
    
    orchestrator.broadcast_message(
        zhtp::runtime::ComponentMessage::HealthCheck
    ).await?;
    
    // Give messages time to process
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    Ok(())
}

#[tokio::test]
async fn test_monitoring_system() -> Result<()> {
    let mut monitoring = MonitoringSystem::new().await?;
    
    // Start monitoring
    monitoring.start().await?;
    
    // Test metrics recording
    let mut tags = std::collections::HashMap::new();
    tags.insert("component".to_string(), "test".to_string());
    
    monitoring.record_metric("test_metric", 42.0, tags).await?;
    
    // Get system metrics
    let metrics = monitoring.get_system_metrics().await?;
    assert!(metrics.cpu_usage_percent > 0.0);
    assert!(metrics.memory_usage_bytes > 0);
    
    // Test health status
    let health = monitoring.get_health_status().await?;
    assert!(matches!(health.overall_status, zhtp::monitoring::health_check::NodeHealth::Healthy | zhtp::monitoring::health_check::NodeHealth::Warning | zhtp::monitoring::health_check::NodeHealth::Critical | zhtp::monitoring::health_check::NodeHealth::Down));
    
    // Stop monitoring
    monitoring.stop().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_integration_manager() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    
    // Initialize integration layer
    integration.initialize().await?;
    
    // Test dependency validation
    let issues = integration.validate_dependencies().await?;
    // Should have issues since no components are registered
    assert!(!issues.is_empty());
    
    // Test health check
    let health = integration.health_check().await?;
    assert!(health.overall_healthy); // Should be healthy even without components
    
    // Shutdown
    integration.shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_graceful_shutdown() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register and start components
    let components = vec![
        (ComponentId::Crypto, false),
        (ComponentId::ZK, false),
        (ComponentId::Identity, false),
    ];
    
    for (id, should_fail) in components {
        let component = std::sync::Arc::new(MockComponent::new(id.clone(), should_fail));
        orchestrator.register_component(component).await?;
        orchestrator.start_component(id).await?;
    }
    
    // Verify all components are running
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.len(), 3);
    assert!(status.values().all(|&running| running));
    
    // Perform graceful shutdown
    orchestrator.graceful_shutdown().await?;
    
    // Verify all components are stopped
    let status = orchestrator.get_component_status().await?;
    assert!(status.values().all(|&running| !running));
    
    Ok(())
}

#[tokio::test]
async fn test_configuration_loading() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let config_path = temp_dir.path().join("test-config.toml");
    
    // Write test configuration
    let config_content = r#"
[node]
mesh_port = 33446
pure_mesh = true
security_level = "high"
environment = "development"

[monitoring]
enabled = true
dashboard_port = 8082

[economics]
ubi_enabled = true
daily_ubi_amount = 50

[network]
max_peers = 150
bootstrap_peers = ["127.0.0.1:33446"]
"#;
    
    std::fs::write(&config_path, config_content)?;
    
    let args = CliArgs {
        mesh_port: 33446,
        pure_mesh: true,
        config: config_path,
        environment: Environment::Development,
        log_level: "info".to_string(),
        data_dir: temp_dir.path().to_path_buf(),
    };
    
    let config = zhtp::config::load_configuration(&args).await?;
    
    // Verify configuration was loaded correctly
    assert_eq!(config.mesh_mode, MeshMode::PureMesh);
    assert_eq!(config.security_level, SecurityLevel::High);
    assert_eq!(config.environment, Environment::Development);
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_operations() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register multiple components
    let component_ids = vec![
        ComponentId::Crypto,
        ComponentId::ZK,
        ComponentId::Identity,
        ComponentId::Storage,
        ComponentId::Network,
    ];
    
    // Register all components concurrently
    let register_tasks: Vec<_> = component_ids.iter().map(|id| {
        let orchestrator = orchestrator.clone();
        let component = std::sync::Arc::new(MockComponent::new(id.clone(), false));
        async move {
            orchestrator.register_component(component).await
        }
    }).collect();
    
    let results = futures::future::join_all(register_tasks).await;
    assert!(results.into_iter().all(|r| r.is_ok()));
    
    // Start all components concurrently
    let start_tasks: Vec<_> = component_ids.iter().map(|id| {
        let orchestrator = orchestrator.clone();
        let id = id.clone();
        async move {
            orchestrator.start_component(id).await
        }
    }).collect();
    
    let results = futures::future::join_all(start_tasks).await;
    assert!(results.into_iter().all(|r| r.is_ok()));
    
    // Verify all components are running
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.len(), component_ids.len());
    assert!(status.values().all(|&running| running));
    
    Ok(())
}

#[tokio::test] 
async fn test_main_loop_operation() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Clone for the shutdown task
    let shutdown_orchestrator = orchestrator.clone();
    
    // Start main loop in background
    let main_loop_task = tokio::spawn(async move {
        orchestrator.run_main_loop().await
    });
    
    // Let it run for a short time
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Trigger shutdown
    shutdown_orchestrator.graceful_shutdown().await?;
    
    // Wait for main loop to complete
    let result = timeout(Duration::from_secs(5), main_loop_task).await;
    assert!(result.is_ok(), "Main loop should complete within timeout");
    assert!(result.unwrap().is_ok(), "Main loop should complete successfully");
    
    Ok(())
}

#[tokio::test]
async fn test_stress_component_operations() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register component
    let component = std::sync::Arc::new(MockComponent::new(ComponentId::Crypto, false));
    orchestrator.register_component(component).await?;
    
    // Perform rapid start/stop cycles
    for i in 0..10 {
        orchestrator.start_component(ComponentId::Crypto).await?;
        
        let status = orchestrator.get_component_status().await?;
        assert_eq!(status.get("crypto"), Some(&true), "Iteration {}", i);
        
        orchestrator.stop_component(ComponentId::Crypto).await?;
        
        let status = orchestrator.get_component_status().await?;
        assert_eq!(status.get("crypto"), Some(&false), "Iteration {}", i);
        
        // Small delay to prevent overwhelming the system
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    
    Ok(())
}

#[tokio::test]
async fn test_error_recovery() -> Result<()> {
    let config = create_test_config().await?;
    let orchestrator = RuntimeOrchestrator::new(config).await?;
    
    // Register both working and failing components
    let working_component = std::sync::Arc::new(MockComponent::new(ComponentId::Crypto, false));
    let failing_component = std::sync::Arc::new(MockComponent::new(ComponentId::Network, true));
    
    orchestrator.register_component(working_component).await?;
    orchestrator.register_component(failing_component).await?;
    
    // Start working component
    orchestrator.start_component(ComponentId::Crypto).await?;
    
    // Attempt to start failing component
    let result = orchestrator.start_component(ComponentId::Network).await;
    assert!(result.is_err());
    
    // Verify working component is still operational
    let status = orchestrator.get_component_status().await?;
    assert_eq!(status.get("crypto"), Some(&true));
    assert_eq!(status.get("network"), Some(&false));
    
    // System should still be functional for working components
    let metrics = orchestrator.get_system_metrics().await?;
    assert_eq!(metrics.get("running_components"), Some(&1.0));
    assert_eq!(metrics.get("error_components"), Some(&1.0));
    
    Ok(())
}
