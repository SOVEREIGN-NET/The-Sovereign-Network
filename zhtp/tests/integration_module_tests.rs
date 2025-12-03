//! Unit Tests for Integration Module
//! 
//! Tests event bus, dependency injection, and service container

use anyhow::Result;
use std::time::Duration;

use zhtp::integration::IntegrationManager;
use zhtp::runtime::ComponentId;

#[tokio::test]
async fn test_integration_manager_lifecycle() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    
    // Initialize
    integration.initialize().await?;
    
    // Test health check
    let health = integration.health_check().await?;
    assert!(health.overall_healthy);
    assert!(health.service_container_healthy);
    assert!(health.event_bus_healthy);
    assert!(health.component_manager_healthy);
    
    // Shutdown
    integration.shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_dependency_validation() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    integration.initialize().await?;
    
    // Test dependency validation with empty system
    let issues = integration.validate_dependencies().await?;
    assert!(issues.is_empty()); // No components registered, so no dependency issues
    
    // Test getting component dependencies
    let crypto_deps = integration.get_component_dependencies(ComponentId::Crypto).await?;
    assert!(crypto_deps.is_empty()); // Crypto has no dependencies
    
    let consensus_deps = integration.get_component_dependencies(ComponentId::Consensus).await?;
    assert!(!consensus_deps.is_empty()); // Consensus has dependencies
    assert!(consensus_deps.contains(&ComponentId::Crypto));
    assert!(consensus_deps.contains(&ComponentId::Network));
    
    integration.shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_startup_order() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    integration.initialize().await?;
    
    // Test that startup order puts crypto first and economics/protocols last
    let startup_order = integration.get_startup_order().await?;
    
    assert!(!startup_order.is_empty());
    assert_eq!(startup_order[0], ComponentId::Crypto); // Should be first
    
    // Economics and Protocols should come after their dependencies
    let crypto_pos = startup_order.iter().position(|x| *x == ComponentId::Crypto).unwrap();
    let blockchain_pos = startup_order.iter().position(|x| *x == ComponentId::Blockchain).unwrap();
    let economics_pos = startup_order.iter().position(|x| *x == ComponentId::Economics).unwrap();
    
    assert!(crypto_pos < blockchain_pos); // Crypto before blockchain
    assert!(blockchain_pos < economics_pos); // Blockchain before economics
    
    integration.shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_integration_health_reporting() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    integration.initialize().await?;
    
    // Get health status
    let health = integration.health_check().await?;
    
    // Verify health structure
    assert!(health.overall_healthy);
    assert!(health.service_container_healthy);
    assert!(health.event_bus_healthy);
    assert!(health.component_manager_healthy);
    assert!(health.dependency_issues.is_empty());
    assert!(health.registered_components.is_empty()); // No components registered yet
    
    integration.shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_service_access() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    integration.initialize().await?;
    
    // Test accessing integration services
    let service_container = integration.service_container();
    let event_bus = integration.event_bus();
    let component_manager = integration.component_manager();
    
    // Services should be accessible
    assert!(service_container.health_check().await?);
    assert!(event_bus.health_check().await?);
    assert!(component_manager.health_check().await?);
    
    integration.shutdown().await?;
    
    Ok(())
}

#[tokio::test]
async fn test_concurrent_initialization() -> Result<()> {
    // Test multiple integration managers can be created concurrently
    let tasks: Vec<_> = (0..5).map(|i| {
        tokio::spawn(async move {
            let integration = IntegrationManager::new().await?;
            integration.initialize().await?;
            
            // Quick health check
            let health = integration.health_check().await?;
            assert!(health.overall_healthy, "Integration {} should be healthy", i);
            
            integration.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        })
    }).collect();
    
    // Wait for all to complete
    for task in tasks {
        task.await??;
    }
    
    Ok(())
}

#[tokio::test]
async fn test_integration_lifecycle_timing() -> Result<()> {
    let start_time = std::time::Instant::now();
    
    let integration = IntegrationManager::new().await?;
    let creation_time = start_time.elapsed();
    
    integration.initialize().await?;
    let init_time = start_time.elapsed();
    
    let health = integration.health_check().await?;
    assert!(health.overall_healthy);
    let health_time = start_time.elapsed();
    
    integration.shutdown().await?;
    let shutdown_time = start_time.elapsed();
    
    // Basic timing sanity checks
    assert!(creation_time < Duration::from_secs(1));
    assert!(init_time < Duration::from_secs(5));
    assert!(health_time < Duration::from_secs(5));
    assert!(shutdown_time < Duration::from_secs(5));
    
    Ok(())
}

#[tokio::test]
async fn test_component_dependency_mapping() -> Result<()> {
    let integration = IntegrationManager::new().await?;
    integration.initialize().await?;
    
    // Test all component dependency mappings
    let all_components = vec![
        ComponentId::Crypto,
        ComponentId::ZK,
        ComponentId::Identity,
        ComponentId::Storage,
        ComponentId::Network,
        ComponentId::Blockchain,
        ComponentId::Consensus,
        ComponentId::Economics,
        ComponentId::Protocols,
    ];
    
    for component in &all_components {
        let deps = integration.get_component_dependencies(component.clone()).await?;
        
        // Verify no circular dependencies
        assert!(!deps.contains(component), "Component {} cannot depend on itself", component);
        
        // Verify all dependencies are valid components
        for dep in deps {
            assert!(all_components.contains(&dep), "Invalid dependency: {}", dep);
        }
    }
    
    integration.shutdown().await?;
    
    Ok(())
}
