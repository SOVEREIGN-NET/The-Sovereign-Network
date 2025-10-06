//! Component Manager for ZHTP
//! 
//! Manages the lifecycle and coordination of all ZHTP components

use anyhow::{Result, Context};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tokio::time::{Duration, Instant};
use tracing::{info, warn, error, debug};
use serde::{Serialize, Deserialize};

use crate::runtime::{ComponentId, Component, ComponentStatus};

/// Component registration information
#[derive(Debug, Clone)]
pub struct ComponentRegistration {
    pub id: ComponentId,
    pub component: Arc<dyn Component>,
    pub dependencies: Vec<ComponentId>,
    pub startup_timeout: Duration,
    pub shutdown_timeout: Duration,
    pub health_check_interval: Duration,
    pub retry_attempts: u32,
}

impl ComponentRegistration {
    pub fn new(component: Arc<dyn Component>) -> Self {
        let id = component.id();
        Self {
            id,
            component,
            dependencies: Vec::new(),
            startup_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(10),
            health_check_interval: Duration::from_secs(30),
            retry_attempts: 3,
        }
    }

    pub fn with_dependencies(mut self, dependencies: Vec<ComponentId>) -> Self {
        self.dependencies = dependencies;
        self
    }

    pub fn with_startup_timeout(mut self, timeout: Duration) -> Self {
        self.startup_timeout = timeout;
        self
    }

    pub fn with_shutdown_timeout(mut self, timeout: Duration) -> Self {
        self.shutdown_timeout = timeout;
        self
    }

    pub fn with_health_check_interval(mut self, interval: Duration) -> Self {
        self.health_check_interval = interval;
        self
    }

    pub fn with_retry_attempts(mut self, attempts: u32) -> Self {
        self.retry_attempts = attempts;
        self
    }
}

/// Component runtime information
#[derive(Debug, Clone)]
pub struct ComponentHandle {
    pub id: ComponentId,
    pub status: ComponentStatus,
    pub last_health_check: Option<Instant>,
    pub start_time: Option<Instant>,
    pub restart_count: u32,
    pub last_error: Option<String>,
}

impl ComponentHandle {
    pub fn new(id: ComponentId) -> Self {
        Self {
            id,
            status: ComponentStatus::Registered,
            last_health_check: None,
            start_time: None,
            restart_count: 0,
            last_error: None,
        }
    }

    pub fn mark_starting(&mut self) {
        self.status = ComponentStatus::Starting;
        self.start_time = Some(Instant::now());
    }

    pub fn mark_running(&mut self) {
        self.status = ComponentStatus::Running;
    }

    pub fn mark_stopping(&mut self) {
        self.status = ComponentStatus::Stopping;
    }

    pub fn mark_stopped(&mut self) {
        self.status = ComponentStatus::Stopped;
        self.start_time = None;
    }

    pub fn mark_failed(&mut self, error: String) {
        self.status = ComponentStatus::Failed;
        self.last_error = Some(error);
        self.restart_count += 1;
    }

    pub fn mark_health_check(&mut self) {
        self.last_health_check = Some(Instant::now());
    }
}

/// Component manager for orchestrating all ZHTP components
pub struct ComponentManager {
    components: Arc<RwLock<HashMap<ComponentId, ComponentRegistration>>>,
    handles: Arc<RwLock<HashMap<ComponentId, ComponentHandle>>>,
    startup_order: Arc<RwLock<Vec<ComponentId>>>,
    health_checker: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    shutdown_requested: Arc<RwLock<bool>>,
}

impl ComponentManager {
    /// Create a new component manager
    pub async fn new() -> Result<Self> {
        Ok(Self {
            components: Arc::new(RwLock::new(HashMap::new())),
            handles: Arc::new(RwLock::new(HashMap::new())),
            startup_order: Arc::new(RwLock::new(Vec::new())),
            health_checker: Arc::new(Mutex::new(None)),
            shutdown_requested: Arc::new(RwLock::new(false)),
        })
    }

    /// Initialize the component manager
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing component manager...");

        // Start health check background task
        self.start_health_checker().await?;

        info!("Component manager initialized");
        Ok(())
    }

    /// Register a component
    pub async fn register_component(&self, component: Arc<dyn Component>) -> Result<()> {
        let id = component.id();
        info!("Registering component: {}", id);

        let registration = ComponentRegistration::new(component);
        let handle = ComponentHandle::new(id.clone());

        // Store registration and handle
        {
            let mut components = self.components.write().await;
            let mut handles = self.handles.write().await;
            
            components.insert(id.clone(), registration);
            handles.insert(id.clone(), handle);
        }

        // Update startup order
        self.update_startup_order().await?;

        info!("Component {} registered successfully", id);
        Ok(())
    }

    /// Register a component with specific configuration
    pub async fn register_component_with_config(&self, registration: ComponentRegistration) -> Result<()> {
        let id = registration.id.clone();
        info!("Registering component with config: {}", id);

        let handle = ComponentHandle::new(id.clone());

        // Store registration and handle
        {
            let mut components = self.components.write().await;
            let mut handles = self.handles.write().await;
            
            components.insert(id.clone(), registration);
            handles.insert(id.clone(), handle);
        }

        // Update startup order
        self.update_startup_order().await?;

        info!("Component {} registered with config", id);
        Ok(())
    }

    /// Start a specific component
    pub async fn start_component(&self, component_id: &ComponentId) -> Result<()> {
        info!(" Starting component: {}", component_id);

        // Check if dependencies are running
        self.check_dependencies(component_id).await?;

        let (component, timeout, retry_attempts) = {
            let components = self.components.read().await;
            let registration = components.get(component_id)
                .ok_or_else(|| anyhow::anyhow!("Component {} not registered", component_id))?;
            
            (
                registration.component.clone(),
                registration.startup_timeout,
                registration.retry_attempts
            )
        };

        // Update status to starting
        {
            let mut handles = self.handles.write().await;
            if let Some(handle) = handles.get_mut(component_id) {
                handle.mark_starting();
            }
        }

        // Attempt to start with retries
        let mut attempts = 0;
        let mut last_error = None;

        while attempts < retry_attempts {
            attempts += 1;
            
            match tokio::time::timeout(timeout, component.start()).await {
                Ok(Ok(())) => {
                    // Successfully started
                    {
                        let mut handles = self.handles.write().await;
                        if let Some(handle) = handles.get_mut(component_id) {
                            handle.mark_running();
                        }
                    }
                    
                    info!("Component {} started successfully", component_id);
                    return Ok(());
                }
                Ok(Err(e)) => {
                    warn!("Component {} start failed (attempt {}): {}", 
                          component_id, attempts, e);
                    last_error = Some(e.to_string());
                }
                Err(_) => {
                    warn!("⏰ Component {} start timed out (attempt {})", 
                          component_id, attempts);
                    last_error = Some("Startup timeout".to_string());
                }
            }

            if attempts < retry_attempts {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }

        // All attempts failed
        let error_msg = last_error.unwrap_or_else(|| "Unknown error".to_string());
        {
            let mut handles = self.handles.write().await;
            if let Some(handle) = handles.get_mut(component_id) {
                handle.mark_failed(error_msg.clone());
            }
        }

        Err(anyhow::anyhow!("Failed to start component {} after {} attempts: {}", 
                           component_id, retry_attempts, error_msg))
    }

    /// Stop a specific component
    pub async fn stop_component(&self, component_id: &ComponentId) -> Result<()> {
        info!("Stopping component: {}", component_id);

        let (component, timeout) = {
            let components = self.components.read().await;
            let registration = components.get(component_id)
                .ok_or_else(|| anyhow::anyhow!("Component {} not registered", component_id))?;
            
            (registration.component.clone(), registration.shutdown_timeout)
        };

        // Update status to stopping
        {
            let mut handles = self.handles.write().await;
            if let Some(handle) = handles.get_mut(component_id) {
                handle.mark_stopping();
            }
        }

        // Attempt graceful shutdown with timeout
        match tokio::time::timeout(timeout, component.stop()).await {
            Ok(Ok(())) => {
                {
                    let mut handles = self.handles.write().await;
                    if let Some(handle) = handles.get_mut(component_id) {
                        handle.mark_stopped();
                    }
                }
                info!("Component {} stopped successfully", component_id);
                Ok(())
            }
            Ok(Err(e)) => {
                warn!("Component {} stop failed: {}", component_id, e);
                {
                    let mut handles = self.handles.write().await;
                    if let Some(handle) = handles.get_mut(component_id) {
                        handle.mark_failed(e.to_string());
                    }
                }
                Err(e)
            }
            Err(_) => {
                warn!("⏰ Component {} stop timed out, forcing shutdown", component_id);
                
                // Force shutdown if timeout
                match component.force_stop().await {
                    Ok(()) => {
                        {
                            let mut handles = self.handles.write().await;
                            if let Some(handle) = handles.get_mut(component_id) {
                                handle.mark_stopped();
                            }
                        }
                        warn!("Component {} force stopped", component_id);
                        Ok(())
                    }
                    Err(e) => {
                        error!("💥 Failed to force stop component {}: {}", component_id, e);
                        {
                            let mut handles = self.handles.write().await;
                            if let Some(handle) = handles.get_mut(component_id) {
                                handle.mark_failed(format!("Force stop failed: {}", e));
                            }
                        }
                        Err(e)
                    }
                }
            }
        }
    }

    /// Start all components in dependency order
    pub async fn start_all(&self) -> Result<()> {
        info!(" Starting all components in dependency order...");

        let startup_order = self.startup_order.read().await.clone();

        for component_id in startup_order {
            if *self.shutdown_requested.read().await {
                warn!("Shutdown requested, aborting startup");
                return Ok(());
            }

            self.start_component(&component_id).await
                .with_context(|| format!("Failed to start component {}", component_id))?;
        }

        info!("All components started successfully");
        Ok(())
    }

    /// Stop all components in reverse dependency order
    pub async fn shutdown_all(&self) -> Result<()> {
        info!("Shutting down all components...");

        // Set shutdown flag
        *self.shutdown_requested.write().await = true;

        // Stop health checker
        if let Some(handle) = self.health_checker.lock().await.take() {
            handle.abort();
        }

        let startup_order = self.startup_order.read().await.clone();
        let shutdown_order: Vec<_> = startup_order.into_iter().rev().collect();

        for component_id in shutdown_order {
            let status = {
                let handles = self.handles.read().await;
                handles.get(&component_id)
                    .map(|h| h.status.clone())
                    .unwrap_or(ComponentStatus::Stopped)
            };

            if matches!(status, ComponentStatus::Running | ComponentStatus::Starting) {
                if let Err(e) = self.stop_component(&component_id).await {
                    warn!("Failed to stop component {}: {}", component_id, e);
                }
            }
        }

        info!("All components shut down");
        Ok(())
    }

    /// Get a component by ID
    pub async fn get_component(&self, component_id: &ComponentId) -> Result<Option<Arc<dyn Component>>> {
        let components = self.components.read().await;
        Ok(components.get(component_id).map(|reg| reg.component.clone()))
    }

    /// Check if a component is registered
    pub async fn is_component_registered(&self, component_id: &ComponentId) -> Result<bool> {
        let components = self.components.read().await;
        Ok(components.contains_key(component_id))
    }

    /// Get all registered components
    pub async fn get_registered_components(&self) -> Result<Vec<ComponentId>> {
        let components = self.components.read().await;
        Ok(components.keys().cloned().collect())
    }

    /// Get component status
    pub async fn get_component_status(&self, component_id: &ComponentId) -> Result<Option<ComponentStatus>> {
        let handles = self.handles.read().await;
        Ok(handles.get(component_id).map(|h| h.status.clone()))
    }

    /// Get component handle
    pub async fn get_component_handle(&self, component_id: &ComponentId) -> Result<Option<ComponentHandle>> {
        let handles = self.handles.read().await;
        Ok(handles.get(component_id).cloned())
    }

    /// Get all component handles
    pub async fn get_all_handles(&self) -> Result<HashMap<ComponentId, ComponentHandle>> {
        let handles = self.handles.read().await;
        Ok(handles.clone())
    }

    /// Restart a component
    pub async fn restart_component(&self, component_id: &ComponentId) -> Result<()> {
        info!(" Restarting component: {}", component_id);

        // Stop first
        if let Err(e) = self.stop_component(component_id).await {
            warn!("Failed to stop component {} for restart: {}", component_id, e);
        }

        // Wait a moment
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Start again
        self.start_component(component_id).await
            .with_context(|| format!("Failed to restart component {}", component_id))?;

        info!("Component {} restarted successfully", component_id);
        Ok(())
    }

    /// Health check for component manager
    pub async fn health_check(&self) -> Result<bool> {
        let handles = self.handles.read().await;
        
        // Check if all running components are healthy
        for (id, handle) in handles.iter() {
            if matches!(handle.status, ComponentStatus::Running) {
                // Check if component has had a recent health check
                if let Some(last_check) = handle.last_health_check {
                    let health_interval = {
                        let components = self.components.read().await;
                        components.get(id)
                            .map(|c| c.health_check_interval)
                            .unwrap_or(Duration::from_secs(30))
                    };

                    if last_check.elapsed() > health_interval * 2 {
                        warn!("Component {} has not had a health check recently", id);
                        return Ok(false);
                    }
                } else {
                    warn!("Component {} has never had a health check", id);
                    return Ok(false);
                }
            }
        }

        Ok(true)
    }

    /// Check component dependencies
    async fn check_dependencies(&self, component_id: &ComponentId) -> Result<()> {
        let dependencies = {
            let components = self.components.read().await;
            components.get(component_id)
                .map(|reg| reg.dependencies.clone())
                .unwrap_or_default()
        };

        let handles = self.handles.read().await;

        for dep_id in dependencies {
            let dep_status = handles.get(&dep_id)
                .map(|h| h.status.clone())
                .unwrap_or(ComponentStatus::Stopped);

            if !matches!(dep_status, ComponentStatus::Running) {
                return Err(anyhow::anyhow!(
                    "Dependency {} of component {} is not running (status: {:?})",
                    dep_id, component_id, dep_status
                ));
            }
        }

        Ok(())
    }

    /// Update startup order based on dependencies (topological sort)
    async fn update_startup_order(&self) -> Result<()> {
        let components = self.components.read().await;
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut temp_visited = std::collections::HashSet::new();

        // Topological sort
        for component_id in components.keys() {
            if !visited.contains(component_id) {
                self.topological_sort_visit(
                    component_id,
                    &components,
                    &mut visited,
                    &mut temp_visited,
                    &mut order,
                )?;
            }
        }

        // Update startup order
        *self.startup_order.write().await = order;
        Ok(())
    }

    /// Recursive function for topological sort
    fn topological_sort_visit(
        &self,
        component_id: &ComponentId,
        components: &HashMap<ComponentId, ComponentRegistration>,
        visited: &mut std::collections::HashSet<ComponentId>,
        temp_visited: &mut std::collections::HashSet<ComponentId>,
        order: &mut Vec<ComponentId>,
    ) -> Result<()> {
        if temp_visited.contains(component_id) {
            return Err(anyhow::anyhow!("Circular dependency detected involving {}", component_id));
        }

        if visited.contains(component_id) {
            return Ok(());
        }

        temp_visited.insert(component_id.clone());

        if let Some(registration) = components.get(component_id) {
            for dep_id in &registration.dependencies {
                self.topological_sort_visit(dep_id, components, visited, temp_visited, order)?;
            }
        }

        temp_visited.remove(component_id);
        visited.insert(component_id.clone());
        order.push(component_id.clone());

        Ok(())
    }

    /// Start health check background task
    async fn start_health_checker(&self) -> Result<()> {
        let components = self.components.clone();
        let handles = self.handles.clone();
        let shutdown_requested = self.shutdown_requested.clone();

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));

            loop {
                interval.tick().await;

                if *shutdown_requested.read().await {
                    break;
                }

                // Perform health checks on all running components
                let component_list = {
                    let handles_guard = handles.read().await;
                    handles_guard.iter()
                        .filter(|(_, handle)| matches!(handle.status, ComponentStatus::Running))
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>()
                };

                for component_id in component_list {
                    let (component, health_interval) = {
                        let components_guard = components.read().await;
                        if let Some(registration) = components_guard.get(&component_id) {
                            (registration.component.clone(), registration.health_check_interval)
                        } else {
                            continue;
                        }
                    };

                    // Check if health check is due
                    let should_check = {
                        let handles_guard = handles.read().await;
                        if let Some(handle) = handles_guard.get(&component_id) {
                            handle.last_health_check
                                .map(|last| last.elapsed() >= health_interval)
                                .unwrap_or(true)
                        } else {
                            false
                        }
                    };

                    if should_check {
                        match component.health_check().await {
                            Ok(health) => {
                                let mut handles_guard = handles.write().await;
                                if let Some(handle) = handles_guard.get_mut(&component_id) {
                                    handle.mark_health_check();
                                }
                                match health.status {
                                    crate::runtime::ComponentStatus::Running => {
                                        debug!("Health check passed for component: {}", component_id);
                                    }
                                    _ => {
                                        warn!("Health check failed for component: {} (status: {:?})", component_id, health.status);
                                    }
                                }
                            }
                            Err(e) => {
                                error!("Health check error for component {}: {}", component_id, e);
                            }
                        }
                    }
                }
            }

            debug!("Health checker task stopped");
        });

        *self.health_checker.lock().await = Some(handle);
        Ok(())
    }
}

/// Component manager statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentManagerStats {
    pub total_components: usize,
    pub running_components: usize,
    pub failed_components: usize,
    pub stopped_components: usize,
    pub components_with_restarts: usize,
    pub average_uptime: Duration,
    pub total_restarts: u32,
}

impl ComponentManager {
    /// Get component manager statistics
    pub async fn get_stats(&self) -> Result<ComponentManagerStats> {
        let handles = self.handles.read().await;
        
        let total_components = handles.len();
        let mut running_components = 0;
        let mut failed_components = 0;
        let mut stopped_components = 0;
        let mut components_with_restarts = 0;
        let mut total_restarts = 0;
        let mut total_uptime = Duration::ZERO;
        let mut uptime_count = 0;

        for handle in handles.values() {
            match handle.status {
                ComponentStatus::Running => {
                    running_components += 1;
                    if let Some(start_time) = handle.start_time {
                        total_uptime += start_time.elapsed();
                        uptime_count += 1;
                    }
                }
                ComponentStatus::Failed => failed_components += 1,
                ComponentStatus::Stopped => stopped_components += 1,
                _ => {}
            }

            if handle.restart_count > 0 {
                components_with_restarts += 1;
                total_restarts += handle.restart_count;
            }
        }

        let average_uptime = if uptime_count > 0 {
            total_uptime / uptime_count as u32
        } else {
            Duration::ZERO
        };

        Ok(ComponentManagerStats {
            total_components,
            running_components,
            failed_components,
            stopped_components,
            components_with_restarts,
            average_uptime,
            total_restarts,
        })
    }
}

/// Injectable trait implementation for ComponentManager
#[async_trait::async_trait]
impl super::dependency_injection::Injectable for ComponentManager {
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
}
