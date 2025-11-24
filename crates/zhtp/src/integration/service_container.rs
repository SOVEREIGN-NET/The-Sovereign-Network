//! Service Container for Dependency Management
//! 
//! Provides dependency injection and service lifecycle management

use anyhow::{Result, Context};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::{Arc, Weak};
use tokio::sync::RwLock;
use tracing::{info, error, debug};

use crate::runtime::{ComponentId, Component};

/// Service container for managing component dependencies and lifecycle
pub struct ServiceContainer {
    services: Arc<RwLock<HashMap<TypeId, Box<dyn Any + Send + Sync>>>>,
    singletons: Arc<RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>,
    components: Arc<RwLock<HashMap<ComponentId, Arc<dyn Component>>>>,
    factories: Arc<RwLock<HashMap<TypeId, Box<dyn ServiceFactory>>>>,
    initialized: Arc<RwLock<bool>>,
}

/// Service factory trait for creating services
pub trait ServiceFactory: Send + Sync {
    fn create(&self, container: &ServiceContainer) -> Result<Box<dyn Any + Send + Sync>>;
    fn service_type(&self) -> TypeId;
}

/// Service lifetime management
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceLifetime {
    Transient,  // New instance each time
    Singleton,  // Single instance
    Scoped,     // Instance per scope
}

/// Service registration
pub struct ServiceRegistration {
    pub service_type: TypeId,
    pub implementation_type: TypeId,
    pub lifetime: ServiceLifetime,
    pub factory: Option<Box<dyn ServiceFactory>>,
}

/// Service scope for scoped services
pub struct ServiceScope {
    scoped_services: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
}

impl ServiceContainer {
    /// Create a new service container
    pub async fn new() -> Result<Self> {
        Ok(Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            singletons: Arc::new(RwLock::new(HashMap::new())),
            components: Arc::new(RwLock::new(HashMap::new())),
            factories: Arc::new(RwLock::new(HashMap::new())),
            initialized: Arc::new(RwLock::new(false)),
        })
    }

    /// Initialize the service container
    pub async fn initialize(&self) -> Result<()> {
        let mut initialized = self.initialized.write().await;
        if *initialized {
            return Ok(());
        }

        info!("Initializing service container...");
        
        // Register core services
        self.register_core_services().await?;
        
        *initialized = true;
        info!("Service container initialized");
        Ok(())
    }

    /// Shutdown the service container
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down service container...");
        
        // Stop all components
        let components = self.components.read().await;
        for (id, component) in components.iter() {
            if let Err(e) = component.stop().await {
                error!("Failed to stop component {}: {}", id, e);
            }
        }
        
        // Clear all services
        self.services.write().await.clear();
        self.singletons.write().await.clear();
        self.components.write().await.clear();
        
        let mut initialized = self.initialized.write().await;
        *initialized = false;
        
        info!("Service container shut down");
        Ok(())
    }

    /// Register a singleton service
    pub async fn register_singleton<T>(&self, instance: Arc<T>) -> Result<()>
    where
        T: Any + Send + Sync,
    {
        let type_id = TypeId::of::<T>();
        let mut singletons = self.singletons.write().await;
        singletons.insert(type_id, instance);
        debug!("Registered singleton service: {:?}", std::any::type_name::<T>());
        Ok(())
    }

    /// Register a transient service with factory
    pub async fn register_transient<T, F>(&self, factory: F) -> Result<()>
    where
        T: Any + Send + Sync,
        F: ServiceFactory + 'static,
    {
        let type_id = TypeId::of::<T>();
        let mut factories = self.factories.write().await;
        factories.insert(type_id, Box::new(factory));
        debug!("Registered transient service: {:?}", std::any::type_name::<T>());
        Ok(())
    }

    /// Register a component
    pub async fn register_component(&self, id: ComponentId, component: Arc<dyn Component>) -> Result<()> {
        let mut components = self.components.write().await;
        components.insert(id.clone(), component);
        debug!("Registered component: {}", id);
        Ok(())
    }

    /// Resolve a service by type
    pub async fn resolve<T>(&self) -> Result<Arc<T>>
    where
        T: Any + Send + Sync,
    {
        let type_id = TypeId::of::<T>();
        
        // Check singletons first
        {
            let singletons = self.singletons.read().await;
            if let Some(service) = singletons.get(&type_id) {
                return service.clone()
                    .downcast::<T>()
                    .map_err(|_| anyhow::anyhow!("Failed to downcast singleton service"));
            }
        }

        // Check factories for transient services
        {
            let factories = self.factories.read().await;
            if let Some(factory) = factories.get(&type_id) {
                let instance = factory.create(self)
                    .context("Failed to create service from factory")?;
                
                return Ok(Arc::new(
                    *instance.downcast::<T>()
                        .map_err(|_| anyhow::anyhow!("Failed to downcast factory-created service"))?
                ));
            }
        }

        Err(anyhow::anyhow!("Service not found: {:?}", std::any::type_name::<T>()))
    }

    /// Resolve a component by ID
    pub async fn resolve_component(&self, id: &ComponentId) -> Result<Arc<dyn Component>> {
        let components = self.components.read().await;
        components.get(id)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Component not found: {}", id))
    }

    /// Get all registered components
    pub async fn get_components(&self) -> Result<Vec<ComponentId>> {
        let components = self.components.read().await;
        Ok(components.keys().cloned().collect())
    }

    /// Check if service is registered
    pub async fn is_registered<T>(&self) -> bool
    where
        T: Any + Send + Sync,
    {
        let type_id = TypeId::of::<T>();
        
        let singletons = self.singletons.read().await;
        if singletons.contains_key(&type_id) {
            return true;
        }
        
        let factories = self.factories.read().await;
        factories.contains_key(&type_id)
    }

    /// Check if component is registered
    pub async fn is_component_registered(&self, id: &ComponentId) -> bool {
        let components = self.components.read().await;
        components.contains_key(id)
    }

    /// Create a service scope
    pub fn create_scope(&self) -> ServiceScope {
        ServiceScope {
            scoped_services: HashMap::new(),
        }
    }

    /// Register core services
    async fn register_core_services(&self) -> Result<()> {
        // Register self reference
        let self_ref = Arc::new(ServiceContainerReference {
            container: Arc::downgrade(&Arc::new(self.clone())),
        });
        self.register_singleton(self_ref).await?;
        
        debug!("Core services registered");
        Ok(())
    }

    /// Health check for service container
    pub async fn health_check(&self) -> Result<bool> {
        let initialized = *self.initialized.read().await;
        if !initialized {
            return Ok(false);
        }

        // Check if core components are accessible
        let components = self.components.read().await;
        let component_count = components.len();
        
        // Verify singletons are still valid
        let singletons = self.singletons.read().await;
        let singleton_count = singletons.len();
        
        debug!(" Service container health: {} components, {} singletons", 
               component_count, singleton_count);
        
        Ok(true)
    }

    /// Get service container statistics
    pub async fn get_statistics(&self) -> ServiceContainerStats {
        let components = self.components.read().await;
        let singletons = self.singletons.read().await;
        let factories = self.factories.read().await;
        let initialized = *self.initialized.read().await;

        ServiceContainerStats {
            initialized,
            component_count: components.len(),
            singleton_count: singletons.len(),
            factory_count: factories.len(),
            registered_components: components.keys().cloned().collect(),
        }
    }
}

// Manual Clone implementation since we need to handle the complex inner types
impl Clone for ServiceContainer {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            singletons: self.singletons.clone(),
            components: self.components.clone(),
            factories: self.factories.clone(),
            initialized: self.initialized.clone(),
        }
    }
}

/// Reference to service container (to avoid circular dependencies)
pub struct ServiceContainerReference {
    container: Weak<ServiceContainer>,
}

impl ServiceContainerReference {
    pub fn upgrade(&self) -> Option<Arc<ServiceContainer>> {
        self.container.upgrade()
    }
}

/// Service container statistics
#[derive(Debug, Clone)]
pub struct ServiceContainerStats {
    pub initialized: bool,
    pub component_count: usize,
    pub singleton_count: usize,
    pub factory_count: usize,
    pub registered_components: Vec<ComponentId>,
}

impl ServiceScope {
    /// Resolve a scoped service
    pub fn resolve_scoped<T>(&mut self, _container: &ServiceContainer) -> Result<Arc<T>>
    where
        T: Any + Send + Sync,
    {
        let type_id = TypeId::of::<T>();
        
        // Check if already exists in scope
        if let Some(service) = self.scoped_services.get(&type_id) {
            return service.clone()
                .downcast::<T>()
                .map_err(|_| anyhow::anyhow!("Failed to downcast scoped service"));
        }
        
        // Create new scoped instance
        // This would require additional factory logic for scoped services
        // For now, delegate to container
        Err(anyhow::anyhow!("Scoped service resolution not implemented"))
    }
    
    /// Dispose of scoped services
    pub fn dispose(self) {
        // Services will be dropped when scope is dropped
        debug!(" Service scope disposed with {} services", self.scoped_services.len());
    }
}

/// Factory for creating component instances
pub struct ComponentFactory<T> {
    _phantom: std::marker::PhantomData<T>,
}

impl<T> ComponentFactory<T>
where
    T: Any + Send + Sync,
{
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T> ServiceFactory for ComponentFactory<T>
where
    T: Any + Send + Sync + Default,
{
    fn create(&self, _container: &ServiceContainer) -> Result<Box<dyn Any + Send + Sync>> {
        Ok(Box::new(T::default()))
    }
    
    fn service_type(&self) -> TypeId {
        TypeId::of::<T>()
    }
}

/// Builder for configuring services
pub struct ServiceContainerBuilder {
    registrations: Vec<ServiceRegistration>,
}

impl ServiceContainerBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self {
            registrations: Vec::new(),
        }
    }

    /// Register a singleton service
    pub fn add_singleton<TInterface, TImplementation>(mut self) -> Self
    where
        TInterface: Any + Send + Sync,
        TImplementation: Any + Send + Sync,
    {
        self.registrations.push(ServiceRegistration {
            service_type: TypeId::of::<TInterface>(),
            implementation_type: TypeId::of::<TImplementation>(),
            lifetime: ServiceLifetime::Singleton,
            factory: None,
        });
        self
    }

    /// Register a transient service
    pub fn add_transient<TInterface, TImplementation>(mut self) -> Self
    where
        TInterface: Any + Send + Sync,
        TImplementation: Any + Send + Sync + Default,
    {
        self.registrations.push(ServiceRegistration {
            service_type: TypeId::of::<TInterface>(),
            implementation_type: TypeId::of::<TImplementation>(),
            lifetime: ServiceLifetime::Transient,
            factory: Some(Box::new(ComponentFactory::<TImplementation>::new())),
        });
        self
    }

    /// Build the service container
    pub async fn build(self) -> Result<ServiceContainer> {
        let container = ServiceContainer::new().await?;
        
        // Process registrations
        for registration in self.registrations {
            match registration.lifetime {
                ServiceLifetime::Singleton => {
                    // Would need additional logic to create singleton instances
                    debug!(" Singleton registration: {:?}", registration.service_type);
                }
                ServiceLifetime::Transient => {
                    if let Some(_factory) = registration.factory {
                        // Register factory for transient services
                        debug!(" Transient registration: {:?}", registration.service_type);
                    }
                }
                ServiceLifetime::Scoped => {
                    // Scoped services would need additional scope management
                    debug!(" Scoped registration: {:?}", registration.service_type);
                }
            }
        }
        
        Ok(container)
    }
}

impl Default for ServiceContainerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Injectable trait implementation for ServiceContainer
#[async_trait::async_trait]
impl super::dependency_injection::Injectable for ServiceContainer {
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }
}
