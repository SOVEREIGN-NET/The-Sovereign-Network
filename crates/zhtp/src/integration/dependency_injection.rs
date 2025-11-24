//! Dependency Injection System for ZHTP
//! 
//! Provides a sophisticated dependency injection container for managing
//! service lifetimes, dependencies, and runtime resolution

use anyhow::{Result, Context};
use std::any::{Any, TypeId};
use std::collections::HashMap;
use std::sync::Arc;
use std::pin::Pin;
use std::future::Future;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use async_trait::async_trait;

/// Service lifetime scopes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// Single instance for the entire application
    Singleton,
    /// New instance for each scope/request
    Transient,
    /// Single instance per scope
    Scoped,
}

/// Injectable trait for services that can be dependency injected
#[async_trait]
pub trait Injectable: Send + Sync + Any {
    /// Type ID for runtime type checking
    fn type_id(&self) -> TypeId {
        TypeId::of::<Self>()
    }
    
    /// Type name for debugging
    fn type_name(&self) -> &'static str {
        std::any::type_name::<Self>()
    }

    /// Initialize the service after all dependencies are injected
    async fn initialize(&self) -> Result<()> {
        Ok(())
    }

    /// Cleanup the service during shutdown
    async fn cleanup(&self) -> Result<()> {
        Ok(())
    }

    /// Health check for the service
    async fn health_check(&self) -> Result<bool> {
        Ok(true)
    }
}

/// Service factory for creating instances
type ServiceFactory = Box<dyn Fn() -> Box<dyn Any + Send + Sync> + Send + Sync>;

/// Async service factory for services that require async initialization
type AsyncServiceFactory = Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Box<dyn Any + Send + Sync>>> + Send>> + Send + Sync>;

/// Service registration information
struct ServiceRegistration {
    type_name: &'static str,
    scope: Scope,
    factory: Option<ServiceFactory>,
    async_factory: Option<AsyncServiceFactory>,
    singleton_instance: Option<Arc<dyn Any + Send + Sync>>,
    dependencies: Vec<TypeId>,
}

impl ServiceRegistration {
    fn new(_type_id: TypeId, type_name: &'static str, scope: Scope) -> Self {
        Self {
            type_name,
            scope,
            factory: None,
            async_factory: None,
            singleton_instance: None,
            dependencies: Vec::new(),
        }
    }

    fn with_factory(mut self, factory: ServiceFactory) -> Self {
        self.factory = Some(factory);
        self
    }

    fn with_async_factory(mut self, factory: AsyncServiceFactory) -> Self {
        self.async_factory = Some(factory);
        self
    }

    fn with_instance(mut self, instance: Arc<dyn Any + Send + Sync>) -> Self {
        self.singleton_instance = Some(instance);
        self
    }
}

/// Dependency injection scope for managing scoped instances
pub struct DIScope {
    instances: HashMap<TypeId, Arc<dyn Any + Send + Sync>>,
    injector: Arc<DependencyInjector>,
}

impl DIScope {
    fn new(injector: Arc<DependencyInjector>) -> Self {
        Self {
            instances: HashMap::new(),
            injector,
        }
    }

    /// Get or create a scoped instance
    pub fn get<T: Injectable + 'static>(&mut self) -> Pin<Box<dyn Future<Output = Result<Arc<T>>> + Send + '_>> {
        Box::pin(async move {
            let type_id = TypeId::of::<T>();
            
            if let Some(instance) = self.instances.get(&type_id) {
                return instance
                    .clone()
                    .downcast::<T>()
                    .map_err(|_| anyhow::anyhow!("Failed to downcast service {}", std::any::type_name::<T>()));
            }

            // Create new scoped instance
            let injector = self.injector.clone();
            let instance = injector.resolve_internal::<T>(Some(self)).await?;
            self.instances.insert(type_id, instance.clone() as Arc<dyn Any + Send + Sync>);
            
            Ok(instance)
        })
    }

    /// Clean up all scoped instances
    pub async fn cleanup(&mut self) -> Result<()> {
        for (type_id, instance) in self.instances.drain() {
            // Try to downcast to Arc<dyn Injectable> first
            if let Ok(injectable_arc) = instance.clone().downcast::<Arc<dyn Injectable>>() {
                if let Err(e) = injectable_arc.cleanup().await {
                    warn!("Failed to cleanup scoped service {:?}: {}", type_id, e);
                }
            }
        }
        Ok(())
    }
}

/// Dependency injection container
pub struct DependencyInjector {
    services: Arc<RwLock<HashMap<TypeId, ServiceRegistration>>>,
    singleton_cache: Arc<RwLock<HashMap<TypeId, Arc<dyn Any + Send + Sync>>>>,
    initialization_order: Arc<RwLock<Vec<TypeId>>>,
}

impl DependencyInjector {
    /// Create a new dependency injector
    pub async fn new() -> Result<Self> {
        Ok(Self {
            services: Arc::new(RwLock::new(HashMap::new())),
            singleton_cache: Arc::new(RwLock::new(HashMap::new())),
            initialization_order: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// Register a singleton service with an instance
    pub async fn register_singleton<T: Injectable + 'static>(&self, instance: Arc<T>) -> Result<()> {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        info!("Registering singleton service: {}", type_name);

        let registration = ServiceRegistration::new(type_id, type_name, Scope::Singleton)
            .with_instance(instance.clone() as Arc<dyn Any + Send + Sync>);

        {
            let mut services = self.services.write().await;
            services.insert(type_id, registration);
        }

        {
            let mut cache = self.singleton_cache.write().await;
            cache.insert(type_id, instance as Arc<dyn Any + Send + Sync>);
        }

        self.update_initialization_order().await?;
        
        debug!("Singleton service {} registered", type_name);
        Ok(())
    }

    /// Register a transient service with a factory
    pub async fn register_transient<T: Injectable + 'static, F>(&self, factory: F) -> Result<()>
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        info!("Registering transient service: {}", type_name);

        let boxed_factory: ServiceFactory = Box::new(move || {
            Box::new(Arc::new(factory()))
        });

        let registration = ServiceRegistration::new(type_id, type_name, Scope::Transient)
            .with_factory(boxed_factory);

        {
            let mut services = self.services.write().await;
            services.insert(type_id, registration);
        }

        self.update_initialization_order().await?;
        
        debug!("Transient service {} registered", type_name);
        Ok(())
    }

    /// Register a transient service with an async factory
    pub async fn register_transient_async<T: Injectable + 'static, F, Fut>(&self, factory: F) -> Result<()>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<T>> + Send + 'static,
    {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        info!("Registering async transient service: {}", type_name);

        let boxed_factory: AsyncServiceFactory = Box::new(move || {
            let future = factory();
            Box::pin(async move {
                let instance = future.await?;
                Ok(Box::new(Arc::new(instance)) as Box<dyn Any + Send + Sync>)
            })
        });

        let registration = ServiceRegistration::new(type_id, type_name, Scope::Transient)
            .with_async_factory(boxed_factory);

        {
            let mut services = self.services.write().await;
            services.insert(type_id, registration);
        }

        self.update_initialization_order().await?;
        
        debug!("Async transient service {} registered", type_name);
        Ok(())
    }

    /// Register a scoped service with a factory
    pub async fn register_scoped<T: Injectable + 'static, F>(&self, factory: F) -> Result<()>
    where
        F: Fn() -> T + Send + Sync + 'static,
    {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        info!("Registering scoped service: {}", type_name);

        let boxed_factory: ServiceFactory = Box::new(move || {
            Box::new(Arc::new(factory()))
        });

        let registration = ServiceRegistration::new(type_id, type_name, Scope::Scoped)
            .with_factory(boxed_factory);

        {
            let mut services = self.services.write().await;
            services.insert(type_id, registration);
        }

        self.update_initialization_order().await?;
        
        debug!("Scoped service {} registered", type_name);
        Ok(())
    }

    /// Register service dependencies
    pub async fn register_dependencies<T: Injectable + 'static>(&self, dependencies: Vec<TypeId>) -> Result<()> {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        debug!("Registering dependencies for {}: {} deps", type_name, dependencies.len());

        {
            let mut services = self.services.write().await;
            if let Some(registration) = services.get_mut(&type_id) {
                registration.dependencies = dependencies;
            } else {
                return Err(anyhow::anyhow!("Service {} not registered", type_name));
            }
        }

        self.update_initialization_order().await?;
        Ok(())
    }

    /// Resolve a service instance
    pub async fn resolve<T: Injectable + 'static>(&self) -> Result<Arc<T>> {
        self.resolve_internal::<T>(None).await
    }

    /// Resolve a service instance with a specific scope
    pub async fn resolve_with_scope<T: Injectable + 'static>(&self, scope: &mut DIScope) -> Result<Arc<T>> {
        self.resolve_internal::<T>(Some(scope)).await
    }

    /// Resolve a service instance with optional scope
    async fn resolve_internal<T: Injectable + 'static>(&self, di_scope: Option<&mut DIScope>) -> Result<Arc<T>> {
        let type_id = TypeId::of::<T>();
        let type_name = std::any::type_name::<T>();
        
        debug!("Resolving service: {}", type_name);

        let scope = {
            let services = self.services.read().await;
            let registration = services.get(&type_id)
                .ok_or_else(|| anyhow::anyhow!("Service {} not registered", type_name))?;
            registration.scope.clone()
        };

        match scope {
            Scope::Singleton => {
                // Check cache first
                {
                    let cache = self.singleton_cache.read().await;
                    if let Some(instance) = cache.get(&type_id) {
                        return instance
                            .clone()
                            .downcast::<T>()
                            .map_err(|_| anyhow::anyhow!("Failed to downcast singleton {}", type_name));
                    }
                }

                // Create and cache singleton
                let instance = self.create_instance_by_type_id::<T>(type_id).await?;
                
                {
                    let mut cache = self.singleton_cache.write().await;
                    cache.insert(type_id, instance.clone() as Arc<dyn Any + Send + Sync>);
                }

                Ok(instance)
            }
            Scope::Transient => {
                // Always create new instance
                self.create_instance_by_type_id::<T>(type_id).await
            }
            Scope::Scoped => {
                if let Some(scope_ref) = di_scope {
                    // Use provided scope to get or create scoped instance
                    scope_ref.get::<T>().await
                } else {
                    // No scope provided, create transient instance
                    warn!("No scope provided for scoped service {}, creating transient instance", type_name);
                    self.create_instance_by_type_id::<T>(type_id).await
                }
            }
        }
    }

    /// Create a new service scope
    pub fn create_scope(&self) -> DIScope {
        DIScope::new(Arc::new(self.clone()))
    }

    /// Helper method to create instance by TypeId
    async fn create_instance_by_type_id<T: Injectable + 'static>(&self, type_id: TypeId) -> Result<Arc<T>> {
        let services = self.services.read().await;
        let registration = services.get(&type_id)
            .ok_or_else(|| anyhow::anyhow!("Service not registered"))?;
        self.create_instance::<T>(registration).await
    }

    /// Create a service instance
    async fn create_instance<T: Injectable + 'static>(&self, registration: &ServiceRegistration) -> Result<Arc<T>> {
        let type_name = registration.type_name;
        
        // Check for singleton instance first
        if let Some(instance) = &registration.singleton_instance {
            return instance
                .clone()
                .downcast::<T>()
                .map_err(|_| anyhow::anyhow!("Failed to downcast existing singleton {}", type_name));
        }

        // Use async factory if available
        if let Some(async_factory) = &registration.async_factory {
            let boxed_instance = async_factory().await
                .with_context(|| format!("Failed to create instance using async factory for {}", type_name))?;
            
            let arc_instance = boxed_instance
                .downcast::<Arc<T>>()
                .map_err(|_| anyhow::anyhow!("Failed to downcast async factory result for {}", type_name))?;
            
            return Ok(*arc_instance);
        }

        // Use sync factory
        if let Some(factory) = &registration.factory {
            let boxed_instance = factory();
            let arc_instance = boxed_instance
                .downcast::<Arc<T>>()
                .map_err(|_| anyhow::anyhow!("Failed to downcast factory result for {}", type_name))?;
            
            return Ok(*arc_instance);
        }

        Err(anyhow::anyhow!("No factory or instance available for {}", type_name))
    }

    /// Initialize all registered services in dependency order
    pub async fn initialize_all(&self) -> Result<()> {
        info!(" Initializing all registered services...");

        let initialization_order = self.initialization_order.read().await.clone();

        for type_id in initialization_order {
            let type_name = {
                let services = self.services.read().await;
                services.get(&type_id)
                    .map(|r| r.type_name)
                    .unwrap_or("Unknown")
            };

            debug!("Initializing service: {}", type_name);

            // Get the service instance
            let instance = {
                let cache = self.singleton_cache.read().await;
                cache.get(&type_id).cloned()
            };

            if let Some(instance) = instance {
                if let Ok(injectable_arc) = instance.downcast::<Arc<dyn Injectable>>() {
                    injectable_arc.initialize().await
                        .with_context(|| format!("Failed to initialize service {}", type_name))?;
                    debug!("Service {} initialized", type_name);
                } else {
                    warn!("Service {} does not implement Injectable", type_name);
                }
            }
        }

        info!("All services initialized successfully");
        Ok(())
    }

    /// Cleanup all services in reverse order
    pub async fn cleanup_all(&self) -> Result<()> {
        info!(" Cleaning up all services...");

        let initialization_order = self.initialization_order.read().await.clone();
        let cleanup_order: Vec<_> = initialization_order.into_iter().rev().collect();

        for type_id in cleanup_order {
            let type_name = {
                let services = self.services.read().await;
                services.get(&type_id)
                    .map(|r| r.type_name)
                    .unwrap_or("Unknown")
            };

            debug!(" Cleaning up service: {}", type_name);

            let instance = {
                let mut cache = self.singleton_cache.write().await;
                cache.remove(&type_id)
            };

            if let Some(instance) = instance {
                if let Ok(injectable_arc) = instance.downcast::<Arc<dyn Injectable>>() {
                    if let Err(e) = injectable_arc.cleanup().await {
                        warn!("Failed to cleanup service {}: {}", type_name, e);
                    } else {
                        debug!("Service {} cleaned up", type_name);
                    }
                }
            }
        }

        info!("All services cleaned up");
        Ok(())
    }

    /// Perform health checks on all services
    pub async fn health_check_all(&self) -> Result<HashMap<String, bool>> {
        debug!("Performing health checks on all services...");

        let mut results = HashMap::new();
        let cache = self.singleton_cache.read().await;

        for (type_id, instance) in cache.iter() {
            let type_name = {
                let services = self.services.read().await;
                services.get(type_id)
                    .map(|r| r.type_name.to_string())
                    .unwrap_or_else(|| format!("Unknown-{:?}", type_id))
            };

            if let Ok(injectable_arc) = instance.clone().downcast::<Arc<dyn Injectable>>() {
                match injectable_arc.health_check().await {
                    Ok(healthy) => {
                        results.insert(type_name.clone(), healthy);
                        if healthy {
                            debug!("Health check passed for: {}", type_name);
                        } else {
                            warn!("Health check failed for: {}", type_name);
                        }
                    }
                    Err(e) => {
                        results.insert(type_name.clone(), false);
                        error!("Health check error for {}: {}", type_name, e);
                    }
                }
            } else {
                // Non-injectable services are considered healthy
                results.insert(type_name, true);
            }
        }

        Ok(results)
    }

    /// Get service information
    pub async fn get_service_info(&self) -> Result<Vec<ServiceInfo>> {
        let services = self.services.read().await;
        let cache = self.singleton_cache.read().await;

        let mut info = Vec::new();

        for (type_id, registration) in services.iter() {
            let is_instantiated = cache.contains_key(type_id);
            
            info.push(ServiceInfo {
                type_name: registration.type_name.to_string(),
                scope: registration.scope.clone(),
                is_instantiated,
                dependency_count: registration.dependencies.len(),
            });
        }

        Ok(info)
    }

    /// Update initialization order based on dependencies (topological sort)
    async fn update_initialization_order(&self) -> Result<()> {
        let services = self.services.read().await;
        let mut order = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut temp_visited = std::collections::HashSet::new();

        // Topological sort
        for type_id in services.keys() {
            if !visited.contains(type_id) {
                self.topological_sort_visit(
                    *type_id,
                    &services,
                    &mut visited,
                    &mut temp_visited,
                    &mut order,
                )?;
            }
        }

        // Update initialization order
        *self.initialization_order.write().await = order;
        Ok(())
    }

    /// Recursive function for topological sort
    fn topological_sort_visit(
        &self,
        type_id: TypeId,
        services: &HashMap<TypeId, ServiceRegistration>,
        visited: &mut std::collections::HashSet<TypeId>,
        temp_visited: &mut std::collections::HashSet<TypeId>,
        order: &mut Vec<TypeId>,
    ) -> Result<()> {
        if temp_visited.contains(&type_id) {
            return Err(anyhow::anyhow!("Circular dependency detected"));
        }

        if visited.contains(&type_id) {
            return Ok(());
        }

        temp_visited.insert(type_id);

        if let Some(registration) = services.get(&type_id) {
            for &dep_type_id in &registration.dependencies {
                self.topological_sort_visit(dep_type_id, services, visited, temp_visited, order)?;
            }
        }

        temp_visited.remove(&type_id);
        visited.insert(type_id);
        order.push(type_id);

        Ok(())
    }
}

// Clone implementation for DependencyInjector
impl Clone for DependencyInjector {
    fn clone(&self) -> Self {
        Self {
            services: self.services.clone(),
            singleton_cache: self.singleton_cache.clone(),
            initialization_order: self.initialization_order.clone(),
        }
    }
}

/// Service information for debugging and monitoring
#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub type_name: String,
    pub scope: Scope,
    pub is_instantiated: bool,
    pub dependency_count: usize,
}

// Convenience macros for dependency injection

/// Register a singleton service
#[macro_export]
macro_rules! register_singleton {
    ($injector:expr, $instance:expr) => {
        $injector.register_singleton($instance).await
    };
}

/// Register a transient service
#[macro_export]
macro_rules! register_transient {
    ($injector:expr, $factory:expr) => {
        $injector.register_transient($factory).await
    };
}

/// Register a scoped service
#[macro_export]
macro_rules! register_scoped {
    ($injector:expr, $factory:expr) => {
        $injector.register_scoped($factory).await
    };
}

/// Resolve a service
#[macro_export]
macro_rules! resolve {
    ($injector:expr, $service_type:ty) => {
        $injector.resolve::<$service_type>().await
    };
}
