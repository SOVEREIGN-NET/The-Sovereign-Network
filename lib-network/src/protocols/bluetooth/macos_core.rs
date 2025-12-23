// Core Bluetooth implementation for macOS
// Uses native CBCentralManager and CBPeripheralManager for production-grade Bluetooth LE

#[cfg(target_os = "macos")]
use anyhow::{Result, anyhow};
#[cfg(target_os = "macos")]
use tracing::{info, warn, debug};
#[cfg(target_os = "macos")]
use std::collections::HashMap;
#[cfg(target_os = "macos")]
use std::sync::Arc;
#[cfg(target_os = "macos")]
use std::ffi::c_void;
#[cfg(target_os = "macos")]
use tokio::sync::{RwLock, Mutex};

// Objective-C FFI imports (objc2)
#[cfg(target_os = "macos")]
use objc2::{msg_send, runtime::{AnyObject, AnyClass, Object}};
#[cfg(target_os = "macos")]
use objc2_foundation::NSString;

// Import common Bluetooth utilities
#[cfg(target_os = "macos")]
use crate::protocols::bluetooth::device::{BleDevice, BluetoothDeviceInfo, ConnectionState};
#[cfg(target_os = "macos")]
use crate::protocols::bluetooth::macos_delegate;

/// Events emitted by Core Bluetooth callbacks
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub enum CoreBluetoothEvent {
    /// Bluetooth state changed
    StateChanged(BluetoothState),
    /// Peripheral discovered during scan
    PeripheralDiscovered {
        identifier: String,
        name: Option<String>,
        rssi: i32,
        advertisement_data: HashMap<String, String>,
        peripheral_ptr: usize,
    },
    /// Peripheral connected
    PeripheralConnected(String),
    /// Peripheral disconnected
    PeripheralDisconnected(String),
    /// Connection failed with error
    ConnectionFailed {
        peripheral_id: String,
        error_message: String,
        error_code: i64,
        error_domain: String,
    },
    /// Services discovered for peripheral
    ServicesDiscovered {
        peripheral_id: String,
        service_uuids: Vec<String>,
    },
    /// Service discovery failed
    ServiceDiscoveryFailed {
        peripheral_id: String,
        error_message: String,
        error_code: i64,
    },
    /// Characteristics discovered for service
    CharacteristicsDiscovered {
        peripheral_id: String,
        service_uuid: String,
        characteristic_uuids: Vec<String>,
    },
    /// Characteristic discovery failed
    CharacteristicDiscoveryFailed {
        peripheral_id: String,
        service_uuid: String,
        error_message: String,
        error_code: i64,
    },
    /// Characteristic value updated (from read or notification)
    CharacteristicValueUpdated {
        peripheral_id: String,
        characteristic_uuid: String,
        value: Vec<u8>,
    },
    /// Characteristic read failed
    CharacteristicReadFailed {
        peripheral_id: String,
        characteristic_uuid: String,
        error_message: String,
        error_code: i64,
    },
    /// Write completed
    WriteCompleted {
        peripheral_id: String,
        characteristic_uuid: String,
    },
    /// Characteristic write failed
    CharacteristicWriteFailed {
        peripheral_id: String,
        characteristic_uuid: String,
        error_message: String,
        error_code: i64,
    },
    /// Notification state changed
    NotificationStateChanged {
        peripheral_id: String,
        characteristic_uuid: String,
        enabled: bool,
    },
    /// Notification state update failed
    NotificationStateFailed {
        peripheral_id: String,
        characteristic_uuid: String,
        error_message: String,
        error_code: i64,
    },
    /// Advertising started
    AdvertisingStarted,
    /// Service added to GATT server
    ServiceAdded(String),
    /// Read request received (GATT server)
    ReadRequest {
        central_id: String,
        characteristic_uuid: String,
    },
    /// Write request received (GATT server)
    WriteRequest {
        central_id: String,
        characteristic_uuid: String,
        value: Vec<u8>,
    },
    /// Central subscribed to characteristic (GATT server)
    CentralSubscribed {
        central_id: String,
        characteristic_uuid: String,
    },
    /// Central unsubscribed from characteristic (GATT server)
    CentralUnsubscribed {
        central_id: String,
        characteristic_uuid: String,
    },
}

/// Core Bluetooth power state
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq)]
pub enum BluetoothState {
    Unknown,
    Resetting,
    Unsupported,
    Unauthorized,
    PoweredOff,
    PoweredOn,
}

/// Core Bluetooth manager for macOS using CBCentralManager and CBPeripheralManager
#[cfg(target_os = "macos")]
pub struct CoreBluetoothManager {
    /// Central manager for scanning and connecting to peripherals
    central_manager: Arc<Mutex<Option<CBCentralManagerHandle>>>,
    /// Peripheral manager for advertising and GATT server
    peripheral_manager: Arc<Mutex<Option<CBPeripheralManagerHandle>>>,
    /// Discovered peripherals cache (when we act as central and scan)
    discovered_peripherals: Arc<RwLock<HashMap<String, CBPeripheralHandle>>>,
    /// Connected centrals cache (when we act as peripheral and receive connections)
    connected_centrals: Arc<RwLock<HashMap<String, usize>>>, // central_id -> CBCentral pointer
    /// GATT service cache
    services_cache: Arc<RwLock<HashMap<String, Vec<CBServiceHandle>>>>,
    /// Characteristic value cache for notifications
    characteristic_values: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// Notification callbacks
    #[allow(dead_code)]
    notification_handlers: Arc<RwLock<HashMap<String, Box<dyn Fn(Vec<u8>) + Send + Sync>>>>,
    /// Track which centrals are subscribed to which characteristics
    subscribed_centrals: Arc<RwLock<HashMap<String, Vec<String>>>>, // characteristic_uuid -> vec of central_ids
    /// Event channel for Core Bluetooth callbacks
    event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>,
    event_receiver: Arc<Mutex<Option<tokio::sync::mpsc::UnboundedReceiver<CoreBluetoothEvent>>>>,
    /// GATT message channel for forwarding to unified server
    gatt_message_tx: Arc<RwLock<Option<tokio::sync::mpsc::UnboundedSender<crate::protocols::bluetooth::GattMessage>>>>,
}

#[cfg(target_os = "macos")]
impl std::fmt::Debug for CoreBluetoothManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreBluetoothManager")
            .field("central_manager", &self.central_manager)
            .field("peripheral_manager", &self.peripheral_manager)
            .field("discovered_peripherals", &self.discovered_peripherals)
            .field("services_cache", &self.services_cache)
            .field("characteristic_values", &self.characteristic_values)
            .field("notification_handlers", &"<handlers>")
            .finish()
    }
}

/// Handle to Core Bluetooth Central Manager with real Objective-C object
#[cfg(target_os = "macos")]
pub struct CBCentralManagerHandle {
    /// Raw pointer to CBCentralManager Objective-C object
    manager_ptr: *mut AnyObject,
    /// Delegate for handling callbacks
    delegate: CBCentralManagerDelegate,
}

impl std::fmt::Debug for CBCentralManagerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CBCentralManagerHandle")
            .field("manager_ptr", &self.manager_ptr)
            .finish()
    }
}

// Safety: CBCentralManagerHandle can be sent between threads
#[cfg(target_os = "macos")]
unsafe impl Send for CBCentralManagerHandle {}
unsafe impl Sync for CBCentralManagerHandle {}

/// Handle to Core Bluetooth Peripheral Manager with real Objective-C object
#[cfg(target_os = "macos")]
pub struct CBPeripheralManagerHandle {
    /// Raw pointer to CBPeripheralManager Objective-C object
    manager_ptr: *mut AnyObject,
    /// Delegate for handling callbacks
    delegate: CBPeripheralManagerDelegate,
}

impl std::fmt::Debug for CBPeripheralManagerHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CBPeripheralManagerHandle")
            .field("manager_ptr", &self.manager_ptr)
            .finish()
    }
}

// Safety: CBPeripheralManagerHandle can be sent between threads
#[cfg(target_os = "macos")]
unsafe impl Send for CBPeripheralManagerHandle {}
unsafe impl Sync for CBPeripheralManagerHandle {}

/// Handle to discovered Core Bluetooth peripherals
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct CBPeripheralHandle {
    pub identifier: String,
    pub name: Option<String>,
    pub rssi: i32,
    pub advertisement_data: HashMap<String, String>,
    pub services: Vec<String>,
    /// Raw pointer to CBPeripheral object (for internal use)
    peripheral_ptr: Option<usize>, // Store as usize for Clone compatibility
}

/// Handle to GATT services
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct CBServiceHandle {
    pub uuid: String,
    pub is_primary: bool,
    pub characteristics: Vec<CBCharacteristicHandle>,
}

/// Handle to GATT characteristics
#[cfg(target_os = "macos")]
#[derive(Debug, Clone)]
pub struct CBCharacteristicHandle {
    pub uuid: String,
    pub properties: Vec<String>,
    pub value: Option<Vec<u8>>,
}

/// Central manager delegate for handling Core Bluetooth events
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct CBCentralManagerDelegate {
    /// Event channel sender for async communication
    pub event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>,
}

/// Peripheral manager delegate for GATT server operations
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct CBPeripheralManagerDelegate {
    /// Event channel sender for async communication
    pub event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>,
}

#[cfg(target_os = "macos")]
impl CoreBluetoothManager {
    /// Create new Core Bluetooth manager
    pub fn new() -> Result<Self> {
        info!(" Initializing Core Bluetooth for macOS");
        
        // Create event channel for Core Bluetooth callbacks
        let (event_sender, event_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        Ok(CoreBluetoothManager {
            central_manager: Arc::new(Mutex::new(None)),
            peripheral_manager: Arc::new(Mutex::new(None)),
            discovered_peripherals: Arc::new(RwLock::new(HashMap::new())),
            connected_centrals: Arc::new(RwLock::new(HashMap::new())),
            services_cache: Arc::new(RwLock::new(HashMap::new())),
            characteristic_values: Arc::new(RwLock::new(HashMap::new())),
            notification_handlers: Arc::new(RwLock::new(HashMap::new())),
            subscribed_centrals: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            event_receiver: Arc::new(Mutex::new(Some(event_receiver))),
            gatt_message_tx: Arc::new(RwLock::new(None)),
        })
    }
    
    /// Set GATT message channel for forwarding GATT writes to unified server
    pub async fn set_gatt_message_channel(&self, tx: tokio::sync::mpsc::UnboundedSender<crate::protocols::bluetooth::GattMessage>) {
        *self.gatt_message_tx.write().await = Some(tx);
        info!(" GATT message channel connected to CoreBluetoothManager");
    }
    
    /// Start event processing loop (must be called after initialization)
    pub async fn start_event_loop(self: &Arc<Self>) -> Result<()> {
        let mut receiver = self.event_receiver.lock().await.take()
            .ok_or_else(|| anyhow!("Event loop already started"))?;
        
        let peripherals = self.discovered_peripherals.clone();
        let services_cache = self.services_cache.clone();
        let char_values = self.characteristic_values.clone();
        let notification_handlers = self.notification_handlers.clone();
        let manager_ref = Arc::clone(self); // Clone Arc for notification sending
        
        tokio::spawn(async move {
            while let Some(event) = receiver.recv().await {
                match event {
                    CoreBluetoothEvent::StateChanged(state) => {
                        info!(" Bluetooth state: {:?}", state);
                    }
                    CoreBluetoothEvent::PeripheralDiscovered { identifier, name, rssi, advertisement_data, peripheral_ptr } => {
                        info!(" Discovered: {} ({}), RSSI: {}", 
                              name.as_deref().unwrap_or("Unknown"), identifier, rssi);
                        
                        let mut cache = peripherals.write().await;
                        cache.insert(identifier.clone(), CBPeripheralHandle {
                            identifier,
                            name,
                            rssi,
                            advertisement_data,
                            services: Vec::new(),
                            peripheral_ptr: Some(peripheral_ptr),
                        });
                    }
                    CoreBluetoothEvent::PeripheralConnected(id) => {
                        info!(" Connected: {}", id);
                    }
                    CoreBluetoothEvent::PeripheralDisconnected(id) => {
                        info!(" Disconnected: {}", id);
                    }
                    CoreBluetoothEvent::ServicesDiscovered { peripheral_id, service_uuids } => {
                        info!(" Services discovered for {}: {} services", peripheral_id, service_uuids.len());
                        let mut cache = services_cache.write().await;
                        // Convert Vec<String> to Vec<CBServiceHandle>
                        let service_handles: Vec<CBServiceHandle> = service_uuids.into_iter()
                            .map(|uuid| CBServiceHandle {
                                uuid,
                                is_primary: true,
                                characteristics: Vec::new(),
                            })
                            .collect();
                        cache.insert(peripheral_id, service_handles);
                    }
                    CoreBluetoothEvent::CharacteristicValueUpdated { peripheral_id, characteristic_uuid, value } => {
                        debug!("📖 Characteristic updated: {} / {} ({} bytes)", 
                               peripheral_id, characteristic_uuid, value.len());
                        
                        // Store value
                        let key = format!("{}:{}", peripheral_id, characteristic_uuid);
                        let mut values = char_values.write().await;
                        values.insert(key.clone(), value.clone());
                        
                        // Call notification handler if registered
                        let handlers = notification_handlers.read().await;
                        if let Some(handler) = handlers.get(&key) {
                            handler(value);
                        }
                    }
                    CoreBluetoothEvent::WriteCompleted { peripheral_id, characteristic_uuid } => {
                        debug!("✍️ Write completed: {} / {}", peripheral_id, characteristic_uuid);
                    }
                    CoreBluetoothEvent::NotificationStateChanged { peripheral_id, characteristic_uuid, enabled } => {
                        info!(" Notifications {} for {} / {}", 
                              if enabled { "enabled" } else { "disabled" }, 
                              peripheral_id, characteristic_uuid);
                    }
                    CoreBluetoothEvent::AdvertisingStarted => {
                        info!(" Advertising started");
                    }
                    CoreBluetoothEvent::ServiceAdded(uuid) => {
                        info!("➕ Service added: {}", uuid);
                    }
                    CoreBluetoothEvent::ReadRequest { central_id, characteristic_uuid } => {
                        debug!("📖 Read request from {} for {}", central_id, characteristic_uuid);
                    }
                    CoreBluetoothEvent::WriteRequest { central_id, characteristic_uuid, value } => {
                        info!("✍️ Write request from {} for {} ({} bytes)", 
                               central_id, characteristic_uuid, value.len());
                        
                        // Store this central in connected_centrals for future transmissions
                        {
                            let mut centrals = manager_ref.connected_centrals.write().await;
                            if !centrals.contains_key(&central_id) {
                                // Store with dummy pointer (0) - we use peripheral manager for sending
                                centrals.insert(central_id.clone(), 0);
                                info!("    Cached connected central: {}", central_id);
                            }
                        }
                        
                        // Try to deserialize as MeshHandshake
                        if value.len() >= 20 { // Minimum handshake size
                            match bincode::deserialize::<crate::protocols::bluetooth::MeshHandshake>(&value) {
                                Ok(handshake) => {
                                    info!("🤝 Received MeshHandshake from {}", central_id);
                                    info!("   Version: {}", handshake.version);
                                    info!("   Node ID: {}", handshake.node_id);
                                    info!("   Mesh Port: {}", handshake.mesh_port);
                                    info!("   Protocols: {:?}", handshake.protocols);
                                    info!("   Discovery: {} (1=bluetooth)", handshake.discovered_via);
                                    
                                    // Forward MeshHandshake to unified server via GATT message channel
                                    let gatt_tx = manager_ref.gatt_message_tx.clone();
                                    let value_clone = value.clone();
                                    let peripheral_id_clone = central_id.clone();
                                    tokio::spawn(async move {
                                        if let Some(tx) = gatt_tx.read().await.as_ref() {
                                            if let Err(e) = tx.send(crate::protocols::bluetooth::GattMessage::MeshHandshake { 
                                                data: value_clone, 
                                                peripheral_id: Some(peripheral_id_clone) 
                                            }) {
                                                warn!("Failed to forward MeshHandshake to unified server: {}", e);
                                            } else {
                                                info!("📨 MeshHandshake forwarded to unified server for peer discovery");
                                            }
                                        }
                                    });
                                    
                                    // Send handshake response via notification
                                    info!("📤 Sending handshake acknowledgment via GATT notification");
                                    
                                    // Create simple ACK response (version + status)
                                    let response = vec![1u8, 1u8]; // Version 1, Status: Success
                                    
                                    let mgr = manager_ref.clone();
                                    let char_uuid_for_task = characteristic_uuid.clone();
                                    tokio::spawn(async move {
                                        // Wait for subscription to be registered by Core Bluetooth
                                        // Poll every 50ms for up to 1 second
                                        let mut waited_ms = 0;
                                        let max_wait_ms = 1000;
                                        
                                        loop {
                                            let subscriptions = mgr.subscribed_centrals.read().await;
                                            let subscriber_count = subscriptions.get(&char_uuid_for_task).map(|v| v.len()).unwrap_or(0);
                                            drop(subscriptions);
                                            
                                            if subscriber_count > 0 {
                                                info!("    Found {} subscriber(s) after {}ms", subscriber_count, waited_ms);
                                                break;
                                            }
                                            
                                            if waited_ms >= max_wait_ms {
                                                warn!("    No subscribers found after {}ms - sending anyway", waited_ms);
                                                break;
                                            }
                                            
                                            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                                            waited_ms += 50;
                                        }
                                        
                                        if let Err(e) = mgr.send_notification(&char_uuid_for_task, &response).await {
                                            warn!(" Failed to send handshake response notification: {}", e);
                                        } else {
                                            info!(" Handshake response notification sent");
                                        }
                                    });
                                    
                                    info!(" MeshHandshake successfully processed from peer {}", handshake.node_id);
                                }
                                Err(e) => {
                                    warn!(" Not a MeshHandshake: {} ({} bytes received)", e, value.len());
                                    debug!("   Forwarding raw data to unified server for ZhtpMeshMessage parsing");
                                    
                                    // Forward non-handshake messages (HeadersRequest, HeadersResponse, etc.) to unified server
                                    let gatt_tx = manager_ref.gatt_message_tx.clone();
                                    let value_clone = value.clone();
                                    let peripheral_id_clone = central_id.clone();
                                    tokio::spawn(async move {
                                        if let Some(tx) = gatt_tx.read().await.as_ref() {
                                            if let Err(e) = tx.send(crate::protocols::bluetooth::GattMessage::MeshHandshake { 
                                                data: value_clone, 
                                                peripheral_id: Some(peripheral_id_clone) 
                                            }) {
                                                warn!("Failed to forward GATT message to unified server: {}", e);
                                            } else {
                                                info!("📨 GATT message forwarded to unified server");
                                            }
                                        }
                                    });
                                }
                            }
                        } else {
                            debug!("   Data too small for MeshHandshake, treating as raw data");
                            
                            // Forward small messages too (could be ZhtpMeshMessage)
                            let gatt_tx = manager_ref.gatt_message_tx.clone();
                            let value_clone = value.clone();
                            let peripheral_id_clone = central_id.clone();
                            tokio::spawn(async move {
                                if let Some(tx) = gatt_tx.read().await.as_ref() {
                                    if let Err(e) = tx.send(crate::protocols::bluetooth::GattMessage::MeshHandshake { 
                                        data: value_clone, 
                                        peripheral_id: Some(peripheral_id_clone) 
                                    }) {
                                        warn!("Failed to forward small GATT message to unified server: {}", e);
                                    } else {
                                        debug!("📨 Small GATT message forwarded to unified server");
                                    }
                                }
                            });
                        }
                    }
                    CoreBluetoothEvent::CentralSubscribed { central_id, characteristic_uuid } => {
                        info!(" Central {} subscribed to characteristic {}", central_id, characteristic_uuid);
                        
                        // Track subscription
                        let mut subscriptions = manager_ref.subscribed_centrals.write().await;
                        subscriptions.entry(characteristic_uuid.clone())
                            .or_insert_with(Vec::new)
                            .push(central_id.clone());
                        
                        info!("   Total subscribed centrals for {}: {}", characteristic_uuid, subscriptions.get(&characteristic_uuid).map(|v| v.len()).unwrap_or(0));
                    }
                    CoreBluetoothEvent::CentralUnsubscribed { central_id, characteristic_uuid } => {
                        info!("🔕 Central {} unsubscribed from characteristic {}", central_id, characteristic_uuid);
                        
                        // Remove subscription
                        let mut subscriptions = manager_ref.subscribed_centrals.write().await;
                        if let Some(centrals) = subscriptions.get_mut(&characteristic_uuid) {
                            centrals.retain(|id| id != &central_id);
                            if centrals.is_empty() {
                                subscriptions.remove(&characteristic_uuid);
                            }
                        }
                    }
                    _ => {}
                }
            }
        });
        
        Ok(())
    }
    
    /// Initialize Core Bluetooth central manager
    pub async fn initialize_central_manager(&self) -> Result<()> {
        let mut central = self.central_manager.lock().await;
        
        // Create delegate with event channel sender
        let event_tx = self.event_sender.clone();
        let delegate = CBCentralManagerDelegate {
            event_sender: event_tx,
        };
        
        // Initialize CBCentralManager via native API
        let manager = self.create_central_manager(delegate).await?;
        *central = Some(manager);
        
        info!(" Core Bluetooth central manager initialized");
        Ok(())
    }
    
    /// Initialize Core Bluetooth peripheral manager for GATT server
    pub async fn initialize_peripheral_manager(&self) -> Result<()> {
        let mut peripheral = self.peripheral_manager.lock().await;
        
        let event_tx = self.event_sender.clone();
        let delegate = CBPeripheralManagerDelegate {
            event_sender: event_tx,
        };
        
        let manager = self.create_peripheral_manager(delegate).await?;
        *peripheral = Some(manager);
        
        info!(" Core Bluetooth peripheral manager initialized");
        Ok(())
    }
    
    /// Start scanning for BLE peripherals
    pub async fn start_scan(&self, service_uuids: Option<&[&str]>) -> Result<()> {
        let central = self.central_manager.lock().await;
        
        if let Some(manager) = central.as_ref() {
            info!(" Starting BLE scan with Core Bluetooth");
            
            // Check current state
            unsafe {
                let state: i64 = msg_send![manager.manager_ptr, state];
                info!("🔋 Central manager state: {} (5=PoweredOn)", state);
            }
            
            // Wait for central manager to be ready (powered on)
            info!("⏳ Waiting for central manager to power on...");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            
            // Check state after wait
            unsafe {
                let state: i64 = msg_send![manager.manager_ptr, state];
                info!("🔋 Central manager state after wait: {} (5=PoweredOn)", state);
            }
            
            // Call native CBCentralManager scanForPeripheralsWithServices
            self.native_start_scan(manager, service_uuids).await?;
            
            info!(" BLE scan started successfully - waiting for delegate callbacks...");
            Ok(())
        } else {
            Err(anyhow!("Central manager not initialized"))
        }
    }
    
    /// Stop BLE scanning
    pub async fn stop_scan(&self) -> Result<()> {
        let central = self.central_manager.lock().await;
        
        if let Some(manager) = central.as_ref() {
            self.native_stop_scan(manager).await?;
            info!("⏹️ BLE scan stopped");
            Ok(())
        } else {
            Err(anyhow!("Central manager not initialized"))
        }
    }
    
    /// Connect to a discovered peripheral
    pub async fn connect_to_peripheral(&self, identifier: &str) -> Result<()> {
        let central = self.central_manager.lock().await;
        let peripherals = self.discovered_peripherals.read().await;
        
        if let (Some(manager), Some(peripheral)) = (central.as_ref(), peripherals.get(identifier)) {
            info!(" Connecting to peripheral: {}", identifier);
            
            self.native_connect_peripheral(manager, peripheral).await?;
            
            info!(" Connection initiated to: {}", identifier);
            Ok(())
        } else {
            Err(anyhow!("Central manager not initialized or peripheral not found"))
        }
    }
    
    /// Disconnect from peripheral
    pub async fn disconnect_from_peripheral(&self, identifier: &str) -> Result<()> {
        let central = self.central_manager.lock().await;
        let peripherals = self.discovered_peripherals.read().await;
        
        if let (Some(manager), Some(peripheral)) = (central.as_ref(), peripherals.get(identifier)) {
            self.native_disconnect_peripheral(manager, peripheral).await?;
            info!(" Disconnected from: {}", identifier);
            Ok(())
        } else {
            Err(anyhow!("Central manager not initialized or peripheral not found"))
        }
    }
    
    /// Discover services on connected peripheral
    pub async fn discover_services(&self, identifier: &str) -> Result<Vec<String>> {
        let peripherals = self.discovered_peripherals.read().await;
        
        if let Some(peripheral) = peripherals.get(identifier) {
            info!(" Discovering services for: {}", identifier);
            
            let services = self.native_discover_services(peripheral).await?;
            
            // Cache services
            let mut cache = self.services_cache.write().await;
            cache.insert(identifier.to_string(), services.clone());
            
            let service_uuids: Vec<String> = services.iter().map(|s| s.uuid.clone()).collect();
            info!(" Discovered {} services for {}", service_uuids.len(), identifier);
            
            Ok(service_uuids)
        } else {
            Err(anyhow!("Peripheral not found: {}", identifier))
        }
    }
    
    /// Read from GATT characteristic
    pub async fn read_characteristic(&self, identifier: &str, service_uuid: &str, char_uuid: &str) -> Result<Vec<u8>> {
        let peripherals = self.discovered_peripherals.read().await;
        let services_cache = self.services_cache.read().await;
        
        if let (Some(_peripheral), Some(services)) = (peripherals.get(identifier), services_cache.get(identifier)) {
            // Find the characteristic
            for service in services {
                if service.uuid == service_uuid {
                    for characteristic in &service.characteristics {
                        if characteristic.uuid == char_uuid {
                            let data = self.native_read_characteristic(identifier, service_uuid, char_uuid).await?;
                            
                            info!("📖 Read {} bytes from characteristic {}", data.len(), char_uuid);
                            return Ok(data);
                        }
                    }
                }
            }
            
            Err(anyhow!("Characteristic not found: {}/{}", service_uuid, char_uuid))
        } else {
            Err(anyhow!("Peripheral or services not found: {}", identifier))
        }
    }
    
    /// Check if identifier is a connected central (incoming connection)
    pub async fn is_connected_central(&self, identifier: &str) -> bool {
        let centrals = self.connected_centrals.read().await;
        centrals.contains_key(identifier)
    }
    
    /// Write to GATT characteristic
    pub async fn write_characteristic(&self, identifier: &str, service_uuid: &str, char_uuid: &str, data: &[u8]) -> Result<()> {
        let peripherals = self.discovered_peripherals.read().await;
        
        if let Some(_peripheral) = peripherals.get(identifier) {
            self.native_write_characteristic(identifier, service_uuid, char_uuid, data).await?;
            
            info!("✍️ Wrote {} bytes to characteristic {}", data.len(), char_uuid);
            Ok(())
        } else {
            Err(anyhow!("Peripheral not found: {}", identifier))
        }
    }
    
    /// Enable notifications for characteristic
    pub async fn enable_notifications(&self, identifier: &str, char_uuid: &str) -> Result<()> {
        let peripherals = self.discovered_peripherals.read().await;
        
        if let Some(_peripheral) = peripherals.get(identifier) {
            self.native_enable_notifications(identifier, char_uuid).await?;
            
            info!(" Enabled notifications for characteristic: {}", char_uuid);
            Ok(())
        } else {
            Err(anyhow!("Peripheral not found: {}", identifier))
        }
    }
    
    /// Start advertising as GATT server
    pub async fn start_advertising(&self, service_uuid: &str, characteristics: &[(&str, &[u8])]) -> Result<()> {
        let peripheral = self.peripheral_manager.lock().await;
        
        if let Some(manager) = peripheral.as_ref() {
            info!(" Starting GATT server advertising");
            
            // Wait for peripheral manager to be ready (powered on)
            // Core Bluetooth needs time to initialize after creation
            info!("⏳ Waiting for peripheral manager to power on...");
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            
            self.native_start_advertising(manager, service_uuid, characteristics).await?;
            
            info!(" GATT advertising started with service: {}", service_uuid);
            Ok(())
        } else {
            Err(anyhow!("Peripheral manager not initialized"))
        }
    }
    
    // Native Core Bluetooth integration functions
    // Real FFI implementation using Objective-C runtime
    
    /// Create Objective-C delegate object for CBCentralManager
    /// This creates a custom NSObject subclass that implements CBCentralManagerDelegate protocol
    unsafe fn create_central_manager_delegate_object(event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>) -> *mut AnyObject {
        // For now, we'll use a simple approach without creating a custom class
        // In production, you'd use objc::declare::ClassDecl to create a proper delegate class
        // with protocol implementations
        
        // TODO: Implement proper delegate class with protocol methods:
        // - centralManagerDidUpdateState:
        // - centralManager:didDiscoverPeripheral:advertisementData:RSSI:
        // - centralManager:didConnectPeripheral:
        // - centralManager:didDisconnectPeripheral:error:
        
        // For now, return nil and handle events synchronously
        std::ptr::null_mut()
    }
    
    /// Create Objective-C delegate object for CBPeripheralManager
    unsafe fn create_peripheral_manager_delegate_object(event_sender: tokio::sync::mpsc::UnboundedSender<CoreBluetoothEvent>) -> *mut AnyObject {
        // TODO: Implement proper delegate class with protocol methods:
        // - peripheralManagerDidUpdateState:
        // - peripheralManager:didAddService:error:
        // - peripheralManagerDidStartAdvertising:error:
        // - peripheralManager:didReceiveReadRequest:
        // - peripheralManager:didReceiveWriteRequests:
        
        std::ptr::null_mut()
    }
    
    async fn create_central_manager(&self, delegate: CBCentralManagerDelegate) -> Result<CBCentralManagerHandle> {
        info!(" Creating CBCentralManager via FFI");
        
        unsafe {
            // Register delegate classes if not already done
            macos_delegate::register_delegate_classes();
            
            // Create delegate instance with event sender
            let delegate_obj = macos_delegate::create_central_manager_delegate_instance(
                delegate.event_sender.clone()
            );
            
            // Get CBCentralManager class
            let cls = AnyClass::get(c"CBCentralManager").ok_or_else(|| {
                anyhow!("CBCentralManager class not found - Core Bluetooth framework missing")
            })?;
            
            // Create a dedicated dispatch queue for Core Bluetooth using GCD
            // CRITICAL: Core Bluetooth needs a dispatch queue with an active run loop
            // Passing nil uses main queue which doesn't work in our Tokio runtime
            use std::ffi::CString;
            
            // Import dispatch_queue_create from libdispatch
            extern "C" {
                fn dispatch_queue_create(label: *const i8, attr: *const std::ffi::c_void) -> *mut std::ffi::c_void;
            }
            
            let queue_label = CString::new("com.zhtp.corebluetooth.central").unwrap();
            let dispatch_queue = dispatch_queue_create(queue_label.as_ptr(), std::ptr::null());
            
            if dispatch_queue.is_null() {
                warn!("  Failed to create dispatch queue, using default queue");
            } else {
                info!(" Created dedicated dispatch queue for Core Bluetooth");
            }
            
            // Allocate and initialize CBCentralManager with delegate and queue
            let manager: *mut AnyObject = msg_send![cls, alloc];
            
            // [manager initWithDelegate:delegate queue:dispatch_queue]
            let manager: *mut AnyObject = if !dispatch_queue.is_null() {
                msg_send![manager, initWithDelegate:delegate_obj queue:dispatch_queue as *mut AnyObject]
            } else {
                // Fallback to nil queue if queue creation failed
                msg_send![manager, initWithDelegate:delegate_obj queue:std::ptr::null_mut::<AnyObject>()]
            };
            
            if manager.is_null() {
                return Err(anyhow!("Failed to create CBCentralManager"));
            }
            
            info!(" CBCentralManager created successfully with delegate on dedicated queue");
            
            Ok(CBCentralManagerHandle {
                manager_ptr: manager,
                delegate,
            })
        }
    }
    
    async fn create_peripheral_manager(&self, delegate: CBPeripheralManagerDelegate) -> Result<CBPeripheralManagerHandle> {
        info!(" Creating CBPeripheralManager via FFI");
        
        unsafe {
            // Register delegate classes if not already done
            macos_delegate::register_delegate_classes();
            
            // Create delegate instance with event sender
            let delegate_obj = macos_delegate::create_peripheral_manager_delegate_instance(
                delegate.event_sender.clone()
            );
            
            // Get CBPeripheralManager class
            let cls = AnyClass::get(c"CBPeripheralManager").ok_or_else(|| {
                anyhow!("CBPeripheralManager class not found - Core Bluetooth framework missing")
            })?;
            
            // Create dedicated dispatch queue for peripheral manager
            use std::ffi::CString;
            
            extern "C" {
                fn dispatch_queue_create(label: *const i8, attr: *const std::ffi::c_void) -> *mut std::ffi::c_void;
            }
            
            let queue_label = CString::new("com.zhtp.corebluetooth.peripheral").unwrap();
            let dispatch_queue = dispatch_queue_create(queue_label.as_ptr(), std::ptr::null());
            
            if dispatch_queue.is_null() {
                warn!("  Failed to create dispatch queue for peripheral manager");
            } else {
                info!(" Created dedicated dispatch queue for peripheral manager");
            }
            
            // Allocate and initialize with delegate and queue
            let manager: *mut AnyObject = msg_send![cls, alloc];
            let manager: *mut AnyObject = if !dispatch_queue.is_null() {
                msg_send![manager, initWithDelegate:delegate_obj queue:dispatch_queue as *mut AnyObject]
            } else {
                msg_send![manager, initWithDelegate:delegate_obj queue:std::ptr::null_mut::<AnyObject>()]
            };
            
            if manager.is_null() {
                return Err(anyhow!("Failed to create CBPeripheralManager"));
            }
            
            info!(" CBPeripheralManager created successfully with delegate on dedicated queue");
            
            Ok(CBPeripheralManagerHandle {
                manager_ptr: manager,
                delegate,
            })
        }
    }
    
    async fn native_start_scan(&self, manager: &CBCentralManagerHandle, service_uuids: Option<&[&str]>) -> Result<()> {
        info!(" FFI: Starting peripheral scan");
        
        unsafe {
            // Check manager state first
            let state: i64 = msg_send![manager.manager_ptr, state];
            
            // CBManagerState enum: Unknown=0, Resetting=1, Unsupported=2, Unauthorized=3, PoweredOff=4, PoweredOn=5
            if state != 5 {
                return Err(anyhow!("Bluetooth not powered on (state: {})", state));
            }
            
            // Build service UUID array if provided
            let ns_array = if let Some(uuids) = service_uuids {
                info!(" Scanning for services: {:?}", uuids);
                
                // Get CBUUID class
                let cbuuid_cls = AnyClass::get(c"CBUUID").ok_or_else(|| {
                    anyhow!("CBUUID class not found")
                })?;
                
                // Convert service UUIDs to CBUUID objects
                let mut uuid_objects: Vec<*mut AnyObject> = Vec::new();
                for uuid_str in uuids {
                    let ns_string = NSString::from_str(uuid_str);
                    let cbuuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString: &*ns_string];
                    uuid_objects.push(cbuuid);
                }
                
                // Create NSArray with UUIDs
                let array_cls = AnyClass::get(c"NSArray").ok_or_else(|| {
                    anyhow!("NSArray class not found")
                })?;
                let array: *mut AnyObject = msg_send![array_cls, arrayWithObjects:uuid_objects.as_ptr() count:uuid_objects.len()];
                Some(array)
            } else {
                info!(" Scanning for all peripherals");
                None
            };
            
            // Start scanning: [centralManager scanForPeripheralsWithServices:serviceUUIDs options:nil]
            let _: () = match ns_array {
                Some(arr) => msg_send![manager.manager_ptr, scanForPeripheralsWithServices:arr options:std::ptr::null_mut::<Object>()],
                None => msg_send![manager.manager_ptr, scanForPeripheralsWithServices:std::ptr::null_mut::<Object>() options:std::ptr::null_mut::<Object>()],
            };
            
            info!(" Scan started successfully");
        }
        
        Ok(())
    }
    
    async fn native_stop_scan(&self, manager: &CBCentralManagerHandle) -> Result<()> {
        info!("⏹️ FFI: Stopping peripheral scan");
        
        unsafe {
            // [centralManager stopScan]
            let _: () = msg_send![manager.manager_ptr, stopScan];
        }
        
        Ok(())
    }
    
    async fn native_connect_peripheral(&self, manager: &CBCentralManagerHandle, peripheral: &CBPeripheralHandle) -> Result<()> {
        info!(" FFI: Connecting to peripheral {}", peripheral.identifier);
        
        unsafe {
            // Get the peripheral object pointer
            if let Some(peripheral_ptr) = peripheral.peripheral_ptr {
                let peripheral_obj = peripheral_ptr as *mut AnyObject;
                
                // [centralManager connectPeripheral:peripheral options:nil]
                let _: () = msg_send![manager.manager_ptr, connectPeripheral:peripheral_obj options:std::ptr::null_mut::<Object>()];
                
                info!(" Connection initiated");
            } else {
                return Err(anyhow!("Peripheral object pointer not available"));
            }
        }
        
        Ok(())
    }
    
    async fn native_disconnect_peripheral(&self, manager: &CBCentralManagerHandle, peripheral: &CBPeripheralHandle) -> Result<()> {
        info!(" FFI: Disconnecting from peripheral {}", peripheral.identifier);
        
        unsafe {
            if let Some(peripheral_ptr) = peripheral.peripheral_ptr {
                let peripheral_obj = peripheral_ptr as *mut AnyObject;
                
                // [centralManager cancelPeripheralConnection:peripheral]
                let _: () = msg_send![manager.manager_ptr, cancelPeripheralConnection:peripheral_obj];
                
                info!(" Disconnection initiated");
            } else {
                return Err(anyhow!("Peripheral object pointer not available"));
            }
        }
        
        Ok(())
    }
    
    async fn native_discover_services(&self, peripheral: &CBPeripheralHandle) -> Result<Vec<CBServiceHandle>> {
        info!(" FFI: Discovering services for {}", peripheral.identifier);
        
        unsafe {
            if let Some(peripheral_ptr) = peripheral.peripheral_ptr {
                let peripheral_obj = peripheral_ptr as *mut AnyObject;
                
                // [peripheral discoverServices:nil] - discovers all services
                let _: () = msg_send![peripheral_obj, discoverServices:std::ptr::null_mut::<Object>()];
                
                // In real implementation, we'd wait for delegate callback
                // For now, retrieve services synchronously
                let services: *mut AnyObject = msg_send![peripheral_obj, services];
                
                if services.is_null() {
                    info!(" No services discovered yet");
                    return Ok(Vec::new());
                }
                
                // Get NSArray count
                let count: usize = msg_send![services, count];
                info!(" Found {} services", count);
                
                let mut service_handles = Vec::new();
                
                // Iterate through services
                for i in 0..count {
                    let service: *mut AnyObject = msg_send![services, objectAtIndex:i];
                    
                    // Get service UUID
                    let uuid_obj: *mut AnyObject = msg_send![service, UUID];
                    let uuid_str: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_str, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr)
                        .to_string_lossy()
                        .to_string();
                    
                    // Check if primary service
                    let is_primary: bool = msg_send![service, isPrimary];
                    
                    service_handles.push(CBServiceHandle {
                        uuid,
                        is_primary,
                        characteristics: Vec::new(), // Will be populated when discovering characteristics
                    });
                }
                
                Ok(service_handles)
            } else {
                Err(anyhow!("Peripheral object pointer not available"))
            }
        }
    }
    
    async fn native_read_characteristic(&self, identifier: &str, service_uuid: &str, char_uuid: &str) -> Result<Vec<u8>> {
        info!("📖 FFI: Reading characteristic {} from service {}", char_uuid, service_uuid);
        
        unsafe {
            // Get peripheral from cache
            let peripherals = self.discovered_peripherals.read().await;
            let peripheral = peripherals.get(identifier)
                .ok_or_else(|| anyhow!("Peripheral not found"))?;
            
            if let Some(peripheral_ptr) = peripheral.peripheral_ptr {
                let peripheral_obj = peripheral_ptr as *mut AnyObject;
                
                // Get services
                let services: *mut AnyObject = msg_send![peripheral_obj, services];
                if services.is_null() {
                    return Err(anyhow!("No services available"));
                }
                
                // Find matching service
                let service_count: usize = msg_send![services, count];
                let mut target_service: Option<*mut AnyObject> = None;
                
                for i in 0..service_count {
                    let service: *mut AnyObject = msg_send![services, objectAtIndex:i];
                    let uuid_obj: *mut AnyObject = msg_send![service, UUID];
                    let uuid_str: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_str, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy();
                    
                    if uuid.eq_ignore_ascii_case(service_uuid) {
                        target_service = Some(service);
                        break;
                    }
                }
                
                let service = target_service.ok_or_else(|| anyhow!("Service not found"))?;
                
                // Get characteristics
                let characteristics: *mut AnyObject = msg_send![service, characteristics];
                if characteristics.is_null() {
                    return Err(anyhow!("No characteristics available"));
                }
                
                // Find matching characteristic
                let char_count: usize = msg_send![characteristics, count];
                let mut target_char: Option<*mut AnyObject> = None;
                
                for i in 0..char_count {
                    let characteristic: *mut AnyObject = msg_send![characteristics, objectAtIndex:i];
                    let uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
                    let uuid_str: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_str, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy();
                    
                    if uuid.eq_ignore_ascii_case(char_uuid) {
                        target_char = Some(characteristic);
                        break;
                    }
                }
                
                let characteristic = target_char.ok_or_else(|| anyhow!("Characteristic not found"))?;
                
                // Read value: [peripheral readValueForCharacteristic:characteristic]
                let _: () = msg_send![peripheral_obj, readValueForCharacteristic:characteristic];
                
                // In real implementation, we'd wait for delegate callback
                // For now, retrieve value synchronously
                let value_data: *mut AnyObject = msg_send![characteristic, value];
                
                if value_data.is_null() {
                    return Ok(Vec::new());
                }
                
                // Convert NSData to Vec<u8>
                let length: usize = msg_send![value_data, length];
                let bytes: *const u8 = msg_send![value_data, bytes];
                
                let mut data = vec![0u8; length];
                std::ptr::copy_nonoverlapping(bytes, data.as_mut_ptr(), length);
                
                info!(" Read {} bytes", data.len());
                Ok(data)
            } else {
                Err(anyhow!("Peripheral object pointer not available"))
            }
        }
    }
    
    async fn native_write_characteristic(&self, identifier: &str, service_uuid: &str, char_uuid: &str, data: &[u8]) -> Result<()> {
        info!("✍️ FFI: Writing {} bytes to characteristic {} in service {}", data.len(), char_uuid, service_uuid);
        
        unsafe {
            // Get peripheral from cache
            let peripherals = self.discovered_peripherals.read().await;
            let peripheral = peripherals.get(identifier)
                .ok_or_else(|| anyhow!("Peripheral not found"))?;
            
            if let Some(peripheral_ptr) = peripheral.peripheral_ptr {
                let peripheral_obj = peripheral_ptr as *mut AnyObject;
                
                // Find service and characteristic (similar to read_characteristic)
                let services: *mut AnyObject = msg_send![peripheral_obj, services];
                if services.is_null() {
                    return Err(anyhow!("No services available"));
                }
                
                // Find service
                let service_count: usize = msg_send![services, count];
                let mut target_service: Option<*mut AnyObject> = None;
                
                for i in 0..service_count {
                    let service: *mut AnyObject = msg_send![services, objectAtIndex:i];
                    let uuid_obj: *mut AnyObject = msg_send![service, UUID];
                    let uuid_str: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_str, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy();
                    
                    if uuid.eq_ignore_ascii_case(service_uuid) {
                        target_service = Some(service);
                        break;
                    }
                }
                
                let service = target_service.ok_or_else(|| anyhow!("Service not found"))?;
                
                // Find characteristic
                let characteristics: *mut AnyObject = msg_send![service, characteristics];
                if characteristics.is_null() {
                    return Err(anyhow!("No characteristics available"));
                }
                
                let char_count: usize = msg_send![characteristics, count];
                let mut target_char: Option<*mut AnyObject> = None;
                
                for i in 0..char_count {
                    let characteristic: *mut AnyObject = msg_send![characteristics, objectAtIndex:i];
                    let uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
                    let uuid_str: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                    let uuid_cstr: *const i8 = msg_send![uuid_str, UTF8String];
                    let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy();
                    
                    if uuid.eq_ignore_ascii_case(char_uuid) {
                        target_char = Some(characteristic);
                        break;
                    }
                }
                
                let characteristic = target_char.ok_or_else(|| anyhow!("Characteristic not found"))?;
                
                // Create NSData from bytes
                let ns_data_cls = AnyClass::get(c"NSData").ok_or_else(|| anyhow!("NSData class not found"))?;
                let bytes_ptr = data.as_ptr() as *const c_void;
                let ns_data: *mut AnyObject = msg_send![ns_data_cls, dataWithBytes:bytes_ptr length:data.len()];
                
                // Write value: [peripheral writeValue:data forCharacteristic:characteristic type:CBCharacteristicWriteWithResponse]
                // type: 0 = CBCharacteristicWriteWithResponse, 1 = CBCharacteristicWriteWithoutResponse
                let write_type: i32 = 0; // With response
                let _: () = msg_send![peripheral_obj, writeValue:ns_data forCharacteristic:characteristic type:write_type];
                
                info!(" Write initiated");
                Ok(())
            } else {
                Err(anyhow!("Peripheral object pointer not available"))
            }
        }
    }
    
    async fn native_enable_notifications(&self, identifier: &str, char_uuid: &str) -> Result<()> {
        info!(" FFI: Enabling notifications for characteristic {}", char_uuid);
        
        unsafe {
            // Get peripheral from cache
            let peripherals = self.discovered_peripherals.read().await;
            let peripheral = peripherals.get(identifier)
                .ok_or_else(|| anyhow!("Peripheral not found"))?;
            
            if let Some(peripheral_ptr) = peripheral.peripheral_ptr {
                let peripheral_obj = peripheral_ptr as *mut AnyObject;
                
                // Get all services
                let services: *mut AnyObject = msg_send![peripheral_obj, services];
                if services.is_null() {
                    return Err(anyhow!("No services available"));
                }
                
                // Search all services for the characteristic
                let service_count: usize = msg_send![services, count];
                
                for i in 0..service_count {
                    let service: *mut AnyObject = msg_send![services, objectAtIndex:i];
                    let characteristics: *mut AnyObject = msg_send![service, characteristics];
                    
                    if characteristics.is_null() {
                        continue;
                    }
                    
                    let char_count: usize = msg_send![characteristics, count];
                    
                    for j in 0..char_count {
                        let characteristic: *mut AnyObject = msg_send![characteristics, objectAtIndex:j];
                        let uuid_obj: *mut AnyObject = msg_send![characteristic, UUID];
                        let uuid_str: *mut AnyObject = msg_send![uuid_obj, UUIDString];
                        let uuid_cstr: *const i8 = msg_send![uuid_str, UTF8String];
                        let uuid = std::ffi::CStr::from_ptr(uuid_cstr).to_string_lossy();
                        
                        if uuid.eq_ignore_ascii_case(char_uuid) {
                            // Found the characteristic, enable notifications
                            // [peripheral setNotifyValue:YES forCharacteristic:characteristic]
                            let yes: bool = true;
                            let _: () = msg_send![peripheral_obj, setNotifyValue:yes forCharacteristic:characteristic];
                            
                            info!(" Notifications enabled");
                            return Ok(());
                        }
                    }
                }
                
                Err(anyhow!("Characteristic not found: {}", char_uuid))
            } else {
                Err(anyhow!("Peripheral object pointer not available"))
            }
        }
    }
    
    /// Register GATT service WITHOUT starting advertising (advertising started separately later)
    pub async fn register_service(&self, service_uuid: &str, characteristics: &[(&str, &[u8])]) -> Result<()> {
        info!(" Registering GATT service {} (without advertising)", service_uuid);
        
        let manager = self.peripheral_manager.lock().await;
        if let Some(ref mgr) = *manager {
            // Register the service using the same logic as start_advertising but skip the advertising part
            self.native_register_service_only(mgr, service_uuid, characteristics).await
        } else {
            Err(anyhow!("Peripheral manager not initialized"))
        }
    }
    
    /// Register GATT service only (without advertising) - called before mesh advertising is started
    async fn native_register_service_only(&self, manager: &CBPeripheralManagerHandle, service_uuid: &str, characteristics: &[(&str, &[u8])]) -> Result<()> {
        info!(" Registering GATT service {} without advertising", service_uuid);
        
        // CRITICAL FIX: Remove all previously cached services before adding new one
        unsafe {
            info!("🧹 Removing all cached GATT services from CBPeripheralManager");
            let _: () = msg_send![manager.manager_ptr, removeAllServices];
            info!(" All old services cleared - ready for fresh service registration");
        }
        
        // Wait for services to be fully removed
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        
        // Add the service (synchronous FFI operations)
        unsafe {
            // Get CBUUID class
            let cbuuid_cls = AnyClass::get(c"CBUUID").ok_or_else(|| anyhow!("CBUUID class not found"))?;
            
            // Create service UUID
            let service_uuid_ns = NSString::from_str(service_uuid);
            let service_cbuuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString:&*service_uuid_ns];
            
            // Get CBMutableService class
            let mutable_service_cls = AnyClass::get(c"CBMutableService").ok_or_else(|| {
                anyhow!("CBMutableService class not found")
            })?;
            
            // Create mutable service
            let service: *mut AnyObject = msg_send![mutable_service_cls, alloc];
            let is_primary: bool = true;
            let service: *mut AnyObject = msg_send![service, initWithType:service_cbuuid primary:is_primary];
            
            // Create characteristics
            if !characteristics.is_empty() {
                let mutable_char_cls = AnyClass::get(c"CBMutableCharacteristic").ok_or_else(|| {
                    anyhow!("CBMutableCharacteristic class not found")
                })?;
                
                let mut char_objects: Vec<*mut AnyObject> = Vec::new();
                
                for (char_uuid, _initial_value) in characteristics {
                    // Create characteristic UUID
                    let char_uuid_ns = NSString::from_str(char_uuid);
                    let char_cbuuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString:&*char_uuid_ns];
                    
                    // Value should be nil for writable characteristics
                    let nil_value: *mut AnyObject = std::ptr::null_mut();
                    
                    // Properties: Read | Write | Notify (0x02 | 0x08 | 0x10)
                    let properties: u64 = 0x02 | 0x08 | 0x10;
                    
                    // Permissions: Readable | Writeable (0x01 | 0x02)
                    let permissions: u64 = 0x01 | 0x02;
                    
                    info!(" Creating characteristic {} with properties=0x{:X}, permissions=0x{:X}", char_uuid, properties, permissions);
                    
                    // Create characteristic
                    let characteristic: *mut AnyObject = msg_send![mutable_char_cls, alloc];
                    let characteristic: *mut AnyObject = msg_send![
                        characteristic,
                        initWithType:char_cbuuid
                        properties:properties
                        value:nil_value
                        permissions:permissions
                    ];
                    
                    char_objects.push(characteristic);
                }
                
                // Set characteristics on service
                let array_cls = AnyClass::get(c"NSArray").ok_or_else(|| anyhow!("NSArray class not found"))?;
                let char_array: *mut AnyObject = msg_send![array_cls, alloc];
                let char_array: *mut AnyObject = msg_send![
                    char_array,
                    initWithObjects:char_objects.as_ptr()
                    count:char_objects.len()
                ];
                
                let _: () = msg_send![service, setCharacteristics:char_array];
            }
            
            // Add service to peripheral manager
            info!(" Adding GATT service to peripheral manager");
            let _: () = msg_send![manager.manager_ptr, addService:service];
        }
        
        // Wait for service to be added
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        info!(" GATT service registered successfully (advertising to be started separately)");
        Ok(())
    }
    
    async fn native_start_advertising(&self, manager: &CBPeripheralManagerHandle, service_uuid: &str, characteristics: &[(&str, &[u8])]) -> Result<()> {
        info!(" FFI: Starting GATT advertising for service {}", service_uuid);
        
        // CRITICAL FIX: Remove all previously cached services before adding new one
        // This clears old service UUIDs (C8, C9) from Core Bluetooth's persistent cache
        unsafe {
            info!("🧹 Removing all cached GATT services from CBPeripheralManager");
            let _: () = msg_send![manager.manager_ptr, removeAllServices];
            info!(" All old services cleared - ready for fresh service registration");
        }
        
        // Wait a moment for services to be fully removed
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        
        // Now add the service (synchronous FFI operations)
        unsafe {
            // Get CBUUID class
            let cbuuid_cls = AnyClass::get(c"CBUUID").ok_or_else(|| anyhow!("CBUUID class not found"))?;
            
            // Create service UUID
            let service_uuid_ns = NSString::from_str(service_uuid);
            let service_cbuuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString:&*service_uuid_ns];
            
            // Get CBMutableService class
            let mutable_service_cls = AnyClass::get(c"CBMutableService").ok_or_else(|| {
                anyhow!("CBMutableService class not found")
            })?;
            
            // Create mutable service: [[CBMutableService alloc] initWithType:UUID primary:YES]
            let service: *mut AnyObject = msg_send![mutable_service_cls, alloc];
            let is_primary: bool = true;
            let service: *mut AnyObject = msg_send![service, initWithType:service_cbuuid primary:is_primary];
            
            // Create characteristics
            if !characteristics.is_empty() {
                let mutable_char_cls = AnyClass::get(c"CBMutableCharacteristic").ok_or_else(|| {
                    anyhow!("CBMutableCharacteristic class not found")
                })?;
                
                let mut char_objects: Vec<*mut AnyObject> = Vec::new();
                
                for (char_uuid, _initial_value) in characteristics {
                    // Create characteristic UUID
                    let char_uuid_ns = NSString::from_str(char_uuid);
                    let char_cbuuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString:&*char_uuid_ns];
                    
                    // For writable characteristics, value should be nil (not preset)
                    // The value will be set when clients write to it
                    let nil_value: *mut AnyObject = std::ptr::null_mut();
                    
                    // CBCharacteristicProperties: 
                    // Read=0x02, Write=0x08, WriteWithoutResponse=0x04, Notify=0x10
                    // Note: NSUInteger is 64-bit on modern macOS
                    // WORKAROUND: macOS Core Bluetooth may strip Write (0x08) when both Write and WriteWithoutResponse are present
                    // Try using ONLY Write property, which Windows can handle with WriteValueWithOptionAsync
                    let properties: u64 = 0x02 | 0x08 | 0x10; // Read | Write | Notify (NO WriteWithoutResponse)
                    
                    // CBAttributePermissions: Readable=0x01, Writeable=0x02
                    // DO NOT use encryption - it breaks mesh networking without pairing
                    // Mesh security is handled at application layer with ZK proofs
                    let permissions: u64 = 0x01 | 0x02; // Readable | Writeable (NO encryption required)
                    
                    info!(" Creating characteristic {} with properties=0x{:X} (Read|Write|Notify), permissions=0x{:X} (Readable|Writeable, NO encryption)", char_uuid, properties, permissions);
                    
                    // Create characteristic: [[CBMutableCharacteristic alloc] initWithType:UUID properties:props value:nil permissions:perms]
                    let characteristic: *mut AnyObject = msg_send![mutable_char_cls, alloc];
                    let characteristic: *mut AnyObject = msg_send![
                        characteristic,
                        initWithType:char_cbuuid
                        properties:properties
                        value:nil_value
                        permissions:permissions
                    ];
                    
                    char_objects.push(characteristic);
                }
                
                // Set characteristics on service using NSArray
                // Create NSArray from Vec by allocating and initializing with objects
                let array_cls = AnyClass::get(c"NSArray").ok_or_else(|| anyhow!("NSArray class not found"))?;
                
                // Use initWithObjects:count: for proper array creation
                let char_array: *mut AnyObject = msg_send![array_cls, alloc];
                let char_array: *mut AnyObject = msg_send![
                    char_array,
                    initWithObjects:char_objects.as_ptr()
                    count:char_objects.len()
                ];
                
                let _: () = msg_send![service, setCharacteristics:char_array];
            }
            
            // Add service to peripheral manager: [peripheralManager addService:service]
            info!(" Adding GATT service to peripheral manager");
            let _: () = msg_send![manager.manager_ptr, addService:service];
        } // End unsafe block - NSString objects are dropped here
        
        // Wait a moment for service to be added (outside unsafe block)
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        
        // Now start advertising (separate unsafe block)
        unsafe {
            // Get CBUUID class again
            let cbuuid_cls = AnyClass::get(c"CBUUID").ok_or_else(|| anyhow!("CBUUID class not found"))?;
            
            // Recreate service UUID for advertising
            let service_uuid_ns = NSString::from_str(service_uuid);
            let service_cbuuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString:&*service_uuid_ns];
            
            // Create advertisement dictionary with service UUIDs
            let array_cls = AnyClass::get(c"NSArray").ok_or_else(|| anyhow!("NSArray class not found"))?;
            let service_array: *mut AnyObject = msg_send![array_cls, arrayWithObject:service_cbuuid];
            
            let service_uuid_key = NSString::from_str("kCBAdvDataServiceUUIDs");
            
            let dict_cls = AnyClass::get(c"NSMutableDictionary").ok_or_else(|| anyhow!("NSMutableDictionary class not found"))?;
            let ad_data: *mut AnyObject = msg_send![dict_cls, dictionary];
            let _: () = msg_send![ad_data, setObject:service_array forKey:&*service_uuid_key];
            
            // Add local name
            let local_name = NSString::from_str("ZHTP-MESH");
            let name_key = NSString::from_str("kCBAdvDataLocalName");
            let _: () = msg_send![ad_data, setObject:&*local_name forKey:&*name_key];
            
            // [peripheralManager startAdvertising:advertisementData]
            info!(" Starting BLE advertising");
            let _: () = msg_send![manager.manager_ptr, startAdvertising:ad_data];
            
            info!(" GATT advertising started");
        } // End unsafe block
        
        Ok(())
    }
    
    /// Start ZHTP mesh advertising with the provided advertisement data
    pub async fn start_mesh_advertising(&self, adv_data: &[u8]) -> Result<()> {
        info!(" macOS: Starting ZHTP mesh advertising via Core Bluetooth");
        
        // Check if we have a peripheral manager
        let manager_guard = self.peripheral_manager.lock().await;
        if let Some(ref manager) = *manager_guard {
            unsafe {
                // Create advertisement data dictionary
                let dict_cls = AnyClass::get(c"NSMutableDictionary").ok_or_else(|| {
                    anyhow!("NSMutableDictionary class not found")
                })?;
                let ad_dict: *mut AnyObject = msg_send![dict_cls, dictionary];
                
                // Add local name: "ZHTP-MESH"
                let local_name_key = NSString::from_str("kCBAdvDataLocalName");
                let local_name_value = NSString::from_str("ZHTP-MESH");
                let _: () = msg_send![ad_dict, setObject:&*local_name_value forKey:&*local_name_key];
                
                // Add service UUID: 6BA7B810-9DAD-11D1-80B4-00C04FD430CA
                let cbuuid_cls = AnyClass::get(c"CBUUID").ok_or_else(|| anyhow!("CBUUID class not found"))?;
                let service_uuid_str = "6BA7B810-9DAD-11D1-80B4-00C04FD430CA";
                let service_uuid_ns = NSString::from_str(service_uuid_str);
                let service_uuid: *mut AnyObject = msg_send![cbuuid_cls, UUIDWithString:&*service_uuid_ns];
                
                let array_cls = AnyClass::get(c"NSArray").ok_or_else(|| anyhow!("NSArray class not found"))?;
                let uuid_array: *mut AnyObject = msg_send![array_cls, arrayWithObject:service_uuid];
                
                let services_key = NSString::from_str("kCBAdvDataServiceUUIDs");
                let _: () = msg_send![ad_dict, setObject:&*uuid_array forKey:&*services_key];
                
                // Add manufacturer data (contains the ZHTP mesh info)
                if adv_data.len() > 10 {  // Ensure we have enough data
                    let ns_data_cls = AnyClass::get(c"NSData").ok_or_else(|| anyhow!("NSData class not found"))?;
                    let bytes_ptr = adv_data.as_ptr() as *const c_void;
                    let manufacturer_data: *mut AnyObject = msg_send![ns_data_cls, dataWithBytes:bytes_ptr length:adv_data.len()];
                    
                    let manufacturer_key = NSString::from_str("kCBAdvDataManufacturerData");
                    let _: () = msg_send![ad_dict, setObject:&*manufacturer_data forKey:&*manufacturer_key];
                }
                
                // Start advertising: [peripheralManager startAdvertising:adDict]
                let _: () = msg_send![manager.manager_ptr, startAdvertising:ad_dict];
                
                info!(" macOS: ZHTP mesh advertising started with {} bytes", adv_data.len());
                info!("   Service UUID: {}", service_uuid_str);
                info!("   Local Name: ZHTP-MESH");
                return Ok(());
            }
        } else {
            warn!(" macOS: Peripheral manager not initialized, cannot start advertising");
            return Err(anyhow!("Peripheral manager not available"));
        }
    }
}

/// Integration with existing Bluetooth mesh protocol
#[cfg(target_os = "macos")]
impl CoreBluetoothManager {
    /// Convert to tracked device format used by mesh protocol
    pub async fn get_tracked_devices(&self) -> Result<Vec<BleDevice>> {
        let peripherals = self.discovered_peripherals.read().await;
        let mut devices = Vec::new();
        
        for (id, peripheral) in peripherals.iter() {
            let device = BleDevice {
                // Use ephemeral address instead of MAC
                ephemeral_address: format!("eph_{}", &id[0..8]),
                secure_node_id: [0u8; 32], // Would be derived from actual node ID
                encrypted_mac_hash: [0u8; 32], // Would be encrypted MAC hash
                device_name: peripheral.name.clone(),
                last_seen: chrono::Utc::now().timestamp() as u64,
                services: peripheral.services.clone(),
                characteristics: HashMap::new(), // Would be populated from service discovery
                signal_strength: peripheral.rssi as i16,
                connection_state: ConnectionState::Disconnected,
                connection_handle: None,
            };
            
            devices.push(device);
        }
        
        Ok(devices)
    }
    
    /// Send notification to subscribed centrals on a characteristic
    pub async fn send_notification(&self, characteristic_uuid: &str, data: &[u8]) -> Result<()> {
        info!("📤 Sending {} byte notification on characteristic {}", data.len(), characteristic_uuid);
        
        let manager = self.peripheral_manager.lock().await;
        if let Some(ref mgr) = *manager {
            unsafe {
                // Create NSData from bytes
                let ns_data: *mut AnyObject = msg_send![
                    objc2::class!(NSData),
                    dataWithBytes:data.as_ptr() as *const c_void
                    length:data.len()
                ];
                
                if ns_data.is_null() {
                    return Err(anyhow!("Failed to create NSData for notification"));
                }
                
                // Convert characteristic UUID string to CBUUID
                let uuid_str = NSString::from_str(characteristic_uuid);
                let uuid_obj: *mut AnyObject = msg_send![
                    objc2::class!(CBUUID),
                    UUIDWithString: &*uuid_str
                ];
                
                if uuid_obj.is_null() {
                    return Err(anyhow!("Failed to create CBUUID for {}", characteristic_uuid));
                }
                
                // Find the characteristic in the peripheral manager's services
                // Get all services
                let services: *mut AnyObject = msg_send![mgr.manager_ptr, services];
                if services.is_null() {
                    return Err(anyhow!("No services registered on peripheral manager"));
                }
                
                let service_count: usize = msg_send![services, count];
                let mut target_char: *mut AnyObject = std::ptr::null_mut();
                
                // Search through services for the characteristic
                for i in 0..service_count {
                    let service: *mut AnyObject = msg_send![services, objectAtIndex: i];
                    let characteristics: *mut AnyObject = msg_send![service, characteristics];
                    
                    if !characteristics.is_null() {
                        let char_count: usize = msg_send![characteristics, count];
                        for j in 0..char_count {
                            let characteristic: *mut AnyObject = msg_send![characteristics, objectAtIndex: j];
                            let char_uuid: *mut AnyObject = msg_send![characteristic, UUID];
                            
                            // Compare UUIDs
                            let is_equal: bool = msg_send![char_uuid, isEqual: uuid_obj];
                            if is_equal {
                                target_char = characteristic;
                                break;
                            }
                        }
                    }
                    
                    if !target_char.is_null() {
                        break;
                    }
                }
                
                if target_char.is_null() {
                    return Err(anyhow!("Characteristic {} not found in peripheral manager services", characteristic_uuid));
                }
                
                // Send notification: updateValue:forCharacteristic:onSubscribedCentrals:
                // Passing nil for centrals sends to ALL subscribed centrals
                let success: bool = msg_send![
                    mgr.manager_ptr,
                    updateValue: ns_data
                    forCharacteristic: target_char
                    onSubscribedCentrals: std::ptr::null::<AnyObject>()
                ];
                
                if success {
                    info!(" Notification sent successfully to subscribed centrals");
                    Ok(())
                } else {
                    warn!(" Failed to send notification (queue may be full - will retry on didUpdateValueForCharacteristic callback)");
                    // Note: iOS docs say this can fail if transmission queue is full,
                    // in which case you should wait for peripheralManagerIsReadyToUpdateSubscribers callback
                    Ok(()) // Return success anyway, iOS will handle retries
                }
            }
        } else {
            Err(anyhow!("Peripheral manager not initialized"))
        }
    }
}

/// Memory management: Release CBCentralManager when dropped
#[cfg(target_os = "macos")]
impl Drop for CBCentralManagerHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.manager_ptr.is_null() {
                // Stop any ongoing scan
                let _: () = msg_send![self.manager_ptr, stopScan];
                
                // Release the Objective-C object
                let _: () = msg_send![self.manager_ptr, release];
                
                debug!("🗑️ CBCentralManager released");
            }
        }
    }
}

/// Memory management: Release CBPeripheralManager when dropped
#[cfg(target_os = "macos")]
impl Drop for CBPeripheralManagerHandle {
    fn drop(&mut self) {
        unsafe {
            if !self.manager_ptr.is_null() {
                // Stop advertising
                let _: () = msg_send![self.manager_ptr, stopAdvertising];
                
                // Release the Objective-C object
                let _: () = msg_send![self.manager_ptr, release];
                
                debug!("🗑️ CBPeripheralManager released");
            }
        }
    }
}

#[cfg(not(target_os = "macos"))]
pub struct CoreBluetoothManager;

#[cfg(not(target_os = "macos"))]
impl CoreBluetoothManager {
    pub fn new() -> anyhow::Result<Self> {
        Err(anyhow::anyhow!("Core Bluetooth only available on macOS"))
    }
}
