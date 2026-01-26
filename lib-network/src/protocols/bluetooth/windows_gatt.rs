// Windows Runtime GATT Implementation
// Comprehensive Windows BLE GATT client/server using WinRT APIs

#[cfg(target_os = "windows")]
use anyhow::{Result, anyhow};
#[cfg(target_os = "windows")]
use tracing::{info, warn, error};
#[cfg(target_os = "windows")]
use std::collections::{HashMap, HashSet};
#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use tokio::sync::{RwLock, Mutex, mpsc};
#[cfg(target_os = "windows")]
use serde::{Serialize, Deserialize};

#[cfg(all(target_os = "windows", feature = "windows-gatt"))]
use windows::{
    core::*,
    Foundation::*,
    Foundation::Collections::*,
    Storage::Streams::*,
    Devices::Bluetooth::*,
    Devices::Bluetooth::GenericAttributeProfile::*,
    Devices::Bluetooth::Advertisement::*,
};

// Import common Bluetooth utilities
#[cfg(target_os = "windows")]
use crate::protocols::bluetooth::device::{BleDevice, CharacteristicInfo, BluetoothDeviceInfo};
#[cfg(all(target_os = "windows", feature = "windows-gatt"))]
use crate::protocols::bluetooth::common::{parse_uuid_to_guid, format_mac_address};
use crate::constants::BLE_MESH_SERVICE_UUID;
#[cfg(target_os = "windows")]
use crate::protocols::bluetooth::gatt::{GattMessage, GattOperation, supports_operation, parse_characteristic_properties};

/// Windows Runtime BLE GATT Manager
#[cfg(target_os = "windows")]
pub struct WindowsGattManager {
    /// Bluetooth LE advertisement watcher for device discovery (conditionally compiled)
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    advertisement_watcher: Arc<Mutex<Option<BluetoothLEAdvertisementWatcher>>>,
    #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
    advertisement_watcher: Arc<Mutex<Option<()>>>,
    
    /// Connected BLE devices cache (conditionally compiled)
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    connected_devices: Arc<RwLock<HashMap<String, BluetoothLEDevice>>>,
    #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
    connected_devices: Arc<RwLock<HashMap<String, ()>>>,
    
    /// GATT services cache per device (conditionally compiled)
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    services_cache: Arc<RwLock<HashMap<String, Vec<GattDeviceService>>>>,
    #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
    services_cache: Arc<RwLock<HashMap<String, Vec<()>>>>,
    
    /// GATT characteristics cache per device (conditionally compiled)
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    characteristics_cache: Arc<RwLock<HashMap<String, Vec<GattCharacteristic>>>>,
    #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
    characteristics_cache: Arc<RwLock<HashMap<String, Vec<()>>>>,
    
    /// Notification event handlers
    notification_handlers: Arc<RwLock<HashMap<String, Box<dyn Fn(Vec<u8>) + Send + Sync>>>>,
    
    /// GATT server (peripheral mode) (conditionally compiled)
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    gatt_service_provider: Arc<Mutex<Option<GattServiceProvider>>>,
    #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
    gatt_service_provider: Arc<Mutex<Option<()>>>,
    
    /// Local GATT services for advertising (conditionally compiled)
    #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
    local_services: Arc<RwLock<HashMap<String, GattLocalService>>>,
    #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
    local_services: Arc<RwLock<HashMap<String, ()>>>,
    
    /// Event channel for notifications
    event_tx: Arc<Mutex<Option<mpsc::UnboundedSender<GattEvent>>>>,
    
    /// Store notification handlers AND characteristics to keep them alive
    /// CRITICAL: Windows WinRT handlers only stay alive while the GattCharacteristic object lives!
    /// We must store both the token AND the characteristic object itself.
    notification_event_handlers: Arc<std::sync::Mutex<Vec<Box<dyn std::any::Any + Send>>>>,
    
    /// Track discovered devices to prevent duplicates
    discovered_devices: Arc<RwLock<HashSet<String>>>,
}

/// GATT events for cross-thread communication
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub enum GattEvent {
    DeviceDiscovered {
        address: String,
        name: Option<String>,
        rssi: i16,
        advertisement_data: Vec<u8>,
    },
    DeviceConnected {
        address: String,
    },
    DeviceDisconnected {
        address: String,
    },
    CharacteristicValueChanged {
        device_address: String,
        char_uuid: String,
        value: Vec<u8>,
    },
    ReadRequest {
        device_address: String,
        char_uuid: String,
    },
    WriteRequest {
        device_address: String,
        char_uuid: String,
        value: Vec<u8>,
    },
}

/// Windows GATT service information
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsGattService {
    pub uuid: String,
    pub handle: u16,
    pub characteristics: Vec<WindowsGattCharacteristic>,
}

/// Windows GATT characteristic information
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WindowsGattCharacteristic {
    pub uuid: String,
    pub handle: u16,
    pub properties: Vec<String>,
    pub value: Option<Vec<u8>>,
}

#[cfg(target_os = "windows")]
impl WindowsGattManager {
    /// Create new Windows GATT manager
    pub fn new() -> Result<Self> {
        info!(" Initializing Windows GATT Manager");
        
        Ok(WindowsGattManager {
            advertisement_watcher: Arc::new(Mutex::new(None)),
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
            services_cache: Arc::new(RwLock::new(HashMap::new())),
            characteristics_cache: Arc::new(RwLock::new(HashMap::new())),
            notification_handlers: Arc::new(RwLock::new(HashMap::new())),
            gatt_service_provider: Arc::new(Mutex::new(None)),
            local_services: Arc::new(RwLock::new(HashMap::new())),
            event_tx: Arc::new(Mutex::new(None)),
            notification_event_handlers: Arc::new(std::sync::Mutex::new(Vec::new())),
            discovered_devices: Arc::new(RwLock::new(HashSet::new())),
        })
    }
    
    /// Initialize Bluetooth radio and check availability
    pub async fn initialize(&self) -> Result<()> {
        info!(" Initializing Windows Bluetooth stack");
        
        #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
        {
            // Note: Bluetooth radio state checking skipped to avoid dependency issues
            // GATT functionality will be attempted and will fail gracefully if radio is off
            info!(" Windows GATT manager initialized - radio state will be checked during operation");
        }
        
        #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
        {
            info!(" Windows GATT feature not enabled, using fallback implementation");
        }
        
        info!(" Windows Bluetooth stack initialized");
        Ok(())
    }
    
    /// Set event channel for notifications
    pub async fn set_event_channel(&self, tx: mpsc::UnboundedSender<GattEvent>) -> Result<()> {
        *self.event_tx.lock().await = Some(tx);
        info!(" Windows GATT event channel configured");
        Ok(())
    }
    
    /// Create a new event channel and return the receiver
    pub fn create_event_channel() -> (mpsc::UnboundedSender<GattEvent>, mpsc::UnboundedReceiver<GattEvent>) {
        mpsc::unbounded_channel()
    }
    
    /// Start BLE device discovery
    pub async fn start_discovery(&self) -> Result<()> {
        info!(" Starting Windows BLE device discovery");
        
        #[cfg(feature = "windows-gatt")]
        {
            let mut watcher_lock = self.advertisement_watcher.lock().await;
            
            if watcher_lock.is_some() {
                warn!(" BLE discovery already running");
                return Ok(());
            }
            
            // Create advertisement watcher
            let watcher = BluetoothLEAdvertisementWatcher::new()?;
            
            // Set scanning mode for active discovery
            watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
            
            // Set up event handlers
            let event_tx = self.event_tx.clone();
            let discovered_devices = self.discovered_devices.clone();
            let received_handler = TypedEventHandler::new({
                let event_tx = event_tx.clone();
                let discovered_devices = discovered_devices.clone();
                move |_sender: &Option<BluetoothLEAdvertisementWatcher>, args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                    if let Some(args) = args {
                        if let Ok(tx_lock) = event_tx.try_lock() {
                            if let Some(ref tx) = *tx_lock {
                                let address = format!("{:012X}", args.BluetoothAddress().unwrap_or(0));
                                let rssi = args.RawSignalStrengthInDBm().unwrap_or(-100);
                                
                                // Extract local name
                                let name = args.Advertisement().ok()
                                    .and_then(|ad| ad.LocalName().ok())
                                    .map(|s| s.to_string());
                                
                                // Extract Service UUIDs from advertisement
                                let mut has_zhtp_service = false;
                                
                                let zhtp_uuid_clean = BLE_MESH_SERVICE_UUID.replace("-", "").to_uppercase();

                                if let Ok(advertisement) = args.Advertisement() {
                                    if let Ok(service_uuids) = advertisement.ServiceUuids() {
                                        for i in 0..service_uuids.Size().unwrap_or(0) {
                                            if let Ok(uuid) = service_uuids.GetAt(i) {
                                                let uuid_str = format!("{:?}", uuid).to_uppercase();
                                                
                                                // Check for ZHTP service UUID
                                                // Remove all formatting characters and compare the hex digits
                                                let clean_uuid = uuid_str.replace("-", "").replace("{", "").replace("}", "");

                                                if clean_uuid.contains(&zhtp_uuid_clean) {
                                                    has_zhtp_service = true;
                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                                
                                // Only send event if this is a ZHTP device AND we haven't seen it before
                                if has_zhtp_service {
                                    // Check if we've already discovered this device
                                    if let Ok(mut discovered) = discovered_devices.try_write() {
                                        if discovered.insert(address.clone()) {
                                            // First time seeing this device - log and send event
                                            info!(" Windows: Discovered ZHTP device {} RSSI: {}", 
                                                name.as_deref().unwrap_or(&address), rssi);
                                            
                                            // Create advertisement data marker for ZHTP
                                            let ad_data = vec![0x02, 0x01, 0x06, 0xFF, 0xFF]; // Flags + ZHTP marker
                                            
                                            if let Err(_) = tx.send(GattEvent::DeviceDiscovered {
                                                address,
                                                name,
                                                rssi,
                                                advertisement_data: ad_data,
                                            }) {
                                                // Handle send error if needed
                                            }
                                        }
                                        // If insert returned false, we've already seen this device - skip event
                                    }
                                }
                            }
                        }
                    }
                    Ok(())
                }
            });
            
            watcher.Received(&received_handler)?;
            
            // Start scanning
            watcher.Start()?;
            *watcher_lock = Some(watcher);
            
            info!(" Windows BLE discovery started");
        }
        
        Ok(())
    }
    
    /// Stop BLE device discovery
    pub async fn stop_discovery(&self) -> Result<()> {
        #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
        {
            let mut watcher_lock: tokio::sync::MutexGuard<Option<BluetoothLEAdvertisementWatcher>> = 
                self.advertisement_watcher.lock().await;
            
            if let Some(watcher) = watcher_lock.take() {
                watcher.Stop()?;
                info!(" Windows BLE discovery stopped");
            }
            
            // Clear discovered devices set for next scan
            self.discovered_devices.write().await.clear();
        }
        
        #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
        {
            let mut watcher_lock = self.advertisement_watcher.lock().await;
            *watcher_lock = None;
            self.discovered_devices.write().await.clear();
            info!(" Fallback BLE discovery stopped");
        }
        
        Ok(())
    }
    
    /// Connect to a BLE device by address
    pub async fn connect_device(&self, address: &str) -> Result<()> {
        info!(" Connecting to Windows BLE device: {}", address);
        
        #[cfg(feature = "windows-gatt")]
        {
            let bluetooth_address = self.parse_bluetooth_address(address)?;
            
            // Get BLE device from address
            let device_async = BluetoothLEDevice::FromBluetoothAddressAsync(bluetooth_address)?;
            let device = device_async.get()?;
            
            // Check connection status
            let connection_status = device.ConnectionStatus()?;
            if connection_status == BluetoothConnectionStatus::Connected {
                info!(" Device {} already connected", address);
            } else {
                // Request connection by accessing GATT services
                let services_async = device.GetGattServicesAsync()?;
                let services_result = services_async.get()?;
                
                if services_result.Status()? == GattCommunicationStatus::Success {
                    info!(" Successfully connected to device {}", address);
                } else {
                    return Err(anyhow!("Failed to connect to device {}", address));
                }
            }
            
            // Cache the connected device
            let mut devices = self.connected_devices.write().await;
            devices.insert(address.to_string(), device);
            
            // Notify connection event
            if let Some(tx) = self.event_tx.lock().await.as_ref() {
                let _ = tx.send(GattEvent::DeviceConnected {
                    address: address.to_string(),
                });
            }
        }
        
        Ok(())
    }
    
    /// Disconnect from a BLE device
    pub async fn disconnect_device(&self, address: &str) -> Result<()> {
        #[cfg(all(target_os = "windows", feature = "windows-gatt"))]
        {
            let mut devices: tokio::sync::RwLockWriteGuard<HashMap<String, BluetoothLEDevice>> = 
                self.connected_devices.write().await;
            
            if devices.remove(address).is_some() {
                info!(" Disconnected from device: {}", address);
                
                // Notify disconnection event
                if let Some(tx) = self.event_tx.lock().await.as_ref() {
                    let _ = tx.send(GattEvent::DeviceDisconnected {
                        address: address.to_string(),
                    });
                }
            }
        }
        
        #[cfg(not(all(target_os = "windows", feature = "windows-gatt")))]
        {
            let mut devices = self.connected_devices.write().await;
            devices.remove(address);
            info!(" Fallback disconnection from device: {}", address);
        }
        
        Ok(())
    }
    
    /// Discover GATT services on connected device
    pub async fn discover_services(&self, address: &str) -> Result<Vec<String>> {
        info!(" Discovering GATT services on device: {}", address);
        
        #[cfg(feature = "windows-gatt")]
        {
            let devices = self.connected_devices.read().await;
            let device = devices.get(address)
                .ok_or_else(|| anyhow!("Device not connected: {}", address))?;
            
            let services_async = device.GetGattServicesAsync()?;
            let services_result = services_async.get()?;
            
            if services_result.Status()? != GattCommunicationStatus::Success {
                return Err(anyhow!("GATT service discovery failed"));
            }
            
            let services = services_result.Services()?;
            let mut service_uuids = Vec::new();
            
            for i in 0..services.Size()? {
                let service = services.GetAt(i)?;
                let uuid = service.Uuid()?;
                let uuid_str = format!("{:?}", uuid);
                
                service_uuids.push(uuid_str);
            }
            
            info!(" Discovered {} GATT services", service_uuids.len());
            return Ok(service_uuids);
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            // Fallback with mock services
            Ok(vec!["00001800-0000-1000-8000-00805f9b34fb".to_string()])
        }
    }
    
    /// Read from GATT characteristic
    pub async fn read_characteristic(&self, address: &str, service_uuid: &str, char_uuid: &str) -> Result<Vec<u8>> {
        info!("📖 Reading GATT characteristic {}/{} on {}", service_uuid, char_uuid, address);
        
        #[cfg(feature = "windows-gatt")]
        {
            let characteristic = self.find_characteristic(address, service_uuid, char_uuid).await?;
            
            let read_async = characteristic.ReadValueAsync()?;
            let read_result = read_async.get()?;
            
            if read_result.Status()? != GattCommunicationStatus::Success {
                return Err(anyhow!("GATT read failed with status: {:?}", read_result.Status()));
            }
            
            let buffer = read_result.Value()?;
            let data_reader = DataReader::FromBuffer(&buffer)?;
            
            let length = buffer.Length()? as usize;
            let mut data = vec![0u8; length];
            data_reader.ReadBytes(&mut data)?;
            
            info!(" Read {} bytes from characteristic", data.len());
            Ok(data)
        }
        
        #[cfg(not(feature = "windows-gatt"))]
        {
            Ok(vec![0x48, 0x65, 0x6c, 0x6c, 0x6f]) // "Hello"
        }
    }
    
    /// Write to GATT characteristic
    pub async fn write_characteristic(&self, address: &str, service_uuid: &str, char_uuid: &str, data: &[u8]) -> Result<()> {
        info!("✍️ Writing {} bytes to GATT characteristic {}/{} on {}", data.len(), service_uuid, char_uuid, address);
        
        #[cfg(feature = "windows-gatt")]
        {
            info!(" Step 1: Finding characteristic...");
            let characteristic = match self.find_characteristic(address, service_uuid, char_uuid).await {
                Ok(c) => {
                    info!(" Step 1: Characteristic found");
                    c
                }
                Err(e) => {
                    return Err(anyhow!("Step 1 failed - Cannot find characteristic {}/{} on {}: {}", service_uuid, char_uuid, address, e));
                }
            };
            
            info!(" Step 2: Creating data buffer...");
            let data_writer = DataWriter::new().map_err(|e| anyhow!("Step 2 failed - DataWriter creation: {}", e))?;
            data_writer.WriteBytes(data).map_err(|e| anyhow!("Step 2 failed - WriteBytes: {}", e))?;
            let buffer = data_writer.DetachBuffer().map_err(|e| anyhow!("Step 2 failed - DetachBuffer: {}", e))?;
            info!(" Step 2: Buffer created with {} bytes", data.len());
            
            // Check characteristic properties for write type
            info!(" Step 3: Checking characteristic properties...");
            let properties = characteristic.CharacteristicProperties().map_err(|e| anyhow!("Step 3 failed - Cannot get properties: {}", e))?;
            info!(" Properties: {:?}", properties);
            
            let can_write = (properties & GattCharacteristicProperties::Write).0 != 0;
            let can_write_no_response = (properties & GattCharacteristicProperties::WriteWithoutResponse).0 != 0;
            
            info!("   - Write (with response): {}", can_write);
            info!("   - Write (without response): {}", can_write_no_response);
            
            if !can_write && !can_write_no_response {
                return Err(anyhow!("Step 3 failed - Characteristic does not support writing! Properties: {:?}", properties));
            }
            
            // CRITICAL FIX: Prioritize Write (with response) over WriteWithoutResponse
            // macOS Core Bluetooth may strip WriteWithoutResponse when both properties are set
            // Windows WriteValueWithOptionAsync works better with explicit Write property
            if can_write {
                info!(" Step 3: Using Write (with response) for reliable mesh communication");
                
                info!("📤 Step 4: Initiating GATT write with response...");
                let write_async = characteristic.WriteValueWithOptionAsync(&buffer, GattWriteOption::WriteWithResponse)
                    .map_err(|e| anyhow!("Step 4 failed - WriteValueWithOptionAsync call failed: {} (HRESULT: 0x{:08X})", e, e.code().0))?;
                
                info!("⏳ Step 5: Waiting for write operation to complete...");
                let write_result = write_async.get()
                    .map_err(|e| anyhow!("Step 5 failed - Write operation failed: {} (HRESULT: 0x{:08X}). This often means: 1) Device disconnected during write, 2) Pairing required, or 3) Characteristic requires authentication.", e, e.code().0))?;
                
                info!(" Step 6: Checking write result status...");
                if write_result != GattCommunicationStatus::Success {
                    return Err(anyhow!("Step 6 failed - GATT write failed with status: {:?}. Device may have disconnected or rejected the write.", write_result));
                }
                
                info!(" Successfully wrote {} bytes to characteristic {}", data.len(), char_uuid);
            } else if can_write_no_response {
                warn!(" Step 3: Falling back to WriteWithoutResponse");
                
                // WriteWithoutResponse: Fire-and-forget write that doesn't wait for acknowledgment
                info!("📤 Step 4: Initiating GATT write (WriteWithoutResponse)...");
                
                // Use WriteValueWithOptionAsync with WriteWithoutResponse option
                // This sends the data without waiting for a response from the peripheral
                let write_async = characteristic.WriteValueWithOptionAsync(&buffer, GattWriteOption::WriteWithoutResponse)
                    .map_err(|e| anyhow!("Step 4 failed - WriteValueWithOptionAsync call failed: {} (HRESULT: 0x{:08X})", e, e.code().0))?;
                
                info!("⏳ Step 5: Waiting for write acknowledgment...");
                let write_result = write_async.get()
                    .map_err(|e| anyhow!("Step 5 failed - Write operation failed: {} (HRESULT: 0x{:08X}). This may indicate the characteristic requires Write permission (0x08) in addition to WriteWithoutResponse (0x04).", e, e.code().0))?;
                
                info!(" Step 6: Checking write result status...");
                if write_result != GattCommunicationStatus::Success {
                    return Err(anyhow!("Step 6 failed - GATT write returned status: {:?}", write_result));
                }
                
                info!(" Successfully wrote {} bytes to characteristic {} (WriteWithoutResponse)", data.len(), char_uuid);
            } else {
                return Err(anyhow!("Step 3 failed - Characteristic does not support writing! Properties: {:?}", properties));
            }
        }
        
        Ok(())
    }
    
    /// Enable notifications for GATT characteristic
    pub async fn enable_notifications(&self, address: &str, char_uuid: &str) -> Result<()> {
        info!(" Enabling notifications for characteristic {} on {}", char_uuid, address);
        
        #[cfg(feature = "windows-gatt")]
        {
            // Use on-demand service discovery instead of cache
            let devices = self.connected_devices.read().await;
            let device = devices.get(address)
                .ok_or_else(|| anyhow!("Device not connected: {}", address))?;
            
            // Discover services to find the characteristic
            let services_async = device.GetGattServicesAsync()?;
            let services_result = services_async.get()?;
            
            if services_result.Status()? != GattCommunicationStatus::Success {
                return Err(anyhow!("GATT service discovery failed"));
            }
            
            let services = services_result.Services()?;
            let target_char_uuid = GUID::from(char_uuid);
            let mut found_characteristic = None;
            
            // Search through all services for the characteristic
            for i in 0..services.Size()? {
                let service = services.GetAt(i)?;
                let chars_async = service.GetCharacteristicsAsync()?;
                let chars_result = chars_async.get()?;
                
                if chars_result.Status()? == GattCommunicationStatus::Success {
                    let characteristics = chars_result.Characteristics()?;
                    
                    for j in 0..characteristics.Size()? {
                        let characteristic = characteristics.GetAt(j)?;
                        if characteristic.Uuid()? == target_char_uuid {
                            found_characteristic = Some(characteristic);
                            break;
                        }
                    }
                }
                
                if found_characteristic.is_some() {
                    break;
                }
            }
            
            let characteristic = found_characteristic
                .ok_or_else(|| anyhow!("Characteristic {} not found", char_uuid))?;
            
            // Check if characteristic supports notifications
            let properties = characteristic.CharacteristicProperties()?;
            let can_notify = (properties & GattCharacteristicProperties::Notify).0 != 0 ||
                            (properties & GattCharacteristicProperties::Indicate).0 != 0;
            
            if !can_notify {
                return Err(anyhow!("Characteristic does not support notifications"));
            }
            
            // Set up value changed handler
            let event_tx = self.event_tx.clone();
            let device_addr = address.to_string();
            let characteristic_uuid = char_uuid.to_string();
            
            let handler = TypedEventHandler::new(move |_characteristic: &Option<GattCharacteristic>, args: &Option<GattValueChangedEventArgs>| {
                info!(" ValueChanged handler triggered!");
                if let Some(args) = args {
                    info!("   Args present, extracting buffer...");
                    if let Ok(buffer) = args.CharacteristicValue() {
                        info!("   Buffer obtained, length: {}", buffer.Length().unwrap_or(0));
                        if let Ok(data_reader) = DataReader::FromBuffer(&buffer) {
                            let length = buffer.Length().unwrap_or(0) as usize;
                            let mut data = vec![0u8; length];
                            if data_reader.ReadBytes(&mut data).is_ok() {
                                info!("   Data read successfully: {} bytes: {:?}", data.len(), data);
                                if let Ok(tx_lock) = event_tx.try_lock() {
                                    if let Some(ref tx) = *tx_lock {
                                        info!("   Sending to event channel...");
                                        let _ = tx.send(GattEvent::CharacteristicValueChanged {
                                            device_address: device_addr.clone(),
                                            char_uuid: characteristic_uuid.clone(),
                                            value: data,
                                        });
                                        info!("    Event sent to channel!");
                                    } else {
                                        warn!("    Event tx is None!");
                                    }
                                } else {
                                    warn!("    Failed to lock event_tx!");
                                }
                            } else {
                                warn!("    Failed to read bytes from buffer!");
                            }
                        } else {
                            warn!("    Failed to create DataReader from buffer!");
                        }
                    } else {
                        warn!("    Failed to get CharacteristicValue from args!");
                    }
                } else {
                    warn!("    Args is None!");
                }
                Ok(())
            });
            
            let token = characteristic.ValueChanged(&handler)?;
            info!("   ValueChanged handler registered, token received");
            
            // CRITICAL: Store BOTH the token AND the characteristic to keep the handler alive!
            // In Windows WinRT, handlers are only active while the GattCharacteristic object exists.
            // Storing just the token is NOT sufficient - the characteristic must stay in memory.
            if let Ok(mut handlers) = self.notification_event_handlers.lock() {
                handlers.push(Box::new(token));  // Store token
                handlers.push(Box::new(characteristic.clone()));  // Store characteristic object
                info!("   Handler token AND characteristic stored to keep subscription alive");
                info!("   Total items stored: {}", handlers.len());
            } else {
                warn!("    Failed to lock notification_event_handlers!");
            }
            
            // Enable notifications via CCCD
            let cccd_value = if (properties & GattCharacteristicProperties::Notify).0 != 0 {
                info!("   Using Notify mode for notifications");
                GattClientCharacteristicConfigurationDescriptorValue::Notify
            } else {
                info!("   Using Indicate mode for notifications");
                GattClientCharacteristicConfigurationDescriptorValue::Indicate
            };
            
            info!("   Writing CCCD to enable notifications...");
            let write_async = characteristic.WriteClientCharacteristicConfigurationDescriptorAsync(cccd_value)?;
            let write_result = write_async.get()?;
            
            if write_result != GattCommunicationStatus::Success {
                return Err(anyhow!("Failed to enable notifications: {:?}", write_result));
            }
            
            info!("   CCCD write completed successfully - peripheral should now send notifications");
            info!(" Notifications enabled for characteristic {}", char_uuid);
        }
        
        Ok(())
    }
    
    /// Start GATT server (peripheral mode)
    pub async fn start_gatt_server(&self, service_uuid: &str, characteristics: &[(&str, &[u8])]) -> Result<()> {
        info!(" Starting Windows GATT server with service {}", service_uuid);
        
        #[cfg(feature = "windows-gatt")]
        {
            // Create GATT service provider
            let service_uuid_guid = GUID::from(service_uuid);
            let provider_async = GattServiceProvider::CreateAsync(service_uuid_guid)?;
            let provider_result = provider_async.get()?;
            
            if provider_result.Error()? != BluetoothError::Success {
                return Err(anyhow!("Failed to create GATT service provider: {:?}", provider_result.Error()));
            }
            
            let service_provider = provider_result.ServiceProvider()?;
            let service = service_provider.Service()?;
            
            // Add characteristics
            for (char_uuid, initial_value) in characteristics {
                let char_uuid_guid = GUID::from(*char_uuid);
                
                // Create characteristic parameters
                let char_params = GattLocalCharacteristicParameters::new()?;
                char_params.SetCharacteristicProperties(
                    GattCharacteristicProperties::Read |
                    GattCharacteristicProperties::Write |
                    GattCharacteristicProperties::Notify
                )?;
                
                // Set initial value
                let data_writer = DataWriter::new()?;
                data_writer.WriteBytes(initial_value)?;
                let buffer = data_writer.DetachBuffer()?;
                char_params.SetStaticValue(&buffer)?;
                
                // Create characteristic
                let char_async = service.CreateCharacteristicAsync(char_uuid_guid, &char_params)?;
                let char_result = char_async.get()?;
                
                if char_result.Error()? != BluetoothError::Success {
                    return Err(anyhow!("Failed to create characteristic {}: {:?}", char_uuid, char_result.Error()));
                }
                
                let characteristic = char_result.Characteristic()?;
                
                // Set up event handlers for read/write requests
                let event_tx = self.event_tx.clone();
                let char_id = char_uuid.to_string();
                
                let read_handler = TypedEventHandler::new({
                    let event_tx = event_tx.clone();
                    let char_id = char_id.clone();
                    move |_char: &Option<GattLocalCharacteristic>, _args: &Option<GattReadRequestedEventArgs>| {
                        if let Ok(tx_lock) = event_tx.try_lock() {
                            if let Some(ref tx) = *tx_lock {
                                let _ = tx.send(GattEvent::ReadRequest {
                                    device_address: "local".to_string(),
                                    char_uuid: char_id.clone(),
                                });
                            }
                        }
                        Ok(())
                    }
                });
                
                let write_handler = TypedEventHandler::new({
                    let event_tx = event_tx.clone();
                    let char_id = char_id.clone();
                    move |_char: &Option<GattLocalCharacteristic>, args: &Option<GattWriteRequestedEventArgs>| {
                        if let Some(args) = args {
                            // Handle write request asynchronously - simplified for now
                            // In production, you'd await GetRequestAsync() properly
                            let mock_data = vec![0u8; 4]; // Placeholder data
                            if let Ok(tx_lock) = event_tx.try_lock() {
                                if let Some(ref tx) = *tx_lock {
                                    let _ = tx.send(GattEvent::WriteRequest {
                                        device_address: "local".to_string(),
                                        char_uuid: char_id.clone(),
                                        value: mock_data,
                                    });
                                }
                            }
                        }
                        Ok(())
                    }
                });
                
                characteristic.ReadRequested(&read_handler)?;
                characteristic.WriteRequested(&write_handler)?;
            }
            
            // Start advertising
            let advertising_params = GattServiceProviderAdvertisingParameters::new()?;
            advertising_params.SetIsConnectable(true)?;
            advertising_params.SetIsDiscoverable(true)?;
            
            service_provider.StartAdvertisingWithParameters(&advertising_params)?;
            
            // Store service provider
            *self.gatt_service_provider.lock().await = Some(service_provider);
            
            info!(" GATT server started and advertising");
        }
        
        Ok(())
    }
    
    /// Stop GATT server
    pub async fn stop_gatt_server(&self) -> Result<()> {
        let mut provider_lock = self.gatt_service_provider.lock().await;
        
        #[cfg(feature = "windows-gatt")]
        {
            if let Some(provider) = provider_lock.take() {
                provider.StopAdvertising()?;
                info!("⏹️ GATT server stopped");
            }
        }
        
        Ok(())
    }
    
    // Helper functions
    
    #[cfg(feature = "windows-gatt")]
    fn parse_bluetooth_address(&self, address: &str) -> Result<u64> {
        let clean_address = address.replace(":", "").replace("-", "");
        u64::from_str_radix(&clean_address, 16)
            .map_err(|e| anyhow!("Invalid Bluetooth address format: {}", e))
    }
    
    #[cfg(feature = "windows-gatt")]
    async fn find_characteristic(&self, address: &str, service_uuid: &str, char_uuid: &str) -> Result<GattCharacteristic> {
        info!(" Finding characteristic: service={}, char={}, device={}", service_uuid, char_uuid, address);
        
        // Get device and discover services on-demand (avoid caching non-Send WinRT types)
        let devices = self.connected_devices.read().await;
        let device = devices.get(address)
            .ok_or_else(|| anyhow!("Device not connected: {}", address))?;
        
        info!("📱 Device found in connected devices, discovering services...");
        
        let services_async = device.GetGattServicesAsync()?;
        let services_result = services_async.get()?;
        
        if services_result.Status()? != GattCommunicationStatus::Success {
            let status = services_result.Status()?;
            return Err(anyhow!("GATT service discovery failed for device {}: status={:?}", address, status));
        }
        
        let services = services_result.Services()?;
        let service_count = services.Size()?;
        info!(" Found {} services on device {}", service_count, address);
        
        let target_service_uuid = GUID::from(service_uuid);
        let target_char_uuid = GUID::from(char_uuid);
        
        info!(" Looking for service UUID: {:?}", target_service_uuid);
        info!(" Looking for char UUID: {:?}", target_char_uuid);
        
        for i in 0..service_count {
            let service = services.GetAt(i)?;
            let found_service_uuid = service.Uuid()?;
            info!("   Service {}: {:?}", i, found_service_uuid);
            
            if found_service_uuid == target_service_uuid {
                info!(" Found matching service! Discovering characteristics...");
                
                let chars_async = service.GetCharacteristicsAsync()?;
                let chars_result = chars_async.get()?;
                
                if chars_result.Status()? == GattCommunicationStatus::Success {
                    let characteristics = chars_result.Characteristics()?;
                    let char_count = characteristics.Size()?;
                    info!(" Found {} characteristics in service", char_count);
                    
                    for j in 0..char_count {
                        let characteristic = characteristics.GetAt(j)?;
                        let found_char_uuid = characteristic.Uuid()?;
                        let properties = characteristic.CharacteristicProperties()?;
                        info!("   Char {}: {:?} (properties: {:?})", j, found_char_uuid, properties);
                        
                        if found_char_uuid == target_char_uuid {
                            info!(" Found matching characteristic with properties: {:?}", properties);
                            return Ok(characteristic);
                        }
                    }
                    warn!(" Characteristic {} not found in service", char_uuid);
                } else {
                    let status = chars_result.Status()?;
                    warn!(" Failed to get characteristics: status={:?}", status);
                }
            }
        }
        
        Err(anyhow!("Characteristic not found: service={}, char={}, device={}", service_uuid, char_uuid, address))
    }
    
    #[cfg(feature = "windows-gatt")]
    async fn find_characteristic_by_uuid(&self, address: &str, char_uuid: &str) -> Result<GattCharacteristic> {
        let services_cache = self.services_cache.read().await;
        let services = services_cache.get(address)
            .ok_or_else(|| anyhow!("Services not cached for device: {}", address))?;
        
        let target_char_uuid = GUID::from(char_uuid);
        
        for service in services {
            let chars_async = service.GetCharacteristicsAsync()?;
            let chars_result = chars_async.get()?;
            
            if chars_result.Status()? == GattCommunicationStatus::Success {
                let characteristics = chars_result.Characteristics()?;
                
                for i in 0..characteristics.Size()? {
                    let characteristic = characteristics.GetAt(i)?;
                    if characteristic.Uuid()? == target_char_uuid {
                        return Ok(characteristic);
                    }
                }
            }
        }
        
        Err(anyhow!("Characteristic not found: {}", char_uuid))
    }
}

// Stub implementations for non-Windows platforms
#[cfg(not(target_os = "windows"))]
pub struct WindowsGattManager;

#[cfg(not(target_os = "windows"))]
impl WindowsGattManager {
    pub fn new() -> anyhow::Result<Self> {
        Err(anyhow::anyhow!("Windows GATT manager only available on Windows"))
    }
}
